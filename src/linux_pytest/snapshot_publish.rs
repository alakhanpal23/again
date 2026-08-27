//! Crash-safe publication of one already-built snapshot directory.
//!
//! This leaf owns only the publication protocol. It creates an owner-private
//! staging directory beneath a trusted directory descriptor and keeps the
//! inode pinned by an owned descriptor. The production path consumes a
//! charged guard after connector-owned recursive durability and four-view
//! verification, seals and fsyncs the staging container, publishes with
//! `renameat2(RENAME_NOREPLACE)`, fsyncs the parent, and reopens the final name
//! with constrained `openat2` resolution before returning it. A legacy
//! test-only seam retains the trusted durability callback used by leaf tests.
//!
//! It does not enumerate, copy, hash, validate, or make a tree immutable, and
//! it is not a sandbox. The connector must finish all tree construction,
//! recursive durability, and mandatory comparisons before charged
//! finalization. No materialized manifest entry may mutate after those
//! comparisons succeed; this leaf changes only the non-manifest staging
//! container to its sealed mode.
//! Physical staging directories must remain owned by the current effective
//! user; source uid/gid are logical manifest metadata, never applied by chown.
//! RAII cleanup is bounded and best-effort: limit exhaustion or uncertain
//! identity leaves the private stage for explicit scavenging rather than
//! risking deletion of a replacement object.

use std::cell::Cell;
use std::ffi::CStr;
use std::fmt;
use std::io;
use std::num::{NonZeroU8, NonZeroU16, NonZeroU32, NonZeroU64};
use std::os::fd::{BorrowedFd, OwnedFd};

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use super::isolation_qualification::{
    IsolationChildOnlyBrandV1, reopen_isolation_child_publication_path_v1,
};
use super::snapshot_connector::{SnapshotChargedErrorV1, SnapshotPublicationSessionV1};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use super::snapshot_manifest::{
    SnapshotChildMountNamespaceSealV1, SnapshotPreparedForkChildRootV1,
    SnapshotPreparedPublishedChildBindV1, SnapshotPreparedRetainedRootProjectionV1,
};
use super::snapshot_policy::SnapshotPipelineResourceErrorV1;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use super::snapshot_policy::{
    SnapshotChargedBytesV1, SnapshotFinalizationAttemptReservationV1,
    SnapshotPublishedChildBindReservationV1,
};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use super::snapshot_tree::SOURCE_TREE_REQUESTED_STATX_MASK_V1;
use super::snapshot_tree::SourceStatxV1;
use super::{Blake3Digest, FileContentDigest};

const STAGING_NAME_PREFIX: &[u8] = b".again-snapshot-stage-";
const STAGING_NONCE_HEX_BYTES: usize = 32;
const MAX_STAGING_NAME_WITH_NUL: u64 =
    (STAGING_NAME_PREFIX.len() + STAGING_NONCE_HEX_BYTES + 1) as u64;
const MAX_BASENAME_BYTES: usize = 255;
const CHILD_NAMESPACE_PATH_BYTES_V1: usize = 4096;
// Two names per frame are the smallest batch that preserves the frozen
// getdents/operation bounds under maximally partial positive directory reads.
// Keeping the batch fixed and small also bounds recursive stack retention.
const CLEANUP_NAME_BATCH_SIZE: usize = 2;
const CLEANUP_GETDENTS_BUFFER_BYTES: usize = 4096;
const DIRENT64_NAME_OFFSET: usize = 19;
const HARD_MAX_OPENAT2_ATTEMPTS: u8 = 32;
const HARD_MAX_SYSCALL_ATTEMPTS: u8 = 32;
const HARD_MAX_SOURCE_TREE_DEPTH: u16 = 256;
const HARD_MAX_CLEANUP_ENTRIES: u32 = 1024 * 1024;
const HARD_MAX_CLEANUP_RETAINED_NAME_BYTES: u64 = 512 * 1024 * 1024;
const SEALED_DIRECTORY_MODE: u32 = 0o500;
// The private staging container and the materialized tree root sit outside
// the source walker's descendant-depth budget.
const PUBLICATION_CONTAINER_LEVELS: u16 = 2;
const HARD_MAX_CLEANUP_DEPTH: u16 = HARD_MAX_SOURCE_TREE_DEPTH + PUBLICATION_CONTAINER_LEVELS;
// One descriptor pins an unpublished staging directory. Publication briefly
// owns that descriptor plus the constrained reopen of its final name. The
// later retained-root projection uses one name-relative `statx` through the
// already-pinned publication descriptor and opens no third descriptor, so the
// exact retained/projection peak remains two.
const MAX_LIVE_STAGED_FDS: u32 = 1;
const MAX_LIVE_PUBLICATION_FDS: u32 = 2;
// Cleanup retains the original staging descriptor and its current-name
// revalidation descriptors. Each recursive level can additionally retain a
// pinned O_PATH child and a directory descriptor. This is the leaf's frozen,
// conservative descriptor envelope; caller-owned parent descriptors are not
// included.
const CLEANUP_FDS_PER_DEPTH: u32 = 2;
const CLEANUP_FIXED_FDS: u32 = 4;
const BOUND_REGULAR_PATH_MAX_COMPONENTS_V1: usize = 40;
const BOUND_REGULAR_SYMLINK_MAX_HOPS_V1: usize = 40;
const BOUND_REGULAR_TARGET_MAX_BYTES_V1: usize = 4096;
const BOUND_REGULAR_MAX_BYTES_V1: u32 = 16 * 1024 * 1024;
const BOUND_REGULAR_MAX_OBSERVED_NODES_V1: usize =
    BOUND_REGULAR_PATH_MAX_COMPONENTS_V1 * (BOUND_REGULAR_SYMLINK_MAX_HOPS_V1 + 1);
const BOUND_REGULAR_IDENTITY_DOMAIN_V1: &str = "again bound published regular identity v1";
const RUNTIME_MEMORY_LIMIT_V1: usize = 128 * 1024 * 1024;

/// Stable, payload-free refusals from the operation-specific published-child
/// reader. These values are diagnostic only and never grant execution.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum BoundRegularReadRefusalV1 {
    InvalidPath,
    ComponentLimit,
    InvalidByteCeiling,
    SymlinkLimit,
    SymlinkCycle,
    SymlinkTargetInvalid,
    MissingNode,
    MountCrossing,
    MagicLink,
    NodeType,
    IdentityDrift,
    SizeMismatch,
    ByteLimit,
    ShortRead,
    Io,
    OperationBudget,
    MemoryBudget,
    UnsupportedPlatform,
}

/// Fixed role of one descriptor selected from the two-publication inventory.
/// The role is sealed by `snapshot_manifest`; callers cannot retag a root.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SnapshotChildRootRoleV1 {
    Workspace,
    Runtime,
}

/// Stable child-only filesystem attachment operation. These values are
/// diagnostics and fault-injection coordinates, never attachment authority.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SnapshotChildAttachOperationV1 {
    ValidateSource,
    OpenTree,
    SetRecursiveAttributes,
    OpenTarget,
    MoveMount,
    ReopenTarget,
    VerifyTarget,
    FinalTargetRevalidation,
    FinalSourceRevalidation,
    CloseKnownDescriptors,
}

/// Typed refusal from the fork-child attachment leaf. It is intentionally
/// operation- and role-specific, but remains private and non-authoritative.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SnapshotChildAttachFailureV1 {
    Injected {
        role: SnapshotChildRootRoleV1,
        operation: SnapshotChildAttachOperationV1,
        errno: i32,
    },
    Unsupported {
        role: SnapshotChildRootRoleV1,
        operation: SnapshotChildAttachOperationV1,
        errno: i32,
    },
    Os {
        role: SnapshotChildRootRoleV1,
        operation: SnapshotChildAttachOperationV1,
        errno: i32,
    },
    Invariant {
        role: SnapshotChildRootRoleV1,
        operation: SnapshotChildAttachOperationV1,
    },
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl SnapshotChildAttachFailureV1 {
    pub(super) const fn errno(self) -> Option<i32> {
        match self {
            Self::Injected { errno, .. }
            | Self::Unsupported { errno, .. }
            | Self::Os { errno, .. } => Some(errno),
            Self::Invariant { .. } => None,
        }
    }

    pub(super) const fn unsupported(self) -> bool {
        matches!(self, Self::Unsupported { .. })
    }

    pub(super) const fn is_fixed_runtime_open_tree_injection(self) -> bool {
        matches!(
            self,
            Self::Injected {
                role: SnapshotChildRootRoleV1::Runtime,
                operation: SnapshotChildAttachOperationV1::OpenTree,
                errno: libc::EIO,
            }
        )
    }
}

/// One non-clonable aggregate budget for every runtime-resolution allocation.
/// It is retained through canonical checkpoint construction so no phase can
/// restart the allowance. Budget admission precedes each fallible allocation;
/// observed capacity is reconciled and charged before the buffer is issued.
pub(super) struct RuntimeMemoryEscrowV1 {
    remaining: Cell<usize>,
}

impl RuntimeMemoryEscrowV1 {
    pub(super) const fn first_checkpoint() -> Self {
        Self {
            remaining: Cell::new(RUNTIME_MEMORY_LIMIT_V1),
        }
    }

    #[cfg(test)]
    pub(super) const fn with_limit_for_test(bytes: usize) -> Self {
        Self {
            remaining: Cell::new(bytes),
        }
    }

    pub(super) fn try_vec_with_capacity<T>(
        &self,
        capacity: usize,
    ) -> Result<Vec<T>, BoundRegularReadRefusalV1> {
        self.try_vec_with_capacity_using(capacity, |output, requested| {
            output.try_reserve_exact(requested).map_err(|_| ())
        })
    }

    fn try_vec_with_capacity_using<T>(
        &self,
        capacity: usize,
        reserve: impl FnOnce(&mut Vec<T>, usize) -> Result<(), ()>,
    ) -> Result<Vec<T>, BoundRegularReadRefusalV1> {
        let element_bytes = std::mem::size_of::<T>();
        let requested_bytes = capacity
            .checked_mul(element_bytes)
            .ok_or(BoundRegularReadRefusalV1::MemoryBudget)?;
        let remaining = self.remaining.get();
        if requested_bytes > remaining {
            return Err(BoundRegularReadRefusalV1::MemoryBudget);
        }
        let mut output = Vec::new();
        reserve(&mut output, capacity).map_err(|()| BoundRegularReadRefusalV1::MemoryBudget)?;
        let observed_bytes = output
            .capacity()
            .checked_mul(element_bytes)
            .ok_or(BoundRegularReadRefusalV1::MemoryBudget)?;
        let reconciled = remaining
            .checked_sub(observed_bytes)
            .ok_or(BoundRegularReadRefusalV1::MemoryBudget)?;
        self.remaining.set(reconciled);
        Ok(output)
    }

    pub(super) fn try_bytes_from_slice(
        &self,
        value: &[u8],
    ) -> Result<Vec<u8>, BoundRegularReadRefusalV1> {
        let mut output = self.try_vec_with_capacity(value.len())?;
        output.extend_from_slice(value);
        Ok(output)
    }

    pub(super) fn try_extend_bytes(
        &self,
        output: &mut Vec<u8>,
        value: &[u8],
    ) -> Result<(), BoundRegularReadRefusalV1> {
        let required_length = output
            .len()
            .checked_add(value.len())
            .ok_or(BoundRegularReadRefusalV1::MemoryBudget)?;
        if required_length > output.capacity() {
            // Allocate a charged replacement instead of growing in place. If
            // the allocator returns unchargeable excess capacity or fails,
            // the replacement is dropped and the existing buffer is unchanged.
            let mut replacement = self.try_vec_with_capacity(required_length)?;
            replacement.extend_from_slice(output);
            replacement.extend_from_slice(value);
            *output = replacement;
            return Ok(());
        }
        output.extend_from_slice(value);
        Ok(())
    }

    #[cfg(test)]
    fn remaining_for_test(&self) -> usize {
        self.remaining.get()
    }

    #[cfg(test)]
    fn try_vec_with_injected_allocation_failure_for_test<T>(
        &self,
        capacity: usize,
    ) -> Result<Vec<T>, BoundRegularReadRefusalV1> {
        self.try_vec_with_capacity_using(capacity, |_, _| Err(()))
    }

    #[cfg(test)]
    fn try_vec_with_excess_capacity_for_test<T>(
        &self,
        requested: usize,
        reserved: usize,
    ) -> Result<Vec<T>, BoundRegularReadRefusalV1> {
        self.try_vec_with_capacity_using(requested, |output, _| {
            output.try_reserve_exact(reserved).map_err(|_| ())
        })
    }
}

impl fmt::Debug for RuntimeMemoryEscrowV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RuntimeMemoryEscrowV1")
            .field("remaining", &"<redacted-budget>")
            .finish()
    }
}

/// A relative raw-byte path admitted for one descriptor-relative read.
/// Construction is bounded and rejects all ambient or escaping spellings.
pub(super) struct ValidatedBoundRelativePathV1(Box<[u8]>);

impl ValidatedBoundRelativePathV1 {
    pub(super) fn parse(path: &[u8]) -> Result<Self, BoundRegularReadRefusalV1> {
        validate_bound_components_v1(path)?;
        Ok(Self(path.into()))
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    pub(super) fn parse_with_memory(
        path: &[u8],
        memory: &RuntimeMemoryEscrowV1,
    ) -> Result<Self, BoundRegularReadRefusalV1> {
        validate_bound_components_v1(path)?;
        Ok(Self(memory.try_bytes_from_slice(path)?.into_boxed_slice()))
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for ValidatedBoundRelativePathV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ValidatedBoundRelativePathV1(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum VerifiedBoundNodeKindV1 {
    Directory,
    Symlink,
    Regular,
}

/// One descriptor-observed node in the normalized resolution walk. Access is
/// intentionally limited to the manifest cross-checking module.
pub(super) struct VerifiedBoundPathNodeV1 {
    normalized_path: Box<[u8]>,
    kind: VerifiedBoundNodeKindV1,
    statx_commitment: [u8; 102],
    symlink_target: Option<Box<[u8]>>,
    normalized_next_path: Option<Box<[u8]>>,
    live_statx: SourceStatxV1,
}

impl VerifiedBoundPathNodeV1 {
    pub(super) fn normalized_path(&self) -> &[u8] {
        &self.normalized_path
    }

    pub(super) const fn kind(&self) -> VerifiedBoundNodeKindV1 {
        self.kind
    }

    pub(super) const fn statx_commitment(&self) -> &[u8; 102] {
        &self.statx_commitment
    }

    pub(super) fn symlink_target(&self) -> Option<&[u8]> {
        self.symlink_target.as_deref()
    }

    pub(super) fn normalized_next_path(&self) -> Option<&[u8]> {
        self.normalized_next_path.as_deref()
    }

    pub(super) const fn live_statx(&self) -> &SourceStatxV1 {
        &self.live_statx
    }
}

impl fmt::Debug for VerifiedBoundPathNodeV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedBoundPathNodeV1")
            .field("kind", &self.kind)
            .field("path", &"<redacted>")
            .field("identity", &"<redacted>")
            .finish()
    }
}

/// Owned output from the sole descriptor-relative regular-byte operation.
/// It retains private descriptor pins for later stability checks, exposes no
/// descriptor or host pathname, and is not clonable.
pub(super) struct VerifiedBoundRegularBytesV1 {
    bytes: Vec<u8>,
    nodes: Vec<VerifiedBoundPathNodeV1>,
    pinned_fds: Vec<VerifiedBoundPinnedFdV1>,
    published_statx_commitment: [u8; 102],
    root_statx_commitment: [u8; 102],
    root_live_statx: SourceStatxV1,
    terminal_identity_digest: Blake3Digest,
    content_digest: FileContentDigest,
}

struct VerifiedBoundPinnedFdV1 {
    fd: OwnedFd,
    expected: [u8; 102],
}

impl VerifiedBoundRegularBytesV1 {
    pub(super) fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(super) fn nodes(&self) -> &[VerifiedBoundPathNodeV1] {
        &self.nodes
    }

    pub(super) const fn root_statx_commitment(&self) -> &[u8; 102] {
        &self.root_statx_commitment
    }

    pub(super) const fn root_live_statx(&self) -> &SourceStatxV1 {
        &self.root_live_statx
    }

    pub(super) const fn terminal_identity_digest(&self) -> Blake3Digest {
        self.terminal_identity_digest
    }

    pub(super) const fn content_digest(&self) -> FileContentDigest {
        self.content_digest
    }

    pub(super) fn pinned_fd_count(&self) -> usize {
        self.pinned_fds.len()
    }
}

impl fmt::Debug for VerifiedBoundRegularBytesV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedBoundRegularBytesV1")
            .field("bytes", &"<redacted>")
            .field("node_count", &self.nodes.len())
            .field("identity", &"<redacted>")
            .finish()
    }
}

impl Drop for VerifiedBoundRegularBytesV1 {
    fn drop(&mut self) {
        self.bytes.fill(0);
    }
}

fn validate_bound_components_v1(path: &[u8]) -> Result<(), BoundRegularReadRefusalV1> {
    if path.is_empty() || path[0] == b'/' || path.contains(&0) {
        return Err(BoundRegularReadRefusalV1::InvalidPath);
    }
    let mut count = 0usize;
    for component in path.split(|byte| *byte == b'/') {
        if component.is_empty() || component == b"." || component == b".." {
            return Err(BoundRegularReadRefusalV1::InvalidPath);
        }
        count = count
            .checked_add(1)
            .ok_or(BoundRegularReadRefusalV1::ComponentLimit)?;
        if count > BOUND_REGULAR_PATH_MAX_COMPONENTS_V1 || component.len() > MAX_BASENAME_BYTES {
            return Err(BoundRegularReadRefusalV1::ComponentLimit);
        }
    }
    Ok(())
}

fn read_exact_bound_regular_size_v1<R: std::io::Read>(
    reader: &mut R,
    size: usize,
    memory: &RuntimeMemoryEscrowV1,
) -> Result<Vec<u8>, BoundRegularReadRefusalV1> {
    let mut bytes = memory.try_vec_with_capacity(size)?;
    bytes.resize(size, 0);
    let mut offset = 0usize;
    let mut interrupted = 0u8;
    while offset < size {
        match reader.read(&mut bytes[offset..]) {
            Ok(0) => {
                bytes.fill(0);
                return Err(BoundRegularReadRefusalV1::ShortRead);
            }
            Ok(count) => {
                offset = offset
                    .checked_add(count)
                    .ok_or(BoundRegularReadRefusalV1::Io)?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted && interrupted < 16 => {
                interrupted += 1;
            }
            Err(_) => {
                bytes.fill(0);
                return Err(BoundRegularReadRefusalV1::Io);
            }
        }
    }
    let mut extra = [0u8; 1];
    let mut extra_interrupted = 0u8;
    let extra_count = loop {
        match reader.read(&mut extra) {
            Ok(count) => break count,
            Err(error) if error.kind() == io::ErrorKind::Interrupted && extra_interrupted < 16 => {
                extra_interrupted += 1;
            }
            Err(_) => {
                bytes.fill(0);
                return Err(BoundRegularReadRefusalV1::Io);
            }
        }
    };
    if extra_count != 0 {
        bytes.fill(0);
        return Err(BoundRegularReadRefusalV1::SizeMismatch);
    }
    Ok(bytes)
}

pub(super) fn read_bound_regular_bytes_v1(
    bound: &BoundPublishedSnapshotChildV1,
    path: &ValidatedBoundRelativePathV1,
    byte_ceiling: u32,
    memory: &RuntimeMemoryEscrowV1,
) -> Result<VerifiedBoundRegularBytesV1, BoundRegularReadRefusalV1> {
    if byte_ceiling == 0 || byte_ceiling > BOUND_REGULAR_MAX_BYTES_V1 {
        return Err(BoundRegularReadRefusalV1::InvalidByteCeiling);
    }
    platform::read_bound_regular_bytes_v1(bound, path.as_bytes(), byte_ceiling, memory)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) fn revalidate_bound_regular_bytes_v1(
    bound: &BoundPublishedSnapshotChildV1,
    verified: &VerifiedBoundRegularBytesV1,
) -> Result<(), BoundRegularReadRefusalV1> {
    platform::revalidate_bound_regular_bytes_v1(bound, verified)
}

/// Consume the manifest-sealed one-attempt projection for one already-bound
/// published root. The leaf performs exactly one non-retrying name-relative
/// `statx`, opens no descriptor, and exposes no generic name/commitment seam.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) fn consume_bound_published_snapshot_root_projection_v1(
    bound: &BoundPublishedSnapshotChildV1,
    prepared: SnapshotPreparedRetainedRootProjectionV1<'_>,
) -> Result<(), BoundRegularReadRefusalV1> {
    let (child_name, expected_root_statx_commitment) = prepared.into_leaf_parts();
    platform::consume_bound_published_snapshot_root_projection_v1(
        bound,
        child_name,
        expected_root_statx_commitment,
    )
}

const fn cleanup_fd_peak(max_cleanup_depth: u16) -> u32 {
    max_cleanup_depth as u32 * CLEANUP_FDS_PER_DEPTH + CLEANUP_FIXED_FDS
}

/// Read-only evidence of the limits actually carried by a staged directory's
/// cleanup guard. Private fields make the value non-forgeable outside this
/// module in safe Rust; it owns no descriptor and grants no cleanup or publish
/// authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SnapshotCleanupEnvelopeV1 {
    max_entries: u32,
    max_source_tree_depth: u16,
    max_basename_bytes: u16,
    openat2_attempts: u8,
    generic_syscall_attempts: u8,
}

impl SnapshotCleanupEnvelopeV1 {
    pub(super) const fn max_source_tree_depth(self) -> u16 {
        self.max_source_tree_depth
    }

    pub(super) const fn max_entries(self) -> u32 {
        self.max_entries
    }

    pub(super) const fn max_basename_bytes(self) -> u16 {
        self.max_basename_bytes
    }

    pub(super) const fn openat2_attempts(self) -> u8 {
        self.openat2_attempts
    }

    pub(super) const fn generic_syscall_attempts(self) -> u8 {
        self.generic_syscall_attempts
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SnapshotPublishPolicyV1 {
    openat2_attempts: NonZeroU8,
    syscall_attempts: NonZeroU8,
    max_cleanup_depth: u16,
    max_cleanup_entries: NonZeroU32,
    max_cleanup_name_bytes: NonZeroU16,
    max_cleanup_retained_name_bytes: NonZeroU64,
    max_cleanup_getdents_attempts: u64,
    finalization_operation_attempt_bound: NonZeroU64,
}

impl SnapshotPublishPolicyV1 {
    /// Returns `None` before any filesystem work when retry work exceeds the
    /// descriptor walker's fixed hard ceiling.
    pub(super) fn checked(
        openat2_attempts: NonZeroU8,
        syscall_attempts: NonZeroU8,
        max_source_tree_depth: u16,
        max_cleanup_entries: NonZeroU32,
        max_cleanup_name_bytes: NonZeroU16,
        max_cleanup_retained_name_bytes: NonZeroU64,
    ) -> Option<Self> {
        if openat2_attempts.get() > HARD_MAX_OPENAT2_ATTEMPTS
            || syscall_attempts.get() > HARD_MAX_SYSCALL_ATTEMPTS
            || max_source_tree_depth > HARD_MAX_SOURCE_TREE_DEPTH
            || max_cleanup_entries.get() > HARD_MAX_CLEANUP_ENTRIES
            || usize::from(max_cleanup_name_bytes.get()) > MAX_BASENAME_BYTES
            || max_cleanup_retained_name_bytes.get() > HARD_MAX_CLEANUP_RETAINED_NAME_BYTES
        {
            return None;
        }
        let max_cleanup_depth = max_source_tree_depth + PUBLICATION_CONTAINER_LEVELS;
        let active_slots = u64::from(max_cleanup_depth)
            .checked_add(1)?
            .checked_mul(CLEANUP_NAME_BATCH_SIZE as u64)?
            .min(u64::from(max_cleanup_entries.get()));
        // Batch slots live on the stack. The shared transient-heap ledger
        // therefore covers only the still-live staging basename and the exact
        // byte buffers retained by active cleanup batches.
        let retained_per_name = u64::from(max_cleanup_name_bytes.get()).checked_add(1)?;
        let minimum_retained = active_slots
            .checked_mul(retained_per_name)?
            .checked_add(MAX_STAGING_NAME_WITH_NUL)?;
        if max_cleanup_retained_name_bytes.get() < minimum_retained {
            return None;
        }
        let max_cleanup_getdents_attempts = (max_cleanup_entries.get() as u64)
            .checked_mul(5)?
            .checked_add(3)?
            .checked_mul(syscall_attempts.get() as u64)?;
        let open_attempts = u64::from(openat2_attempts.get());
        let generic_attempts = u64::from(syscall_attempts.get());
        // Integrated charged finalization performs three staging
        // revalidations and one final reopen (four openat2 retry groups and
        // sixteen fixed fstat/statx calls). Each retryable rename iteration
        // performs the rename plus one expected and one missing name binding,
        // for `2O + 2` attempts. Container sealing and the two fsyncs add the
        // remaining three generic retry groups. The terminal both-present
        // reconciliation branch costs one more attempt but cannot execute the
        // post-rename tail, so it is not the whole-path maximum.
        let finalization_operation_attempt_bound =
            open_attempts.checked_mul(4)?.checked_add(16)?.checked_add(
                generic_attempts.checked_mul(open_attempts.checked_mul(2)?.checked_add(5)?)?,
            )?;
        let finalization_operation_attempt_bound =
            NonZeroU64::new(finalization_operation_attempt_bound)?;
        Some(Self {
            openat2_attempts,
            syscall_attempts,
            max_cleanup_depth,
            max_cleanup_entries,
            max_cleanup_name_bytes,
            max_cleanup_retained_name_bytes,
            max_cleanup_getdents_attempts,
            finalization_operation_attempt_bound,
        })
    }

    pub(super) const fn openat2_attempts(self) -> u8 {
        self.openat2_attempts.get()
    }

    pub(super) const fn syscall_attempts(self) -> u8 {
        self.syscall_attempts.get()
    }

    pub(super) const fn max_cleanup_depth(self) -> u16 {
        self.max_cleanup_depth
    }

    pub(super) const fn max_cleanup_entries(self) -> u32 {
        self.max_cleanup_entries.get()
    }

    pub(super) const fn max_cleanup_name_bytes(self) -> u16 {
        self.max_cleanup_name_bytes.get()
    }

    pub(super) const fn max_cleanup_retained_name_bytes(self) -> u64 {
        self.max_cleanup_retained_name_bytes.get()
    }

    pub(super) const fn max_cleanup_getdents_attempts(self) -> u64 {
        self.max_cleanup_getdents_attempts
    }

    /// Exact worst-case raw-attempt escrow for the integrated charged
    /// seal-and-publish state machine.
    pub(super) const fn finalization_operation_attempt_bound(self) -> NonZeroU64 {
        self.finalization_operation_attempt_bound
    }

    /// Exact post-publication child-binding escrow: at most `O` constrained
    /// `openat2` attempts, one descriptor-based bind `statx`, and one permit
    /// precharge for the later exact, non-retrying root-name `statx`.
    pub(super) fn published_child_bind_operation_attempt_bound(self) -> NonZeroU64 {
        NonZeroU64::new(u64::from(self.openat2_attempts.get()) + 2)
            .expect("a nonzero u8 retry count plus two is nonzero")
    }

    /// Descriptor retained while the caller builds and seals the stage.
    pub(super) const fn max_live_staged_fds(self) -> u32 {
        MAX_LIVE_STAGED_FDS
    }

    /// Conservative leaf-owned cleanup peak for this policy's depth.
    pub(super) const fn max_live_cleanup_fds(self) -> u32 {
        cleanup_fd_peak(self.max_cleanup_depth)
    }

    /// Descriptor peak while the final name is bound and while the later
    /// no-new-FD retained-root projection runs.
    pub(super) const fn max_live_publication_fds(self) -> u32 {
        MAX_LIVE_PUBLICATION_FDS
    }

    const fn cleanup_envelope(self) -> SnapshotCleanupEnvelopeV1 {
        SnapshotCleanupEnvelopeV1 {
            max_entries: self.max_cleanup_entries.get(),
            max_source_tree_depth: self.max_cleanup_depth - PUBLICATION_CONTAINER_LEVELS,
            max_basename_bytes: self.max_cleanup_name_bytes.get(),
            openat2_attempts: self.openat2_attempts.get(),
            generic_syscall_attempts: self.syscall_attempts.get(),
        }
    }

    /// Worst-case cleanup attempts for two-name raw-`getdents64` batches. Five
    /// opens per entry cover fresh rescans and exact-full-batch EOF probes.
    /// Five bounded raw directory reads plus the other per-entry
    /// identity/chmod/unlink work give twelve conservative generic calls per
    /// entry, including maximally partial positive reads.
    pub(super) fn cleanup_operation_attempt_bound(self) -> Option<u64> {
        let entries = self.max_cleanup_entries.get() as u64;
        let opens = entries.checked_mul(5)?.checked_add(3)?;
        let generic = entries.checked_mul(12)?.checked_add(12)?;
        let open_attempts = opens.checked_mul(self.openat2_attempts.get() as u64)?;
        let generic_attempts = generic.checked_mul(self.syscall_attempts.get() as u64)?;
        open_attempts.checked_add(generic_attempts)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SnapshotPublishStageV1 {
    ValidateStagingName,
    InspectParent,
    CreateAndOpenStaging,
    BindStagingIdentity,
    VerifyRecursiveDurability,
    RevalidateStaging,
    SealStaging,
    SyncStaging,
    ValidateFinalName,
    PublishRename,
    SyncParent,
    ReopenPublished,
    BindPublishedIdentity,
    ValidatePublishedChildName,
    OpenPublishedChild,
    StatPublishedChild,
    BindPublishedChildIdentity,
}

impl SnapshotPublishStageV1 {
    #[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
    const LEGACY_TRANSITIONS: [Self; 12] = [
        Self::ValidateStagingName,
        Self::InspectParent,
        Self::CreateAndOpenStaging,
        Self::BindStagingIdentity,
        Self::VerifyRecursiveDurability,
        Self::RevalidateStaging,
        Self::SyncStaging,
        Self::ValidateFinalName,
        Self::PublishRename,
        Self::SyncParent,
        Self::ReopenPublished,
        Self::BindPublishedIdentity,
    ];
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SnapshotPublicationStateV1 {
    Unpublished,
    PublishedDurabilityUnknown,
    PublishedDurable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SnapshotPublishErrorKindV1 {
    InvalidStagingName,
    InvalidFinalName,
    UntrustedParent,
    StagingCollision,
    FinalCollision,
    RequiredKernelCapabilityMissing,
    RecursiveDurabilityFailed,
    IdentityMismatch,
    InvalidPublishedChildName,
    Io,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SnapshotPublishErrorV1 {
    kind: SnapshotPublishErrorKindV1,
    stage: SnapshotPublishStageV1,
    publication_state: SnapshotPublicationStateV1,
    errno: Option<i32>,
}

impl SnapshotPublishErrorV1 {
    const fn new(
        kind: SnapshotPublishErrorKindV1,
        stage: SnapshotPublishStageV1,
        publication_state: SnapshotPublicationStateV1,
        errno: Option<i32>,
    ) -> Self {
        Self {
            kind,
            stage,
            publication_state,
            errno,
        }
    }

    pub(super) const fn kind(self) -> SnapshotPublishErrorKindV1 {
        self.kind
    }

    pub(super) const fn stage(self) -> SnapshotPublishStageV1 {
        self.stage
    }

    /// `PublishedDurabilityUnknown` and `PublishedDurable` mean the final name
    /// may be externally visible and must be reconciled, never blindly retried.
    pub(super) const fn publication_state(self) -> SnapshotPublicationStateV1 {
        self.publication_state
    }

    pub(super) const fn errno(self) -> Option<i32> {
        self.errno
    }
}

impl fmt::Display for SnapshotPublishErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "snapshot publication {:?} during {:?} ({:?})",
            self.kind, self.stage, self.publication_state
        )?;
        if let Some(errno) = self.errno {
            write!(formatter, " (errno {errno})")?;
        }
        Ok(())
    }
}

impl std::error::Error for SnapshotPublishErrorV1 {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SnapshotPublishedChildBindFailureV1 {
    Resource(SnapshotPipelineResourceErrorV1),
    Leaf(SnapshotPublishErrorV1),
}

/// A post-publication failure that can never imply that the final name is
/// unpublished or safe to remove. Private construction keeps the durable
/// state invariant structural while preserving the underlying resource or
/// leaf evidence for the connector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SnapshotPublishedChildBindErrorV1 {
    failure: SnapshotPublishedChildBindFailureV1,
}

impl SnapshotPublishedChildBindErrorV1 {
    fn resource(error: SnapshotPipelineResourceErrorV1) -> Self {
        Self {
            failure: SnapshotPublishedChildBindFailureV1::Resource(error),
        }
    }

    fn leaf(
        kind: SnapshotPublishErrorKindV1,
        stage: SnapshotPublishStageV1,
        errno: Option<i32>,
    ) -> Self {
        Self {
            failure: SnapshotPublishedChildBindFailureV1::Leaf(SnapshotPublishErrorV1::new(
                kind,
                stage,
                SnapshotPublicationStateV1::PublishedDurable,
                errno,
            )),
        }
    }

    pub(super) const fn failure(self) -> SnapshotPublishedChildBindFailureV1 {
        self.failure
    }

    pub(super) const fn publication_state(self) -> SnapshotPublicationStateV1 {
        SnapshotPublicationStateV1::PublishedDurable
    }
}

impl fmt::Display for SnapshotPublishedChildBindErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.failure {
            SnapshotPublishedChildBindFailureV1::Resource(error) => write!(
                formatter,
                "published snapshot child binding resource failure {error:?} ({:?})",
                SnapshotPublicationStateV1::PublishedDurable
            ),
            SnapshotPublishedChildBindFailureV1::Leaf(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for SnapshotPublishedChildBindErrorV1 {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SnapshotDirectoryIdentityV1 {
    mount_id: u64,
    device_major: u32,
    device_minor: u32,
    inode: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    link_count: u64,
}

fn valid_raw_basename(name: &CStr) -> bool {
    let bytes = name.to_bytes();
    !bytes.is_empty()
        && bytes.len() <= MAX_BASENAME_BYTES
        && bytes != b"."
        && bytes != b".."
        && !bytes.contains(&b'/')
}

fn valid_staging_basename(name: &CStr) -> bool {
    let bytes = name.to_bytes();
    let Some(nonce) = bytes.strip_prefix(STAGING_NAME_PREFIX) else {
        return false;
    };
    nonce.len() == STAGING_NONCE_HEX_BYTES
        && nonce
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte))
}

/// Pure validation shared by the connector and both publication paths. It
/// performs no allocation, resource charge, or filesystem operation.
pub(super) fn validate_snapshot_final_name(
    staging_name: &CStr,
    final_name: &CStr,
) -> Result<(), SnapshotPublishErrorV1> {
    if valid_raw_basename(final_name) && final_name != staging_name {
        return Ok(());
    }
    Err(SnapshotPublishErrorV1::new(
        SnapshotPublishErrorKindV1::InvalidFinalName,
        SnapshotPublishStageV1::ValidateFinalName,
        SnapshotPublicationStateV1::Unpublished,
        None,
    ))
}

pub(super) type StagedSnapshotDirectoryV1<'parent> = platform::StagedSnapshotDirectoryV1<'parent>;
pub(super) type ChargedStagedSnapshotDirectoryV1<'resources> =
    platform::ChargedStagedSnapshotDirectoryV1<'resources>;
pub(super) type VerifiedReadySnapshotDirectoryV1<'parent> =
    platform::VerifiedReadySnapshotDirectoryV1<'parent>;
#[cfg(test)]
pub(super) type PublishedSnapshotDirectoryV1 = platform::PublishedSnapshotDirectoryV1;
/// Point-in-time physical descriptor binding only. It neither makes the path
/// or descendants immutable nor grants isolation, execution, or reuse.
pub(super) type BoundPublishedSnapshotChildV1 = platform::BoundPublishedSnapshotChildV1;

/// Fork-safe child half of one exact publication root. It has no descriptor
/// accessor and its Drop implementation is one raw `close(2)` syscall.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) type ForkChildPublishedRootV1 = platform::ForkChildPublishedRootV1;

/// Duplicate and independently revalidate one manifest-sealed publication
/// root for the fork child. The original descriptor remains retained by the
/// parent inventory owner; no generic descriptor is returned.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) fn prepare_fork_child_published_root_v1(
    bound: &BoundPublishedSnapshotChildV1,
    prepared: SnapshotPreparedForkChildRootV1,
) -> Result<ForkChildPublishedRootV1, BoundRegularReadRefusalV1> {
    let (role, root_name, expected) = prepared.into_leaf_parts();
    platform::prepare_fork_child_published_root_v1(bound, role, root_name, expected)
}

/// Attach exactly the workspace and runtime child halves at the fixed
/// `/workspace` and `/runtime` targets. The operation runs only in namespace
/// PID 1 before capability elimination and consumes both descriptors.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) fn attach_fork_child_published_roots_v1(
    workspace: ForkChildPublishedRootV1,
    runtime: ForkChildPublishedRootV1,
    _child_namespace_seal: SnapshotChildMountNamespaceSealV1,
    child_brand: IsolationChildOnlyBrandV1,
) -> Result<(), SnapshotChildAttachFailureV1> {
    platform::attach_fork_child_published_roots_v1(workspace, runtime, &child_brand)
}

/// Fixed command-free diagnostic refusal after the workspace root has been
/// attached and immediately before the runtime `open_tree(2)` operation.
///
/// This is deliberately not a generic fault-injection surface: callers cannot
/// select a role, operation, errno, descriptor, path, or command. The only
/// outcome it can introduce is the frozen `EIO` refusal used to prove cleanup
/// of the partially attached child on a provisioned kernel.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) fn attach_fork_child_published_roots_with_fixed_runtime_refusal_v1(
    workspace: ForkChildPublishedRootV1,
    runtime: ForkChildPublishedRootV1,
    _child_namespace_seal: SnapshotChildMountNamespaceSealV1,
    child_brand: IsolationChildOnlyBrandV1,
) -> Result<(), SnapshotChildAttachFailureV1> {
    platform::attach_fork_child_published_roots_with_fixed_runtime_refusal_v1(
        workspace,
        runtime,
        &child_brand,
    )
}

/// Test-only injection at one real child attachment operation. This enters
/// the same production leaf and is unavailable to non-test siblings.
#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
pub(super) fn attach_fork_child_published_roots_with_test_fault_v1(
    workspace: ForkChildPublishedRootV1,
    runtime: ForkChildPublishedRootV1,
    _child_namespace_seal: SnapshotChildMountNamespaceSealV1,
    child_brand: IsolationChildOnlyBrandV1,
    role: SnapshotChildRootRoleV1,
    operation: SnapshotChildAttachOperationV1,
) -> Result<(), SnapshotChildAttachFailureV1> {
    platform::attach_fork_child_published_roots_with_test_fault_v1(
        workspace,
        runtime,
        &child_brand,
        role,
        operation,
    )
}

/// Test-only inspection of the pinned published-container descriptor. This is
/// deliberately absent from production because `BorrowedFd` can be cloned to
/// an owned descriptor in safe Rust.
#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
pub(super) fn bound_published_snapshot_directory_fd(
    bound: &BoundPublishedSnapshotChildV1,
) -> BorrowedFd<'_> {
    bound.published_directory()
}

/// Test-only inspection of the exact child selected at bind time. Production
/// consumers must use a future operation-specific isolation transition rather
/// than receiving a clonable descriptor borrow.
#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
pub(super) fn bound_published_snapshot_root_fd(
    bound: &BoundPublishedSnapshotChildV1,
) -> BorrowedFd<'_> {
    bound.root_directory()
}

pub(super) fn create_charged_staged_snapshot_directory_at<'scope>(
    parent: BorrowedFd<'scope>,
    staging_name: &CStr,
    session: SnapshotPublicationSessionV1<'scope>,
) -> Result<ChargedStagedSnapshotDirectoryV1<'scope>, SnapshotChargedErrorV1<SnapshotPublishErrorV1>>
{
    platform::create_charged_staged_snapshot_directory_at(parent, staging_name, session)
}

/// Test-only access to physical publication without canonical binding.
/// Production has no irreversible publication operation that omits the
/// verifier/compiler handoff.
#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
pub(super) fn seal_and_publish_charged_at(
    staged: ChargedStagedSnapshotDirectoryV1<'_>,
    final_name: &CStr,
) -> Result<PublishedSnapshotDirectoryV1, SnapshotChargedErrorV1<SnapshotPublishErrorV1>> {
    platform::seal_and_publish_charged_at(staged, final_name)
}

/// Distinguishes failure before durable publication from failure while
/// binding a final name that is already durable.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) enum SnapshotPublishAndBindErrorV1 {
    Finalization(SnapshotChargedErrorV1<SnapshotPublishErrorV1>),
    PublishedChildBind(SnapshotPublishedChildBindErrorV1),
}

/// The sole production irreversible transition. It requires the manifest
/// compiler's non-forgeable linear handoff before sealing, then publishes and
/// pins the exact child selected beneath the durable final name. Raw
/// commitment bytes and separately minted reservations are not accepted at
/// this boundary. Success remains point-in-time evidence only; it neither
/// prevents same-UID mutation nor grants isolation, execution, or reuse.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) fn seal_publish_and_bind_snapshot_child_at(
    staged: ChargedStagedSnapshotDirectoryV1<'_>,
    final_name: &CStr,
    prepared: SnapshotPreparedPublishedChildBindV1<'_, '_>,
) -> Result<BoundPublishedSnapshotChildV1, SnapshotPublishAndBindErrorV1> {
    let (child_name, expected_statx_commitment, reservation) = prepared.into_leaf_parts();
    let published = platform::seal_and_publish_charged_at(staged, final_name)
        .map_err(SnapshotPublishAndBindErrorV1::Finalization)?;
    platform::bind_published_snapshot_child_at(
        published,
        child_name,
        expected_statx_commitment,
        reservation,
    )
    .map_err(SnapshotPublishAndBindErrorV1::PublishedChildBind)
}

#[cfg(test)]
pub(super) fn create_staged_snapshot_directory_at<'parent>(
    parent: BorrowedFd<'parent>,
    staging_name: &CStr,
    policy: SnapshotPublishPolicyV1,
) -> Result<StagedSnapshotDirectoryV1<'parent>, SnapshotPublishErrorV1> {
    platform::create_unmetered_staged_snapshot_directory_at(parent, staging_name, policy)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod platform {
    use std::ffi::CString;
    use std::mem::{self, MaybeUninit};
    use std::os::fd::{AsFd, AsRawFd, FromRawFd, IntoRawFd, RawFd};

    use super::*;

    #[cfg(test)]
    std::thread_local! {
        static DIRECTORY_FSTAT_CALLS: std::cell::Cell<u64> = const {
            std::cell::Cell::new(0)
        };
        static FINALIZATION_ATTEMPT_CHARGES: std::cell::Cell<u64> = const {
            std::cell::Cell::new(0)
        };
        static PUBLISHED_CHILD_STATX_CALLS: std::cell::Cell<u64> = const {
            std::cell::Cell::new(0)
        };
    }

    const RESOLVE_NO_XDEV: u64 = 0x01;
    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    const RESOLVE_BENEATH: u64 = 0x08;
    const SNAPSHOT_RESOLVE: u64 = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV;
    const RENAME_NOREPLACE: u32 = 1;
    const AT_EMPTY_PATH: i32 = 0x1000;
    const STATX_MNT_ID: u32 = 0x1000;
    const REQUIRED_STATX_MASK: u32 = libc::STATX_TYPE
        | libc::STATX_MODE
        | libc::STATX_NLINK
        | libc::STATX_UID
        | libc::STATX_GID
        | libc::STATX_INO
        | STATX_MNT_ID;
    const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    trait TransitionHookV1 {
        fn checkpoint(&mut self, _stage: SnapshotPublishStageV1) -> io::Result<()> {
            Ok(())
        }

        fn rename_noreplace(
            &mut self,
            old_parent: BorrowedFd<'_>,
            old_name: &CStr,
            new_parent: BorrowedFd<'_>,
            new_name: &CStr,
        ) -> io::Result<()> {
            rename_noreplace_at(old_parent, old_name, new_parent, new_name)
        }

        fn seal_directory(&mut self, directory: BorrowedFd<'_>) -> io::Result<()> {
            let result = unsafe {
                libc::fchmod(directory.as_raw_fd(), SEALED_DIRECTORY_MODE as libc::mode_t)
            };
            if result == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }
    }

    struct KernelTransitions;

    impl TransitionHookV1 for KernelTransitions {}

    trait PublisherAttemptGateV1 {
        fn run_attempt<T>(
            &self,
            attempt: impl FnOnce() -> T,
        ) -> Result<T, SnapshotPipelineResourceErrorV1>;
    }

    impl PublisherAttemptGateV1 for SnapshotFinalizationAttemptReservationV1<'_> {
        fn run_attempt<T>(
            &self,
            attempt: impl FnOnce() -> T,
        ) -> Result<T, SnapshotPipelineResourceErrorV1> {
            self.run_attempt(|| {
                #[cfg(test)]
                FINALIZATION_ATTEMPT_CHARGES.with(|calls| calls.set(calls.get() + 1));
                attempt()
            })
        }
    }

    impl PublisherAttemptGateV1 for SnapshotPublishedChildBindReservationV1<'_> {
        fn run_attempt<T>(
            &self,
            attempt: impl FnOnce() -> T,
        ) -> Result<T, SnapshotPipelineResourceErrorV1> {
            SnapshotPublishedChildBindReservationV1::run_attempt(self, attempt)
        }
    }

    struct UnmeteredPublisherAttemptGateV1;

    impl PublisherAttemptGateV1 for UnmeteredPublisherAttemptGateV1 {
        fn run_attempt<T>(
            &self,
            attempt: impl FnOnce() -> T,
        ) -> Result<T, SnapshotPipelineResourceErrorV1> {
            Ok(attempt())
        }
    }

    fn unmetered_leaf<T, E>(result: Result<T, SnapshotChargedErrorV1<E>>) -> Result<T, E> {
        match result {
            Ok(value) => Ok(value),
            Err(SnapshotChargedErrorV1::Leaf(error)) => Err(error),
            Err(
                SnapshotChargedErrorV1::Resource(_)
                | SnapshotChargedErrorV1::PublicationAlreadyStarted,
            ) => unreachable!("an unmetered publisher gate cannot refuse"),
        }
    }

    #[derive(Clone, Copy)]
    enum PublisherAttemptBucketV1 {
        Forward,
        Cleanup,
    }

    enum PublisherAuthorityV1<'resources> {
        Charged {
            session: SnapshotPublicationSessionV1<'resources>,
        },
        #[cfg(test)]
        Unmetered { policy: SnapshotPublishPolicyV1 },
    }

    impl<'resources> PublisherAuthorityV1<'resources> {
        fn policy(&self) -> SnapshotPublishPolicyV1 {
            match self {
                Self::Charged { session } => *session.policy(),
                #[cfg(test)]
                Self::Unmetered { policy } => *policy,
            }
        }

        fn run_attempt<T>(
            &self,
            bucket: PublisherAttemptBucketV1,
            attempt: impl FnOnce() -> T,
        ) -> Result<T, SnapshotPipelineResourceErrorV1> {
            match (self, bucket) {
                (Self::Charged { session }, PublisherAttemptBucketV1::Forward) => {
                    session.run_forward_attempt(attempt)
                }
                (Self::Charged { session }, PublisherAttemptBucketV1::Cleanup) => {
                    session.run_publisher_cleanup_attempt(attempt)
                }
                #[cfg(test)]
                (Self::Unmetered { .. }, _) => Ok(attempt()),
            }
        }

        fn reserve_finalization_attempts(
            &self,
        ) -> Result<
            SnapshotFinalizationAttemptReservationV1<'resources>,
            SnapshotPipelineResourceErrorV1,
        > {
            match self {
                Self::Charged { session } => session.reserve_finalization_attempts(),
                #[cfg(test)]
                Self::Unmetered { .. } => {
                    unreachable!("the legacy test authority does not reserve shared attempts")
                }
            }
        }

        /// Reserves the exact post-publication child-bind ceiling derived by
        /// the publication policy carried inside this charged authority.
        /// Callers cannot select a count or recover the broader resource
        /// ledger from the narrowed reservation.
        fn reserve_published_child_bind_attempts(
            &self,
        ) -> Result<
            SnapshotPublishedChildBindReservationV1<'resources>,
            SnapshotPipelineResourceErrorV1,
        > {
            match self {
                Self::Charged { session } => session.reserve_published_child_bind_attempts(),
                #[cfg(test)]
                Self::Unmetered { .. } => {
                    unreachable!("the legacy test authority does not reserve shared attempts")
                }
            }
        }

        #[cfg(test)]
        fn remaining_attempts(&self, bucket: PublisherAttemptBucketV1) -> Option<u64> {
            match (self, bucket) {
                (Self::Charged { session }, PublisherAttemptBucketV1::Forward) => {
                    Some(session.forward_attempts_remaining())
                }
                (Self::Charged { session }, PublisherAttemptBucketV1::Cleanup) => {
                    Some(session.publisher_cleanup_attempts_remaining())
                }
                (Self::Unmetered { .. }, _) => None,
            }
        }
    }

    struct PublisherBucketAttemptGateV1<'authority, 'resources> {
        authority: &'authority PublisherAuthorityV1<'resources>,
        bucket: PublisherAttemptBucketV1,
    }

    impl PublisherAttemptGateV1 for PublisherBucketAttemptGateV1<'_, '_> {
        fn run_attempt<T>(
            &self,
            attempt: impl FnOnce() -> T,
        ) -> Result<T, SnapshotPipelineResourceErrorV1> {
            self.authority.run_attempt(self.bucket, attempt)
        }
    }

    enum PublisherBytesV1<'resources> {
        Charged(SnapshotChargedBytesV1<'resources>),
        #[cfg(test)]
        Unmetered {
            values: Vec<u8>,
            max_capacity: usize,
        },
    }

    impl<'resources> PublisherBytesV1<'resources> {
        fn charged_for(
            authority: &PublisherAuthorityV1<'resources>,
            bucket: PublisherAttemptBucketV1,
            max_capacity: usize,
        ) -> Result<Self, SnapshotChargedErrorV1<io::Error>> {
            match authority {
                PublisherAuthorityV1::Charged { session } => {
                    let bytes = match bucket {
                        PublisherAttemptBucketV1::Forward => {
                            session.charged_forward_bytes(max_capacity)
                        }
                        PublisherAttemptBucketV1::Cleanup => {
                            session.charged_cleanup_bytes(max_capacity)
                        }
                    };
                    bytes
                        .map(Self::Charged)
                        .map_err(SnapshotChargedErrorV1::Resource)
                }
                #[cfg(test)]
                PublisherAuthorityV1::Unmetered { .. } => {
                    let mut values = Vec::new();
                    values.try_reserve_exact(max_capacity).map_err(|_| {
                        SnapshotChargedErrorV1::Leaf(io::Error::from_raw_os_error(libc::ENOMEM))
                    })?;
                    Ok(Self::Unmetered {
                        values,
                        max_capacity,
                    })
                }
            }
        }

        fn as_slice(&self) -> &[u8] {
            match self {
                Self::Charged(values) => values.as_slice(),
                #[cfg(test)]
                Self::Unmetered { values, .. } => values,
            }
        }

        fn try_extend_from_slice(
            &mut self,
            bytes: &[u8],
        ) -> Result<(), SnapshotChargedErrorV1<io::Error>> {
            match self {
                Self::Charged(values) => values
                    .try_extend_from_slice(bytes)
                    .map_err(SnapshotChargedErrorV1::Resource),
                #[cfg(test)]
                Self::Unmetered {
                    values,
                    max_capacity,
                } => {
                    let required = values.len().checked_add(bytes.len()).ok_or_else(|| {
                        SnapshotChargedErrorV1::Leaf(io::Error::from_raw_os_error(libc::E2BIG))
                    })?;
                    if required > *max_capacity {
                        return Err(SnapshotChargedErrorV1::Leaf(io::Error::from_raw_os_error(
                            libc::E2BIG,
                        )));
                    }
                    values.extend_from_slice(bytes);
                    Ok(())
                }
            }
        }
    }

    struct RetainedCStringV1<'resources> {
        bytes_with_nul: PublisherBytesV1<'resources>,
    }

    impl RetainedCStringV1<'_> {
        fn as_c_str(&self) -> &CStr {
            // SAFETY: the only constructors reject interior NUL bytes and
            // retain exactly one trailing terminator.
            unsafe { CStr::from_bytes_with_nul_unchecked(self.bytes_with_nul.as_slice()) }
        }

        fn retained_capacity_bytes(&self) -> io::Result<u64> {
            u64::try_from(self.bytes_with_nul.as_slice().len())
                .map_err(|_| io::Error::from_raw_os_error(libc::E2BIG))
        }
    }

    struct StagingCleanupV1<'scope> {
        parent: BorrowedFd<'scope>,
        staging_name: RetainedCStringV1<'scope>,
        directory: Option<OwnedFd>,
        expected_identity: Option<SnapshotDirectoryIdentityV1>,
        effective_uid: u32,
        authority: PublisherAuthorityV1<'scope>,
        cleanup_budget: CleanupBudgetV1,
        armed: bool,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct CleanupBudgetV1 {
        entries_seen: u32,
        retained_name_bytes: u64,
        getdents_attempts_seen: u64,
    }

    impl CleanupBudgetV1 {
        const fn new() -> Self {
            Self {
                entries_seen: 0,
                retained_name_bytes: 0,
                getdents_attempts_seen: 0,
            }
        }

        fn retain_batch(
            &mut self,
            policy: SnapshotPublishPolicyV1,
            entry_count: usize,
            retained_name_bytes: u64,
        ) -> io::Result<()> {
            let entry_count = u32::try_from(entry_count)
                .map_err(|_| io::Error::from_raw_os_error(libc::E2BIG))?;
            let entries_seen = self
                .entries_seen
                .checked_add(entry_count)
                .filter(|count| *count <= policy.max_cleanup_entries.get())
                .ok_or_else(|| io::Error::from_raw_os_error(libc::E2BIG))?;
            let retained = self
                .retained_name_bytes
                .checked_add(retained_name_bytes)
                .filter(|bytes| *bytes <= policy.max_cleanup_retained_name_bytes.get())
                .ok_or_else(|| io::Error::from_raw_os_error(libc::E2BIG))?;
            self.entries_seen = entries_seen;
            self.retained_name_bytes = retained;
            Ok(())
        }

        fn release_batch(&mut self, retained_name_bytes: u64) {
            self.retained_name_bytes = self
                .retained_name_bytes
                .checked_sub(retained_name_bytes)
                .expect("cleanup releases only its private retained-name charge");
        }

        fn charge_getdents_attempt(&mut self, policy: SnapshotPublishPolicyV1) -> io::Result<()> {
            let attempts = self
                .getdents_attempts_seen
                .checked_add(1)
                .filter(|attempts| *attempts <= policy.max_cleanup_getdents_attempts)
                .ok_or_else(|| io::Error::from_raw_os_error(libc::E2BIG))?;
            self.getdents_attempts_seen = attempts;
            Ok(())
        }
    }

    pub(in crate::linux_pytest) struct StagedSnapshotDirectoryV1<'parent> {
        cleanup: StagingCleanupV1<'parent>,
    }

    /// A resource-charged staging guard. It exposes no public ready token or
    /// publication method and can only be consumed by integrated charged
    /// finalization after the connector completes its mandatory comparisons.
    pub(in crate::linux_pytest) struct ChargedStagedSnapshotDirectoryV1<'resources> {
        cleanup: StagingCleanupV1<'resources>,
    }

    pub(in crate::linux_pytest) struct VerifiedReadySnapshotDirectoryV1<'parent> {
        cleanup: StagingCleanupV1<'parent>,
    }

    pub(in crate::linux_pytest) struct PublishedSnapshotDirectoryV1 {
        directory: OwnedFd,
        openat2_attempts: u8,
    }

    /// A durable published container together with the child inode selected
    /// beneath it at bind time. Neither descriptor is detachable or clonable.
    /// The pair does not stop same-UID mutation after binding and grants no
    /// execution authority.
    pub(in crate::linux_pytest) struct BoundPublishedSnapshotChildV1 {
        published: OwnedFd,
        root: OwnedFd,
        retained_root_projection_admitted: Cell<bool>,
    }

    /// Raw child half only. `clone3` copies it into both processes; the parent
    /// copy is dropped immediately, so destruction must stay fork-safe.
    pub(in crate::linux_pytest) struct ForkChildPublishedRootV1 {
        published_descriptor: RawFd,
        root_descriptor: RawFd,
        root_name: [u8; MAX_BASENAME_BYTES + 1],
        root_name_len: u16,
        published_namespace_path: [u8; CHILD_NAMESPACE_PATH_BYTES_V1],
        published_namespace_path_len: u16,
        root_namespace_path: [u8; CHILD_NAMESPACE_PATH_BYTES_V1],
        root_namespace_path_len: u16,
        /// Exact host-user-namespace commitment authenticated before clone.
        /// It is retained as provenance but is never compared to the child
        /// namespace's remapped ownership view.
        _expected_host_statx_commitment: [u8; 102],
        /// Separately typed child-user-namespace view. Only uid/gid differ
        /// from the host commitment, and both are normalized to namespace 0
        /// after authenticating the host owner against the exact single-ID
        /// map inputs.
        expected_child_statx_commitment: ChildMappedStatxCommitmentV1,
        role: SnapshotChildRootRoleV1,
    }

    #[derive(Clone, Copy, Eq, PartialEq)]
    struct ChildMappedStatxCommitmentV1([u8; 102]);

    fn child_mapped_statx_commitment_v1(
        host: [u8; 102],
        mapped_host_uid: u32,
        mapped_host_gid: u32,
    ) -> Option<ChildMappedStatxCommitmentV1> {
        let observed_uid = u32::from_le_bytes(host[29..33].try_into().ok()?);
        let observed_gid = u32::from_le_bytes(host[33..37].try_into().ok()?);
        if observed_uid != mapped_host_uid || observed_gid != mapped_host_gid {
            return None;
        }
        let mut child = host;
        child[29..33].copy_from_slice(&0_u32.to_le_bytes());
        child[33..37].copy_from_slice(&0_u32.to_le_bytes());
        Some(ChildMappedStatxCommitmentV1(child))
    }

    impl Drop for ForkChildPublishedRootV1 {
        fn drop(&mut self) {
            for descriptor in [&mut self.root_descriptor, &mut self.published_descriptor] {
                if *descriptor >= 0 {
                    let _ = unsafe { libc::syscall(libc::SYS_close, *descriptor) };
                    *descriptor = -1;
                }
            }
        }
    }

    impl fmt::Debug for ForkChildPublishedRootV1 {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("ForkChildPublishedRootV1")
                .field("role", &self.role)
                .field("descriptor", &"<child-only-redacted>")
                .finish()
        }
    }

    impl fmt::Debug for VerifiedReadySnapshotDirectoryV1<'_> {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("VerifiedReadySnapshotDirectoryV1")
                .field("staging_name", &"<private-basename>")
                .field("identity", &self.cleanup.expected_identity)
                .field("directory_capability", &"<owned-fd>")
                .finish()
        }
    }

    impl fmt::Debug for BoundPublishedSnapshotChildV1 {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("BoundPublishedSnapshotChildV1")
                .field("published_directory", &"<owned-fd>")
                .field("root_directory", &"<owned-fd>")
                .finish()
        }
    }

    impl<'parent> StagedSnapshotDirectoryV1<'parent> {
        pub(in crate::linux_pytest) fn directory(&self) -> BorrowedFd<'_> {
            self.cleanup.directory()
        }

        pub(in crate::linux_pytest) fn cleanup_envelope(&self) -> SnapshotCleanupEnvelopeV1 {
            self.cleanup.policy().cleanup_envelope()
        }

        /// The callback is a trusted durability boundary. Before returning
        /// `Ok(())`, it must finish population, fsync every regular file, and
        /// fsync descendant directories bottom-up. This method then pins and
        /// revalidates the root and fsyncs that root itself.
        pub(in crate::linux_pytest) fn verify_ready_with<F>(
            self,
            verify_recursive_durability: F,
        ) -> Result<VerifiedReadySnapshotDirectoryV1<'parent>, SnapshotPublishErrorV1>
        where
            F: FnOnce(BorrowedFd<'_>) -> io::Result<()>,
        {
            let mut transitions = KernelTransitions;
            self.verify_ready_with_transitions(verify_recursive_durability, &mut transitions)
        }
    }

    impl<'resources> ChargedStagedSnapshotDirectoryV1<'resources> {
        pub(in crate::linux_pytest) fn directory(&self) -> BorrowedFd<'_> {
            self.cleanup.directory()
        }

        /// Returns the owner recorded when the connector created and pinned
        /// this private stage. The pair is comparison input only; it carries
        /// no descriptor, cleanup, readiness, or publication authority.
        pub(in crate::linux_pytest) fn expected_owner(&self) -> (u32, u32) {
            let identity = self.cleanup.expected_identity();
            (identity.uid, identity.gid)
        }

        pub(in crate::linux_pytest) fn cleanup_envelope(&self) -> SnapshotCleanupEnvelopeV1 {
            self.cleanup.policy().cleanup_envelope()
        }

        /// Escrows the leaf's complete child-binding work before sealing can
        /// make publication irreversible. The count comes only from the
        /// embedded charged publication policy. This is operation authority,
        /// not evidence that any child is stable, immutable, isolated, or
        /// eligible for execution or reuse.
        pub(in crate::linux_pytest) fn reserve_published_child_bind_attempts(
            &self,
        ) -> Result<
            SnapshotPublishedChildBindReservationV1<'resources>,
            SnapshotPipelineResourceErrorV1,
        > {
            self.cleanup
                .authority
                .reserve_published_child_bind_attempts()
        }
    }

    impl<'parent> VerifiedReadySnapshotDirectoryV1<'parent> {
        pub(super) fn publish_at(
            self,
            final_name: &CStr,
        ) -> Result<PublishedSnapshotDirectoryV1, SnapshotPublishErrorV1> {
            let mut transitions = KernelTransitions;
            self.publish_at_with_transitions(final_name, &mut transitions)
        }
    }

    impl PublishedSnapshotDirectoryV1 {
        pub(super) fn directory(&self) -> BorrowedFd<'_> {
            self.directory.as_fd()
        }
    }

    impl BoundPublishedSnapshotChildV1 {
        #[cfg(test)]
        pub(super) fn published_directory(&self) -> BorrowedFd<'_> {
            self.published.as_fd()
        }

        #[cfg(test)]
        pub(super) fn root_directory(&self) -> BorrowedFd<'_> {
            self.root.as_fd()
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum BoundReadStageV1 {
        AfterComponentOpen,
        AfterDirectoryRecorded,
        BeforeSymlinkRead,
        BeforeFinalRecheck,
    }

    trait BoundReadHookV1 {
        fn checkpoint(&mut self, _stage: BoundReadStageV1) -> io::Result<()> {
            Ok(())
        }
    }

    struct KernelBoundReadHookV1;
    impl BoundReadHookV1 for KernelBoundReadHookV1 {}

    pub(super) fn read_bound_regular_bytes_v1(
        bound: &BoundPublishedSnapshotChildV1,
        path: &[u8],
        byte_ceiling: u32,
        memory: &RuntimeMemoryEscrowV1,
    ) -> Result<VerifiedBoundRegularBytesV1, BoundRegularReadRefusalV1> {
        read_bound_regular_bytes_with_hook_v1(
            bound,
            path,
            byte_ceiling,
            memory,
            &mut KernelBoundReadHookV1,
        )
    }

    fn read_bound_regular_bytes_with_hook_v1<H: BoundReadHookV1>(
        bound: &BoundPublishedSnapshotChildV1,
        path: &[u8],
        byte_ceiling: u32,
        memory: &RuntimeMemoryEscrowV1,
        hook: &mut H,
    ) -> Result<VerifiedBoundRegularBytesV1, BoundRegularReadRefusalV1> {
        let published_before = node_statx_v1(bound.published.as_fd())?;
        let root_before = node_statx_v1(bound.root.as_fd())?;
        if published_before.mode() & libc::S_IFMT != libc::S_IFDIR
            || root_before.mode() & libc::S_IFMT != libc::S_IFDIR
        {
            return Err(BoundRegularReadRefusalV1::IdentityDrift);
        }
        let root_commitment = root_before.commitment_bytes_v1();
        let initial = split_bound_path_v1(path, memory)?;
        let initial_path = join_bound_components_v1(&initial, memory)?;
        let mut pending = initial;
        let mut resolved_prefix =
            memory.try_vec_with_capacity(BOUND_REGULAR_PATH_MAX_COMPONENTS_V1)?;
        let mut ancestors =
            memory.try_vec_with_capacity(BOUND_REGULAR_PATH_MAX_COMPONENTS_V1 + 1)?;
        let mut nodes = memory.try_vec_with_capacity(BOUND_REGULAR_MAX_OBSERVED_NODES_V1)?;
        let mut normalized_paths =
            memory.try_vec_with_capacity(BOUND_REGULAR_SYMLINK_MAX_HOPS_V1 + 1)?;
        normalized_paths.push(initial_path);
        let mut visited_symlink_identities =
            memory.try_vec_with_capacity(BOUND_REGULAR_SYMLINK_MAX_HOPS_V1)?;
        let mut symlink_hops = 0usize;

        loop {
            let component = memory.try_bytes_from_slice(
                pending
                    .first()
                    .ok_or(BoundRegularReadRefusalV1::InvalidPath)?,
            )?;
            let name_capacity = component
                .len()
                .checked_add(1)
                .ok_or(BoundRegularReadRefusalV1::MemoryBudget)?;
            let mut component_name_bytes = memory.try_vec_with_capacity(name_capacity)?;
            component_name_bytes.extend_from_slice(&component);
            component_name_bytes.push(0);
            let component_name =
                unsafe { CString::from_vec_with_nul_unchecked(component_name_bytes) };
            revalidate_bound_ancestors_v1(bound, root_commitment, &ancestors)?;
            let parent = ancestors
                .last()
                .map_or(bound.root.as_fd(), |ancestor: &VerifiedBoundPinnedFdV1| {
                    ancestor.fd.as_fd()
                });
            let path_fd = open_bound_component_v1(
                parent,
                &component_name,
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )?;
            hook.checkpoint(BoundReadStageV1::AfterComponentOpen)
                .map_err(map_bound_io_v1)?;
            revalidate_bound_ancestors_v1(bound, root_commitment, &ancestors)?;
            let before = node_statx_v1(path_fd.as_fd())?;
            let mut observed_path_components = clone_bound_components_v1(
                &resolved_prefix,
                resolved_prefix
                    .len()
                    .checked_add(1)
                    .ok_or(BoundRegularReadRefusalV1::MemoryBudget)?,
                memory,
            )?;
            observed_path_components.push(memory.try_bytes_from_slice(&component)?);
            let observed_path = join_bound_components_v1(&observed_path_components, memory)?;
            let mode_type = before.mode() & libc::S_IFMT;

            if mode_type == libc::S_IFLNK {
                symlink_hops = symlink_hops
                    .checked_add(1)
                    .ok_or(BoundRegularReadRefusalV1::SymlinkLimit)?;
                if symlink_hops > BOUND_REGULAR_SYMLINK_MAX_HOPS_V1 {
                    return Err(BoundRegularReadRefusalV1::SymlinkLimit);
                }
                let mut identity = [0u8; 24];
                identity.copy_from_slice(&before.commitment_bytes_v1()[1..25]);
                if visited_symlink_identities.contains(&identity) {
                    return Err(BoundRegularReadRefusalV1::SymlinkCycle);
                }
                visited_symlink_identities.push(identity);
                hook.checkpoint(BoundReadStageV1::BeforeSymlinkRead)
                    .map_err(map_bound_io_v1)?;
                let target = read_bound_link_v1(path_fd.as_fd(), memory)?;
                let after = node_statx_v1(path_fd.as_fd())?;
                if before.commitment_bytes_v1() != after.commitment_bytes_v1() {
                    return Err(BoundRegularReadRefusalV1::IdentityDrift);
                }
                revalidate_bound_ancestors_v1(bound, root_commitment, &ancestors)?;
                let target_components = split_bound_path_v1(&target, memory).map_err(|error| {
                    if error == BoundRegularReadRefusalV1::MemoryBudget {
                        error
                    } else {
                        BoundRegularReadRefusalV1::SymlinkTargetInvalid
                    }
                })?;
                let next_count = resolved_prefix
                    .len()
                    .checked_add(target_components.len())
                    .and_then(|count| count.checked_add(pending.len().saturating_sub(1)))
                    .ok_or(BoundRegularReadRefusalV1::ComponentLimit)?;
                if next_count > BOUND_REGULAR_PATH_MAX_COMPONENTS_V1 {
                    return Err(BoundRegularReadRefusalV1::ComponentLimit);
                }
                let mut next = clone_bound_components_v1(&resolved_prefix, next_count, memory)?;
                for target_component in target_components {
                    next.push(target_component);
                }
                for remaining in pending.iter().skip(1) {
                    next.push(memory.try_bytes_from_slice(remaining)?);
                }
                let normalized_next = join_bound_components_v1(&next, memory)?;
                if normalized_paths
                    .iter()
                    .any(|existing| existing.as_slice() == normalized_next.as_slice())
                {
                    return Err(BoundRegularReadRefusalV1::SymlinkCycle);
                }
                normalized_paths.push(memory.try_bytes_from_slice(&normalized_next)?);
                push_unique_bound_node_v1(
                    &mut nodes,
                    VerifiedBoundPathNodeV1 {
                        normalized_path: observed_path.into_boxed_slice(),
                        kind: VerifiedBoundNodeKindV1::Symlink,
                        statx_commitment: before.commitment_bytes_v1(),
                        symlink_target: Some(target.into_boxed_slice()),
                        normalized_next_path: Some(normalized_next.into_boxed_slice()),
                        live_statx: before,
                    },
                )?;
                pending = next;
                resolved_prefix.clear();
                ancestors.clear();
                continue;
            }

            let terminal = pending.len() == 1;
            if mode_type == libc::S_IFDIR && !terminal {
                push_unique_bound_node_v1(
                    &mut nodes,
                    VerifiedBoundPathNodeV1 {
                        normalized_path: observed_path.into_boxed_slice(),
                        kind: VerifiedBoundNodeKindV1::Directory,
                        statx_commitment: before.commitment_bytes_v1(),
                        symlink_target: None,
                        normalized_next_path: None,
                        live_statx: before.clone(),
                    },
                )?;
                resolved_prefix.push(component);
                pending.remove(0);
                ancestors.push(VerifiedBoundPinnedFdV1 {
                    fd: path_fd,
                    expected: before.commitment_bytes_v1(),
                });
                hook.checkpoint(BoundReadStageV1::AfterDirectoryRecorded)
                    .map_err(map_bound_io_v1)?;
                continue;
            }
            if mode_type != libc::S_IFREG || !terminal {
                return Err(BoundRegularReadRefusalV1::NodeType);
            }

            let read_fd = open_bound_component_v1(
                parent,
                &component_name,
                libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NOATIME | libc::O_CLOEXEC,
            )?;
            let opened = node_statx_v1(read_fd.as_fd())?;
            if before.commitment_bytes_v1() != opened.commitment_bytes_v1() {
                return Err(BoundRegularReadRefusalV1::IdentityDrift);
            }
            if opened.nlink() != 1 {
                return Err(BoundRegularReadRefusalV1::IdentityDrift);
            }
            let size =
                usize::try_from(opened.size()).map_err(|_| BoundRegularReadRefusalV1::ByteLimit)?;
            if size > byte_ceiling as usize {
                return Err(BoundRegularReadRefusalV1::ByteLimit);
            }
            let mut file = std::fs::File::from(read_fd);
            let mut bytes = read_exact_bound_regular_size_v1(&mut file, size, memory)?;
            let after = node_statx_v1(file.as_fd())?;
            if opened.commitment_bytes_v1() != after.commitment_bytes_v1() {
                bytes.fill(0);
                return Err(BoundRegularReadRefusalV1::IdentityDrift);
            }
            let terminal_commitment = opened.commitment_bytes_v1();
            push_unique_bound_node_v1(
                &mut nodes,
                VerifiedBoundPathNodeV1 {
                    normalized_path: observed_path.into_boxed_slice(),
                    kind: VerifiedBoundNodeKindV1::Regular,
                    statx_commitment: terminal_commitment,
                    symlink_target: None,
                    normalized_next_path: None,
                    live_statx: opened.clone(),
                },
            )?;
            hook.checkpoint(BoundReadStageV1::BeforeFinalRecheck)
                .map_err(map_bound_io_v1)?;
            revalidate_bound_ancestors_v1(bound, root_commitment, &ancestors)?;
            let root_after = node_statx_v1(bound.root.as_fd())?;
            let published_after = node_statx_v1(bound.published.as_fd())?;
            if root_commitment != root_after.commitment_bytes_v1()
                || published_before.commitment_bytes_v1() != published_after.commitment_bytes_v1()
            {
                bytes.fill(0);
                return Err(BoundRegularReadRefusalV1::IdentityDrift);
            }
            let content_digest =
                FileContentDigest::derive(super::super::FILE_CONTENT_DOMAIN, &[&bytes]);
            let read_fd: OwnedFd = file.into();
            ancestors.push(VerifiedBoundPinnedFdV1 {
                fd: read_fd,
                expected: terminal_commitment,
            });
            return Ok(VerifiedBoundRegularBytesV1 {
                terminal_identity_digest: Blake3Digest::derive(
                    BOUND_REGULAR_IDENTITY_DOMAIN_V1,
                    &[&terminal_commitment],
                ),
                bytes,
                nodes,
                pinned_fds: ancestors,
                published_statx_commitment: published_before.commitment_bytes_v1(),
                root_statx_commitment: root_commitment,
                root_live_statx: root_before,
                content_digest,
            });
        }
    }

    fn revalidate_bound_ancestors_v1(
        bound: &BoundPublishedSnapshotChildV1,
        root_commitment: [u8; 102],
        ancestors: &[VerifiedBoundPinnedFdV1],
    ) -> Result<(), BoundRegularReadRefusalV1> {
        if node_statx_v1(bound.root.as_fd())?.commitment_bytes_v1() != root_commitment {
            return Err(BoundRegularReadRefusalV1::IdentityDrift);
        }
        for ancestor in ancestors {
            if node_statx_v1(ancestor.fd.as_fd())?.commitment_bytes_v1() != ancestor.expected {
                return Err(BoundRegularReadRefusalV1::IdentityDrift);
            }
        }
        Ok(())
    }

    pub(super) fn revalidate_bound_regular_bytes_v1(
        bound: &BoundPublishedSnapshotChildV1,
        verified: &VerifiedBoundRegularBytesV1,
    ) -> Result<(), BoundRegularReadRefusalV1> {
        if node_statx_v1(bound.published.as_fd())?.commitment_bytes_v1()
            != verified.published_statx_commitment
        {
            return Err(BoundRegularReadRefusalV1::IdentityDrift);
        }
        revalidate_bound_ancestors_v1(bound, verified.root_statx_commitment, &verified.pinned_fds)
    }

    pub(super) fn consume_bound_published_snapshot_root_projection_v1(
        bound: &BoundPublishedSnapshotChildV1,
        child_name: &CStr,
        expected_root_statx_commitment: [u8; 102],
    ) -> Result<(), BoundRegularReadRefusalV1> {
        if !valid_raw_basename(child_name) {
            return Err(BoundRegularReadRefusalV1::InvalidPath);
        }
        if !bound.retained_root_projection_admitted.replace(false) {
            return Err(BoundRegularReadRefusalV1::OperationBudget);
        }
        let named = node_statx_at_name_v1(bound.published.as_fd(), child_name)?;
        if named.mode() & libc::S_IFMT != libc::S_IFDIR
            || named.commitment_bytes_v1() != expected_root_statx_commitment
        {
            return Err(BoundRegularReadRefusalV1::IdentityDrift);
        }
        Ok(())
    }

    pub(super) fn prepare_fork_child_published_root_v1(
        bound: &BoundPublishedSnapshotChildV1,
        role: SnapshotChildRootRoleV1,
        root_name: &CStr,
        expected_statx_commitment: [u8; 102],
    ) -> Result<ForkChildPublishedRootV1, BoundRegularReadRefusalV1> {
        if !valid_raw_basename(root_name) {
            return Err(BoundRegularReadRefusalV1::InvalidPath);
        }
        let published_path_before = namespace_path_for_descriptor_v1(bound.published.as_raw_fd())?;
        let root_path_before = namespace_path_for_descriptor_v1(bound.root.as_raw_fd())?;
        let named_before = node_statx_at_name_v1(bound.published.as_fd(), root_name)?;
        let root_before = node_statx_v1(bound.root.as_fd())?;
        if named_before.commitment_bytes_v1() != expected_statx_commitment
            || root_before.commitment_bytes_v1() != expected_statx_commitment
        {
            return Err(BoundRegularReadRefusalV1::IdentityDrift);
        }
        let expected_child_statx_commitment = child_mapped_statx_commitment_v1(
            expected_statx_commitment,
            unsafe { libc::getuid() },
            unsafe { libc::getgid() },
        )
        .ok_or(BoundRegularReadRefusalV1::IdentityDrift)?;

        let published_raw =
            unsafe { libc::fcntl(bound.published.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 5) };
        if published_raw < 0 {
            return Err(map_bound_io_v1(io::Error::last_os_error()));
        }
        let published = unsafe { OwnedFd::from_raw_fd(published_raw) };
        let root_raw = unsafe { libc::fcntl(bound.root.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 5) };
        if root_raw < 0 {
            return Err(map_bound_io_v1(io::Error::last_os_error()));
        }
        let root = unsafe { OwnedFd::from_raw_fd(root_raw) };

        let named_duplicate = node_statx_at_name_v1(published.as_fd(), root_name)?;
        let root_duplicate = node_statx_v1(root.as_fd())?;
        let named_after = node_statx_at_name_v1(bound.published.as_fd(), root_name)?;
        let root_after = node_statx_v1(bound.root.as_fd())?;
        let published_path_after = namespace_path_for_descriptor_v1(bound.published.as_raw_fd())?;
        let root_path_after = namespace_path_for_descriptor_v1(bound.root.as_raw_fd())?;
        if named_duplicate.commitment_bytes_v1() != expected_statx_commitment
            || root_duplicate.commitment_bytes_v1() != expected_statx_commitment
            || named_after.commitment_bytes_v1() != expected_statx_commitment
            || root_after.commitment_bytes_v1() != expected_statx_commitment
            || published_path_before != published_path_after
            || root_path_before != root_path_after
        {
            return Err(BoundRegularReadRefusalV1::IdentityDrift);
        }
        let name = root_name.to_bytes();
        let mut root_name_bytes = [0_u8; MAX_BASENAME_BYTES + 1];
        root_name_bytes[..name.len()].copy_from_slice(name);
        let root_name_len =
            u16::try_from(name.len()).map_err(|_| BoundRegularReadRefusalV1::InvalidPath)?;
        Ok(ForkChildPublishedRootV1 {
            published_descriptor: published.into_raw_fd(),
            root_descriptor: root.into_raw_fd(),
            root_name: root_name_bytes,
            root_name_len,
            published_namespace_path: published_path_before.0,
            published_namespace_path_len: published_path_before.1,
            root_namespace_path: root_path_before.0,
            root_namespace_path_len: root_path_before.1,
            _expected_host_statx_commitment: expected_statx_commitment,
            expected_child_statx_commitment,
            role,
        })
    }

    fn namespace_path_for_descriptor_v1(
        descriptor: RawFd,
    ) -> Result<([u8; CHILD_NAMESPACE_PATH_BYTES_V1], u16), BoundRegularReadRefusalV1> {
        if descriptor < 0 {
            return Err(BoundRegularReadRefusalV1::IdentityDrift);
        }
        let proc_root = authenticated_proc_root_for_namespace_path_v1()?;
        let proc_path = CString::new(format!("self/fd/{descriptor}"))
            .map_err(|_| BoundRegularReadRefusalV1::IdentityDrift)?;
        let mut bytes = [0_u8; CHILD_NAMESPACE_PATH_BYTES_V1];
        let count = unsafe {
            libc::readlinkat(
                proc_root.as_raw_fd(),
                proc_path.as_ptr(),
                bytes.as_mut_ptr().cast(),
                bytes.len(),
            )
        };
        finish_namespace_path_capture_v1(bytes, count)
    }

    fn authenticated_proc_root_for_namespace_path_v1() -> Result<OwnedFd, BoundRegularReadRefusalV1>
    {
        const PROC_SUPER_MAGIC_V1: libc::c_long = 0x0000_9fa0;
        let raw = unsafe {
            libc::open(
                c"/proc".as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if raw < 0 {
            return Err(map_bound_io_v1(io::Error::last_os_error()));
        }
        let proc_root = unsafe { OwnedFd::from_raw_fd(raw) };
        let mut filesystem = MaybeUninit::<libc::statfs>::zeroed();
        if unsafe { libc::fstatfs(proc_root.as_raw_fd(), filesystem.as_mut_ptr()) } != 0 {
            return Err(map_bound_io_v1(io::Error::last_os_error()));
        }
        let filesystem = unsafe { filesystem.assume_init() };
        if filesystem.f_type != PROC_SUPER_MAGIC_V1 {
            return Err(BoundRegularReadRefusalV1::IdentityDrift);
        }
        let mut self_link = [0_u8; 32];
        let count = unsafe {
            libc::readlinkat(
                proc_root.as_raw_fd(),
                c"self".as_ptr(),
                self_link.as_mut_ptr().cast(),
                self_link.len(),
            )
        };
        let count = usize::try_from(count)
            .ok()
            .filter(|count| *count > 0 && *count < self_link.len())
            .ok_or(BoundRegularReadRefusalV1::IdentityDrift)?;
        if self_link[..count] != unsafe { libc::getpid() }.to_string().as_bytes()[..] {
            return Err(BoundRegularReadRefusalV1::IdentityDrift);
        }
        Ok(proc_root)
    }

    fn finish_namespace_path_capture_v1(
        mut bytes: [u8; CHILD_NAMESPACE_PATH_BYTES_V1],
        count: isize,
    ) -> Result<([u8; CHILD_NAMESPACE_PATH_BYTES_V1], u16), BoundRegularReadRefusalV1> {
        let count = usize::try_from(count)
            .ok()
            .filter(|count| *count > 1 && *count < bytes.len())
            .ok_or(BoundRegularReadRefusalV1::IdentityDrift)?;
        if bytes[0] != b'/'
            || bytes[..count].contains(&0)
            || bytes[..count].ends_with(b" (deleted)")
        {
            return Err(BoundRegularReadRefusalV1::IdentityDrift);
        }
        bytes[count] = 0;
        let count = u16::try_from(count).map_err(|_| BoundRegularReadRefusalV1::IdentityDrift)?;
        Ok((bytes, count))
    }

    const OPEN_TREE_CLONE_V1: libc::c_uint = 1;
    const OPEN_TREE_CLOEXEC_V1: libc::c_uint = libc::O_CLOEXEC as libc::c_uint;
    const AT_RECURSIVE_V1: libc::c_uint = 0x8000;
    const MOVE_MOUNT_F_EMPTY_PATH_V1: libc::c_uint = 0x0000_0004;
    const MOVE_MOUNT_T_EMPTY_PATH_V1: libc::c_uint = 0x0000_0040;
    const MOUNT_ATTR_RDONLY_V1: u64 = 0x0000_0001;
    const MOUNT_ATTR_NOSUID_V1: u64 = 0x0000_0002;
    const MOUNT_ATTR_NODEV_V1: u64 = 0x0000_0004;
    const REQUIRED_ATTACHED_STATFS_FLAGS_V1: libc::c_ulong =
        (libc::ST_RDONLY | libc::ST_NOSUID | libc::ST_NODEV) as libc::c_ulong;
    const EMPTY_PATH_V1: &CStr = c"";
    const WORKSPACE_TARGET_V1: &CStr = c"/workspace";
    const RUNTIME_TARGET_V1: &CStr = c"/runtime";

    #[repr(C)]
    struct LinuxMountAttrV1 {
        attr_set: u64,
        attr_clr: u64,
        propagation: u64,
        userns_fd: u64,
    }

    #[derive(Clone, Copy, Debug, Default)]
    struct ChildAttachOperationPlanV1 {
        failures: [Option<(SnapshotChildRootRoleV1, SnapshotChildAttachOperationV1)>; 2],
    }

    impl ChildAttachOperationPlanV1 {
        const fn fail(
            role: SnapshotChildRootRoleV1,
            operation: SnapshotChildAttachOperationV1,
        ) -> Self {
            Self {
                failures: [Some((role, operation)), None],
            }
        }

        fn check(
            self,
            role: SnapshotChildRootRoleV1,
            operation: SnapshotChildAttachOperationV1,
        ) -> Result<(), SnapshotChildAttachFailureV1> {
            if self.failures.contains(&Some((role, operation))) {
                Err(SnapshotChildAttachFailureV1::Injected {
                    role,
                    operation,
                    errno: libc::EIO,
                })
            } else {
                Ok(())
            }
        }
    }

    struct ChildTrackedAttachFdV1 {
        descriptor: RawFd,
    }

    impl ChildTrackedAttachFdV1 {
        fn from_syscall(
            result: libc::c_long,
            role: SnapshotChildRootRoleV1,
            operation: SnapshotChildAttachOperationV1,
        ) -> Result<Self, SnapshotChildAttachFailureV1> {
            let descriptor = i32::try_from(result)
                .ok()
                .filter(|fd| *fd >= 0)
                .ok_or_else(|| child_attach_os_failure_v1(role, operation))?;
            Ok(Self { descriptor })
        }

        fn close(
            &mut self,
            role: SnapshotChildRootRoleV1,
        ) -> Result<(), SnapshotChildAttachFailureV1> {
            if self.descriptor < 0 {
                return Ok(());
            }
            let descriptor = self.descriptor;
            self.descriptor = -1;
            if unsafe { libc::syscall(libc::SYS_close, descriptor) } == 0 {
                Ok(())
            } else {
                Err(child_attach_os_failure_v1(
                    role,
                    SnapshotChildAttachOperationV1::CloseKnownDescriptors,
                ))
            }
        }
    }

    impl Drop for ChildTrackedAttachFdV1 {
        fn drop(&mut self) {
            if self.descriptor >= 0 {
                let _ = unsafe { libc::syscall(libc::SYS_close, self.descriptor) };
                self.descriptor = -1;
            }
        }
    }

    pub(super) fn attach_fork_child_published_roots_v1(
        mut workspace: ForkChildPublishedRootV1,
        mut runtime: ForkChildPublishedRootV1,
        child_brand: &IsolationChildOnlyBrandV1,
    ) -> Result<(), SnapshotChildAttachFailureV1> {
        attach_fork_child_published_roots_with_plan_v1(
            &mut workspace,
            &mut runtime,
            child_brand,
            ChildAttachOperationPlanV1::default(),
        )
    }

    #[cfg(test)]
    pub(super) fn attach_fork_child_published_roots_with_test_fault_v1(
        mut workspace: ForkChildPublishedRootV1,
        mut runtime: ForkChildPublishedRootV1,
        child_brand: &IsolationChildOnlyBrandV1,
        role: SnapshotChildRootRoleV1,
        operation: SnapshotChildAttachOperationV1,
    ) -> Result<(), SnapshotChildAttachFailureV1> {
        attach_fork_child_published_roots_with_plan_v1(
            &mut workspace,
            &mut runtime,
            child_brand,
            ChildAttachOperationPlanV1::fail(role, operation),
        )
    }

    pub(super) fn attach_fork_child_published_roots_with_fixed_runtime_refusal_v1(
        mut workspace: ForkChildPublishedRootV1,
        mut runtime: ForkChildPublishedRootV1,
        child_brand: &IsolationChildOnlyBrandV1,
    ) -> Result<(), SnapshotChildAttachFailureV1> {
        attach_fork_child_published_roots_with_plan_v1(
            &mut workspace,
            &mut runtime,
            child_brand,
            ChildAttachOperationPlanV1::fail(
                SnapshotChildRootRoleV1::Runtime,
                SnapshotChildAttachOperationV1::OpenTree,
            ),
        )
    }

    fn attach_fork_child_published_roots_with_plan_v1(
        workspace: &mut ForkChildPublishedRootV1,
        runtime: &mut ForkChildPublishedRootV1,
        child_brand: &IsolationChildOnlyBrandV1,
        plan: ChildAttachOperationPlanV1,
    ) -> Result<(), SnapshotChildAttachFailureV1> {
        child_validate_fork_child_root_pair_v1(workspace, runtime)?;
        child_rebind_source_in_current_mount_namespace_v1(workspace, child_brand)?;
        child_rebind_source_in_current_mount_namespace_v1(runtime, child_brand)?;
        child_attach_validate_source_v1(workspace, plan)?;
        child_attach_validate_source_v1(runtime, plan)?;
        let workspace_target = child_attach_one_root_v1(workspace, WORKSPACE_TARGET_V1, plan)?;
        let runtime_target = child_attach_one_root_v1(runtime, RUNTIME_TARGET_V1, plan)?;
        child_verify_final_attached_target_v1(
            SnapshotChildRootRoleV1::Workspace,
            WORKSPACE_TARGET_V1,
            workspace_target,
            plan,
        )?;
        child_verify_final_attached_target_v1(
            SnapshotChildRootRoleV1::Runtime,
            RUNTIME_TARGET_V1,
            runtime_target,
            plan,
        )?;
        child_attach_final_source_revalidation_v1(workspace, plan)?;
        child_attach_final_source_revalidation_v1(runtime, plan)?;
        child_attach_close_root_v1(workspace, plan)?;
        child_attach_close_root_v1(runtime, plan)?;
        Ok(())
    }

    fn child_validate_fork_child_root_pair_v1(
        workspace: &ForkChildPublishedRootV1,
        runtime: &ForkChildPublishedRootV1,
    ) -> Result<(), SnapshotChildAttachFailureV1> {
        if workspace.role != SnapshotChildRootRoleV1::Workspace {
            return Err(SnapshotChildAttachFailureV1::Invariant {
                role: SnapshotChildRootRoleV1::Workspace,
                operation: SnapshotChildAttachOperationV1::ValidateSource,
            });
        }
        if runtime.role != SnapshotChildRootRoleV1::Runtime {
            return Err(SnapshotChildAttachFailureV1::Invariant {
                role: SnapshotChildRootRoleV1::Runtime,
                operation: SnapshotChildAttachOperationV1::ValidateSource,
            });
        }
        if workspace.expected_child_statx_commitment.0[1..25]
            == runtime.expected_child_statx_commitment.0[1..25]
        {
            return Err(SnapshotChildAttachFailureV1::Invariant {
                role: SnapshotChildRootRoleV1::Runtime,
                operation: SnapshotChildAttachOperationV1::ValidateSource,
            });
        }
        Ok(())
    }

    fn child_rebind_source_in_current_mount_namespace_v1(
        root: &mut ForkChildPublishedRootV1,
        child_brand: &IsolationChildOnlyBrandV1,
    ) -> Result<(), SnapshotChildAttachFailureV1> {
        let operation = SnapshotChildAttachOperationV1::ValidateSource;
        let role = root.role;
        let published_end = usize::from(root.published_namespace_path_len)
            .checked_add(1)
            .filter(|end| *end <= root.published_namespace_path.len())
            .ok_or(SnapshotChildAttachFailureV1::Invariant { role, operation })?;
        let root_end = usize::from(root.root_namespace_path_len)
            .checked_add(1)
            .filter(|end| *end <= root.root_namespace_path.len())
            .ok_or(SnapshotChildAttachFailureV1::Invariant { role, operation })?;
        let published_path =
            CStr::from_bytes_with_nul(&root.published_namespace_path[..published_end])
                .map_err(|_| SnapshotChildAttachFailureV1::Invariant { role, operation })?;
        let root_path = CStr::from_bytes_with_nul(&root.root_namespace_path[..root_end])
            .map_err(|_| SnapshotChildAttachFailureV1::Invariant { role, operation })?;
        let published = reopen_isolation_child_publication_path_v1(child_brand, published_path)
            .map_err(|errno| child_attach_error_from_errno_v1(role, operation, Some(errno)))?;
        let mut published = ChildTrackedAttachFdV1 {
            descriptor: published,
        };
        let rebound_root = reopen_isolation_child_publication_path_v1(child_brand, root_path)
            .map_err(|errno| child_attach_error_from_errno_v1(role, operation, Some(errno)))?;
        let mut rebound_root = ChildTrackedAttachFdV1 {
            descriptor: rebound_root,
        };
        let rebound_named = child_statx_at_name_v1(
            published.descriptor,
            child_root_name_v1(root)
                .ok_or(SnapshotChildAttachFailureV1::Invariant { role, operation })?,
            role,
            operation,
        )?;
        let rebound_selected = child_statx_fd_v1(rebound_root.descriptor, role, operation)?;
        if rebound_named != rebound_selected
            || rebound_named[1..9] == 0_u64.to_le_bytes()
            || rebound_named[0] != root.expected_child_statx_commitment.0[0]
            || rebound_named[9..] != root.expected_child_statx_commitment.0[9..]
        {
            return Err(SnapshotChildAttachFailureV1::Invariant { role, operation });
        }
        root.expected_child_statx_commitment.0[1..9].copy_from_slice(&rebound_named[1..9]);
        for descriptor in [&mut root.root_descriptor, &mut root.published_descriptor] {
            if *descriptor < 0 || unsafe { libc::syscall(libc::SYS_close, *descriptor) } != 0 {
                return Err(child_attach_os_failure_v1(role, operation));
            }
            *descriptor = -1;
        }
        root.published_descriptor = published.descriptor;
        published.descriptor = -1;
        root.root_descriptor = rebound_root.descriptor;
        rebound_root.descriptor = -1;
        Ok(())
    }

    fn child_attach_validate_source_v1(
        root: &ForkChildPublishedRootV1,
        plan: ChildAttachOperationPlanV1,
    ) -> Result<(), SnapshotChildAttachFailureV1> {
        let role = root.role;
        plan.check(role, SnapshotChildAttachOperationV1::ValidateSource)?;
        let name = child_root_name_v1(root).ok_or(SnapshotChildAttachFailureV1::Invariant {
            role,
            operation: SnapshotChildAttachOperationV1::ValidateSource,
        })?;
        let named = child_statx_at_name_v1(
            root.published_descriptor,
            name,
            role,
            SnapshotChildAttachOperationV1::ValidateSource,
        )?;
        let selected = child_statx_fd_v1(
            root.root_descriptor,
            role,
            SnapshotChildAttachOperationV1::ValidateSource,
        )?;
        if named != root.expected_child_statx_commitment.0
            || selected != root.expected_child_statx_commitment.0
        {
            return Err(SnapshotChildAttachFailureV1::Invariant {
                role,
                operation: SnapshotChildAttachOperationV1::ValidateSource,
            });
        }
        Ok(())
    }

    fn child_attach_one_root_v1(
        root: &ForkChildPublishedRootV1,
        target: &CStr,
        plan: ChildAttachOperationPlanV1,
    ) -> Result<[u8; 102], SnapshotChildAttachFailureV1> {
        let role = root.role;
        plan.check(role, SnapshotChildAttachOperationV1::OpenTree)?;
        let clone_result = unsafe {
            libc::syscall(
                libc::SYS_open_tree,
                root.root_descriptor,
                EMPTY_PATH_V1.as_ptr(),
                libc::AT_EMPTY_PATH as libc::c_uint | OPEN_TREE_CLONE_V1 | OPEN_TREE_CLOEXEC_V1,
            )
        };
        let mut detached = ChildTrackedAttachFdV1::from_syscall(
            clone_result,
            role,
            SnapshotChildAttachOperationV1::OpenTree,
        )?;
        let detached_identity = child_statx_fd_v1(
            detached.descriptor,
            role,
            SnapshotChildAttachOperationV1::OpenTree,
        )?;
        if detached_identity[9..] != root.expected_child_statx_commitment.0[9..] {
            return Err(SnapshotChildAttachFailureV1::Invariant {
                role,
                operation: SnapshotChildAttachOperationV1::OpenTree,
            });
        }

        plan.check(role, SnapshotChildAttachOperationV1::SetRecursiveAttributes)?;
        let attributes = LinuxMountAttrV1 {
            attr_set: MOUNT_ATTR_RDONLY_V1 | MOUNT_ATTR_NOSUID_V1 | MOUNT_ATTR_NODEV_V1,
            attr_clr: 0,
            propagation: 0,
            userns_fd: 0,
        };
        if unsafe {
            libc::syscall(
                libc::SYS_mount_setattr,
                detached.descriptor,
                EMPTY_PATH_V1.as_ptr(),
                libc::AT_EMPTY_PATH as libc::c_uint | AT_RECURSIVE_V1,
                &attributes,
                std::mem::size_of::<LinuxMountAttrV1>(),
            )
        } != 0
        {
            return Err(child_attach_os_failure_v1(
                role,
                SnapshotChildAttachOperationV1::SetRecursiveAttributes,
            ));
        }

        plan.check(role, SnapshotChildAttachOperationV1::OpenTarget)?;
        let target_result = unsafe {
            libc::syscall(
                libc::SYS_openat,
                libc::AT_FDCWD,
                target.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0_u32,
            )
        };
        let mut target_before = ChildTrackedAttachFdV1::from_syscall(
            target_result,
            role,
            SnapshotChildAttachOperationV1::OpenTarget,
        )?;
        let target_before_identity = child_statx_fd_v1(
            target_before.descriptor,
            role,
            SnapshotChildAttachOperationV1::OpenTarget,
        )?;
        if target_before_identity[25..29] != (libc::S_IFDIR | 0o755_u32).to_le_bytes() {
            return Err(SnapshotChildAttachFailureV1::Invariant {
                role,
                operation: SnapshotChildAttachOperationV1::OpenTarget,
            });
        }

        plan.check(role, SnapshotChildAttachOperationV1::MoveMount)?;
        if unsafe {
            libc::syscall(
                libc::SYS_move_mount,
                detached.descriptor,
                EMPTY_PATH_V1.as_ptr(),
                target_before.descriptor,
                EMPTY_PATH_V1.as_ptr(),
                MOVE_MOUNT_F_EMPTY_PATH_V1 | MOVE_MOUNT_T_EMPTY_PATH_V1,
            )
        } != 0
        {
            return Err(child_attach_os_failure_v1(
                role,
                SnapshotChildAttachOperationV1::MoveMount,
            ));
        }

        plan.check(role, SnapshotChildAttachOperationV1::ReopenTarget)?;
        let target_after_result = unsafe {
            libc::syscall(
                libc::SYS_openat,
                libc::AT_FDCWD,
                target.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0_u32,
            )
        };
        let mut target_after = ChildTrackedAttachFdV1::from_syscall(
            target_after_result,
            role,
            SnapshotChildAttachOperationV1::ReopenTarget,
        )?;
        plan.check(role, SnapshotChildAttachOperationV1::VerifyTarget)?;
        let target_after_identity = child_statx_fd_v1(
            target_after.descriptor,
            role,
            SnapshotChildAttachOperationV1::VerifyTarget,
        )?;
        if target_after_identity != detached_identity {
            return Err(SnapshotChildAttachFailureV1::Invariant {
                role,
                operation: SnapshotChildAttachOperationV1::VerifyTarget,
            });
        }
        let mut filesystem = MaybeUninit::<libc::statfs64>::zeroed();
        if unsafe {
            libc::syscall(
                libc::SYS_fstatfs,
                target_after.descriptor,
                filesystem.as_mut_ptr(),
            )
        } != 0
        {
            return Err(child_attach_os_failure_v1(
                role,
                SnapshotChildAttachOperationV1::VerifyTarget,
            ));
        }
        let filesystem = unsafe { filesystem.assume_init() };
        if filesystem.f_flags as libc::c_ulong & REQUIRED_ATTACHED_STATFS_FLAGS_V1
            != REQUIRED_ATTACHED_STATFS_FLAGS_V1
        {
            return Err(SnapshotChildAttachFailureV1::Invariant {
                role,
                operation: SnapshotChildAttachOperationV1::VerifyTarget,
            });
        }
        target_after.close(role)?;
        target_before.close(role)?;
        detached.close(role)?;
        Ok(detached_identity)
    }

    fn child_verify_final_attached_target_v1(
        role: SnapshotChildRootRoleV1,
        target: &CStr,
        expected: [u8; 102],
        plan: ChildAttachOperationPlanV1,
    ) -> Result<(), SnapshotChildAttachFailureV1> {
        plan.check(
            role,
            SnapshotChildAttachOperationV1::FinalTargetRevalidation,
        )?;
        let result = unsafe {
            libc::syscall(
                libc::SYS_openat,
                libc::AT_FDCWD,
                target.as_ptr(),
                libc::O_PATH | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0_u32,
            )
        };
        let mut target = ChildTrackedAttachFdV1::from_syscall(
            result,
            role,
            SnapshotChildAttachOperationV1::FinalTargetRevalidation,
        )?;
        if child_statx_fd_v1(
            target.descriptor,
            role,
            SnapshotChildAttachOperationV1::FinalTargetRevalidation,
        )? != expected
        {
            return Err(SnapshotChildAttachFailureV1::Invariant {
                role,
                operation: SnapshotChildAttachOperationV1::FinalTargetRevalidation,
            });
        }
        let mut filesystem = MaybeUninit::<libc::statfs64>::zeroed();
        if unsafe {
            libc::syscall(
                libc::SYS_fstatfs,
                target.descriptor,
                filesystem.as_mut_ptr(),
            )
        } != 0
        {
            return Err(child_attach_os_failure_v1(
                role,
                SnapshotChildAttachOperationV1::FinalTargetRevalidation,
            ));
        }
        let filesystem = unsafe { filesystem.assume_init() };
        if filesystem.f_flags as libc::c_ulong & REQUIRED_ATTACHED_STATFS_FLAGS_V1
            != REQUIRED_ATTACHED_STATFS_FLAGS_V1
        {
            return Err(SnapshotChildAttachFailureV1::Invariant {
                role,
                operation: SnapshotChildAttachOperationV1::FinalTargetRevalidation,
            });
        }
        target.close(role)
    }

    fn child_attach_final_source_revalidation_v1(
        root: &ForkChildPublishedRootV1,
        plan: ChildAttachOperationPlanV1,
    ) -> Result<(), SnapshotChildAttachFailureV1> {
        let role = root.role;
        plan.check(
            role,
            SnapshotChildAttachOperationV1::FinalSourceRevalidation,
        )?;
        let name = child_root_name_v1(root).ok_or(SnapshotChildAttachFailureV1::Invariant {
            role,
            operation: SnapshotChildAttachOperationV1::FinalSourceRevalidation,
        })?;
        let named = child_statx_at_name_v1(
            root.published_descriptor,
            name,
            role,
            SnapshotChildAttachOperationV1::FinalSourceRevalidation,
        )?;
        let selected = child_statx_fd_v1(
            root.root_descriptor,
            role,
            SnapshotChildAttachOperationV1::FinalSourceRevalidation,
        )?;
        if named != root.expected_child_statx_commitment.0
            || selected != root.expected_child_statx_commitment.0
        {
            return Err(SnapshotChildAttachFailureV1::Invariant {
                role,
                operation: SnapshotChildAttachOperationV1::FinalSourceRevalidation,
            });
        }
        Ok(())
    }

    fn child_attach_close_root_v1(
        root: &mut ForkChildPublishedRootV1,
        plan: ChildAttachOperationPlanV1,
    ) -> Result<(), SnapshotChildAttachFailureV1> {
        let role = root.role;
        plan.check(role, SnapshotChildAttachOperationV1::CloseKnownDescriptors)?;
        for descriptor in [&mut root.root_descriptor, &mut root.published_descriptor] {
            let raw = *descriptor;
            *descriptor = -1;
            if raw >= 0 && unsafe { libc::syscall(libc::SYS_close, raw) } != 0 {
                return Err(child_attach_os_failure_v1(
                    role,
                    SnapshotChildAttachOperationV1::CloseKnownDescriptors,
                ));
            }
        }
        Ok(())
    }

    fn child_root_name_v1(root: &ForkChildPublishedRootV1) -> Option<&CStr> {
        let length = usize::from(root.root_name_len);
        if length == 0 || length > MAX_BASENAME_BYTES || root.root_name[length] != 0 {
            return None;
        }
        CStr::from_bytes_with_nul(&root.root_name[..=length]).ok()
    }

    fn child_statx_fd_v1(
        descriptor: RawFd,
        role: SnapshotChildRootRoleV1,
        operation: SnapshotChildAttachOperationV1,
    ) -> Result<[u8; 102], SnapshotChildAttachFailureV1> {
        child_statx_v1(
            descriptor,
            EMPTY_PATH_V1,
            libc::AT_EMPTY_PATH,
            role,
            operation,
        )
    }

    fn child_statx_at_name_v1(
        descriptor: RawFd,
        name: &CStr,
        role: SnapshotChildRootRoleV1,
        operation: SnapshotChildAttachOperationV1,
    ) -> Result<[u8; 102], SnapshotChildAttachFailureV1> {
        child_statx_v1(descriptor, name, libc::AT_SYMLINK_NOFOLLOW, role, operation)
    }

    fn child_statx_v1(
        descriptor: RawFd,
        path: &CStr,
        flags: libc::c_int,
        role: SnapshotChildRootRoleV1,
        operation: SnapshotChildAttachOperationV1,
    ) -> Result<[u8; 102], SnapshotChildAttachFailureV1> {
        let mut raw = MaybeUninit::<libc::statx>::zeroed();
        if unsafe {
            libc::syscall(
                libc::SYS_statx,
                descriptor,
                path.as_ptr(),
                flags,
                SOURCE_TREE_REQUESTED_STATX_MASK_V1,
                raw.as_mut_ptr(),
            )
        } != 0
        {
            return Err(child_attach_os_failure_v1(role, operation));
        }
        let raw = unsafe { raw.assume_init() };
        SourceStatxV1::from_linux_statx_v1(&raw)
            .map(|value| value.commitment_bytes_v1())
            .map_err(|error| {
                child_attach_error_from_errno_v1(role, operation, error.raw_os_error())
            })
    }

    fn child_attach_os_failure_v1(
        role: SnapshotChildRootRoleV1,
        operation: SnapshotChildAttachOperationV1,
    ) -> SnapshotChildAttachFailureV1 {
        child_attach_error_from_errno_v1(role, operation, io::Error::last_os_error().raw_os_error())
    }

    fn child_attach_error_from_errno_v1(
        role: SnapshotChildRootRoleV1,
        operation: SnapshotChildAttachOperationV1,
        errno: Option<i32>,
    ) -> SnapshotChildAttachFailureV1 {
        let Some(errno) = errno.filter(|errno| (1..=4095).contains(errno)) else {
            return SnapshotChildAttachFailureV1::Invariant { role, operation };
        };
        if matches!(errno, libc::ENOSYS | libc::EOPNOTSUPP)
            || (matches!(
                operation,
                SnapshotChildAttachOperationV1::OpenTree
                    | SnapshotChildAttachOperationV1::SetRecursiveAttributes
                    | SnapshotChildAttachOperationV1::MoveMount
            ) && matches!(errno, libc::EPERM | libc::EACCES))
        {
            SnapshotChildAttachFailureV1::Unsupported {
                role,
                operation,
                errno,
            }
        } else {
            SnapshotChildAttachFailureV1::Os {
                role,
                operation,
                errno,
            }
        }
    }

    fn split_bound_path_v1(
        path: &[u8],
        memory: &RuntimeMemoryEscrowV1,
    ) -> Result<Vec<Vec<u8>>, BoundRegularReadRefusalV1> {
        validate_bound_components_v1(path)?;
        let count = path.split(|byte| *byte == b'/').count();
        let mut output = memory.try_vec_with_capacity(count)?;
        for component in path.split(|byte| *byte == b'/') {
            output.push(memory.try_bytes_from_slice(component)?);
        }
        Ok(output)
    }

    fn clone_bound_components_v1(
        components: &[Vec<u8>],
        capacity: usize,
        memory: &RuntimeMemoryEscrowV1,
    ) -> Result<Vec<Vec<u8>>, BoundRegularReadRefusalV1> {
        if capacity < components.len() || capacity > BOUND_REGULAR_PATH_MAX_COMPONENTS_V1 {
            return Err(BoundRegularReadRefusalV1::ComponentLimit);
        }
        let mut output = memory.try_vec_with_capacity(capacity)?;
        for component in components {
            output.push(memory.try_bytes_from_slice(component)?);
        }
        Ok(output)
    }

    fn join_bound_components_v1(
        components: &[Vec<u8>],
        memory: &RuntimeMemoryEscrowV1,
    ) -> Result<Vec<u8>, BoundRegularReadRefusalV1> {
        if components.is_empty() || components.len() > BOUND_REGULAR_PATH_MAX_COMPONENTS_V1 {
            return Err(BoundRegularReadRefusalV1::ComponentLimit);
        }
        let length = components
            .iter()
            .try_fold(components.len() - 1, |total, component| {
                total.checked_add(component.len())
            })
            .ok_or(BoundRegularReadRefusalV1::ComponentLimit)?;
        let mut joined = memory.try_vec_with_capacity(length)?;
        for (index, component) in components.iter().enumerate() {
            if index != 0 {
                joined.push(b'/');
            }
            joined.extend_from_slice(component);
        }
        validate_bound_components_v1(&joined)?;
        Ok(joined)
    }

    fn push_unique_bound_node_v1(
        nodes: &mut Vec<VerifiedBoundPathNodeV1>,
        node: VerifiedBoundPathNodeV1,
    ) -> Result<(), BoundRegularReadRefusalV1> {
        if let Some(existing) = nodes
            .iter()
            .find(|existing| existing.normalized_path == node.normalized_path)
        {
            if existing.kind != node.kind
                || existing.statx_commitment != node.statx_commitment
                || existing.symlink_target != node.symlink_target
            {
                return Err(BoundRegularReadRefusalV1::IdentityDrift);
            }
            return Ok(());
        }
        if nodes.len() == BOUND_REGULAR_MAX_OBSERVED_NODES_V1 {
            return Err(BoundRegularReadRefusalV1::ComponentLimit);
        }
        nodes.push(node);
        Ok(())
    }

    fn open_bound_component_v1(
        parent: BorrowedFd<'_>,
        name: &CStr,
        flags: i32,
    ) -> Result<OwnedFd, BoundRegularReadRefusalV1> {
        openat2_owned(parent, name, flags, HARD_MAX_OPENAT2_ATTEMPTS).map_err(map_bound_io_v1)
    }

    fn read_bound_link_v1(
        symlink: BorrowedFd<'_>,
        memory: &RuntimeMemoryEscrowV1,
    ) -> Result<Vec<u8>, BoundRegularReadRefusalV1> {
        let mut target = memory.try_vec_with_capacity(BOUND_REGULAR_TARGET_MAX_BYTES_V1 + 1)?;
        target.resize(BOUND_REGULAR_TARGET_MAX_BYTES_V1 + 1, 0);
        let count = unsafe {
            libc::readlinkat(
                symlink.as_raw_fd(),
                c"".as_ptr(),
                target.as_mut_ptr().cast(),
                target.len(),
            )
        };
        if count < 0 {
            return Err(map_bound_io_v1(io::Error::last_os_error()));
        }
        let count = usize::try_from(count).map_err(|_| BoundRegularReadRefusalV1::Io)?;
        if count == 0 || count > BOUND_REGULAR_TARGET_MAX_BYTES_V1 {
            return Err(BoundRegularReadRefusalV1::SymlinkTargetInvalid);
        }
        target.truncate(count);
        Ok(target)
    }

    fn node_statx_v1(fd: BorrowedFd<'_>) -> Result<SourceStatxV1, BoundRegularReadRefusalV1> {
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
            return Err(map_bound_io_v1(io::Error::last_os_error()));
        }
        let raw = unsafe { raw.assume_init() };
        SourceStatxV1::from_linux_statx_v1(&raw).map_err(map_bound_io_v1)
    }

    fn node_statx_at_name_v1(
        parent: BorrowedFd<'_>,
        name: &CStr,
    ) -> Result<SourceStatxV1, BoundRegularReadRefusalV1> {
        let mut raw = MaybeUninit::<libc::statx>::zeroed();
        let result = unsafe {
            libc::syscall(
                libc::SYS_statx,
                parent.as_raw_fd(),
                name.as_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
                SOURCE_TREE_REQUESTED_STATX_MASK_V1,
                raw.as_mut_ptr(),
            )
        };
        if result != 0 {
            return Err(map_bound_io_v1(io::Error::last_os_error()));
        }
        let raw = unsafe { raw.assume_init() };
        SourceStatxV1::from_linux_statx_v1(&raw).map_err(map_bound_io_v1)
    }

    fn map_bound_io_v1(error: io::Error) -> BoundRegularReadRefusalV1 {
        match error.raw_os_error() {
            Some(libc::ENOENT) | Some(libc::ENOTDIR) => BoundRegularReadRefusalV1::MissingNode,
            Some(libc::EXDEV) => BoundRegularReadRefusalV1::MountCrossing,
            Some(libc::ELOOP) => BoundRegularReadRefusalV1::MagicLink,
            Some(libc::EFBIG) => BoundRegularReadRefusalV1::ByteLimit,
            Some(libc::ESTALE) => BoundRegularReadRefusalV1::IdentityDrift,
            _ => BoundRegularReadRefusalV1::Io,
        }
    }

    pub(super) fn bind_published_snapshot_child_at(
        published: PublishedSnapshotDirectoryV1,
        child_name: &CStr,
        expected_statx_commitment: [u8; 102],
        reservation: SnapshotPublishedChildBindReservationV1<'_>,
    ) -> Result<BoundPublishedSnapshotChildV1, SnapshotPublishedChildBindErrorV1> {
        bind_published_snapshot_child_at_with_projection_hook(
            published,
            child_name,
            expected_statx_commitment,
            reservation,
            |_| {},
        )
    }

    fn bind_published_snapshot_child_at_with_projection_hook<F>(
        published: PublishedSnapshotDirectoryV1,
        child_name: &CStr,
        expected_statx_commitment: [u8; 102],
        reservation: SnapshotPublishedChildBindReservationV1<'_>,
        projection_hook: F,
    ) -> Result<BoundPublishedSnapshotChildV1, SnapshotPublishedChildBindErrorV1>
    where
        F: FnOnce(BorrowedFd<'_>),
    {
        if !valid_raw_basename(child_name) {
            return Err(SnapshotPublishedChildBindErrorV1::leaf(
                SnapshotPublishErrorKindV1::InvalidPublishedChildName,
                SnapshotPublishStageV1::ValidatePublishedChildName,
                None,
            ));
        }

        let PublishedSnapshotDirectoryV1 {
            directory,
            openat2_attempts,
        } = published;
        let root = open_path_at_with_gate(
            directory.as_fd(),
            child_name,
            openat2_attempts,
            &reservation,
        )
        .map_err(|error| {
            published_child_bind_failure(
                error,
                SnapshotPublishStageV1::OpenPublishedChild,
                |error| {
                    if missing_kernel_capability(error) {
                        SnapshotPublishErrorKindV1::RequiredKernelCapabilityMissing
                    } else {
                        SnapshotPublishErrorKindV1::Io
                    }
                },
            )
        })?;

        let observed =
            published_child_statx_with_gate(root.as_fd(), &reservation).map_err(|error| {
                published_child_bind_failure(
                    error,
                    SnapshotPublishStageV1::StatPublishedChild,
                    |error| {
                        if missing_kernel_capability(error) {
                            SnapshotPublishErrorKindV1::RequiredKernelCapabilityMissing
                        } else if error.raw_os_error() == Some(libc::ESTALE)
                            || error.kind() == io::ErrorKind::InvalidData
                        {
                            SnapshotPublishErrorKindV1::IdentityMismatch
                        } else {
                            SnapshotPublishErrorKindV1::Io
                        }
                    },
                )
            })?;
        if observed.commitment_bytes_v1() != expected_statx_commitment {
            return Err(SnapshotPublishedChildBindErrorV1::leaf(
                SnapshotPublishErrorKindV1::IdentityMismatch,
                SnapshotPublishStageV1::BindPublishedChildIdentity,
                None,
            ));
        }
        projection_hook(root.as_fd());

        // Consume one already-escrowed attempt as the non-forgeable permit
        // for the later exact, non-retrying name-relative root `statx`. No raw
        // operation runs here; the private marker can authorize the leaf once.
        reservation
            .run_attempt(|| ())
            .map_err(SnapshotPublishedChildBindErrorV1::resource)?;

        Ok(BoundPublishedSnapshotChildV1 {
            published: directory,
            root,
            retained_root_projection_admitted: Cell::new(true),
        })
    }

    impl<'parent> StagedSnapshotDirectoryV1<'parent> {
        fn verify_ready_with_transitions<F, H>(
            self,
            verify_recursive_durability: F,
            transitions: &mut H,
        ) -> Result<VerifiedReadySnapshotDirectoryV1<'parent>, SnapshotPublishErrorV1>
        where
            F: FnOnce(BorrowedFd<'_>) -> io::Result<()>,
            H: TransitionHookV1,
        {
            let mut cleanup = self.cleanup;
            checkpoint(
                transitions,
                SnapshotPublishStageV1::VerifyRecursiveDurability,
                SnapshotPublicationStateV1::Unpublished,
            )?;
            verify_recursive_durability(cleanup.directory()).map_err(|error| {
                SnapshotPublishErrorV1::new(
                    SnapshotPublishErrorKindV1::RecursiveDurabilityFailed,
                    SnapshotPublishStageV1::VerifyRecursiveDurability,
                    SnapshotPublicationStateV1::Unpublished,
                    error.raw_os_error(),
                )
            })?;

            checkpoint(
                transitions,
                SnapshotPublishStageV1::RevalidateStaging,
                SnapshotPublicationStateV1::Unpublished,
            )?;
            let final_staging_identity = revalidate_staging(&cleanup)?;
            cleanup.expected_identity = Some(final_staging_identity);

            checkpoint(
                transitions,
                SnapshotPublishStageV1::SyncStaging,
                SnapshotPublicationStateV1::Unpublished,
            )?;
            fsync_fd(cleanup.directory(), cleanup.policy().syscall_attempts()).map_err(
                |error| {
                    io_failure(
                        SnapshotPublishStageV1::SyncStaging,
                        SnapshotPublicationStateV1::Unpublished,
                        error,
                    )
                },
            )?;
            let after_sync = revalidate_staging(&cleanup)?;
            if after_sync != cleanup.expected_identity() {
                return Err(identity_failure(
                    SnapshotPublishStageV1::SyncStaging,
                    SnapshotPublicationStateV1::Unpublished,
                ));
            }

            Ok(VerifiedReadySnapshotDirectoryV1 { cleanup })
        }
    }

    impl<'parent> VerifiedReadySnapshotDirectoryV1<'parent> {
        fn publish_at_with_transitions<H>(
            self,
            final_name: &CStr,
            transitions: &mut H,
        ) -> Result<PublishedSnapshotDirectoryV1, SnapshotPublishErrorV1>
        where
            H: TransitionHookV1,
        {
            let mut cleanup = self.cleanup;
            checkpoint(
                transitions,
                SnapshotPublishStageV1::ValidateFinalName,
                SnapshotPublicationStateV1::Unpublished,
            )?;
            validate_snapshot_final_name(cleanup.staging_name.as_c_str(), final_name)?;

            let before_rename = revalidate_staging(&cleanup)?;
            if before_rename != cleanup.expected_identity() {
                return Err(identity_failure(
                    SnapshotPublishStageV1::PublishRename,
                    SnapshotPublicationStateV1::Unpublished,
                ));
            }
            checkpoint(
                transitions,
                SnapshotPublishStageV1::PublishRename,
                SnapshotPublicationStateV1::Unpublished,
            )?;
            rename_staging_with_reconciliation(&mut cleanup, final_name, transitions)?;

            checkpoint(
                transitions,
                SnapshotPublishStageV1::SyncParent,
                SnapshotPublicationStateV1::PublishedDurabilityUnknown,
            )?;
            fsync_fd(cleanup.parent, cleanup.policy().syscall_attempts()).map_err(|error| {
                io_failure(
                    SnapshotPublishStageV1::SyncParent,
                    SnapshotPublicationStateV1::PublishedDurabilityUnknown,
                    error,
                )
            })?;

            checkpoint(
                transitions,
                SnapshotPublishStageV1::ReopenPublished,
                SnapshotPublicationStateV1::PublishedDurable,
            )?;
            let reopened = open_directory_at(
                cleanup.parent,
                final_name,
                cleanup.policy().openat2_attempts(),
            )
            .map_err(|error| {
                io_failure(
                    SnapshotPublishStageV1::ReopenPublished,
                    SnapshotPublicationStateV1::PublishedDurable,
                    error,
                )
            })?;

            checkpoint(
                transitions,
                SnapshotPublishStageV1::BindPublishedIdentity,
                SnapshotPublicationStateV1::PublishedDurable,
            )?;
            let original_identity = directory_identity(cleanup.directory()).map_err(|error| {
                identity_io_failure(
                    SnapshotPublishStageV1::BindPublishedIdentity,
                    SnapshotPublicationStateV1::PublishedDurable,
                    error,
                )
            })?;
            let reopened_identity = directory_identity(reopened.as_fd()).map_err(|error| {
                identity_io_failure(
                    SnapshotPublishStageV1::BindPublishedIdentity,
                    SnapshotPublicationStateV1::PublishedDurable,
                    error,
                )
            })?;
            if original_identity != cleanup.expected_identity()
                || reopened_identity != cleanup.expected_identity()
            {
                return Err(identity_failure(
                    SnapshotPublishStageV1::BindPublishedIdentity,
                    SnapshotPublicationStateV1::PublishedDurable,
                ));
            }

            Ok(PublishedSnapshotDirectoryV1 {
                directory: reopened,
                openat2_attempts: cleanup.policy().openat2_attempts(),
            })
        }
    }

    fn seal_and_publish_charged_with_transitions<H>(
        staged: ChargedStagedSnapshotDirectoryV1<'_>,
        final_name: &CStr,
        transitions: &mut H,
    ) -> Result<PublishedSnapshotDirectoryV1, SnapshotChargedErrorV1<SnapshotPublishErrorV1>>
    where
        H: TransitionHookV1,
    {
        let mut cleanup = staged.cleanup;

        // This validation is allocation- and filesystem-free. Keep it before
        // reservation and even before the first test hook or sealing mutation
        // so an invalid caller-controlled name cannot consume authority.
        validate_snapshot_final_name(cleanup.staging_name.as_c_str(), final_name)
            .map_err(SnapshotChargedErrorV1::Leaf)?;
        checkpoint(
            transitions,
            SnapshotPublishStageV1::ValidateFinalName,
            SnapshotPublicationStateV1::Unpublished,
        )
        .map_err(SnapshotChargedErrorV1::Leaf)?;

        let reservation = cleanup
            .authority
            .reserve_finalization_attempts()
            .map_err(SnapshotChargedErrorV1::Resource)?;

        // Materialization legitimately changed the private container's link
        // count by creating its root directory. This is the sole refresh that
        // admits metadata drift: the pinned object, its current name, owner,
        // and exact builder mode must still agree.
        let builder_identity = revalidate_staging_refresh_with_gate(
            &cleanup,
            PRIVATE_DIRECTORY_MODE,
            &reservation,
            SnapshotPublishStageV1::RevalidateStaging,
        )?;
        cleanup.expected_identity = Some(builder_identity);

        checkpoint(
            transitions,
            SnapshotPublishStageV1::SealStaging,
            SnapshotPublicationStateV1::Unpublished,
        )
        .map_err(SnapshotChargedErrorV1::Leaf)?;
        retry_eintr_result_with_gate(&reservation, cleanup.policy().syscall_attempts(), || {
            transitions.seal_directory(cleanup.directory())
        })
        .map_err(|error| {
            map_charged_io(
                error,
                SnapshotPublishStageV1::SealStaging,
                SnapshotPublicationStateV1::Unpublished,
            )
        })?;

        let sealed_identity = identity_with_mode(builder_identity, SEALED_DIRECTORY_MODE);
        revalidate_staging_exact_with_gate(
            &cleanup,
            sealed_identity,
            &reservation,
            SnapshotPublishStageV1::SealStaging,
        )?;
        cleanup.expected_identity = Some(sealed_identity);

        checkpoint(
            transitions,
            SnapshotPublishStageV1::SyncStaging,
            SnapshotPublicationStateV1::Unpublished,
        )
        .map_err(SnapshotChargedErrorV1::Leaf)?;
        fsync_fd_with_gate(
            cleanup.directory(),
            cleanup.policy().syscall_attempts(),
            &reservation,
        )
        .map_err(|error| {
            map_charged_io(
                error,
                SnapshotPublishStageV1::SyncStaging,
                SnapshotPublicationStateV1::Unpublished,
            )
        })?;

        checkpoint(
            transitions,
            SnapshotPublishStageV1::PublishRename,
            SnapshotPublicationStateV1::Unpublished,
        )
        .map_err(SnapshotChargedErrorV1::Leaf)?;
        // This post-fsync check is immediately adjacent to rename and serves
        // as the pre-rename check as well. All checkpoints precede it, and no
        // caller callback or intermediate token can re-enter afterward;
        // production `KernelTransitions` immediately issues the charged
        // rename.
        revalidate_staging_exact_with_gate(
            &cleanup,
            sealed_identity,
            &reservation,
            SnapshotPublishStageV1::RevalidateStaging,
        )?;
        rename_staging_with_reconciliation_and_gate(
            &mut cleanup,
            final_name,
            transitions,
            &reservation,
        )?;

        checkpoint(
            transitions,
            SnapshotPublishStageV1::SyncParent,
            SnapshotPublicationStateV1::PublishedDurabilityUnknown,
        )
        .map_err(SnapshotChargedErrorV1::Leaf)?;
        fsync_fd_with_gate(
            cleanup.parent,
            cleanup.policy().syscall_attempts(),
            &reservation,
        )
        .map_err(|error| {
            map_charged_io(
                error,
                SnapshotPublishStageV1::SyncParent,
                SnapshotPublicationStateV1::PublishedDurabilityUnknown,
            )
        })?;

        checkpoint(
            transitions,
            SnapshotPublishStageV1::ReopenPublished,
            SnapshotPublicationStateV1::PublishedDurable,
        )
        .map_err(SnapshotChargedErrorV1::Leaf)?;
        let reopened = open_directory_at_with_gate(
            cleanup.parent,
            final_name,
            cleanup.policy().openat2_attempts(),
            &reservation,
        )
        .map_err(|error| {
            map_charged_io(
                error,
                SnapshotPublishStageV1::ReopenPublished,
                SnapshotPublicationStateV1::PublishedDurable,
            )
        })?;

        checkpoint(
            transitions,
            SnapshotPublishStageV1::BindPublishedIdentity,
            SnapshotPublicationStateV1::PublishedDurable,
        )
        .map_err(SnapshotChargedErrorV1::Leaf)?;
        let original_identity = directory_identity_with_gate(cleanup.directory(), &reservation)
            .map_err(|error| {
                map_charged_identity_io(
                    error,
                    SnapshotPublishStageV1::BindPublishedIdentity,
                    SnapshotPublicationStateV1::PublishedDurable,
                )
            })?;
        let reopened_identity = directory_identity_with_gate(reopened.as_fd(), &reservation)
            .map_err(|error| {
                map_charged_identity_io(
                    error,
                    SnapshotPublishStageV1::BindPublishedIdentity,
                    SnapshotPublicationStateV1::PublishedDurable,
                )
            })?;
        if original_identity != sealed_identity || reopened_identity != sealed_identity {
            return Err(SnapshotChargedErrorV1::Leaf(identity_failure(
                SnapshotPublishStageV1::BindPublishedIdentity,
                SnapshotPublicationStateV1::PublishedDurable,
            )));
        }

        Ok(PublishedSnapshotDirectoryV1 {
            directory: reopened,
            openat2_attempts: cleanup.policy().openat2_attempts(),
        })
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum NameBindingV1 {
        Missing,
        Expected,
        Other,
    }

    fn rename_staging_with_reconciliation<H: TransitionHookV1>(
        cleanup: &mut StagingCleanupV1<'_>,
        final_name: &CStr,
        transitions: &mut H,
    ) -> Result<(), SnapshotPublishErrorV1> {
        unmetered_leaf(rename_staging_with_reconciliation_and_gate(
            cleanup,
            final_name,
            transitions,
            &UnmeteredPublisherAttemptGateV1,
        ))
    }

    fn rename_staging_with_reconciliation_and_gate<
        H: TransitionHookV1,
        G: PublisherAttemptGateV1,
    >(
        cleanup: &mut StagingCleanupV1<'_>,
        final_name: &CStr,
        transitions: &mut H,
        gate: &G,
    ) -> Result<(), SnapshotChargedErrorV1<SnapshotPublishErrorV1>> {
        for _ in 0..cleanup.policy().syscall_attempts() {
            let rename = gate
                .run_attempt(|| {
                    transitions.rename_noreplace(
                        cleanup.parent,
                        cleanup.staging_name.as_c_str(),
                        cleanup.parent,
                        final_name,
                    )
                })
                .map_err(SnapshotChargedErrorV1::Resource)?;
            match rename {
                Ok(()) => {
                    cleanup.disarm();
                    return Ok(());
                }
                Err(error) => {
                    let old_binding = name_binding_with_gate(
                        cleanup.parent,
                        cleanup.staging_name.as_c_str(),
                        cleanup.expected_identity(),
                        cleanup.policy().openat2_attempts(),
                        gate,
                    );
                    let final_binding = name_binding_with_gate(
                        cleanup.parent,
                        final_name,
                        cleanup.expected_identity(),
                        cleanup.policy().openat2_attempts(),
                        gate,
                    );
                    match (old_binding, final_binding) {
                        (Ok(NameBindingV1::Missing), Ok(NameBindingV1::Expected)) => {
                            cleanup.disarm();
                            return Ok(());
                        }
                        (Ok(NameBindingV1::Expected), Ok(NameBindingV1::Missing))
                            if error.kind() == io::ErrorKind::Interrupted =>
                        {
                            continue;
                        }
                        (Ok(NameBindingV1::Expected), Ok(NameBindingV1::Missing))
                        | (Ok(NameBindingV1::Expected), Ok(NameBindingV1::Other))
                            if error.raw_os_error() == Some(libc::EEXIST) =>
                        {
                            return Err(SnapshotChargedErrorV1::Leaf(rename_error(
                                error,
                                SnapshotPublicationStateV1::Unpublished,
                            )));
                        }
                        (Ok(NameBindingV1::Expected), Ok(NameBindingV1::Missing)) => {
                            return Err(SnapshotChargedErrorV1::Leaf(rename_error(
                                error,
                                SnapshotPublicationStateV1::Unpublished,
                            )));
                        }
                        _ => {
                            cleanup.disarm();
                            return Err(SnapshotChargedErrorV1::Leaf(rename_error(
                                error,
                                SnapshotPublicationStateV1::PublishedDurabilityUnknown,
                            )));
                        }
                    }
                }
            }
        }
        Err(SnapshotChargedErrorV1::Leaf(SnapshotPublishErrorV1::new(
            SnapshotPublishErrorKindV1::Io,
            SnapshotPublishStageV1::PublishRename,
            SnapshotPublicationStateV1::Unpublished,
            Some(libc::EINTR),
        )))
    }

    fn rename_error(
        error: io::Error,
        publication_state: SnapshotPublicationStateV1,
    ) -> SnapshotPublishErrorV1 {
        let kind = if error.raw_os_error() == Some(libc::EEXIST) {
            SnapshotPublishErrorKindV1::FinalCollision
        } else if missing_kernel_capability(&error) {
            SnapshotPublishErrorKindV1::RequiredKernelCapabilityMissing
        } else {
            SnapshotPublishErrorKindV1::Io
        };
        SnapshotPublishErrorV1::new(
            kind,
            SnapshotPublishStageV1::PublishRename,
            publication_state,
            error.raw_os_error(),
        )
    }

    fn name_binding_with_gate<G: PublisherAttemptGateV1>(
        parent: BorrowedFd<'_>,
        name: &CStr,
        expected: SnapshotDirectoryIdentityV1,
        attempts: u8,
        gate: &G,
    ) -> Result<NameBindingV1, SnapshotChargedErrorV1<io::Error>> {
        let current = match open_path_at_with_gate(parent, name, attempts, gate) {
            Ok(current) => current,
            Err(SnapshotChargedErrorV1::Leaf(error))
                if error.raw_os_error() == Some(libc::ENOENT) =>
            {
                return Ok(NameBindingV1::Missing);
            }
            Err(error) => return Err(error),
        };
        // Reconciliation needs only physical name binding, not a second full
        // manifest identity. One charged fstat preserves the frozen `2O + 2`
        // per-iteration bound: one expected name has a fstat and one missing
        // name does not.
        let current = cleanup_identity_with_gate(current.as_fd(), gate)?;
        if current.mode_type == libc::S_IFDIR
            && linux_device_major(current.device) == expected.device_major
            && linux_device_minor(current.device) == expected.device_minor
            && current.inode == expected.inode
        {
            Ok(NameBindingV1::Expected)
        } else {
            Ok(NameBindingV1::Other)
        }
    }

    impl StagingCleanupV1<'_> {
        fn directory(&self) -> BorrowedFd<'_> {
            self.directory
                .as_ref()
                .expect("a returned staged directory has a bound descriptor")
                .as_fd()
        }

        fn policy(&self) -> SnapshotPublishPolicyV1 {
            self.authority.policy()
        }

        #[cfg(test)]
        fn policy_mut(&mut self) -> &mut SnapshotPublishPolicyV1 {
            match &mut self.authority {
                PublisherAuthorityV1::Unmetered { policy } => policy,
                PublisherAuthorityV1::Charged { .. } => {
                    panic!("charged publication policy is immutable")
                }
            }
        }

        fn expected_identity(&self) -> SnapshotDirectoryIdentityV1 {
            self.expected_identity
                .expect("a returned staged directory has a bound identity")
        }

        fn disarm(&mut self) {
            self.armed = false;
        }

        fn remove_current(&mut self) -> Result<(), SnapshotChargedErrorV1<io::Error>> {
            if !self.armed {
                return Ok(());
            }
            let policy = self.policy();
            let current = match open_directory_at_charged(
                &self.authority,
                PublisherAttemptBucketV1::Cleanup,
                self.parent,
                self.staging_name.as_c_str(),
                policy.openat2_attempts(),
            ) {
                Ok(current) => current,
                Err(SnapshotChargedErrorV1::Leaf(error))
                    if error.raw_os_error() == Some(libc::ENOENT) =>
                {
                    self.disarm();
                    return Ok(());
                }
                Err(error) => return Err(error),
            };
            let current_identity = directory_identity_charged(
                &self.authority,
                PublisherAttemptBucketV1::Cleanup,
                current.as_fd(),
            )?;
            let pinned_identity = if let Some(expected) = self.expected_identity {
                expected
            } else if let Some(directory) = self.directory.as_ref() {
                directory_identity_charged(
                    &self.authority,
                    PublisherAttemptBucketV1::Cleanup,
                    directory.as_fd(),
                )?
            } else {
                current_identity
            };
            if !same_directory_object(current_identity, pinned_identity)
                || !owner_staging_directory(current_identity, self.effective_uid)
            {
                return Err(SnapshotChargedErrorV1::Leaf(io::Error::from_raw_os_error(
                    libc::ESTALE,
                )));
            }
            let prepared = prepare_owned_directory_for_cleanup_charged(
                &self.authority,
                current.as_fd(),
                cleanup_identity_charged(&self.authority, current.as_fd())?,
                self.effective_uid,
                policy.syscall_attempts(),
            )?;
            remove_directory_contents(
                current.as_fd(),
                &self.authority,
                self.effective_uid,
                policy,
                0,
                &mut self.cleanup_budget,
            )?;
            let current_again = open_directory_at_charged(
                &self.authority,
                PublisherAttemptBucketV1::Cleanup,
                self.parent,
                self.staging_name.as_c_str(),
                policy.openat2_attempts(),
            )?;
            let current_again = cleanup_identity_charged(&self.authority, current_again.as_fd())?;
            if !same_cleanup_object(current_again, prepared)
                || !owned_directory_for_uid(current_again, self.effective_uid)
            {
                return Err(SnapshotChargedErrorV1::Leaf(io::Error::from_raw_os_error(
                    libc::ESTALE,
                )));
            }
            unlink_at_charged(
                &self.authority,
                self.parent,
                self.staging_name.as_c_str(),
                libc::AT_REMOVEDIR,
                policy.syscall_attempts(),
            )?;
            self.disarm();
            Ok(())
        }
    }

    impl Drop for StagingCleanupV1<'_> {
        fn drop(&mut self) {
            let _ = self.remove_current();
        }
    }

    pub(super) fn create_charged_staged_snapshot_directory_at<'scope>(
        parent: BorrowedFd<'scope>,
        staging_name: &CStr,
        session: SnapshotPublicationSessionV1<'scope>,
    ) -> Result<
        ChargedStagedSnapshotDirectoryV1<'scope>,
        SnapshotChargedErrorV1<SnapshotPublishErrorV1>,
    > {
        let mut transitions = KernelTransitions;
        create_staged_snapshot_directory_with_authority(
            parent,
            staging_name,
            PublisherAuthorityV1::Charged { session },
            &mut transitions,
        )
        .map(|cleanup| ChargedStagedSnapshotDirectoryV1 { cleanup })
    }

    pub(super) fn seal_and_publish_charged_at(
        staged: ChargedStagedSnapshotDirectoryV1<'_>,
        final_name: &CStr,
    ) -> Result<PublishedSnapshotDirectoryV1, SnapshotChargedErrorV1<SnapshotPublishErrorV1>> {
        let mut transitions = KernelTransitions;
        seal_and_publish_charged_with_transitions(staged, final_name, &mut transitions)
    }

    #[cfg(test)]
    pub(super) fn create_unmetered_staged_snapshot_directory_at<'parent>(
        parent: BorrowedFd<'parent>,
        staging_name: &CStr,
        policy: SnapshotPublishPolicyV1,
    ) -> Result<StagedSnapshotDirectoryV1<'parent>, SnapshotPublishErrorV1> {
        let mut transitions = KernelTransitions;
        create_staged_snapshot_directory_with(parent, staging_name, policy, &mut transitions)
    }

    #[cfg(test)]
    fn create_staged_snapshot_directory_with<'parent, H>(
        parent: BorrowedFd<'parent>,
        staging_name: &CStr,
        policy: SnapshotPublishPolicyV1,
        transitions: &mut H,
    ) -> Result<StagedSnapshotDirectoryV1<'parent>, SnapshotPublishErrorV1>
    where
        H: TransitionHookV1,
    {
        match create_staged_snapshot_directory_with_authority(
            parent,
            staging_name,
            PublisherAuthorityV1::Unmetered { policy },
            transitions,
        ) {
            Ok(cleanup) => Ok(StagedSnapshotDirectoryV1 { cleanup }),
            Err(SnapshotChargedErrorV1::Leaf(error)) => Err(error),
            Err(SnapshotChargedErrorV1::PublicationAlreadyStarted) => {
                unreachable!("the test-only unmetered authority has no issuance state")
            }
            Err(SnapshotChargedErrorV1::Resource(_)) => {
                unreachable!("the test-only unmetered authority cannot exhaust a shared ledger")
            }
        }
    }

    fn create_staged_snapshot_directory_with_authority<'scope, H>(
        parent: BorrowedFd<'scope>,
        staging_name: &CStr,
        authority: PublisherAuthorityV1<'scope>,
        transitions: &mut H,
    ) -> Result<StagingCleanupV1<'scope>, SnapshotChargedErrorV1<SnapshotPublishErrorV1>>
    where
        H: TransitionHookV1,
    {
        checkpoint(
            transitions,
            SnapshotPublishStageV1::ValidateStagingName,
            SnapshotPublicationStateV1::Unpublished,
        )
        .map_err(SnapshotChargedErrorV1::Leaf)?;
        if !valid_staging_basename(staging_name) {
            return Err(SnapshotChargedErrorV1::Leaf(SnapshotPublishErrorV1::new(
                SnapshotPublishErrorKindV1::InvalidStagingName,
                SnapshotPublishStageV1::ValidateStagingName,
                SnapshotPublicationStateV1::Unpublished,
                None,
            )));
        }
        let owned_staging_name =
            try_clone_cstr_charged(&authority, PublisherAttemptBucketV1::Forward, staging_name)
                .map_err(|error| {
                    map_charged_io(
                        error,
                        SnapshotPublishStageV1::CreateAndOpenStaging,
                        SnapshotPublicationStateV1::Unpublished,
                    )
                })?;

        checkpoint(
            transitions,
            SnapshotPublishStageV1::InspectParent,
            SnapshotPublicationStateV1::Unpublished,
        )
        .map_err(SnapshotChargedErrorV1::Leaf)?;
        let effective_uid = validate_trusted_parent_charged(&authority, parent)?;
        let policy = authority.policy();

        let mut cleanup = StagingCleanupV1 {
            parent,
            staging_name: owned_staging_name,
            directory: None,
            expected_identity: None,
            effective_uid,
            authority,
            cleanup_budget: CleanupBudgetV1::new(),
            armed: false,
        };

        checkpoint(
            transitions,
            SnapshotPublishStageV1::CreateAndOpenStaging,
            SnapshotPublicationStateV1::Unpublished,
        )
        .map_err(SnapshotChargedErrorV1::Leaf)?;
        mkdir_private_at_charged(
            &cleanup.authority,
            parent,
            staging_name,
            policy.syscall_attempts(),
        )
        .map_err(|error| {
            map_charged_io_with(
                error,
                SnapshotPublishStageV1::CreateAndOpenStaging,
                SnapshotPublicationStateV1::Unpublished,
                |error| {
                    if error.raw_os_error() == Some(libc::EEXIST) {
                        SnapshotPublishErrorKindV1::StagingCollision
                    } else {
                        SnapshotPublishErrorKindV1::Io
                    }
                },
            )
        })?;
        cleanup.armed = true;

        let directory = open_directory_at_charged(
            &cleanup.authority,
            PublisherAttemptBucketV1::Forward,
            parent,
            staging_name,
            policy.openat2_attempts(),
        )
        .map_err(|error| {
            map_charged_io(
                error,
                SnapshotPublishStageV1::CreateAndOpenStaging,
                SnapshotPublicationStateV1::Unpublished,
            )
        })?;
        cleanup.directory = Some(directory);
        let identity = directory_identity_charged(
            &cleanup.authority,
            PublisherAttemptBucketV1::Forward,
            cleanup.directory(),
        )
        .map_err(|error| {
            map_charged_identity_io(
                error,
                SnapshotPublishStageV1::BindStagingIdentity,
                SnapshotPublicationStateV1::Unpublished,
            )
        })?;
        cleanup.expected_identity = Some(identity);
        if !owner_private_directory(identity, effective_uid) {
            return Err(SnapshotChargedErrorV1::Leaf(identity_failure(
                SnapshotPublishStageV1::BindStagingIdentity,
                SnapshotPublicationStateV1::Unpublished,
            )));
        }
        checkpoint(
            transitions,
            SnapshotPublishStageV1::BindStagingIdentity,
            SnapshotPublicationStateV1::Unpublished,
        )
        .map_err(SnapshotChargedErrorV1::Leaf)?;
        Ok(cleanup)
    }

    fn checkpoint<H: TransitionHookV1>(
        transitions: &mut H,
        stage: SnapshotPublishStageV1,
        publication_state: SnapshotPublicationStateV1,
    ) -> Result<(), SnapshotPublishErrorV1> {
        transitions
            .checkpoint(stage)
            .map_err(|error| io_failure(stage, publication_state, error))
    }

    fn validate_trusted_parent_charged(
        authority: &PublisherAuthorityV1<'_>,
        parent: BorrowedFd<'_>,
    ) -> Result<u32, SnapshotChargedErrorV1<SnapshotPublishErrorV1>> {
        let identity =
            directory_identity_charged(authority, PublisherAttemptBucketV1::Forward, parent)
                .map_err(|error| {
                    map_charged_identity_io(
                        error,
                        SnapshotPublishStageV1::InspectParent,
                        SnapshotPublicationStateV1::Unpublished,
                    )
                })?;
        let effective_uid = authority
            .run_attempt(PublisherAttemptBucketV1::Forward, || unsafe {
                libc::geteuid()
            })
            .map_err(SnapshotChargedErrorV1::Resource)?;
        if identity.mode & libc::S_IFMT != libc::S_IFDIR
            || identity.uid != effective_uid
            || identity.mode & 0o022 != 0
        {
            return Err(SnapshotChargedErrorV1::Leaf(SnapshotPublishErrorV1::new(
                SnapshotPublishErrorKindV1::UntrustedParent,
                SnapshotPublishStageV1::InspectParent,
                SnapshotPublicationStateV1::Unpublished,
                None,
            )));
        }
        Ok(effective_uid)
    }

    fn revalidate_staging(
        cleanup: &StagingCleanupV1<'_>,
    ) -> Result<SnapshotDirectoryIdentityV1, SnapshotPublishErrorV1> {
        unmetered_leaf(revalidate_staging_refresh_with_gate(
            cleanup,
            PRIVATE_DIRECTORY_MODE,
            &UnmeteredPublisherAttemptGateV1,
            SnapshotPublishStageV1::RevalidateStaging,
        ))
    }

    fn revalidate_staging_refresh_with_gate<G: PublisherAttemptGateV1>(
        cleanup: &StagingCleanupV1<'_>,
        required_mode: u32,
        gate: &G,
        stage: SnapshotPublishStageV1,
    ) -> Result<SnapshotDirectoryIdentityV1, SnapshotChargedErrorV1<SnapshotPublishErrorV1>> {
        let fd_identity =
            directory_identity_with_gate(cleanup.directory(), gate).map_err(|error| {
                map_charged_identity_io(error, stage, SnapshotPublicationStateV1::Unpublished)
            })?;
        let reopened = open_directory_at_with_gate(
            cleanup.parent,
            cleanup.staging_name.as_c_str(),
            cleanup.policy().openat2_attempts(),
            gate,
        )
        .map_err(|error| map_charged_io(error, stage, SnapshotPublicationStateV1::Unpublished))?;
        let reopened_identity =
            directory_identity_with_gate(reopened.as_fd(), gate).map_err(|error| {
                map_charged_identity_io(error, stage, SnapshotPublicationStateV1::Unpublished)
            })?;
        if !same_staging_identity_except_link_count(fd_identity, cleanup.expected_identity())
            || reopened_identity != fd_identity
            || !owned_directory_with_exact_mode(fd_identity, cleanup.effective_uid, required_mode)
        {
            return Err(SnapshotChargedErrorV1::Leaf(identity_failure(
                stage,
                SnapshotPublicationStateV1::Unpublished,
            )));
        }
        Ok(fd_identity)
    }

    fn revalidate_staging_exact_with_gate<G: PublisherAttemptGateV1>(
        cleanup: &StagingCleanupV1<'_>,
        expected: SnapshotDirectoryIdentityV1,
        gate: &G,
        stage: SnapshotPublishStageV1,
    ) -> Result<(), SnapshotChargedErrorV1<SnapshotPublishErrorV1>> {
        let fd_identity =
            directory_identity_with_gate(cleanup.directory(), gate).map_err(|error| {
                map_charged_identity_io(error, stage, SnapshotPublicationStateV1::Unpublished)
            })?;
        let reopened = open_directory_at_with_gate(
            cleanup.parent,
            cleanup.staging_name.as_c_str(),
            cleanup.policy().openat2_attempts(),
            gate,
        )
        .map_err(|error| map_charged_io(error, stage, SnapshotPublicationStateV1::Unpublished))?;
        let reopened_identity =
            directory_identity_with_gate(reopened.as_fd(), gate).map_err(|error| {
                map_charged_identity_io(error, stage, SnapshotPublicationStateV1::Unpublished)
            })?;
        if fd_identity != expected || reopened_identity != expected {
            return Err(SnapshotChargedErrorV1::Leaf(identity_failure(
                stage,
                SnapshotPublicationStateV1::Unpublished,
            )));
        }
        Ok(())
    }

    fn identity_with_mode(
        identity: SnapshotDirectoryIdentityV1,
        permissions: u32,
    ) -> SnapshotDirectoryIdentityV1 {
        SnapshotDirectoryIdentityV1 {
            mode: (identity.mode & !0o7777) | permissions,
            ..identity
        }
    }

    fn same_staging_identity_except_link_count(
        current: SnapshotDirectoryIdentityV1,
        expected: SnapshotDirectoryIdentityV1,
    ) -> bool {
        current.mount_id == expected.mount_id
            && current.device_major == expected.device_major
            && current.device_minor == expected.device_minor
            && current.inode == expected.inode
            && current.mode == expected.mode
            && current.uid == expected.uid
            && current.gid == expected.gid
    }

    fn owned_directory_with_exact_mode(
        identity: SnapshotDirectoryIdentityV1,
        effective_uid: u32,
        permissions: u32,
    ) -> bool {
        identity.mode & libc::S_IFMT == libc::S_IFDIR
            && identity.mode & 0o7777 == permissions
            && identity.uid == effective_uid
    }

    fn owner_private_directory(identity: SnapshotDirectoryIdentityV1, effective_uid: u32) -> bool {
        owned_directory_with_exact_mode(identity, effective_uid, PRIVATE_DIRECTORY_MODE)
    }

    fn owner_staging_directory(identity: SnapshotDirectoryIdentityV1, effective_uid: u32) -> bool {
        owner_private_directory(identity, effective_uid)
            || owned_directory_with_exact_mode(identity, effective_uid, SEALED_DIRECTORY_MODE)
    }

    fn same_directory_object(
        left: SnapshotDirectoryIdentityV1,
        right: SnapshotDirectoryIdentityV1,
    ) -> bool {
        left.mount_id == right.mount_id
            && left.device_major == right.device_major
            && left.device_minor == right.device_minor
            && left.inode == right.inode
    }

    fn mkdir_private_at_charged(
        authority: &PublisherAuthorityV1<'_>,
        parent: BorrowedFd<'_>,
        name: &CStr,
        attempts: u8,
    ) -> Result<(), SnapshotChargedErrorV1<io::Error>> {
        retry_eintr_zero_charged(
            authority,
            PublisherAttemptBucketV1::Forward,
            attempts,
            || unsafe {
                libc::mkdirat(
                    parent.as_raw_fd(),
                    name.as_ptr(),
                    PRIVATE_DIRECTORY_MODE as libc::mode_t,
                )
            },
        )
    }

    fn open_directory_at(parent: BorrowedFd<'_>, name: &CStr, attempts: u8) -> io::Result<OwnedFd> {
        openat2_owned(
            parent,
            name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            attempts,
        )
    }

    fn open_directory_at_with_gate<G: PublisherAttemptGateV1>(
        parent: BorrowedFd<'_>,
        name: &CStr,
        attempts: u8,
        gate: &G,
    ) -> Result<OwnedFd, SnapshotChargedErrorV1<io::Error>> {
        openat2_owned_with_gate(
            parent,
            name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            attempts,
            gate,
        )
    }

    fn open_directory_at_charged(
        authority: &PublisherAuthorityV1<'_>,
        bucket: PublisherAttemptBucketV1,
        parent: BorrowedFd<'_>,
        name: &CStr,
        attempts: u8,
    ) -> Result<OwnedFd, SnapshotChargedErrorV1<io::Error>> {
        openat2_owned_charged(
            authority,
            bucket,
            parent,
            name,
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            attempts,
        )
    }

    fn directory_identity(directory: BorrowedFd<'_>) -> io::Result<SnapshotDirectoryIdentityV1> {
        unmetered_leaf(directory_identity_with_gate(
            directory,
            &UnmeteredPublisherAttemptGateV1,
        ))
    }

    fn directory_identity_with_gate<G: PublisherAttemptGateV1>(
        directory: BorrowedFd<'_>,
        gate: &G,
    ) -> Result<SnapshotDirectoryIdentityV1, SnapshotChargedErrorV1<io::Error>> {
        let mut stat = MaybeUninit::<libc::stat>::zeroed();
        let fstat_result = gate
            .run_attempt(|| unsafe {
                #[cfg(test)]
                DIRECTORY_FSTAT_CALLS.with(|calls| calls.set(calls.get() + 1));
                libc::fstat(directory.as_raw_fd(), stat.as_mut_ptr())
            })
            .map_err(SnapshotChargedErrorV1::Resource)?;
        if fstat_result != 0 {
            return Err(SnapshotChargedErrorV1::Leaf(io::Error::last_os_error()));
        }
        let stat = unsafe { stat.assume_init() };

        let mut statx = MaybeUninit::<libc::statx>::zeroed();
        let statx_result = gate
            .run_attempt(|| unsafe {
                libc::syscall(
                    libc::SYS_statx,
                    directory.as_raw_fd(),
                    c"".as_ptr(),
                    AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                    REQUIRED_STATX_MASK,
                    statx.as_mut_ptr(),
                )
            })
            .map_err(SnapshotChargedErrorV1::Resource)?;
        if statx_result != 0 {
            return Err(SnapshotChargedErrorV1::Leaf(io::Error::last_os_error()));
        }
        let statx = unsafe { statx.assume_init() };
        if statx.stx_mask & REQUIRED_STATX_MASK != REQUIRED_STATX_MASK
            || statx.stx_ino != stat.st_ino
            || statx.stx_dev_major != linux_device_major(stat.st_dev)
            || statx.stx_dev_minor != linux_device_minor(stat.st_dev)
            || u32::from(statx.stx_mode) != stat.st_mode
            || statx.stx_uid != stat.st_uid
            || statx.stx_gid != stat.st_gid
            || u64::from(statx.stx_nlink) != stat.st_nlink
            || stat.st_mode & libc::S_IFMT != libc::S_IFDIR
        {
            return Err(SnapshotChargedErrorV1::Leaf(io::Error::from_raw_os_error(
                libc::ESTALE,
            )));
        }
        Ok(SnapshotDirectoryIdentityV1 {
            mount_id: statx.stx_mnt_id,
            device_major: statx.stx_dev_major,
            device_minor: statx.stx_dev_minor,
            inode: statx.stx_ino,
            mode: u32::from(statx.stx_mode),
            uid: statx.stx_uid,
            gid: statx.stx_gid,
            link_count: u64::from(statx.stx_nlink),
        })
    }

    fn published_child_statx_with_gate<G: PublisherAttemptGateV1>(
        child: BorrowedFd<'_>,
        gate: &G,
    ) -> Result<SourceStatxV1, SnapshotChargedErrorV1<io::Error>> {
        let mut raw = MaybeUninit::<libc::statx>::zeroed();
        let result = gate
            .run_attempt(|| unsafe {
                #[cfg(test)]
                PUBLISHED_CHILD_STATX_CALLS.with(|calls| calls.set(calls.get() + 1));
                libc::syscall(
                    libc::SYS_statx,
                    child.as_raw_fd(),
                    c"".as_ptr(),
                    AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                    SOURCE_TREE_REQUESTED_STATX_MASK_V1,
                    raw.as_mut_ptr(),
                )
            })
            .map_err(SnapshotChargedErrorV1::Resource)?;
        if result != 0 {
            return Err(SnapshotChargedErrorV1::Leaf(io::Error::last_os_error()));
        }
        let raw = unsafe { raw.assume_init() };
        let observed =
            SourceStatxV1::from_linux_statx_v1(&raw).map_err(SnapshotChargedErrorV1::Leaf)?;
        if u32::from(raw.stx_mode) & libc::S_IFMT != libc::S_IFDIR {
            return Err(SnapshotChargedErrorV1::Leaf(io::Error::from_raw_os_error(
                libc::ESTALE,
            )));
        }
        Ok(observed)
    }

    fn directory_identity_charged(
        authority: &PublisherAuthorityV1<'_>,
        bucket: PublisherAttemptBucketV1,
        directory: BorrowedFd<'_>,
    ) -> Result<SnapshotDirectoryIdentityV1, SnapshotChargedErrorV1<io::Error>> {
        directory_identity_with_gate(
            directory,
            &PublisherBucketAttemptGateV1 { authority, bucket },
        )
    }

    const fn linux_device_major(device: libc::dev_t) -> u32 {
        (((device & 0x0000_0000_000f_ff00) >> 8) | ((device & 0xffff_f000_0000_0000) >> 32)) as u32
    }

    const fn linux_device_minor(device: libc::dev_t) -> u32 {
        ((device & 0x0000_0000_0000_00ff) | ((device & 0x0000_0fff_fff0_0000) >> 12)) as u32
    }

    fn fsync_fd(fd: BorrowedFd<'_>, attempts: u8) -> io::Result<()> {
        unmetered_leaf(fsync_fd_with_gate(
            fd,
            attempts,
            &UnmeteredPublisherAttemptGateV1,
        ))
    }

    fn fsync_fd_with_gate<G: PublisherAttemptGateV1>(
        fd: BorrowedFd<'_>,
        attempts: u8,
        gate: &G,
    ) -> Result<(), SnapshotChargedErrorV1<io::Error>> {
        retry_eintr_result_with_gate(gate, attempts, || {
            let result = unsafe { libc::fsync(fd.as_raw_fd()) };
            if result == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        })
    }

    fn rename_noreplace_at(
        old_parent: BorrowedFd<'_>,
        old_name: &CStr,
        new_parent: BorrowedFd<'_>,
        new_name: &CStr,
    ) -> io::Result<()> {
        rename_noreplace_once(|| unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                old_parent.as_raw_fd(),
                old_name.as_ptr(),
                new_parent.as_raw_fd(),
                new_name.as_ptr(),
                RENAME_NOREPLACE,
            )
        })
    }

    fn rename_noreplace_once(operation: impl FnOnce() -> libc::c_long) -> io::Result<()> {
        let result = operation();
        if result == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn unlink_at_charged(
        authority: &PublisherAuthorityV1<'_>,
        parent: BorrowedFd<'_>,
        name: &CStr,
        flags: i32,
        attempts: u8,
    ) -> Result<(), SnapshotChargedErrorV1<io::Error>> {
        retry_eintr_zero_charged(
            authority,
            PublisherAttemptBucketV1::Cleanup,
            attempts,
            || unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), flags) },
        )
    }

    fn retry_eintr_zero<F>(attempts: u8, mut operation: F) -> io::Result<()>
    where
        F: FnMut() -> libc::c_int,
    {
        let result =
            retry_eintr_result_with_gate(&UnmeteredPublisherAttemptGateV1, attempts, || {
                let result = operation();
                if result == 0 {
                    Ok(())
                } else {
                    Err(io::Error::last_os_error())
                }
            });
        unmetered_leaf(result)
    }

    fn retry_eintr_result_with_gate<G, F>(
        gate: &G,
        attempts: u8,
        mut operation: F,
    ) -> Result<(), SnapshotChargedErrorV1<io::Error>>
    where
        G: PublisherAttemptGateV1,
        F: FnMut() -> io::Result<()>,
    {
        let mut last = io::Error::from_raw_os_error(libc::EINTR);
        for _ in 0..attempts {
            match gate
                .run_attempt(&mut operation)
                .map_err(SnapshotChargedErrorV1::Resource)?
            {
                Ok(()) => return Ok(()),
                Err(error) => {
                    last = error;
                    if last.kind() != io::ErrorKind::Interrupted {
                        return Err(SnapshotChargedErrorV1::Leaf(last));
                    }
                }
            }
        }
        Err(SnapshotChargedErrorV1::Leaf(last))
    }

    fn retry_eintr_zero_charged<F>(
        authority: &PublisherAuthorityV1<'_>,
        bucket: PublisherAttemptBucketV1,
        attempts: u8,
        mut operation: F,
    ) -> Result<(), SnapshotChargedErrorV1<io::Error>>
    where
        F: FnMut() -> libc::c_int,
    {
        retry_eintr_result_with_gate(
            &PublisherBucketAttemptGateV1 { authority, bucket },
            attempts,
            || {
                let result = operation();
                if result == 0 {
                    Ok(())
                } else {
                    Err(io::Error::last_os_error())
                }
            },
        )
    }

    fn remove_directory_contents<'resources>(
        directory: BorrowedFd<'_>,
        authority: &PublisherAuthorityV1<'resources>,
        effective_uid: u32,
        policy: SnapshotPublishPolicyV1,
        depth: u16,
        budget: &mut CleanupBudgetV1,
    ) -> Result<(), SnapshotChargedErrorV1<io::Error>> {
        if depth > policy.max_cleanup_depth {
            return Err(SnapshotChargedErrorV1::Leaf(io::Error::from_raw_os_error(
                libc::ELOOP,
            )));
        }
        loop {
            let remaining_entries = policy
                .max_cleanup_entries
                .get()
                .saturating_sub(budget.entries_seen);
            let batch =
                read_directory_names(directory, authority, policy, remaining_entries, budget)?;
            if batch.is_empty() {
                return Ok(());
            }
            let reached_eof = batch.reached_eof;
            let retained_name_bytes = batch
                .retained_name_bytes()
                .map_err(SnapshotChargedErrorV1::Leaf)?;
            budget
                .retain_batch(policy, batch.len(), retained_name_bytes)
                .map_err(SnapshotChargedErrorV1::Leaf)?;
            let result: Result<(), SnapshotChargedErrorV1<io::Error>> = (|| {
                for retained_name in batch.iter() {
                    let name = retained_name.as_c_str();
                    let child = open_path_at_charged(
                        authority,
                        directory,
                        name,
                        policy.openat2_attempts(),
                    )?;
                    let pinned_child = cleanup_identity_charged(authority, child.as_fd())?;
                    if pinned_child.mode_type == libc::S_IFDIR {
                        if !owned_directory_for_uid(pinned_child, effective_uid) {
                            return Err(SnapshotChargedErrorV1::Leaf(
                                io::Error::from_raw_os_error(libc::EPERM),
                            ));
                        }
                        let child_directory = open_directory_at_charged(
                            authority,
                            PublisherAttemptBucketV1::Cleanup,
                            directory,
                            name,
                            policy.openat2_attempts(),
                        )?;
                        if cleanup_identity_charged(authority, child_directory.as_fd())?
                            != pinned_child
                        {
                            return Err(SnapshotChargedErrorV1::Leaf(
                                io::Error::from_raw_os_error(libc::ESTALE),
                            ));
                        }
                        let before = prepare_owned_directory_for_cleanup_charged(
                            authority,
                            child_directory.as_fd(),
                            pinned_child,
                            effective_uid,
                            policy.syscall_attempts(),
                        )?;
                        remove_directory_contents(
                            child_directory.as_fd(),
                            authority,
                            effective_uid,
                            policy,
                            depth + 1,
                            budget,
                        )?;
                        let reopened = open_directory_at_charged(
                            authority,
                            PublisherAttemptBucketV1::Cleanup,
                            directory,
                            name,
                            policy.openat2_attempts(),
                        )?;
                        let reopened_identity =
                            cleanup_identity_charged(authority, reopened.as_fd())?;
                        if !same_cleanup_object(reopened_identity, before)
                            || !owned_directory_for_uid(reopened_identity, effective_uid)
                        {
                            return Err(SnapshotChargedErrorV1::Leaf(
                                io::Error::from_raw_os_error(libc::ESTALE),
                            ));
                        }
                        unlink_at_charged(
                            authority,
                            directory,
                            name,
                            libc::AT_REMOVEDIR,
                            policy.syscall_attempts(),
                        )?;
                    } else {
                        let reopened = open_path_at_charged(
                            authority,
                            directory,
                            name,
                            policy.openat2_attempts(),
                        )?;
                        if cleanup_identity_charged(authority, reopened.as_fd())? != pinned_child {
                            return Err(SnapshotChargedErrorV1::Leaf(
                                io::Error::from_raw_os_error(libc::ESTALE),
                            ));
                        }
                        unlink_at_charged(
                            authority,
                            directory,
                            name,
                            0,
                            policy.syscall_attempts(),
                        )?;
                    }
                }
                Ok(())
            })();
            drop(batch);
            budget.release_batch(retained_name_bytes);
            result?;
            if reached_eof {
                return Ok(());
            }
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct CleanupIdentityV1 {
        device: libc::dev_t,
        inode: libc::ino_t,
        mode_type: libc::mode_t,
        mode_permissions: libc::mode_t,
        uid: libc::uid_t,
    }

    fn cleanup_identity(fd: BorrowedFd<'_>) -> io::Result<CleanupIdentityV1> {
        let stat = fstat_raw(fd)?;
        Ok(CleanupIdentityV1 {
            device: stat.st_dev,
            inode: stat.st_ino,
            mode_type: stat.st_mode & libc::S_IFMT,
            mode_permissions: stat.st_mode & 0o7777,
            uid: stat.st_uid,
        })
    }

    fn owned_directory_for_uid(identity: CleanupIdentityV1, effective_uid: u32) -> bool {
        identity.mode_type == libc::S_IFDIR && identity.uid == effective_uid
    }

    fn same_cleanup_object(left: CleanupIdentityV1, right: CleanupIdentityV1) -> bool {
        left.device == right.device
            && left.inode == right.inode
            && left.mode_type == right.mode_type
            && left.uid == right.uid
    }

    fn prepare_owned_directory_for_cleanup_charged(
        authority: &PublisherAuthorityV1<'_>,
        directory: BorrowedFd<'_>,
        expected: CleanupIdentityV1,
        effective_uid: u32,
        attempts: u8,
    ) -> Result<CleanupIdentityV1, SnapshotChargedErrorV1<io::Error>> {
        let before = cleanup_identity_charged(authority, directory)?;
        if before != expected {
            return Err(SnapshotChargedErrorV1::Leaf(io::Error::from_raw_os_error(
                libc::ESTALE,
            )));
        }
        if !owned_directory_for_uid(before, effective_uid) {
            return Err(SnapshotChargedErrorV1::Leaf(io::Error::from_raw_os_error(
                libc::EPERM,
            )));
        }
        retry_eintr_zero_charged(
            authority,
            PublisherAttemptBucketV1::Cleanup,
            attempts,
            || unsafe {
                libc::fchmod(
                    directory.as_raw_fd(),
                    PRIVATE_DIRECTORY_MODE as libc::mode_t,
                )
            },
        )?;
        let after = cleanup_identity_charged(authority, directory)?;
        if !same_cleanup_object(after, before)
            || !owned_directory_for_uid(after, effective_uid)
            || after.mode_permissions != PRIVATE_DIRECTORY_MODE as libc::mode_t
        {
            return Err(SnapshotChargedErrorV1::Leaf(io::Error::from_raw_os_error(
                libc::ESTALE,
            )));
        }
        Ok(after)
    }

    fn fstat_raw(fd: BorrowedFd<'_>) -> io::Result<libc::stat> {
        unmetered_leaf(fstat_raw_with_gate(fd, &UnmeteredPublisherAttemptGateV1))
    }

    fn fstat_raw_with_gate<G: PublisherAttemptGateV1>(
        fd: BorrowedFd<'_>,
        gate: &G,
    ) -> Result<libc::stat, SnapshotChargedErrorV1<io::Error>> {
        let mut stat = MaybeUninit::<libc::stat>::zeroed();
        let result = gate
            .run_attempt(|| unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) })
            .map_err(SnapshotChargedErrorV1::Resource)?;
        if result != 0 {
            return Err(SnapshotChargedErrorV1::Leaf(io::Error::last_os_error()));
        }
        Ok(unsafe { stat.assume_init() })
    }

    fn cleanup_identity_charged(
        authority: &PublisherAuthorityV1<'_>,
        fd: BorrowedFd<'_>,
    ) -> Result<CleanupIdentityV1, SnapshotChargedErrorV1<io::Error>> {
        cleanup_identity_with_gate(
            fd,
            &PublisherBucketAttemptGateV1 {
                authority,
                bucket: PublisherAttemptBucketV1::Cleanup,
            },
        )
    }

    fn cleanup_identity_with_gate<G: PublisherAttemptGateV1>(
        fd: BorrowedFd<'_>,
        gate: &G,
    ) -> Result<CleanupIdentityV1, SnapshotChargedErrorV1<io::Error>> {
        let stat = fstat_raw_with_gate(fd, gate)?;
        Ok(CleanupIdentityV1 {
            device: stat.st_dev,
            inode: stat.st_ino,
            mode_type: stat.st_mode & libc::S_IFMT,
            mode_permissions: stat.st_mode & 0o7777,
            uid: stat.st_uid,
        })
    }

    fn open_path_at_with_gate<G: PublisherAttemptGateV1>(
        parent: BorrowedFd<'_>,
        name: &CStr,
        attempts: u8,
        gate: &G,
    ) -> Result<OwnedFd, SnapshotChargedErrorV1<io::Error>> {
        openat2_owned_with_gate(
            parent,
            name,
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            attempts,
            gate,
        )
    }

    fn open_path_at_charged(
        authority: &PublisherAuthorityV1<'_>,
        parent: BorrowedFd<'_>,
        name: &CStr,
        attempts: u8,
    ) -> Result<OwnedFd, SnapshotChargedErrorV1<io::Error>> {
        openat2_owned_charged(
            authority,
            PublisherAttemptBucketV1::Cleanup,
            parent,
            name,
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            attempts,
        )
    }

    fn openat2_owned(
        parent: BorrowedFd<'_>,
        name: &CStr,
        flags: i32,
        attempts: u8,
    ) -> io::Result<OwnedFd> {
        unmetered_leaf(openat2_owned_with_gate(
            parent,
            name,
            flags,
            attempts,
            &UnmeteredPublisherAttemptGateV1,
        ))
    }

    fn openat2_owned_with_gate<G: PublisherAttemptGateV1>(
        parent: BorrowedFd<'_>,
        name: &CStr,
        flags: i32,
        attempts: u8,
        gate: &G,
    ) -> Result<OwnedFd, SnapshotChargedErrorV1<io::Error>> {
        let how = OpenHow {
            flags: flags as u64,
            mode: 0,
            resolve: SNAPSHOT_RESOLVE,
        };
        let mut last = io::Error::from_raw_os_error(libc::EAGAIN);
        for _ in 0..attempts {
            let result = gate
                .run_attempt(|| unsafe {
                    libc::syscall(
                        libc::SYS_openat2,
                        parent.as_raw_fd(),
                        name.as_ptr(),
                        &how,
                        mem::size_of::<OpenHow>(),
                    )
                })
                .map_err(SnapshotChargedErrorV1::Resource)?;
            if result >= 0 {
                // `close(2)` performed by `OwnedFd` is the explicit
                // non-budgeted RAII exception: it releases authority and
                // cannot be retried safely after an ambiguous result.
                return Ok(unsafe { OwnedFd::from_raw_fd(result as RawFd) });
            }
            last = io::Error::last_os_error();
            if last.raw_os_error() != Some(libc::EAGAIN) {
                return Err(SnapshotChargedErrorV1::Leaf(last));
            }
        }
        Err(SnapshotChargedErrorV1::Leaf(last))
    }

    fn openat2_owned_charged(
        authority: &PublisherAuthorityV1<'_>,
        bucket: PublisherAttemptBucketV1,
        parent: BorrowedFd<'_>,
        name: &CStr,
        flags: i32,
        attempts: u8,
    ) -> Result<OwnedFd, SnapshotChargedErrorV1<io::Error>> {
        openat2_owned_with_gate(
            parent,
            name,
            flags,
            attempts,
            &PublisherBucketAttemptGateV1 { authority, bucket },
        )
    }

    struct CleanupNameBatchV1<'resources> {
        names: [Option<RetainedCStringV1<'resources>>; CLEANUP_NAME_BATCH_SIZE],
        len: usize,
        reached_eof: bool,
    }

    impl<'resources> CleanupNameBatchV1<'resources> {
        fn new() -> Self {
            Self {
                names: std::array::from_fn(|_| None),
                len: 0,
                reached_eof: false,
            }
        }

        fn is_empty(&self) -> bool {
            self.len == 0
        }

        fn len(&self) -> usize {
            self.len
        }

        fn push(&mut self, name: RetainedCStringV1<'resources>) -> io::Result<()> {
            let slot = self
                .names
                .get_mut(self.len)
                .ok_or_else(|| io::Error::from_raw_os_error(libc::E2BIG))?;
            *slot = Some(name);
            self.len += 1;
            Ok(())
        }

        fn iter(&self) -> impl Iterator<Item = &RetainedCStringV1<'_>> {
            self.names[..self.len]
                .iter()
                .map(|name| name.as_ref().expect("retained-name prefix is dense"))
        }

        fn retained_name_bytes(&self) -> io::Result<u64> {
            let mut retained = 0_u64;
            for name in self.iter() {
                retained = retained
                    .checked_add(name.retained_capacity_bytes()?)
                    .ok_or_else(|| io::Error::from_raw_os_error(libc::E2BIG))?;
            }
            Ok(retained)
        }
    }

    fn read_directory_names<'resources>(
        directory: BorrowedFd<'_>,
        authority: &PublisherAuthorityV1<'resources>,
        policy: SnapshotPublishPolicyV1,
        remaining_entries: u32,
        budget: &mut CleanupBudgetV1,
    ) -> Result<CleanupNameBatchV1<'resources>, SnapshotChargedErrorV1<io::Error>> {
        let reopened = open_directory_at_charged(
            authority,
            PublisherAttemptBucketV1::Cleanup,
            directory,
            c".",
            policy.openat2_attempts(),
        )?;
        let mut buffer = [0_u8; CLEANUP_GETDENTS_BUFFER_BYTES];
        let mut batch = CleanupNameBatchV1::new();
        let batch_limit = CLEANUP_NAME_BATCH_SIZE.min(remaining_entries as usize);
        loop {
            let length =
                getdents64_bounded(reopened.as_fd(), authority, &mut buffer, policy, budget)?;
            if length == 0 {
                batch.reached_eof = true;
                break;
            }
            let mut offset = 0;
            while offset < length {
                if length - offset < DIRENT64_NAME_OFFSET + 1 {
                    return Err(SnapshotChargedErrorV1::Leaf(io::Error::from_raw_os_error(
                        libc::EIO,
                    )));
                }
                let record_length = usize::from(u16::from_ne_bytes([
                    buffer[offset + 16],
                    buffer[offset + 17],
                ]));
                if record_length < DIRENT64_NAME_OFFSET + 1 || record_length > length - offset {
                    return Err(SnapshotChargedErrorV1::Leaf(io::Error::from_raw_os_error(
                        libc::EIO,
                    )));
                }
                let record = &buffer[offset..offset + record_length];
                let name =
                    CStr::from_bytes_until_nul(&record[DIRENT64_NAME_OFFSET..]).map_err(|_| {
                        SnapshotChargedErrorV1::Leaf(io::Error::from_raw_os_error(libc::EIO))
                    })?;
                offset += record_length;
                if name.to_bytes() == b"." || name.to_bytes() == b".." {
                    continue;
                }
                if !valid_raw_basename(name) {
                    return Err(SnapshotChargedErrorV1::Leaf(io::Error::from_raw_os_error(
                        libc::EIO,
                    )));
                }
                if name.to_bytes().len() > usize::from(policy.max_cleanup_name_bytes.get()) {
                    return Err(SnapshotChargedErrorV1::Leaf(io::Error::from_raw_os_error(
                        libc::ENAMETOOLONG,
                    )));
                }
                if batch_limit == 0 {
                    return Err(SnapshotChargedErrorV1::Leaf(io::Error::from_raw_os_error(
                        libc::E2BIG,
                    )));
                }
                batch
                    .push(try_clone_cstr_charged(
                        authority,
                        PublisherAttemptBucketV1::Cleanup,
                        name,
                    )?)
                    .map_err(SnapshotChargedErrorV1::Leaf)?;
                if batch.len() == batch_limit {
                    break;
                }
            }
            if batch.len() == batch_limit && batch_limit != 0 {
                break;
            }
        }
        Ok(batch)
    }

    fn getdents64_bounded(
        directory: BorrowedFd<'_>,
        authority: &PublisherAuthorityV1<'_>,
        buffer: &mut [u8; CLEANUP_GETDENTS_BUFFER_BYTES],
        policy: SnapshotPublishPolicyV1,
        budget: &mut CleanupBudgetV1,
    ) -> Result<usize, SnapshotChargedErrorV1<io::Error>> {
        let mut last = io::Error::from_raw_os_error(libc::EINTR);
        for _ in 0..policy.syscall_attempts() {
            budget
                .charge_getdents_attempt(policy)
                .map_err(SnapshotChargedErrorV1::Leaf)?;
            let result = authority
                .run_attempt(PublisherAttemptBucketV1::Cleanup, || unsafe {
                    libc::syscall(
                        libc::SYS_getdents64,
                        directory.as_raw_fd(),
                        buffer.as_mut_ptr(),
                        buffer.len(),
                    )
                })
                .map_err(SnapshotChargedErrorV1::Resource)?;
            if result >= 0 {
                return usize::try_from(result)
                    .ok()
                    .filter(|length| *length <= buffer.len())
                    .ok_or_else(|| {
                        SnapshotChargedErrorV1::Leaf(io::Error::from_raw_os_error(libc::EIO))
                    });
            }
            last = io::Error::last_os_error();
            if last.kind() != io::ErrorKind::Interrupted {
                return Err(SnapshotChargedErrorV1::Leaf(last));
            }
        }
        Err(SnapshotChargedErrorV1::Leaf(last))
    }

    fn try_clone_cstr_charged<'resources>(
        authority: &PublisherAuthorityV1<'resources>,
        bucket: PublisherAttemptBucketV1,
        value: &CStr,
    ) -> Result<RetainedCStringV1<'resources>, SnapshotChargedErrorV1<io::Error>> {
        let bytes = value.to_bytes_with_nul();
        let mut bytes_with_nul = PublisherBytesV1::charged_for(authority, bucket, bytes.len())?;
        bytes_with_nul.try_extend_from_slice(bytes)?;
        Ok(RetainedCStringV1 { bytes_with_nul })
    }

    fn map_charged_io(
        error: SnapshotChargedErrorV1<io::Error>,
        stage: SnapshotPublishStageV1,
        publication_state: SnapshotPublicationStateV1,
    ) -> SnapshotChargedErrorV1<SnapshotPublishErrorV1> {
        match error {
            SnapshotChargedErrorV1::PublicationAlreadyStarted => {
                SnapshotChargedErrorV1::PublicationAlreadyStarted
            }
            SnapshotChargedErrorV1::Resource(error) => SnapshotChargedErrorV1::Resource(error),
            SnapshotChargedErrorV1::Leaf(error) => {
                SnapshotChargedErrorV1::Leaf(io_failure(stage, publication_state, error))
            }
        }
    }

    fn published_child_bind_failure(
        error: SnapshotChargedErrorV1<io::Error>,
        stage: SnapshotPublishStageV1,
        leaf_kind: impl FnOnce(&io::Error) -> SnapshotPublishErrorKindV1,
    ) -> SnapshotPublishedChildBindErrorV1 {
        match map_charged_io_with(
            error,
            stage,
            SnapshotPublicationStateV1::PublishedDurable,
            leaf_kind,
        ) {
            SnapshotChargedErrorV1::Resource(error) => {
                SnapshotPublishedChildBindErrorV1::resource(error)
            }
            SnapshotChargedErrorV1::Leaf(error) => {
                debug_assert_eq!(
                    error.publication_state(),
                    SnapshotPublicationStateV1::PublishedDurable
                );
                SnapshotPublishedChildBindErrorV1 {
                    failure: SnapshotPublishedChildBindFailureV1::Leaf(error),
                }
            }
            SnapshotChargedErrorV1::PublicationAlreadyStarted => {
                unreachable!("a published-child bind reservation has no one-shot connector state")
            }
        }
    }

    fn map_charged_identity_io(
        error: SnapshotChargedErrorV1<io::Error>,
        stage: SnapshotPublishStageV1,
        publication_state: SnapshotPublicationStateV1,
    ) -> SnapshotChargedErrorV1<SnapshotPublishErrorV1> {
        match error {
            SnapshotChargedErrorV1::PublicationAlreadyStarted => {
                SnapshotChargedErrorV1::PublicationAlreadyStarted
            }
            SnapshotChargedErrorV1::Resource(error) => SnapshotChargedErrorV1::Resource(error),
            SnapshotChargedErrorV1::Leaf(error) => {
                SnapshotChargedErrorV1::Leaf(identity_io_failure(stage, publication_state, error))
            }
        }
    }

    fn map_charged_io_with(
        error: SnapshotChargedErrorV1<io::Error>,
        stage: SnapshotPublishStageV1,
        publication_state: SnapshotPublicationStateV1,
        leaf_kind: impl FnOnce(&io::Error) -> SnapshotPublishErrorKindV1,
    ) -> SnapshotChargedErrorV1<SnapshotPublishErrorV1> {
        match error {
            SnapshotChargedErrorV1::PublicationAlreadyStarted => {
                SnapshotChargedErrorV1::PublicationAlreadyStarted
            }
            SnapshotChargedErrorV1::Resource(error) => SnapshotChargedErrorV1::Resource(error),
            SnapshotChargedErrorV1::Leaf(error) => {
                let kind = leaf_kind(&error);
                SnapshotChargedErrorV1::Leaf(SnapshotPublishErrorV1::new(
                    kind,
                    stage,
                    publication_state,
                    error.raw_os_error(),
                ))
            }
        }
    }

    fn identity_failure(
        stage: SnapshotPublishStageV1,
        publication_state: SnapshotPublicationStateV1,
    ) -> SnapshotPublishErrorV1 {
        SnapshotPublishErrorV1::new(
            SnapshotPublishErrorKindV1::IdentityMismatch,
            stage,
            publication_state,
            None,
        )
    }

    fn identity_io_failure(
        stage: SnapshotPublishStageV1,
        publication_state: SnapshotPublicationStateV1,
        error: io::Error,
    ) -> SnapshotPublishErrorV1 {
        let kind = if missing_kernel_capability(&error) {
            SnapshotPublishErrorKindV1::RequiredKernelCapabilityMissing
        } else if error.raw_os_error() == Some(libc::ESTALE) {
            SnapshotPublishErrorKindV1::IdentityMismatch
        } else {
            SnapshotPublishErrorKindV1::Io
        };
        SnapshotPublishErrorV1::new(kind, stage, publication_state, error.raw_os_error())
    }

    fn io_failure(
        stage: SnapshotPublishStageV1,
        publication_state: SnapshotPublicationStateV1,
        error: io::Error,
    ) -> SnapshotPublishErrorV1 {
        let kind = if missing_kernel_capability(&error) {
            SnapshotPublishErrorKindV1::RequiredKernelCapabilityMissing
        } else {
            SnapshotPublishErrorKindV1::Io
        };
        SnapshotPublishErrorV1::new(kind, stage, publication_state, error.raw_os_error())
    }

    fn missing_kernel_capability(error: &io::Error) -> bool {
        matches!(
            error.raw_os_error(),
            Some(libc::ENOSYS | libc::EOPNOTSUPP | libc::EINVAL | libc::E2BIG)
        )
    }

    #[cfg(test)]
    mod tests {
        use std::ffi::{CString, OsStr};
        use std::fs::{self, File, FileTimes, OpenOptions};
        use std::os::fd::AsFd;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink};
        use std::path::{Path, PathBuf};

        use tempfile::TempDir;

        use super::*;
        use crate::linux_pytest::snapshot_connector::{
            SnapshotConnectorV1, connect_snapshot_pipeline,
        };
        use crate::linux_pytest::snapshot_policy::{
            SnapshotPipelineAttemptBucketV1, SnapshotPipelineForwardStageV1,
            SnapshotPipelineResourcesV1, SnapshotPipelineStageV1, SnapshotResourcePolicyV1,
        };

        const STAGING: &CStr = c".again-snapshot-stage-0123456789abcdef0123456789abcdef";
        const FINAL: &CStr = c"snapshot-final";
        const ROOT: &CStr = c"root";
        const CLEANUP_STRESS_NAME_COUNT: usize = 65;
        const CREATE_TRANSITION_COUNT: usize = 4;
        const READY_TRANSITION_COUNT: usize = 3;
        const LOCAL_REGULAR_CLEANUP_RESERVE: u64 = 4 + 2 * 3;

        fn policy() -> SnapshotPublishPolicyV1 {
            SnapshotPublishPolicyV1::checked(
                NonZeroU8::new(4).unwrap(),
                NonZeroU8::new(4).unwrap(),
                HARD_MAX_SOURCE_TREE_DEPTH,
                NonZeroU32::new(HARD_MAX_CLEANUP_ENTRIES).unwrap(),
                NonZeroU16::new(MAX_BASENAME_BYTES as u16).unwrap(),
                NonZeroU64::new(HARD_MAX_CLEANUP_RETAINED_NAME_BYTES).unwrap(),
            )
            .unwrap()
        }

        fn charged_connector(
            operation_attempts: u64,
            transient_heap_bytes: u64,
        ) -> SnapshotConnectorV1 {
            charged_connector_with_entries(operation_attempts, transient_heap_bytes, 4)
        }

        fn charged_connector_with_entries(
            operation_attempts: u64,
            transient_heap_bytes: u64,
            entries: u32,
        ) -> SnapshotConnectorV1 {
            connect_snapshot_pipeline(charged_resources_with_entries(
                operation_attempts,
                transient_heap_bytes,
                entries,
            ))
            .unwrap()
        }

        fn charged_resources_with_entries(
            operation_attempts: u64,
            transient_heap_bytes: u64,
            entries: u32,
        ) -> SnapshotPipelineResourcesV1 {
            let resource_policy = SnapshotResourcePolicyV1::checked(
                2,
                NonZeroU32::new(entries).unwrap(),
                NonZeroU16::new(64).unwrap(),
                1024,
                1024,
                1024 * 1024,
                4 * 1024 * 1024,
                8,
                u64::from(entries) * 8,
                4,
                u64::from(entries) * 4,
                64,
                1024,
                4096,
                64 * 1024,
                NonZeroU64::new(8 * 1024 * 1024).unwrap(),
                0,
                transient_heap_bytes,
                NonZeroU64::new(operation_attempts).unwrap(),
                NonZeroU8::new(4).unwrap(),
                NonZeroU8::new(3).unwrap(),
                NonZeroU8::new(2).unwrap(),
            )
            .unwrap();
            SnapshotPipelineResourcesV1::preflight(resource_policy, 0, u64::MAX, u64::MAX).unwrap()
        }

        fn charged_leaf_errno(error: SnapshotChargedErrorV1<io::Error>) -> Option<i32> {
            match error {
                SnapshotChargedErrorV1::Leaf(error) => error.raw_os_error(),
                SnapshotChargedErrorV1::PublicationAlreadyStarted => None,
                SnapshotChargedErrorV1::Resource(_) => None,
            }
        }

        #[test]
        fn charged_creation_consumes_exactly_seven_forward_attempts() {
            let fixture = Fixture::new();
            // Four entries reserve 272 publisher-cleanup attempts and ten
            // leaf-local attempts; charged creation consumes seven forward.
            let connector = charged_connector(279 + LOCAL_REGULAR_CLEANUP_RESERVE, 1024 * 1024);
            let staged = connector
                .create_staged_snapshot_directory_at(fixture.parent.as_fd(), STAGING)
                .unwrap();
            let authority = &staged.cleanup.authority;
            assert_eq!(
                authority.remaining_attempts(PublisherAttemptBucketV1::Forward),
                Some(0)
            );
            drop(staged);
            assert!(!fixture.staging_path().exists());
        }

        #[test]
        fn charged_stage_reserves_the_exact_child_bind_ceiling_before_sealing() {
            let fixture = Fixture::new();
            let connector = charged_connector(1_000_000, 1024 * 1024);
            let staged = connector
                .create_staged_snapshot_directory_at(fixture.parent.as_fd(), STAGING)
                .unwrap();
            let authority = &staged.cleanup.authority;
            let before = authority
                .remaining_attempts(PublisherAttemptBucketV1::Forward)
                .unwrap();
            let exact = u64::from(staged.cleanup.policy().openat2_attempts()) + 2;
            let fstats_before = DIRECTORY_FSTAT_CALLS.with(|calls| calls.get());
            PUBLISHED_CHILD_STATX_CALLS.with(|calls| calls.set(0));

            let reservation = staged.reserve_published_child_bind_attempts().unwrap();

            assert_eq!(
                authority.remaining_attempts(PublisherAttemptBucketV1::Forward),
                Some(before - exact)
            );
            assert_eq!(
                DIRECTORY_FSTAT_CALLS.with(|calls| calls.get()),
                fstats_before
            );
            assert_eq!(PUBLISHED_CHILD_STATX_CALLS.with(|calls| calls.get()), 0);
            assert_eq!(
                fs::metadata(fixture.staging_path())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777,
                PRIVATE_DIRECTORY_MODE
            );
            assert!(!fixture.final_path().exists());

            drop(reservation);
            assert_eq!(
                authority.remaining_attempts(PublisherAttemptBucketV1::Forward),
                Some(before)
            );
            drop(staged);
            assert!(!fixture.staging_path().exists());
        }

        #[test]
        fn zero_forward_budget_refuses_before_the_first_kernel_attempt() {
            // Four entries reserve exactly 272 publisher-cleanup attempts plus
            // the disjoint leaf-local reserve and leave no forward attempt.
            let fixture = Fixture::new();
            let connector = charged_connector(272 + LOCAL_REGULAR_CLEANUP_RESERVE, 1024 * 1024);
            DIRECTORY_FSTAT_CALLS.with(|calls| calls.set(0));
            let error = connector
                .create_staged_snapshot_directory_at(fixture.parent.as_fd(), STAGING)
                .err()
                .unwrap();
            assert_eq!(
                error,
                SnapshotChargedErrorV1::Resource(
                    SnapshotPipelineResourceErrorV1::OperationBudgetExhausted {
                        stage: SnapshotPipelineStageV1::Forward(
                            SnapshotPipelineForwardStageV1::Publication,
                        ),
                        bucket: SnapshotPipelineAttemptBucketV1::Forward,
                    },
                )
            );
            assert_eq!(DIRECTORY_FSTAT_CALLS.with(|calls| calls.get()), 0);
            assert!(!fixture.staging_path().exists());
        }

        #[test]
        fn exhaustion_immediately_after_mkdir_uses_only_cleanup_reserve() {
            let fixture = Fixture::new();
            // Parent fstat/statx/geteuid plus mkdir consume four forward
            // attempts. The openat2 charge then refuses before its raw hook.
            let connector = charged_connector(276 + LOCAL_REGULAR_CLEANUP_RESERVE, 1024 * 1024);
            let error = connector
                .create_staged_snapshot_directory_at(fixture.parent.as_fd(), STAGING)
                .err()
                .unwrap();
            assert!(matches!(error, SnapshotChargedErrorV1::Resource(_)));
            assert!(!fixture.staging_path().exists());
        }

        #[test]
        fn charged_retries_are_exact_and_attempt_buckets_are_disjoint() {
            let fixture = Fixture::new();
            let connector = charged_connector(1_000_000, 1024 * 1024);
            let staged = connector
                .create_staged_snapshot_directory_at(fixture.parent.as_fd(), STAGING)
                .unwrap();
            let authority = &staged.cleanup.authority;
            let forward_before = authority
                .remaining_attempts(PublisherAttemptBucketV1::Forward)
                .unwrap();
            let cleanup_before = authority
                .remaining_attempts(PublisherAttemptBucketV1::Cleanup)
                .unwrap();

            let mut raw_calls = 0;
            let error =
                retry_eintr_zero_charged(authority, PublisherAttemptBucketV1::Forward, 3, || {
                    raw_calls += 1;
                    unsafe { *libc::__errno_location() = libc::EINTR };
                    -1
                })
                .unwrap_err();
            assert_eq!(charged_leaf_errno(error), Some(libc::EINTR));
            assert_eq!(raw_calls, 3);
            assert_eq!(
                authority.remaining_attempts(PublisherAttemptBucketV1::Forward),
                Some(forward_before - 3)
            );
            assert_eq!(
                authority.remaining_attempts(PublisherAttemptBucketV1::Cleanup),
                Some(cleanup_before)
            );

            retry_eintr_zero_charged(authority, PublisherAttemptBucketV1::Cleanup, 1, || 0)
                .unwrap();
            assert_eq!(
                authority.remaining_attempts(PublisherAttemptBucketV1::Forward),
                Some(forward_before - 3)
            );
            assert_eq!(
                authority.remaining_attempts(PublisherAttemptBucketV1::Cleanup),
                Some(cleanup_before - 1)
            );
            drop(staged);
            assert!(!fixture.staging_path().exists());
        }

        #[test]
        fn charged_drop_cleans_many_siblings_nested_read_only_tree_from_exact_operation_reserve() {
            const ENTRIES: u32 = 66;
            const OPEN_ATTEMPTS: u64 = 4;
            const SYSCALL_ATTEMPTS: u64 = 3;
            let cleanup_reserve = (5 * u64::from(ENTRIES) + 3) * OPEN_ATTEMPTS
                + (12 * u64::from(ENTRIES) + 12) * SYSCALL_ATTEMPTS;
            let fixture = Fixture::new();
            let connector = charged_connector_with_entries(
                cleanup_reserve + LOCAL_REGULAR_CLEANUP_RESERVE + 7,
                1024 * 1024,
                ENTRIES,
            );
            let staged = connector
                .create_staged_snapshot_directory_at(fixture.parent.as_fd(), STAGING)
                .unwrap();
            assert_eq!(
                staged
                    .cleanup
                    .authority
                    .remaining_attempts(PublisherAttemptBucketV1::Forward),
                Some(0)
            );
            assert_eq!(
                staged
                    .cleanup
                    .authority
                    .remaining_attempts(PublisherAttemptBucketV1::Cleanup),
                Some(cleanup_reserve)
            );

            // Sixty-three files plus the read-only directory make 64 root
            // siblings. Its nested directory and file bring the exact charged
            // cleanup entry count to 66 and force repeated two-name rescans.
            for index in 0..63 {
                fs::write(
                    fixture.staging_path().join(format!("batch-{index:02}")),
                    b"content",
                )
                .unwrap();
            }
            populate_read_only_tree(&fixture.staging_path());

            drop(staged);
            assert!(!fixture.staging_path().exists());
        }

        #[test]
        fn charged_byte_capacity_is_released_only_after_storage_drop() {
            let fixture = Fixture::new();
            let connector = charged_connector(1_000_000, 1024 * 1024);
            let staged = connector
                .create_staged_snapshot_directory_at(fixture.parent.as_fd(), STAGING)
                .unwrap();
            let authority = &staged.cleanup.authority;

            let forward_error = PublisherBytesV1::charged_for(
                authority,
                PublisherAttemptBucketV1::Forward,
                1_100_000,
            )
            .err()
            .unwrap();
            assert!(matches!(
                forward_error,
                SnapshotChargedErrorV1::Resource(
                    SnapshotPipelineResourceErrorV1::TransientHeapCapacityExceeded {
                        stage: SnapshotPipelineStageV1::Forward(
                            SnapshotPipelineForwardStageV1::Publication
                        ),
                        ..
                    }
                )
            ));
            let cleanup_error = PublisherBytesV1::charged_for(
                authority,
                PublisherAttemptBucketV1::Cleanup,
                1_100_000,
            )
            .err()
            .unwrap();
            assert!(matches!(
                cleanup_error,
                SnapshotChargedErrorV1::Resource(
                    SnapshotPipelineResourceErrorV1::TransientHeapCapacityExceeded {
                        stage: SnapshotPipelineStageV1::Cleanup,
                        ..
                    }
                )
            ));

            let first = PublisherBytesV1::charged_for(
                authority,
                PublisherAttemptBucketV1::Cleanup,
                600_000,
            )
            .unwrap();
            assert!(matches!(
                PublisherBytesV1::charged_for(
                    authority,
                    PublisherAttemptBucketV1::Cleanup,
                    600_000,
                ),
                Err(SnapshotChargedErrorV1::Resource(_))
            ));
            drop(first);
            let replacement = PublisherBytesV1::charged_for(
                authority,
                PublisherAttemptBucketV1::Cleanup,
                600_000,
            )
            .unwrap();
            drop(replacement);
            drop(staged);
            assert!(!fixture.staging_path().exists());
        }

        fn open_directory(path: &Path) -> File {
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
                .open(path)
                .unwrap()
        }

        fn populate_read_only_tree(staging_path: &Path) {
            let outer = staging_path.join("read-only");
            let inner = outer.join("owner-search-only");
            fs::create_dir_all(&inner).unwrap();
            fs::write(inner.join("content"), b"content").unwrap();
            fs::set_permissions(&inner, fs::Permissions::from_mode(0o500)).unwrap();
            fs::set_permissions(&outer, fs::Permissions::from_mode(0o555)).unwrap();
        }

        struct Fixture {
            temp: TempDir,
            parent: File,
        }

        impl Drop for Fixture {
            fn drop(&mut self) {
                make_fixture_tree_removable(self.temp.path());
            }
        }

        impl Fixture {
            fn new() -> Self {
                let temp = TempDir::new().unwrap();
                fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
                let parent = open_directory(temp.path());
                Self { temp, parent }
            }

            fn path(&self, name: &CStr) -> PathBuf {
                self.temp.path().join(OsStr::from_bytes(name.to_bytes()))
            }

            fn staging_path(&self) -> PathBuf {
                self.path(STAGING)
            }

            fn final_path(&self) -> PathBuf {
                self.path(FINAL)
            }

            fn stage(&self) -> StagedSnapshotDirectoryV1<'_> {
                create_staged_snapshot_directory_at(self.parent.as_fd(), STAGING, policy()).unwrap()
            }

            fn publish_empty(&self) -> PublishedSnapshotDirectoryV1 {
                self.stage()
                    .verify_ready_with(|_| Ok(()))
                    .unwrap()
                    .publish_at(FINAL)
                    .unwrap()
            }

            fn publish_root(&self) -> PublishedSnapshotDirectoryV1 {
                let staged = self.stage();
                fs::create_dir(self.staging_path().join(OsStr::from_bytes(ROOT.to_bytes())))
                    .unwrap();
                staged
                    .verify_ready_with(|_| Ok(()))
                    .unwrap()
                    .publish_at(FINAL)
                    .unwrap()
            }
        }

        fn make_fixture_tree_removable(path: &Path) {
            let Ok(metadata) = fs::symlink_metadata(path) else {
                return;
            };
            if !metadata.file_type().is_dir() {
                return;
            }
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
            let Ok(entries) = fs::read_dir(path) else {
                return;
            };
            for entry in entries.flatten() {
                make_fixture_tree_removable(&entry.path());
            }
        }

        fn published_child_commitment(
            published: &PublishedSnapshotDirectoryV1,
            child_name: &CStr,
        ) -> [u8; 102] {
            let child = unmetered_leaf(open_path_at_with_gate(
                published.directory(),
                child_name,
                published.openat2_attempts,
                &UnmeteredPublisherAttemptGateV1,
            ))
            .unwrap();
            unmetered_leaf(published_child_statx_with_gate(
                child.as_fd(),
                &UnmeteredPublisherAttemptGateV1,
            ))
            .unwrap()
            .commitment_bytes_v1()
        }

        fn publish_bound_tree(
            fixture: &Fixture,
            populate: impl FnOnce(&Path),
        ) -> BoundPublishedSnapshotChildV1 {
            let staged = fixture.stage();
            let root = fixture
                .staging_path()
                .join(OsStr::from_bytes(ROOT.to_bytes()));
            fs::create_dir(&root).unwrap();
            populate(&root);
            let published = staged
                .verify_ready_with(|_| Ok(()))
                .unwrap()
                .publish_at(FINAL)
                .unwrap();
            let expected = published_child_commitment(&published, ROOT);
            let resources = charged_resources_with_entries(1_000_000, 1024 * 1024, 4);
            let reservation = resources
                .reserve_published_child_bind_attempts(
                    policy().published_child_bind_operation_attempt_bound(),
                )
                .unwrap();
            bind_published_snapshot_child_at(published, ROOT, expected, reservation).unwrap()
        }

        fn bind_leaf(error: SnapshotPublishedChildBindErrorV1) -> SnapshotPublishErrorV1 {
            assert_eq!(
                error.publication_state(),
                SnapshotPublicationStateV1::PublishedDurable
            );
            match error.failure() {
                SnapshotPublishedChildBindFailureV1::Leaf(error) => error,
                SnapshotPublishedChildBindFailureV1::Resource(error) => {
                    panic!("expected leaf failure, got {error:?}")
                }
            }
        }

        struct FailAt {
            stage: SnapshotPublishStageV1,
        }

        impl TransitionHookV1 for FailAt {
            fn checkpoint(&mut self, stage: SnapshotPublishStageV1) -> io::Result<()> {
                if stage == self.stage {
                    Err(io::Error::from_raw_os_error(libc::EIO))
                } else {
                    Ok(())
                }
            }
        }

        #[derive(Clone, Copy)]
        enum InterruptedRenameV1 {
            NoEffectThenSuccess,
            EffectThenInterrupt,
            AlwaysNoEffect,
            NoEffectIo,
            EffectThenIo,
        }

        struct InterruptRename {
            behavior: InterruptedRenameV1,
            calls: u8,
        }

        impl TransitionHookV1 for InterruptRename {
            fn rename_noreplace(
                &mut self,
                old_parent: BorrowedFd<'_>,
                old_name: &CStr,
                new_parent: BorrowedFd<'_>,
                new_name: &CStr,
            ) -> io::Result<()> {
                self.calls += 1;
                match self.behavior {
                    InterruptedRenameV1::NoEffectThenSuccess if self.calls > 1 => {
                        rename_noreplace_at(old_parent, old_name, new_parent, new_name)
                    }
                    InterruptedRenameV1::EffectThenInterrupt
                    | InterruptedRenameV1::EffectThenIo => {
                        rename_noreplace_at(old_parent, old_name, new_parent, new_name)?;
                        let errno = if matches!(self.behavior, InterruptedRenameV1::EffectThenIo) {
                            libc::EIO
                        } else {
                            libc::EINTR
                        };
                        Err(io::Error::from_raw_os_error(errno))
                    }
                    InterruptedRenameV1::NoEffectThenSuccess
                    | InterruptedRenameV1::AlwaysNoEffect => {
                        Err(io::Error::from_raw_os_error(libc::EINTR))
                    }
                    InterruptedRenameV1::NoEffectIo => Err(io::Error::from_raw_os_error(libc::EIO)),
                }
            }
        }

        struct SealEffectThenInterrupt {
            calls: u8,
        }

        impl TransitionHookV1 for SealEffectThenInterrupt {
            fn seal_directory(&mut self, directory: BorrowedFd<'_>) -> io::Result<()> {
                self.calls += 1;
                if self.calls == 1 {
                    let result = unsafe {
                        libc::fchmod(directory.as_raw_fd(), SEALED_DIRECTORY_MODE as libc::mode_t)
                    };
                    if result != 0 {
                        return Err(io::Error::last_os_error());
                    }
                }
                Err(io::Error::from_raw_os_error(libc::EINTR))
            }
        }

        struct ReplaceAtPublishCheckpoint {
            parent_path: PathBuf,
        }

        impl TransitionHookV1 for ReplaceAtPublishCheckpoint {
            fn checkpoint(&mut self, stage: SnapshotPublishStageV1) -> io::Result<()> {
                if stage != SnapshotPublishStageV1::PublishRename {
                    return Ok(());
                }
                let staging = self.parent_path.join(OsStr::from_bytes(STAGING.to_bytes()));
                fs::rename(&staging, self.parent_path.join("moved-original"))?;
                fs::create_dir(&staging)?;
                fs::write(staging.join("replacement"), b"preserved")?;
                fs::set_permissions(&staging, fs::Permissions::from_mode(SEALED_DIRECTORY_MODE))
            }
        }

        #[test]
        fn charged_finalization_seals_exactly_and_reconciles_effected_rename() {
            let fixture = Fixture::new();
            let connector = charged_connector(1_000_000, 1024 * 1024);
            let staged = connector
                .create_staged_snapshot_directory_at(fixture.parent.as_fd(), STAGING)
                .unwrap();
            fs::create_dir(fixture.staging_path().join("root")).unwrap();
            let mut interrupt = InterruptRename {
                behavior: InterruptedRenameV1::EffectThenInterrupt,
                calls: 0,
            };
            FINALIZATION_ATTEMPT_CHARGES.with(|calls| calls.set(0));

            let published =
                seal_and_publish_charged_with_transitions(staged, FINAL, &mut interrupt).unwrap();

            assert_eq!(interrupt.calls, 1);
            // Three one-open revalidations cost five charges each. Seal and
            // staging fsync cost two; effected-rename reconciliation costs
            // four; parent fsync, final reopen, and two identities cost six.
            assert_eq!(
                FINALIZATION_ATTEMPT_CHARGES.with(|calls| calls.get()),
                3 * 5 + 2 + 4 + 6
            );
            assert!(!fixture.staging_path().exists());
            assert!(fixture.final_path().is_dir());
            assert!(fixture.final_path().join("root").is_dir());
            assert_eq!(
                fs::metadata(fixture.final_path())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777,
                SEALED_DIRECTORY_MODE
            );
            assert_eq!(
                directory_identity(published.directory()).unwrap().mode & 0o7777,
                SEALED_DIRECTORY_MODE
            );
        }

        #[test]
        fn charged_seal_effect_then_eintr_cleans_the_same_sealed_stage() {
            let fixture = Fixture::new();
            let connector = charged_connector(1_000_000, 1024 * 1024);
            let staged = connector
                .create_staged_snapshot_directory_at(fixture.parent.as_fd(), STAGING)
                .unwrap();
            let mut interrupt = SealEffectThenInterrupt { calls: 0 };

            let error = seal_and_publish_charged_with_transitions(staged, FINAL, &mut interrupt)
                .err()
                .unwrap();
            let SnapshotChargedErrorV1::Leaf(error) = error else {
                panic!("seal failure must remain a publication-leaf error");
            };
            assert_eq!(interrupt.calls, 3);
            assert_eq!(error.stage(), SnapshotPublishStageV1::SealStaging);
            assert_eq!(error.errno(), Some(libc::EINTR));
            assert_eq!(
                error.publication_state(),
                SnapshotPublicationStateV1::Unpublished
            );
            assert!(!fixture.staging_path().exists());
            assert!(!fixture.final_path().exists());
        }

        #[test]
        fn charged_post_fsync_revalidation_never_publishes_or_deletes_a_replacement() {
            let fixture = Fixture::new();
            let connector = charged_connector(1_000_000, 1024 * 1024);
            let staged = connector
                .create_staged_snapshot_directory_at(fixture.parent.as_fd(), STAGING)
                .unwrap();
            let moved_original = fixture.temp.path().join("moved-original");
            let mut replacement = ReplaceAtPublishCheckpoint {
                parent_path: fixture.temp.path().to_owned(),
            };

            let error = seal_and_publish_charged_with_transitions(staged, FINAL, &mut replacement)
                .err()
                .unwrap();
            let SnapshotChargedErrorV1::Leaf(error) = error else {
                panic!("post-fsync identity drift must remain a publication-leaf error");
            };
            assert_eq!(error.kind(), SnapshotPublishErrorKindV1::IdentityMismatch);
            assert_eq!(error.stage(), SnapshotPublishStageV1::RevalidateStaging);
            assert_eq!(
                error.publication_state(),
                SnapshotPublicationStateV1::Unpublished
            );
            assert!(moved_original.is_dir());
            assert_eq!(
                fs::metadata(&moved_original).unwrap().permissions().mode() & 0o7777,
                SEALED_DIRECTORY_MODE
            );
            assert_eq!(
                fs::read(fixture.staging_path().join("replacement")).unwrap(),
                b"preserved"
            );
            assert_eq!(
                fs::metadata(fixture.staging_path())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777,
                SEALED_DIRECTORY_MODE
            );
            assert!(!fixture.final_path().exists());
        }

        #[test]
        fn charged_seal_checkpoint_and_post_rename_failure_report_exact_states() {
            let before_seal = Fixture::new();
            let connector = charged_connector(1_000_000, 1024 * 1024);
            let staged = connector
                .create_staged_snapshot_directory_at(before_seal.parent.as_fd(), STAGING)
                .unwrap();
            let mut fault = FailAt {
                stage: SnapshotPublishStageV1::SealStaging,
            };
            let error = seal_and_publish_charged_with_transitions(staged, FINAL, &mut fault)
                .err()
                .unwrap();
            let SnapshotChargedErrorV1::Leaf(error) = error else {
                panic!("checkpoint failure must remain a publication-leaf error");
            };
            assert_eq!(error.stage(), SnapshotPublishStageV1::SealStaging);
            assert_eq!(
                error.publication_state(),
                SnapshotPublicationStateV1::Unpublished
            );
            assert!(!before_seal.staging_path().exists());
            assert!(!before_seal.final_path().exists());

            let after_rename = Fixture::new();
            let connector = charged_connector(1_000_000, 1024 * 1024);
            let staged = connector
                .create_staged_snapshot_directory_at(after_rename.parent.as_fd(), STAGING)
                .unwrap();
            let mut fault = FailAt {
                stage: SnapshotPublishStageV1::SyncParent,
            };
            let error = seal_and_publish_charged_with_transitions(staged, FINAL, &mut fault)
                .err()
                .unwrap();
            let SnapshotChargedErrorV1::Leaf(error) = error else {
                panic!("post-rename failure must remain a publication-leaf error");
            };
            assert_eq!(error.stage(), SnapshotPublishStageV1::SyncParent);
            assert_eq!(
                error.publication_state(),
                SnapshotPublicationStateV1::PublishedDurabilityUnknown
            );
            assert!(!after_rename.staging_path().exists());
            assert!(after_rename.final_path().is_dir());
            assert_eq!(
                fs::metadata(after_rename.final_path())
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777,
                SEALED_DIRECTORY_MODE
            );

            let after_parent_sync = Fixture::new();
            let connector = charged_connector(1_000_000, 1024 * 1024);
            let staged = connector
                .create_staged_snapshot_directory_at(after_parent_sync.parent.as_fd(), STAGING)
                .unwrap();
            let mut fault = FailAt {
                stage: SnapshotPublishStageV1::ReopenPublished,
            };
            let error = seal_and_publish_charged_with_transitions(staged, FINAL, &mut fault)
                .err()
                .unwrap();
            let SnapshotChargedErrorV1::Leaf(error) = error else {
                panic!("durable publication failure must remain a publication-leaf error");
            };
            assert_eq!(error.stage(), SnapshotPublishStageV1::ReopenPublished);
            assert_eq!(
                error.publication_state(),
                SnapshotPublicationStateV1::PublishedDurable
            );
            assert!(!after_parent_sync.staging_path().exists());
            assert!(after_parent_sync.final_path().is_dir());
        }

        #[test]
        fn every_legacy_transition_has_a_deterministic_fail_closed_checkpoint() {
            for (index, stage) in SnapshotPublishStageV1::LEGACY_TRANSITIONS
                .into_iter()
                .enumerate()
            {
                let fixture = Fixture::new();
                let mut fault = FailAt { stage };
                let staged = create_staged_snapshot_directory_with(
                    fixture.parent.as_fd(),
                    STAGING,
                    policy(),
                    &mut fault,
                );
                if index < CREATE_TRANSITION_COUNT {
                    let error = staged.err().unwrap();
                    assert_eq!(error.stage(), stage);
                    assert_eq!(
                        error.publication_state(),
                        SnapshotPublicationStateV1::Unpublished
                    );
                    assert!(!fixture.staging_path().exists());
                    continue;
                }
                let staged = staged.unwrap();
                let ready = staged.verify_ready_with_transitions(|_| Ok(()), &mut fault);
                if index < CREATE_TRANSITION_COUNT + READY_TRANSITION_COUNT {
                    let error = ready.unwrap_err();
                    assert_eq!(error.stage(), stage);
                    assert_eq!(
                        error.publication_state(),
                        SnapshotPublicationStateV1::Unpublished
                    );
                    assert!(!fixture.staging_path().exists());
                    continue;
                }
                let ready = ready.unwrap();
                let published = ready.publish_at_with_transitions(FINAL, &mut fault);
                let error = published.err().unwrap();
                assert_eq!(error.stage(), stage);
                if matches!(
                    stage,
                    SnapshotPublishStageV1::ValidateFinalName
                        | SnapshotPublishStageV1::PublishRename
                ) {
                    assert_eq!(
                        error.publication_state(),
                        SnapshotPublicationStateV1::Unpublished
                    );
                    assert!(!fixture.final_path().exists());
                } else {
                    assert!(fixture.final_path().is_dir());
                }
            }
        }

        #[test]
        fn staging_and_final_collisions_preserve_the_existing_entries() {
            let fixture = Fixture::new();
            let staging_path = fixture.staging_path();
            fs::create_dir(&staging_path).unwrap();
            let error =
                create_staged_snapshot_directory_at(fixture.parent.as_fd(), STAGING, policy())
                    .err()
                    .unwrap();
            assert_eq!(error.kind(), SnapshotPublishErrorKindV1::StagingCollision);
            assert!(staging_path.is_dir());

            fs::remove_dir(&staging_path).unwrap();
            let final_path = fixture.final_path();
            fs::create_dir(&final_path).unwrap();
            fs::write(final_path.join("existing"), b"keep").unwrap();
            let staged = fixture.stage();
            populate_read_only_tree(&staging_path);
            let error = staged
                .verify_ready_with(|_| Ok(()))
                .unwrap()
                .publish_at(FINAL)
                .err()
                .unwrap();
            assert_eq!(error.kind(), SnapshotPublishErrorKindV1::FinalCollision);
            assert_eq!(fs::read(final_path.join("existing")).unwrap(), b"keep");
            assert!(!staging_path.exists());
        }

        #[test]
        fn staged_directory_exposes_its_exact_cleanup_envelope() {
            let fixture = Fixture::new();
            let cleanup_policy = SnapshotPublishPolicyV1::checked(
                NonZeroU8::new(2).unwrap(),
                NonZeroU8::new(3).unwrap(),
                7,
                NonZeroU32::new(11).unwrap(),
                NonZeroU16::new(13).unwrap(),
                NonZeroU64::new(64 * 1024).unwrap(),
            )
            .unwrap();
            let staged = create_staged_snapshot_directory_at(
                fixture.parent.as_fd(),
                STAGING,
                cleanup_policy,
            )
            .unwrap();
            let envelope = staged.cleanup_envelope();

            assert_eq!(envelope.max_source_tree_depth(), 7);
            assert_eq!(envelope.max_entries(), 11);
            assert_eq!(envelope.max_basename_bytes(), 13);
            assert_eq!(envelope.openat2_attempts(), 2);
            assert_eq!(envelope.generic_syscall_attempts(), 3);
        }

        #[test]
        fn replacement_of_the_staging_name_is_detected_and_never_deleted() {
            let fixture = Fixture::new();
            let staging_path = fixture.staging_path();
            let moved_path = fixture.temp.path().join("moved-original");
            let error = fixture
                .stage()
                .verify_ready_with(|_| {
                    fs::rename(&staging_path, &moved_path)?;
                    fs::create_dir(&staging_path)?;
                    fs::write(staging_path.join("replacement"), b"survives")?;
                    fs::set_permissions(&staging_path, fs::Permissions::from_mode(0o500))?;
                    Ok(())
                })
                .unwrap_err();
            assert_eq!(error.kind(), SnapshotPublishErrorKindV1::IdentityMismatch);
            assert_eq!(
                fs::read(staging_path.join("replacement")).unwrap(),
                b"survives"
            );
            assert_eq!(
                fs::metadata(&staging_path).unwrap().permissions().mode() & 0o7777,
                0o500
            );
            assert!(moved_path.is_dir());
        }

        #[test]
        fn injected_staging_fsync_and_rename_failures_cleanup_recursively() {
            for stage in [
                SnapshotPublishStageV1::SyncStaging,
                SnapshotPublishStageV1::PublishRename,
            ] {
                let fixture = Fixture::new();
                let staging_path = fixture.staging_path();
                let staged = fixture.stage();
                fs::create_dir(staging_path.join("nested")).unwrap();
                fs::write(staging_path.join("nested/file"), b"content").unwrap();
                for index in 0..CLEANUP_STRESS_NAME_COUNT {
                    fs::write(
                        staging_path.join("nested").join(format!("batch-{index}")),
                        b"content",
                    )
                    .unwrap();
                }
                fs::write(
                    staging_path
                        .join("nested")
                        .join(OsStr::from_bytes(b"raw-\xff")),
                    b"raw",
                )
                .unwrap();
                symlink("nested/file", staging_path.join("link")).unwrap();
                let mut fault = FailAt { stage };
                if stage == SnapshotPublishStageV1::SyncStaging {
                    let error = staged
                        .verify_ready_with_transitions(|_| Ok(()), &mut fault)
                        .unwrap_err();
                    assert_eq!(error.stage(), stage);
                } else {
                    let ready = staged.verify_ready_with(|_| Ok(())).unwrap();
                    let error = ready
                        .publish_at_with_transitions(FINAL, &mut fault)
                        .err()
                        .unwrap();
                    assert_eq!(error.stage(), stage);
                }
                assert!(!staging_path.exists());
                assert!(!fixture.final_path().exists());
            }
        }

        #[test]
        fn cleanup_depth_accepts_the_tree_limit_and_rejects_one_more_level() {
            let fixture = Fixture::new();
            let staged = fixture.stage();
            let mut deepest = fixture.staging_path();
            for _ in 0..=HARD_MAX_CLEANUP_DEPTH {
                deepest.push("d");
                fs::create_dir(&deepest).unwrap();
            }

            let mut cleanup = staged.cleanup;
            assert_eq!(
                charged_leaf_errno(cleanup.remove_current().unwrap_err()),
                Some(libc::ELOOP)
            );
            assert!(fixture.staging_path().is_dir());

            fs::remove_dir(&deepest).unwrap();
            cleanup.remove_current().unwrap();
            assert!(!fixture.staging_path().exists());
        }

        #[test]
        fn cleanup_entry_name_and_retained_byte_limits_are_inclusive() {
            let exact_entries = Fixture::new();
            let mut staged = exact_entries.stage();
            staged.cleanup.policy_mut().max_cleanup_entries = NonZeroU32::new(2).unwrap();
            fs::write(exact_entries.staging_path().join("a"), b"a").unwrap();
            fs::write(exact_entries.staging_path().join("b"), b"b").unwrap();
            staged.cleanup.remove_current().unwrap();
            assert!(!exact_entries.staging_path().exists());

            let excess_entries = Fixture::new();
            let mut staged = excess_entries.stage();
            staged.cleanup.policy_mut().max_cleanup_entries = NonZeroU32::new(2).unwrap();
            for name in ["a", "b", "c"] {
                fs::write(excess_entries.staging_path().join(name), name).unwrap();
            }
            assert_eq!(
                charged_leaf_errno(staged.cleanup.remove_current().unwrap_err()),
                Some(libc::E2BIG)
            );
            assert!(excess_entries.staging_path().is_dir());

            let exact_name = Fixture::new();
            let mut staged = exact_name.stage();
            staged.cleanup.policy_mut().max_cleanup_name_bytes = NonZeroU16::new(4).unwrap();
            fs::write(exact_name.staging_path().join("1234"), b"exact").unwrap();
            staged.cleanup.remove_current().unwrap();
            assert!(!exact_name.staging_path().exists());

            let excess_name = Fixture::new();
            let mut staged = excess_name.stage();
            staged.cleanup.policy_mut().max_cleanup_name_bytes = NonZeroU16::new(4).unwrap();
            fs::write(excess_name.staging_path().join("12345"), b"excess").unwrap();
            assert_eq!(
                charged_leaf_errno(staged.cleanup.remove_current().unwrap_err()),
                Some(libc::ENAMETOOLONG)
            );
            assert!(excess_name.staging_path().join("12345").is_file());

            let mut retained_policy = policy();
            retained_policy.max_cleanup_entries = NonZeroU32::new(2).unwrap();
            retained_policy.max_cleanup_retained_name_bytes = NonZeroU64::new(10).unwrap();
            let mut budget = CleanupBudgetV1::new();
            budget.retain_batch(retained_policy, 1, 10).unwrap();
            assert_eq!(budget.retained_name_bytes, 10);
            budget.release_batch(10);
            assert_eq!(budget.retained_name_bytes, 0);
            assert_eq!(
                budget
                    .retain_batch(retained_policy, 1, 11)
                    .unwrap_err()
                    .raw_os_error(),
                Some(libc::E2BIG)
            );
            assert_eq!(budget.entries_seen, 1);
        }

        #[test]
        fn raw_getdents_attempts_cover_chain_two_name_batch_and_exact_refusal() {
            let one_directory = Fixture::new();
            let mut staged = one_directory.stage();
            staged.cleanup.policy_mut().max_cleanup_getdents_attempts = 4;
            fs::create_dir(one_directory.staging_path().join("child")).unwrap();
            staged.cleanup.remove_current().unwrap();
            assert_eq!(staged.cleanup.cleanup_budget.getdents_attempts_seen, 4);

            let exhausted = Fixture::new();
            let mut staged = exhausted.stage();
            staged.cleanup.policy_mut().max_cleanup_getdents_attempts = 3;
            fs::create_dir(exhausted.staging_path().join("child")).unwrap();
            assert_eq!(
                charged_leaf_errno(staged.cleanup.remove_current().unwrap_err()),
                Some(libc::E2BIG)
            );
            assert!(exhausted.staging_path().is_dir());

            let two_name_batch = Fixture::new();
            let mut staged = two_name_batch.stage();
            for index in 0..CLEANUP_NAME_BATCH_SIZE {
                fs::create_dir(
                    two_name_batch
                        .staging_path()
                        .join(format!("dir-{index:02}")),
                )
                .unwrap();
            }
            staged.cleanup.remove_current().unwrap();
            assert_eq!(
                staged.cleanup.cleanup_budget.getdents_attempts_seen,
                2 * CLEANUP_NAME_BATCH_SIZE as u64 + 3
            );
        }

        #[test]
        fn parent_fsync_failure_reports_ambiguous_publication_and_keeps_final_name() {
            let fixture = Fixture::new();
            let ready = fixture.stage().verify_ready_with(|_| Ok(())).unwrap();
            let mut fault = FailAt {
                stage: SnapshotPublishStageV1::SyncParent,
            };
            let error = ready
                .publish_at_with_transitions(FINAL, &mut fault)
                .err()
                .unwrap();
            assert_eq!(
                error.publication_state(),
                SnapshotPublicationStateV1::PublishedDurabilityUnknown
            );
            assert!(fixture.final_path().is_dir());
        }

        #[test]
        fn rename_interruption_reconciles_no_effect_effect_and_exhaustion() {
            let no_effect = Fixture::new();
            let ready = no_effect.stage().verify_ready_with(|_| Ok(())).unwrap();
            let mut interrupt = InterruptRename {
                behavior: InterruptedRenameV1::NoEffectThenSuccess,
                calls: 0,
            };
            ready
                .publish_at_with_transitions(FINAL, &mut interrupt)
                .unwrap();
            assert_eq!(interrupt.calls, 2);
            assert!(no_effect.final_path().is_dir());
            assert!(!no_effect.staging_path().exists());

            let effected = Fixture::new();
            let ready = effected.stage().verify_ready_with(|_| Ok(())).unwrap();
            let mut interrupt = InterruptRename {
                behavior: InterruptedRenameV1::EffectThenInterrupt,
                calls: 0,
            };
            ready
                .publish_at_with_transitions(FINAL, &mut interrupt)
                .unwrap();
            assert_eq!(interrupt.calls, 1);
            assert!(effected.final_path().is_dir());
            assert!(!effected.staging_path().exists());

            let exhausted = Fixture::new();
            let mut ready = exhausted.stage().verify_ready_with(|_| Ok(())).unwrap();
            ready.cleanup.policy_mut().syscall_attempts = NonZeroU8::new(3).unwrap();
            let mut interrupt = InterruptRename {
                behavior: InterruptedRenameV1::AlwaysNoEffect,
                calls: 0,
            };
            let error = ready
                .publish_at_with_transitions(FINAL, &mut interrupt)
                .err()
                .unwrap();
            assert_eq!(interrupt.calls, 3);
            assert_eq!(error.errno(), Some(libc::EINTR));
            assert_eq!(
                error.publication_state(),
                SnapshotPublicationStateV1::Unpublished
            );
            assert!(!exhausted.staging_path().exists());
            assert!(!exhausted.final_path().exists());
        }

        #[test]
        fn rename_io_error_reconciles_no_effect_and_committed_effect() {
            let no_effect = Fixture::new();
            let ready = no_effect.stage().verify_ready_with(|_| Ok(())).unwrap();
            let mut failure = InterruptRename {
                behavior: InterruptedRenameV1::NoEffectIo,
                calls: 0,
            };
            let error = ready
                .publish_at_with_transitions(FINAL, &mut failure)
                .err()
                .unwrap();
            assert_eq!(failure.calls, 1);
            assert_eq!(error.errno(), Some(libc::EIO));
            assert_eq!(
                error.publication_state(),
                SnapshotPublicationStateV1::Unpublished
            );
            assert!(!no_effect.staging_path().exists());
            assert!(!no_effect.final_path().exists());

            let effected = Fixture::new();
            let ready = effected.stage().verify_ready_with(|_| Ok(())).unwrap();
            let mut failure = InterruptRename {
                behavior: InterruptedRenameV1::EffectThenIo,
                calls: 0,
            };
            ready
                .publish_at_with_transitions(FINAL, &mut failure)
                .unwrap();
            assert_eq!(failure.calls, 1);
            assert!(effected.final_path().is_dir());
            assert!(!effected.staging_path().exists());
        }

        #[test]
        fn raw_rename_and_generic_eintr_retries_have_exact_attempt_bounds() {
            let mut raw_calls = 0;
            let error = rename_noreplace_once(|| {
                raw_calls += 1;
                unsafe { *libc::__errno_location() = libc::EINTR };
                -1
            })
            .unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EINTR));
            assert_eq!(raw_calls, 1);

            let mut generic_calls = 0;
            let error = retry_eintr_zero(3, || {
                generic_calls += 1;
                unsafe { *libc::__errno_location() = libc::EINTR };
                -1
            })
            .unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EINTR));
            assert_eq!(generic_calls, 3);
        }

        #[test]
        fn successful_publication_binds_the_reopened_inode_identity() {
            let fixture = Fixture::new();
            let mut callback_ran = false;
            let ready = fixture
                .stage()
                .verify_ready_with(|_| {
                    callback_ran = true;
                    Ok(())
                })
                .unwrap();
            let ready_identity = ready.cleanup.expected_identity();
            let published = ready.publish_at(FINAL).unwrap();
            assert!(callback_ran);
            assert_eq!(
                directory_identity(published.directory()).unwrap(),
                ready_identity
            );
            assert!(fixture.final_path().is_dir());
            assert!(!fixture.staging_path().exists());
        }

        #[test]
        fn published_child_binding_pins_the_exact_directory_and_refunds_unused_escrow() {
            let fixture = Fixture::new();
            let published = fixture.publish_root();
            let expected = published_child_commitment(&published, ROOT);
            let resources = charged_resources_with_entries(1_000_000, 1024 * 1024, 4);
            let before = resources.forward_attempts_remaining_for_test();
            let reservation = resources
                .reserve_published_child_bind_attempts(
                    policy().published_child_bind_operation_attempt_bound(),
                )
                .unwrap();
            assert_eq!(
                resources.forward_attempts_remaining_for_test(),
                before - u64::from(policy().openat2_attempts()) - 2
            );

            let bound =
                bind_published_snapshot_child_at(published, ROOT, expected, reservation).unwrap();

            // The first constrained open and bind statx are the only raw
            // attempts so far. One additional attempt was consumed as the
            // one-shot projection permit; the unused open retry suffix was
            // returned to the shared ledger.
            assert_eq!(resources.forward_attempts_remaining_for_test(), before - 3);
            assert_eq!(
                fstat_raw(bound_published_snapshot_root_fd(&bound))
                    .unwrap()
                    .st_mode
                    & libc::S_IFMT,
                libc::S_IFDIR
            );
            assert_eq!(
                fstat_raw(bound_published_snapshot_directory_fd(&bound))
                    .unwrap()
                    .st_mode
                    & libc::S_IFMT,
                libc::S_IFDIR
            );
            assert_eq!(
                format!("{bound:?}"),
                "BoundPublishedSnapshotChildV1 { published_directory: \"<owned-fd>\", root_directory: \"<owned-fd>\" }"
            );
            drop(bound);
            assert!(fixture.final_path().join("root").is_dir());
        }

        fn bound_root_for_projection(
            fixture: &Fixture,
        ) -> (BoundPublishedSnapshotChildV1, [u8; 102]) {
            let published = fixture.publish_root();
            let expected = published_child_commitment(&published, ROOT);
            let resources = charged_resources_with_entries(1_000_000, 1024 * 1024, 4);
            let reservation = resources
                .reserve_published_child_bind_attempts(
                    policy().published_child_bind_operation_attempt_bound(),
                )
                .unwrap();
            (
                bind_published_snapshot_child_at(published, ROOT, expected, reservation).unwrap(),
                expected,
            )
        }

        #[test]
        fn retained_root_projection_is_one_shot_and_refuses_missing_replacement_and_drift() {
            let fixture = Fixture::new();
            let (bound, expected) = bound_root_for_projection(&fixture);

            assert_eq!(
                super::consume_bound_published_snapshot_root_projection_v1(&bound, ROOT, expected,),
                Ok(())
            );
            assert_eq!(
                super::consume_bound_published_snapshot_root_projection_v1(&bound, ROOT, expected,),
                Err(BoundRegularReadRefusalV1::OperationBudget)
            );

            let missing = Fixture::new();
            let (missing_bound, missing_expected) = bound_root_for_projection(&missing);
            fs::rename(
                missing
                    .final_path()
                    .join(OsStr::from_bytes(ROOT.to_bytes())),
                missing.final_path().join("root-moved"),
            )
            .unwrap();
            assert_eq!(
                super::consume_bound_published_snapshot_root_projection_v1(
                    &missing_bound,
                    ROOT,
                    missing_expected,
                ),
                Err(BoundRegularReadRefusalV1::MissingNode)
            );

            let replacement = Fixture::new();
            let (replacement_bound, replacement_expected) = bound_root_for_projection(&replacement);
            fs::rename(
                replacement
                    .final_path()
                    .join(OsStr::from_bytes(ROOT.to_bytes())),
                replacement.final_path().join("root-moved"),
            )
            .unwrap();
            fs::create_dir(
                replacement
                    .final_path()
                    .join(OsStr::from_bytes(ROOT.to_bytes())),
            )
            .unwrap();
            assert_eq!(
                super::consume_bound_published_snapshot_root_projection_v1(
                    &replacement_bound,
                    ROOT,
                    replacement_expected,
                ),
                Err(BoundRegularReadRefusalV1::IdentityDrift)
            );

            let drift = Fixture::new();
            let (drift_bound, drift_expected) = bound_root_for_projection(&drift);
            fs::set_permissions(
                drift.final_path().join(OsStr::from_bytes(ROOT.to_bytes())),
                fs::Permissions::from_mode(0o700),
            )
            .unwrap();
            assert_eq!(
                super::consume_bound_published_snapshot_root_projection_v1(
                    &drift_bound,
                    ROOT,
                    drift_expected,
                ),
                Err(BoundRegularReadRefusalV1::IdentityDrift)
            );
        }

        #[test]
        fn projection_permit_exhaustion_closes_both_bound_descriptors() {
            let fixture = Fixture::new();
            let published = fixture.publish_root();
            let expected = published_child_commitment(&published, ROOT);
            let published_raw = published.directory().as_raw_fd();
            let resources = charged_resources_with_entries(1_000_000, 1024 * 1024, 4);
            let before = resources.forward_attempts_remaining_for_test();
            let reservation = resources
                .reserve_published_child_bind_attempts(NonZeroU64::new(2).unwrap())
                .unwrap();
            let root_raw = Cell::new(-1);
            let error = bind_published_snapshot_child_at_with_projection_hook(
                published,
                ROOT,
                expected,
                reservation,
                |root| root_raw.set(root.as_raw_fd()),
            )
            .unwrap_err();
            assert!(matches!(
                error.failure(),
                SnapshotPublishedChildBindFailureV1::Resource(
                    SnapshotPipelineResourceErrorV1::OperationBudgetExhausted { .. }
                )
            ));
            assert_eq!(resources.forward_attempts_remaining_for_test(), before - 2);
            assert_ne!(root_raw.get(), -1);
            assert_eq!(unsafe { libc::fcntl(published_raw, libc::F_GETFD) }, -1);
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
            assert_eq!(unsafe { libc::fcntl(root_raw.get(), libc::F_GETFD) }, -1);
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
        }

        fn fake_fork_child_root(
            role: SnapshotChildRootRoleV1,
            identity_byte: u8,
        ) -> ForkChildPublishedRootV1 {
            let mut expected = [0_u8; 102];
            expected[0] = 1;
            expected[1..25].fill(identity_byte);
            let mut root_name = [0_u8; MAX_BASENAME_BYTES + 1];
            root_name[..4].copy_from_slice(b"root");
            ForkChildPublishedRootV1 {
                published_descriptor: -1,
                root_descriptor: -1,
                root_name,
                root_name_len: 4,
                published_namespace_path: [0_u8; CHILD_NAMESPACE_PATH_BYTES_V1],
                published_namespace_path_len: 0,
                root_namespace_path: [0_u8; CHILD_NAMESPACE_PATH_BYTES_V1],
                root_namespace_path_len: 0,
                _expected_host_statx_commitment: expected,
                expected_child_statx_commitment: ChildMappedStatxCommitmentV1(expected),
                role,
            }
        }

        #[test]
        fn child_namespace_commitment_requires_exact_mapped_owner_and_normalizes_only_owner() {
            let mut host = [0_u8; 102];
            host[0] = 1;
            host[1..29].fill(0x51);
            host[29..33].copy_from_slice(&1001_u32.to_le_bytes());
            host[33..37].copy_from_slice(&1002_u32.to_le_bytes());
            host[37..].fill(0xa7);

            assert!(child_mapped_statx_commitment_v1(host, 1000, 1002).is_none());
            assert!(child_mapped_statx_commitment_v1(host, 1001, 1000).is_none());
            let child = child_mapped_statx_commitment_v1(host, 1001, 1002)
                .expect("the exact single-ID map owner is admitted")
                .0;
            assert_eq!(&child[..29], &host[..29]);
            assert_eq!(&child[29..37], &[0_u8; 8]);
            assert_eq!(&child[37..], &host[37..]);
        }

        #[test]
        fn namespace_path_capture_accepts_exact_capacity_minus_terminator() {
            let mut bytes = [b'a'; CHILD_NAMESPACE_PATH_BYTES_V1];
            bytes[0] = b'/';
            let count = isize::try_from(bytes.len() - 1).unwrap();
            let (captured, captured_len) = finish_namespace_path_capture_v1(bytes, count).unwrap();
            assert_eq!(usize::from(captured_len), CHILD_NAMESPACE_PATH_BYTES_V1 - 1);
            assert_eq!(captured[CHILD_NAMESPACE_PATH_BYTES_V1 - 1], 0);
        }

        #[test]
        fn namespace_path_capture_rejects_full_buffer_truncation_signal() {
            let mut bytes = [b'a'; CHILD_NAMESPACE_PATH_BYTES_V1];
            bytes[0] = b'/';
            let count = isize::try_from(bytes.len()).unwrap();
            assert_eq!(
                finish_namespace_path_capture_v1(bytes, count),
                Err(BoundRegularReadRefusalV1::IdentityDrift)
            );
        }

        #[test]
        fn fork_child_pair_rejects_role_swap_and_duplicate_before_any_mount_syscall() {
            let swapped_workspace = fake_fork_child_root(SnapshotChildRootRoleV1::Runtime, 1);
            let swapped_runtime = fake_fork_child_root(SnapshotChildRootRoleV1::Workspace, 2);
            assert_eq!(
                child_validate_fork_child_root_pair_v1(&swapped_workspace, &swapped_runtime,),
                Err(SnapshotChildAttachFailureV1::Invariant {
                    role: SnapshotChildRootRoleV1::Workspace,
                    operation: SnapshotChildAttachOperationV1::ValidateSource,
                })
            );

            let workspace = fake_fork_child_root(SnapshotChildRootRoleV1::Workspace, 9);
            let duplicate = fake_fork_child_root(SnapshotChildRootRoleV1::Runtime, 9);
            assert_eq!(
                child_validate_fork_child_root_pair_v1(&workspace, &duplicate),
                Err(SnapshotChildAttachFailureV1::Invariant {
                    role: SnapshotChildRootRoleV1::Runtime,
                    operation: SnapshotChildAttachOperationV1::ValidateSource,
                })
            );
        }

        #[test]
        fn fixed_capacity_fault_plan_addresses_every_mount_leaf_for_both_roles() {
            const OPERATIONS: [SnapshotChildAttachOperationV1; 10] = [
                SnapshotChildAttachOperationV1::ValidateSource,
                SnapshotChildAttachOperationV1::OpenTree,
                SnapshotChildAttachOperationV1::SetRecursiveAttributes,
                SnapshotChildAttachOperationV1::OpenTarget,
                SnapshotChildAttachOperationV1::MoveMount,
                SnapshotChildAttachOperationV1::ReopenTarget,
                SnapshotChildAttachOperationV1::VerifyTarget,
                SnapshotChildAttachOperationV1::FinalTargetRevalidation,
                SnapshotChildAttachOperationV1::FinalSourceRevalidation,
                SnapshotChildAttachOperationV1::CloseKnownDescriptors,
            ];
            for role in [
                SnapshotChildRootRoleV1::Workspace,
                SnapshotChildRootRoleV1::Runtime,
            ] {
                for operation in OPERATIONS {
                    let plan = ChildAttachOperationPlanV1::fail(role, operation);
                    assert_eq!(
                        plan.check(role, operation),
                        Err(SnapshotChildAttachFailureV1::Injected {
                            role,
                            operation,
                            errno: libc::EIO,
                        })
                    );
                }
            }
        }

        #[test]
        fn tracked_child_attachment_descriptor_drop_is_raw_close_and_idempotent() {
            let mut descriptors = [-1_i32; 2];
            assert_eq!(
                unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) },
                0
            );
            let first = descriptors[0];
            let second = descriptors[1];
            let mut tracked = ChildTrackedAttachFdV1 { descriptor: first };
            tracked.close(SnapshotChildRootRoleV1::Workspace).unwrap();
            drop(tracked);
            assert_eq!(unsafe { libc::fcntl(first, libc::F_GETFD) }, -1);
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
            drop(ChildTrackedAttachFdV1 { descriptor: second });
            assert_eq!(unsafe { libc::fcntl(second, libc::F_GETFD) }, -1);
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
        }

        fn read_bound_for_test(
            bound: &BoundPublishedSnapshotChildV1,
            path: &ValidatedBoundRelativePathV1,
            ceiling: u32,
        ) -> Result<VerifiedBoundRegularBytesV1, BoundRegularReadRefusalV1> {
            super::super::read_bound_regular_bytes_v1(
                bound,
                path,
                ceiling,
                &RuntimeMemoryEscrowV1::first_checkpoint(),
            )
        }

        struct TestBoundReadHookV1<F>(F);

        impl<F> BoundReadHookV1 for TestBoundReadHookV1<F>
        where
            F: FnMut(BoundReadStageV1) -> io::Result<()>,
        {
            fn checkpoint(&mut self, stage: BoundReadStageV1) -> io::Result<()> {
                (self.0)(stage)
            }
        }

        fn read_bound_with_hook_for_test<F>(
            bound: &BoundPublishedSnapshotChildV1,
            path: &ValidatedBoundRelativePathV1,
            ceiling: u32,
            hook: F,
        ) -> Result<VerifiedBoundRegularBytesV1, BoundRegularReadRefusalV1>
        where
            F: FnMut(BoundReadStageV1) -> io::Result<()>,
        {
            super::read_bound_regular_bytes_with_hook_v1(
                bound,
                path.as_bytes(),
                ceiling,
                &RuntimeMemoryEscrowV1::first_checkpoint(),
                &mut TestBoundReadHookV1(hook),
            )
        }

        fn symlink_with_stable_test_atime(target: &str, link: &Path) {
            symlink(target, link).unwrap();
            let path = CString::new(link.as_os_str().as_bytes()).unwrap();
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap();
            let times = [
                libc::timespec {
                    tv_sec: i64::try_from(now.as_secs()).unwrap() + 3_600,
                    tv_nsec: libc::c_long::from(now.subsec_nanos()),
                },
                libc::timespec {
                    tv_sec: 0,
                    tv_nsec: libc::UTIME_OMIT,
                },
            ];
            assert_eq!(
                unsafe {
                    libc::utimensat(
                        libc::AT_FDCWD,
                        path.as_ptr(),
                        times.as_ptr(),
                        libc::AT_SYMLINK_NOFOLLOW,
                    )
                },
                0,
                "symlink atime fixture must emulate the qualified no-atime view"
            );
        }

        #[test]
        fn bound_regular_reader_accepts_direct_and_relative_symlink_terminal_bytes() {
            let direct_fixture = Fixture::new();
            let direct = publish_bound_tree(&direct_fixture, |root| {
                fs::create_dir_all(root.join(".venv/bin")).unwrap();
                fs::write(root.join(".venv/bin/python"), b"direct").unwrap();
            });
            let path = ValidatedBoundRelativePathV1::parse(b".venv/bin/python").unwrap();
            let direct_bytes = read_bound_for_test(&direct, &path, 6).unwrap();
            assert_eq!(direct_bytes.bytes(), b"direct");
            assert_eq!(
                direct_bytes.nodes().last().unwrap().kind(),
                VerifiedBoundNodeKindV1::Regular
            );

            let link_fixture = Fixture::new();
            let linked = publish_bound_tree(&link_fixture, |root| {
                fs::create_dir_all(root.join(".venv/bin")).unwrap();
                fs::write(root.join(".venv/bin/python-real"), b"linked").unwrap();
                symlink_with_stable_test_atime("python-real", &root.join(".venv/bin/python"));
            });
            let linked_bytes = read_bound_for_test(&linked, &path, 6).unwrap();
            assert_eq!(linked_bytes.bytes(), b"linked");
            let symlink = linked_bytes
                .nodes()
                .iter()
                .find(|node| node.kind() == VerifiedBoundNodeKindV1::Symlink)
                .unwrap();
            assert_eq!(symlink.symlink_target(), Some(b"python-real".as_slice()));
            assert_eq!(
                symlink.normalized_next_path(),
                Some(b".venv/bin/python-real".as_slice())
            );
        }

        #[test]
        fn bound_regular_reader_enforces_exact_symlink_hop_boundary() {
            let path = ValidatedBoundRelativePathV1::parse(b".venv/bin/python").unwrap();
            for (hop_count, expected) in [
                (BOUND_REGULAR_SYMLINK_MAX_HOPS_V1, Ok(())),
                (
                    BOUND_REGULAR_SYMLINK_MAX_HOPS_V1 + 1,
                    Err(BoundRegularReadRefusalV1::SymlinkLimit),
                ),
            ] {
                let fixture = Fixture::new();
                let bound = publish_bound_tree(&fixture, |root| {
                    let bin = root.join(".venv/bin");
                    fs::create_dir_all(&bin).unwrap();
                    fs::write(bin.join("terminal"), b"x").unwrap();
                    for index in 0..hop_count {
                        let name = if index == 0 {
                            "python".to_owned()
                        } else {
                            format!("link-{index}")
                        };
                        let target = if index + 1 == hop_count {
                            "terminal".to_owned()
                        } else {
                            format!("link-{}", index + 1)
                        };
                        symlink_with_stable_test_atime(&target, &bin.join(name));
                    }
                });
                assert_eq!(read_bound_for_test(&bound, &path, 1).map(|_| ()), expected);
            }
        }

        #[test]
        fn bound_regular_reader_rejects_cycle_escape_missing_special_and_size() {
            let path = ValidatedBoundRelativePathV1::parse(b".venv/bin/python").unwrap();
            for (target, expected) in [
                ("python", BoundRegularReadRefusalV1::SymlinkCycle),
                ("/bin/sh", BoundRegularReadRefusalV1::SymlinkTargetInvalid),
                ("../python", BoundRegularReadRefusalV1::SymlinkTargetInvalid),
            ] {
                let fixture = Fixture::new();
                let bound = publish_bound_tree(&fixture, |root| {
                    fs::create_dir_all(root.join(".venv/bin")).unwrap();
                    symlink_with_stable_test_atime(target, &root.join(".venv/bin/python"));
                });
                assert_eq!(
                    read_bound_for_test(&bound, &path, 64).unwrap_err(),
                    expected
                );
            }

            let missing_fixture = Fixture::new();
            let missing = publish_bound_tree(&missing_fixture, |root| {
                fs::create_dir_all(root.join(".venv/bin")).unwrap();
            });
            assert_eq!(
                read_bound_for_test(&missing, &path, 64).unwrap_err(),
                BoundRegularReadRefusalV1::MissingNode
            );

            let special_fixture = Fixture::new();
            let special = publish_bound_tree(&special_fixture, |root| {
                fs::create_dir_all(root.join(".venv/bin")).unwrap();
                std::os::unix::net::UnixListener::bind(root.join(".venv/bin/python")).unwrap();
            });
            assert_eq!(
                read_bound_for_test(&special, &path, 64).unwrap_err(),
                BoundRegularReadRefusalV1::NodeType
            );

            let large_fixture = Fixture::new();
            let large = publish_bound_tree(&large_fixture, |root| {
                fs::create_dir_all(root.join(".venv/bin")).unwrap();
                fs::write(root.join(".venv/bin/python"), [0u8; 65]).unwrap();
            });
            assert_eq!(
                read_bound_for_test(&large, &path, 64).unwrap_err(),
                BoundRegularReadRefusalV1::ByteLimit
            );
            assert_eq!(
                read_bound_for_test(&large, &path, 0).unwrap_err(),
                BoundRegularReadRefusalV1::InvalidByteCeiling
            );
        }

        #[test]
        fn bound_regular_reader_classifies_expanding_self_reference_as_cycle() {
            let fixture = Fixture::new();
            let bound = publish_bound_tree(&fixture, |root| {
                fs::create_dir_all(root.join(".venv/bin")).unwrap();
                symlink_with_stable_test_atime("python/tail", &root.join(".venv/bin/python"));
            });
            let path = ValidatedBoundRelativePathV1::parse(b".venv/bin/python").unwrap();
            assert_eq!(
                read_bound_for_test(&bound, &path, 64).unwrap_err(),
                BoundRegularReadRefusalV1::SymlinkCycle
            );
        }

        #[test]
        fn bound_regular_reader_revalidates_every_pinned_ancestor() {
            let fixture = Fixture::new();
            let bound = publish_bound_tree(&fixture, |root| {
                fs::create_dir_all(root.join(".venv/bin")).unwrap();
                fs::write(root.join(".venv/bin/python"), b"python").unwrap();
            });
            let path = ValidatedBoundRelativePathV1::parse(b".venv/bin/python").unwrap();
            let ancestor = fixture.final_path().join("root/.venv");
            let mut mutated = false;
            let result = read_bound_with_hook_for_test(&bound, &path, 6, |stage| {
                if !mutated && stage == BoundReadStageV1::AfterDirectoryRecorded {
                    fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o700))?;
                    mutated = true;
                }
                Ok(())
            });
            assert!(mutated);
            assert_eq!(
                result.unwrap_err(),
                BoundRegularReadRefusalV1::IdentityDrift
            );
        }

        #[test]
        fn retained_bound_object_detects_post_read_ancestor_and_terminal_mutation() {
            for mutate_terminal in [false, true] {
                let fixture = Fixture::new();
                let bound = publish_bound_tree(&fixture, |root| {
                    fs::create_dir_all(root.join(".venv/bin")).unwrap();
                    fs::write(root.join(".venv/bin/python"), b"python").unwrap();
                });
                let path = ValidatedBoundRelativePathV1::parse(b".venv/bin/python").unwrap();
                let verified = read_bound_for_test(&bound, &path, 6).unwrap();
                assert_eq!(verified.pinned_fd_count(), 3);
                if mutate_terminal {
                    fs::write(
                        fixture.final_path().join("root/.venv/bin/python"),
                        b"changed",
                    )
                    .unwrap();
                } else {
                    fs::set_permissions(
                        fixture.final_path().join("root/.venv"),
                        fs::Permissions::from_mode(0o700),
                    )
                    .unwrap();
                }
                assert_eq!(
                    super::super::revalidate_bound_regular_bytes_v1(&bound, &verified),
                    Err(BoundRegularReadRefusalV1::IdentityDrift)
                );
            }
        }

        #[test]
        fn bound_regular_reader_reads_symlink_through_pinned_fd_and_detects_parent_drift() {
            let fixture = Fixture::new();
            let bound = publish_bound_tree(&fixture, |root| {
                fs::create_dir_all(root.join(".venv/bin")).unwrap();
                fs::write(root.join(".venv/bin/first"), b"first!").unwrap();
                fs::write(root.join(".venv/bin/second"), b"second").unwrap();
                symlink("first", root.join(".venv/bin/python")).unwrap();
            });
            let path = ValidatedBoundRelativePathV1::parse(b".venv/bin/python").unwrap();
            let symlink_path = fixture.final_path().join("root/.venv/bin/python");
            let mut replaced = false;
            let result = read_bound_with_hook_for_test(&bound, &path, 6, |stage| {
                if !replaced && stage == BoundReadStageV1::BeforeSymlinkRead {
                    fs::remove_file(&symlink_path)?;
                    symlink("second", &symlink_path)?;
                    replaced = true;
                }
                Ok(())
            });
            assert!(replaced);
            assert_eq!(
                result.unwrap_err(),
                BoundRegularReadRefusalV1::IdentityDrift
            );
        }

        #[test]
        fn published_real_x86_64_elf_round_trips_through_bound_reader() {
            let executable = fs::read("/bin/true").unwrap();
            let ceiling = u32::try_from(executable.len()).unwrap();
            let fixture = Fixture::new();
            let bound = publish_bound_tree(&fixture, |root| {
                fs::create_dir_all(root.join(".venv/bin")).unwrap();
                fs::write(root.join(".venv/bin/python"), &executable).unwrap();
            });
            let path = ValidatedBoundRelativePathV1::parse(b".venv/bin/python").unwrap();
            let observed = read_bound_for_test(&bound, &path, ceiling).unwrap();
            assert_eq!(observed.bytes(), executable);
            assert_eq!(
                crate::linux_pytest::execute_only_runtime::validate_x86_64_elf_v1(observed.bytes()),
                Ok(())
            );
        }

        #[test]
        fn same_uid_post_bind_replacement_is_evidence_for_manifest_rejection_not_containment() {
            let fixture = Fixture::new();
            let bound = publish_bound_tree(&fixture, |root| {
                fs::create_dir_all(root.join(".venv/bin")).unwrap();
                fs::write(root.join(".venv/bin/python"), b"before").unwrap();
            });
            fs::write(
                fixture.final_path().join("root/.venv/bin/python"),
                b"after!",
            )
            .unwrap();
            let path = ValidatedBoundRelativePathV1::parse(b".venv/bin/python").unwrap();
            let observed = read_bound_for_test(&bound, &path, 6).unwrap();
            assert_eq!(observed.bytes(), b"after!");
            assert_ne!(
                observed.content_digest(),
                FileContentDigest::derive(super::super::super::FILE_CONTENT_DOMAIN, &[b"before"])
            );
        }

        #[test]
        fn invalid_and_missing_published_child_names_fail_with_durable_state() {
            let invalid = Fixture::new();
            let published = invalid.publish_root();
            let resources = charged_resources_with_entries(1_000_000, 1024 * 1024, 4);
            let before = resources.forward_attempts_remaining_for_test();
            let reservation = resources
                .reserve_published_child_bind_attempts(
                    policy().published_child_bind_operation_attempt_bound(),
                )
                .unwrap();
            let error = bind_leaf(
                bind_published_snapshot_child_at(published, c"nested/root", [0; 102], reservation)
                    .unwrap_err(),
            );
            assert_eq!(
                error.kind(),
                SnapshotPublishErrorKindV1::InvalidPublishedChildName
            );
            assert_eq!(
                error.stage(),
                SnapshotPublishStageV1::ValidatePublishedChildName
            );
            assert_eq!(resources.forward_attempts_remaining_for_test(), before);
            assert!(invalid.final_path().join("root").is_dir());

            let missing = Fixture::new();
            let published = missing.publish_empty();
            let resources = charged_resources_with_entries(1_000_000, 1024 * 1024, 4);
            let before = resources.forward_attempts_remaining_for_test();
            let reservation = resources
                .reserve_published_child_bind_attempts(
                    policy().published_child_bind_operation_attempt_bound(),
                )
                .unwrap();
            let error = bind_leaf(
                bind_published_snapshot_child_at(published, ROOT, [0; 102], reservation)
                    .unwrap_err(),
            );
            assert_eq!(error.kind(), SnapshotPublishErrorKindV1::Io);
            assert_eq!(error.stage(), SnapshotPublishStageV1::OpenPublishedChild);
            assert_eq!(error.errno(), Some(libc::ENOENT));
            assert_eq!(resources.forward_attempts_remaining_for_test(), before - 1);
            assert!(missing.final_path().is_dir());
        }

        #[test]
        fn published_child_symlink_is_never_admitted_as_the_root_directory() {
            let fixture = Fixture::new();
            let staged = fixture.stage();
            fs::create_dir(fixture.staging_path().join("target")).unwrap();
            symlink("target", fixture.staging_path().join("root")).unwrap();
            let published = staged
                .verify_ready_with(|_| Ok(()))
                .unwrap()
                .publish_at(FINAL)
                .unwrap();
            let resources = charged_resources_with_entries(1_000_000, 1024 * 1024, 4);
            let reservation = resources
                .reserve_published_child_bind_attempts(
                    policy().published_child_bind_operation_attempt_bound(),
                )
                .unwrap();

            let error = bind_leaf(
                bind_published_snapshot_child_at(published, ROOT, [0; 102], reservation)
                    .unwrap_err(),
            );

            assert_eq!(error.kind(), SnapshotPublishErrorKindV1::IdentityMismatch);
            assert_eq!(error.stage(), SnapshotPublishStageV1::StatPublishedChild);
            assert!(fixture.final_path().join("root").is_symlink());
        }

        #[test]
        fn replacement_and_metadata_mutation_cannot_match_the_stable_commitment() {
            let replacement = Fixture::new();
            let published = replacement.publish_root();
            let expected = published_child_commitment(&published, ROOT);
            let original_root_metadata =
                fs::metadata(replacement.final_path().join("root")).unwrap();
            fs::set_permissions(
                replacement.final_path(),
                fs::Permissions::from_mode(PRIVATE_DIRECTORY_MODE),
            )
            .unwrap();
            fs::rename(
                replacement.final_path().join("root"),
                replacement.final_path().join("old-root"),
            )
            .unwrap();
            fs::create_dir(replacement.final_path().join("root")).unwrap();
            fs::set_permissions(
                replacement.final_path().join("root"),
                fs::Permissions::from_mode(original_root_metadata.permissions().mode() & 0o7777),
            )
            .unwrap();
            File::open(replacement.final_path().join("root"))
                .unwrap()
                .set_times(
                    FileTimes::new()
                        .set_accessed(original_root_metadata.accessed().unwrap())
                        .set_modified(original_root_metadata.modified().unwrap()),
                )
                .unwrap();
            fs::set_permissions(
                replacement.final_path(),
                fs::Permissions::from_mode(SEALED_DIRECTORY_MODE),
            )
            .unwrap();
            let resources = charged_resources_with_entries(1_000_000, 1024 * 1024, 4);
            let reservation = resources
                .reserve_published_child_bind_attempts(
                    policy().published_child_bind_operation_attempt_bound(),
                )
                .unwrap();
            let error = bind_leaf(
                bind_published_snapshot_child_at(published, ROOT, expected, reservation)
                    .unwrap_err(),
            );
            assert_eq!(error.kind(), SnapshotPublishErrorKindV1::IdentityMismatch);
            assert_eq!(
                error.stage(),
                SnapshotPublishStageV1::BindPublishedChildIdentity
            );
            assert!(replacement.final_path().join("old-root").is_dir());
            assert!(replacement.final_path().join("root").is_dir());

            let metadata = Fixture::new();
            let published = metadata.publish_root();
            let expected = published_child_commitment(&published, ROOT);
            fs::set_permissions(
                metadata.final_path().join("root"),
                fs::Permissions::from_mode(0o700),
            )
            .unwrap();
            let resources = charged_resources_with_entries(1_000_000, 1024 * 1024, 4);
            let reservation = resources
                .reserve_published_child_bind_attempts(
                    policy().published_child_bind_operation_attempt_bound(),
                )
                .unwrap();
            let error = bind_leaf(
                bind_published_snapshot_child_at(published, ROOT, expected, reservation)
                    .unwrap_err(),
            );
            assert_eq!(error.kind(), SnapshotPublishErrorKindV1::IdentityMismatch);
            assert_eq!(
                error.stage(),
                SnapshotPublishStageV1::BindPublishedChildIdentity
            );
            assert_eq!(
                fs::metadata(metadata.final_path().join("root"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777,
                0o700
            );
        }

        #[test]
        fn representative_source_statx_commitment_bytes_are_bound_exactly() {
            for index in [0, 51, 101] {
                let fixture = Fixture::new();
                let published = fixture.publish_root();
                let mut expected = published_child_commitment(&published, ROOT);
                expected[index] ^= 0x80;
                let resources = charged_resources_with_entries(1_000_000, 1024 * 1024, 4);
                let reservation = resources
                    .reserve_published_child_bind_attempts(
                        policy().published_child_bind_operation_attempt_bound(),
                    )
                    .unwrap();

                let error = bind_leaf(
                    bind_published_snapshot_child_at(published, ROOT, expected, reservation)
                        .unwrap_err(),
                );

                assert_eq!(error.kind(), SnapshotPublishErrorKindV1::IdentityMismatch);
                assert_eq!(
                    error.stage(),
                    SnapshotPublishStageV1::BindPublishedChildIdentity
                );
                assert!(fixture.final_path().join("root").is_dir());
            }
        }

        #[test]
        fn exhausted_bind_escrow_is_a_durable_resource_failure_and_keeps_the_tree() {
            let fixture = Fixture::new();
            let published = fixture.publish_root();
            let expected = published_child_commitment(&published, ROOT);
            let resources = charged_resources_with_entries(1_000_000, 1024 * 1024, 4);
            let before = resources.forward_attempts_remaining_for_test();
            // The constrained open consumes this sole attempt. The statx
            // closure must never run and the typed post-publication wrapper
            // still reports a durable final name.
            let reservation = resources
                .reserve_published_child_bind_attempts(NonZeroU64::new(1).unwrap())
                .unwrap();
            PUBLISHED_CHILD_STATX_CALLS.with(|calls| calls.set(0));
            let error = bind_published_snapshot_child_at(published, ROOT, expected, reservation)
                .unwrap_err();
            assert_eq!(
                error.publication_state(),
                SnapshotPublicationStateV1::PublishedDurable
            );
            assert!(matches!(
                error.failure(),
                SnapshotPublishedChildBindFailureV1::Resource(
                    SnapshotPipelineResourceErrorV1::OperationBudgetExhausted {
                        stage: SnapshotPipelineStageV1::Forward(
                            SnapshotPipelineForwardStageV1::Publication
                        ),
                        bucket: SnapshotPipelineAttemptBucketV1::Forward,
                    }
                )
            ));
            assert_eq!(resources.forward_attempts_remaining_for_test(), before - 1);
            assert_eq!(PUBLISHED_CHILD_STATX_CALLS.with(|calls| calls.get()), 0);
            assert!(fixture.final_path().join("root").is_dir());
        }

        #[test]
        fn publish_time_replacement_cannot_be_mistaken_for_the_pinned_inode() {
            struct ReplaceBeforeRename {
                parent_path: PathBuf,
            }

            impl TransitionHookV1 for ReplaceBeforeRename {
                fn checkpoint(&mut self, stage: SnapshotPublishStageV1) -> io::Result<()> {
                    if stage == SnapshotPublishStageV1::PublishRename {
                        let staging = self.parent_path.join(OsStr::from_bytes(STAGING.to_bytes()));
                        fs::rename(&staging, self.parent_path.join("moved-before-rename"))?;
                        fs::create_dir(&staging)?;
                        fs::write(staging.join("replacement"), b"replacement")?;
                    }
                    Ok(())
                }
            }

            let fixture = Fixture::new();
            let ready = fixture.stage().verify_ready_with(|_| Ok(())).unwrap();
            let mut replace = ReplaceBeforeRename {
                parent_path: fixture.temp.path().to_owned(),
            };
            let error = ready
                .publish_at_with_transitions(FINAL, &mut replace)
                .err()
                .unwrap();
            assert_eq!(error.kind(), SnapshotPublishErrorKindV1::IdentityMismatch);
            assert_eq!(
                error.publication_state(),
                SnapshotPublicationStateV1::PublishedDurable
            );
            assert_eq!(
                fs::read(fixture.final_path().join("replacement")).unwrap(),
                b"replacement"
            );
            assert!(fixture.temp.path().join("moved-before-rename").is_dir());
        }

        #[test]
        fn invalid_final_name_drops_the_unpublished_stage() {
            let fixture = Fixture::new();
            let error = fixture
                .stage()
                .verify_ready_with(|_| Ok(()))
                .unwrap()
                .publish_at(c"nested/final")
                .err()
                .unwrap();
            assert_eq!(error.kind(), SnapshotPublishErrorKindV1::InvalidFinalName);
            assert!(!fixture.staging_path().exists());
        }

        #[test]
        fn recursive_durability_callback_failure_cleans_the_stage() {
            let fixture = Fixture::new();
            let staged = fixture.stage();
            populate_read_only_tree(&fixture.staging_path());
            let error = staged
                .verify_ready_with(|_| Err(io::Error::from_raw_os_error(libc::ENOSPC)))
                .unwrap_err();
            assert_eq!(
                error.kind(),
                SnapshotPublishErrorKindV1::RecursiveDurabilityFailed
            );
            assert_eq!(error.errno(), Some(libc::ENOSPC));
            assert!(!fixture.staging_path().exists());
        }

        #[test]
        fn staged_directory_accessor_remains_descriptor_selected() {
            let fixture = Fixture::new();
            let staged = fixture.stage();
            assert!(fstat_raw(staged.directory()).is_ok());
        }

        #[test]
        fn final_name_may_be_raw_non_utf8() {
            let fixture = Fixture::new();
            let raw = CString::new(b"final-\xff".to_vec()).unwrap();
            let _published = fixture
                .stage()
                .verify_ready_with(|_| Ok(()))
                .unwrap()
                .publish_at(&raw)
                .unwrap();
            assert!(fixture.path(&raw).is_dir());
        }
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
mod platform {
    use std::marker::PhantomData;
    use std::os::fd::AsFd;

    use super::*;

    pub(in crate::linux_pytest) struct StagedSnapshotDirectoryV1<'parent> {
        policy: SnapshotPublishPolicyV1,
        parent: PhantomData<BorrowedFd<'parent>>,
    }
    pub(in crate::linux_pytest) struct ChargedStagedSnapshotDirectoryV1<'resources> {
        policy: SnapshotPublishPolicyV1,
        resources: PhantomData<BorrowedFd<'resources>>,
    }
    pub(in crate::linux_pytest) struct VerifiedReadySnapshotDirectoryV1<'parent>(
        PhantomData<BorrowedFd<'parent>>,
    );

    pub(in crate::linux_pytest) struct PublishedSnapshotDirectoryV1 {
        directory: OwnedFd,
        openat2_attempts: u8,
    }

    pub(in crate::linux_pytest) struct BoundPublishedSnapshotChildV1 {
        published: OwnedFd,
        root: OwnedFd,
        retained_root_projection_admitted: Cell<bool>,
    }

    impl<'parent> StagedSnapshotDirectoryV1<'parent> {
        pub(in crate::linux_pytest) fn directory(&self) -> BorrowedFd<'_> {
            unreachable!("unsupported platform cannot create a staging directory")
        }

        pub(in crate::linux_pytest) const fn cleanup_envelope(&self) -> SnapshotCleanupEnvelopeV1 {
            self.policy.cleanup_envelope()
        }

        pub(in crate::linux_pytest) fn verify_ready_with<F>(
            self,
            _verify_recursive_durability: F,
        ) -> Result<VerifiedReadySnapshotDirectoryV1<'parent>, SnapshotPublishErrorV1>
        where
            F: FnOnce(BorrowedFd<'_>) -> io::Result<()>,
        {
            Err(unsupported_platform())
        }
    }

    impl ChargedStagedSnapshotDirectoryV1<'_> {
        pub(in crate::linux_pytest) fn directory(&self) -> BorrowedFd<'_> {
            unreachable!("unsupported platform cannot create a staging directory")
        }

        pub(in crate::linux_pytest) const fn cleanup_envelope(&self) -> SnapshotCleanupEnvelopeV1 {
            self.policy.cleanup_envelope()
        }
    }

    impl VerifiedReadySnapshotDirectoryV1<'_> {
        pub(super) fn publish_at(
            self,
            _final_name: &CStr,
        ) -> Result<PublishedSnapshotDirectoryV1, SnapshotPublishErrorV1> {
            Err(unsupported_platform())
        }
    }

    impl PublishedSnapshotDirectoryV1 {
        pub(super) fn directory(&self) -> BorrowedFd<'_> {
            self.directory.as_fd()
        }
    }

    impl BoundPublishedSnapshotChildV1 {
        #[cfg(test)]
        pub(super) fn published_directory(&self) -> BorrowedFd<'_> {
            self.published.as_fd()
        }

        #[cfg(test)]
        pub(super) fn root_directory(&self) -> BorrowedFd<'_> {
            self.root.as_fd()
        }
    }

    pub(super) fn read_bound_regular_bytes_v1(
        _bound: &BoundPublishedSnapshotChildV1,
        _path: &[u8],
        _byte_ceiling: u32,
        _memory: &RuntimeMemoryEscrowV1,
    ) -> Result<VerifiedBoundRegularBytesV1, BoundRegularReadRefusalV1> {
        Err(BoundRegularReadRefusalV1::UnsupportedPlatform)
    }

    impl fmt::Debug for BoundPublishedSnapshotChildV1 {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("BoundPublishedSnapshotChildV1")
                .field("published_directory", &"<owned-fd>")
                .field("root_directory", &"<owned-fd>")
                .finish()
        }
    }

    pub(super) fn create_charged_staged_snapshot_directory_at<'resources>(
        _parent: BorrowedFd<'resources>,
        _staging_name: &CStr,
        _session: SnapshotPublicationSessionV1<'resources>,
    ) -> Result<
        ChargedStagedSnapshotDirectoryV1<'resources>,
        SnapshotChargedErrorV1<SnapshotPublishErrorV1>,
    > {
        Err(SnapshotChargedErrorV1::Leaf(unsupported_platform()))
    }

    #[cfg(test)]
    pub(super) fn create_unmetered_staged_snapshot_directory_at<'parent>(
        _parent: BorrowedFd<'parent>,
        _staging_name: &CStr,
        _policy: SnapshotPublishPolicyV1,
    ) -> Result<StagedSnapshotDirectoryV1<'parent>, SnapshotPublishErrorV1> {
        Err(unsupported_platform())
    }

    fn unsupported_platform() -> SnapshotPublishErrorV1 {
        SnapshotPublishErrorV1::new(
            SnapshotPublishErrorKindV1::RequiredKernelCapabilityMissing,
            SnapshotPublishStageV1::InspectParent,
            SnapshotPublicationStateV1::Unpublished,
            None,
        )
    }
}

#[cfg(test)]
mod portable_tests {
    use super::*;

    trait AmbiguousIfClone<A> {
        fn probe() {}
    }

    impl<T: ?Sized> AmbiguousIfClone<()> for T {}
    impl<T: Clone> AmbiguousIfClone<u8> for T {}

    fn checked_policy(
        openat2_attempts: u8,
        syscall_attempts: u8,
        depth: u16,
        entries: u32,
        name_bytes: u16,
        retained_name_bytes: u64,
    ) -> Option<SnapshotPublishPolicyV1> {
        SnapshotPublishPolicyV1::checked(
            NonZeroU8::new(openat2_attempts).unwrap(),
            NonZeroU8::new(syscall_attempts).unwrap(),
            depth,
            NonZeroU32::new(entries).unwrap(),
            NonZeroU16::new(name_bytes).unwrap(),
            NonZeroU64::new(retained_name_bytes).unwrap(),
        )
    }

    #[test]
    fn staging_name_requires_a_canonical_128_bit_nonce() {
        assert!(valid_staging_basename(
            c".again-snapshot-stage-0123456789abcdef0123456789abcdef"
        ));
        assert!(!valid_staging_basename(c"stage-0123456789abcdef"));
        assert!(!valid_staging_basename(
            c".again-snapshot-stage-0123456789ABCDEF0123456789ABCDEF"
        ));
        assert!(!valid_staging_basename(
            c".again-snapshot-stage-0123456789abcdef0123456789abcde"
        ));
    }

    #[test]
    fn bound_published_child_authority_is_not_cloneable() {
        <BoundPublishedSnapshotChildV1 as AmbiguousIfClone<_>>::probe();
    }

    #[test]
    fn pure_final_name_validation_returns_one_typed_failure() {
        let staging = c".again-snapshot-stage-0123456789abcdef0123456789abcdef";
        assert_eq!(
            validate_snapshot_final_name(staging, c"snapshot-\xFF"),
            Ok(())
        );

        for invalid in [c"", c".", c"..", c"nested/name", staging] {
            let error = validate_snapshot_final_name(staging, invalid).unwrap_err();
            assert_eq!(error.kind(), SnapshotPublishErrorKindV1::InvalidFinalName);
            assert_eq!(error.stage(), SnapshotPublishStageV1::ValidateFinalName);
            assert_eq!(
                error.publication_state(),
                SnapshotPublicationStateV1::Unpublished
            );
            assert_eq!(error.errno(), None);
        }
    }

    #[test]
    fn published_child_bind_bound_adds_bind_statx_and_one_shot_projection_permit() {
        for openat2_attempts in [1, 4, HARD_MAX_OPENAT2_ATTEMPTS] {
            let policy = checked_policy(openat2_attempts, 1, 0, 1, 1, 4096).unwrap();
            assert_eq!(
                policy.published_child_bind_operation_attempt_bound().get(),
                u64::from(openat2_attempts) + 2
            );
        }
    }

    #[test]
    fn policy_enforces_every_hard_ceiling_and_exact_work_bound() {
        let policy = checked_policy(
            HARD_MAX_OPENAT2_ATTEMPTS,
            HARD_MAX_SYSCALL_ATTEMPTS,
            HARD_MAX_SOURCE_TREE_DEPTH,
            HARD_MAX_CLEANUP_ENTRIES,
            MAX_BASENAME_BYTES as u16,
            HARD_MAX_CLEANUP_RETAINED_NAME_BYTES,
        )
        .unwrap();
        assert_eq!(policy.openat2_attempts(), HARD_MAX_OPENAT2_ATTEMPTS);
        assert_eq!(policy.syscall_attempts(), HARD_MAX_SYSCALL_ATTEMPTS);
        assert_eq!(policy.max_cleanup_depth, HARD_MAX_CLEANUP_DEPTH);
        let entries = u64::from(HARD_MAX_CLEANUP_ENTRIES);
        assert_eq!(
            policy.cleanup_operation_attempt_bound(),
            Some(
                ((5 * entries + 3) * u64::from(HARD_MAX_OPENAT2_ATTEMPTS))
                    + ((12 * entries + 12) * u64::from(HARD_MAX_SYSCALL_ATTEMPTS))
            )
        );
        let exact = (HARD_MAX_OPENAT2_ATTEMPTS, HARD_MAX_SYSCALL_ATTEMPTS);
        assert!(checked_policy(exact.0 + 1, 1, 0, 1, 1, 4096).is_none());
        assert!(checked_policy(1, exact.1 + 1, 0, 1, 1, 4096).is_none());
        assert!(checked_policy(1, 1, HARD_MAX_SOURCE_TREE_DEPTH + 1, 1, 1, 4096).is_none());
        assert!(checked_policy(1, 1, 0, HARD_MAX_CLEANUP_ENTRIES + 1, 1, 4096).is_none());
        assert!(checked_policy(1, 1, 0, 1, MAX_BASENAME_BYTES as u16 + 1, 4096).is_none());
        assert!(checked_policy(1, 1, 0, 1, 1, HARD_MAX_CLEANUP_RETAINED_NAME_BYTES + 1).is_none());
        assert!(checked_policy(1, 1, 0, 1, 1, 1).is_none());
    }

    #[test]
    fn policy_uses_the_exact_live_cleanup_heap_shape() {
        // Depth seven permits ten simultaneous cleanup frames after adding
        // the publication container levels. Eleven total entries therefore
        // cap the live slots before the fixed two-name batch width does.
        let entry_capped = MAX_STAGING_NAME_WITH_NUL + 11 * (13 + 1);
        assert!(checked_policy(2, 3, 7, 11, 13, entry_capped).is_some());
        assert!(checked_policy(2, 3, 7, 11, 13, entry_capped - 1).is_none());

        // Source depth zero becomes cleanup depth two, so three active
        // two-name batches cap seven admitted entries at six live names.
        let depth_capped = MAX_STAGING_NAME_WITH_NUL + 6 * (13 + 1);
        assert!(checked_policy(2, 3, 0, 7, 13, depth_capped).is_some());
        assert!(checked_policy(2, 3, 0, 7, 13, depth_capped - 1).is_none());
    }

    #[test]
    fn cleanup_envelope_reports_exact_policy_values_without_authority() {
        let policy = checked_policy(2, 3, 7, 11, 13, 64 * 1024).unwrap();
        let envelope = policy.cleanup_envelope();

        assert_eq!(envelope.max_source_tree_depth(), 7);
        assert_eq!(envelope.max_entries(), 11);
        assert_eq!(envelope.max_basename_bytes(), 13);
        assert_eq!(envelope.openat2_attempts(), 2);
        assert_eq!(envelope.generic_syscall_attempts(), 3);
        assert!(!std::mem::needs_drop::<SnapshotCleanupEnvelopeV1>());
    }

    #[test]
    fn policy_reports_exact_cleanup_and_descriptor_witnesses() {
        let policy = checked_policy(2, 3, 7, 11, 13, 64 * 1024).unwrap();

        assert_eq!(policy.max_cleanup_depth(), 9);
        assert_eq!(policy.max_cleanup_entries(), 11);
        assert_eq!(policy.max_cleanup_name_bytes(), 13);
        assert_eq!(policy.max_cleanup_retained_name_bytes(), 64 * 1024);
        assert_eq!(policy.max_cleanup_getdents_attempts(), (5 * 11 + 3) * 3);
        assert_eq!(policy.max_live_staged_fds(), 1);
        assert_eq!(policy.max_live_cleanup_fds(), 2 * 9 + 4);
        assert_eq!(policy.max_live_publication_fds(), 2);
    }

    #[test]
    fn policy_reports_the_exact_integrated_finalization_attempt_ceiling() {
        let open_retries = 4_u64;
        let generic_retries = 3_u64;
        let policy = checked_policy(
            open_retries as u8,
            generic_retries as u8,
            7,
            11,
            13,
            64 * 1024,
        )
        .unwrap();
        let staging_revalidations = 3 * (open_retries + 4);
        let seal_and_staging_sync = 2 * generic_retries;
        let rename_reconciliation = generic_retries * (2 * open_retries + 2);
        let parent_sync = generic_retries;
        let final_reopen_and_identity = open_retries + 4;
        let decomposed = staging_revalidations
            + seal_and_staging_sync
            + rename_reconciliation
            + parent_sync
            + final_reopen_and_identity;

        assert_eq!(
            policy.finalization_operation_attempt_bound().get(),
            decomposed
        );
        assert_eq!(
            decomposed,
            4 * open_retries + 16 + generic_retries * (2 * open_retries + 5)
        );
    }

    #[test]
    fn bound_regular_path_validation_is_raw_bounded_and_relative() {
        assert!(ValidatedBoundRelativePathV1::parse(b".venv/bin/python").is_ok());
        assert!(ValidatedBoundRelativePathV1::parse(&[0xff]).is_ok());
        for invalid in [
            b"".as_slice(),
            b"/absolute",
            b"a//b",
            b"a/./b",
            b"a/../b",
            b"a/",
            b"a\0b",
        ] {
            assert_eq!(
                ValidatedBoundRelativePathV1::parse(invalid).unwrap_err(),
                BoundRegularReadRefusalV1::InvalidPath
            );
        }
    }

    #[test]
    fn bound_regular_path_component_and_name_ceilings_are_exact() {
        let exact = std::iter::repeat_n("a", BOUND_REGULAR_PATH_MAX_COMPONENTS_V1)
            .collect::<Vec<_>>()
            .join("/");
        assert!(ValidatedBoundRelativePathV1::parse(exact.as_bytes()).is_ok());
        let excessive = format!("{exact}/a");
        assert_eq!(
            ValidatedBoundRelativePathV1::parse(excessive.as_bytes()).unwrap_err(),
            BoundRegularReadRefusalV1::ComponentLimit
        );
        assert!(ValidatedBoundRelativePathV1::parse(&vec![b'a'; MAX_BASENAME_BYTES]).is_ok());
        assert_eq!(
            ValidatedBoundRelativePathV1::parse(&vec![b'a'; MAX_BASENAME_BYTES + 1]).unwrap_err(),
            BoundRegularReadRefusalV1::ComponentLimit
        );
    }

    #[test]
    fn verified_regular_bytes_are_linear_zeroing_and_redacted() {
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

        <VerifiedBoundRegularBytesV1 as AmbiguousIfClone<_>>::probe();
        <VerifiedBoundRegularBytesV1 as AmbiguousIfCopy<_>>::probe();
        assert!(std::mem::needs_drop::<VerifiedBoundRegularBytesV1>());
        #[cfg(target_os = "linux")]
        let directory_mode = libc::S_IFDIR;
        #[cfg(not(target_os = "linux"))]
        let directory_mode = u32::from(libc::S_IFDIR);
        let root_live_statx = SourceStatxV1::for_test(
            1,
            1,
            1,
            1,
            directory_mode | 0o500,
            1,
            1,
            1,
            0,
            super::super::TimespecV1 {
                seconds: 0,
                nanoseconds: 0,
            },
            super::super::TimespecV1 {
                seconds: 0,
                nanoseconds: 0,
            },
            super::super::TimespecV1 {
                seconds: 0,
                nanoseconds: 0,
            },
            None,
        );
        let value = VerifiedBoundRegularBytesV1 {
            bytes: b"secret".to_vec(),
            nodes: Vec::new(),
            pinned_fds: Vec::new(),
            published_statx_commitment: [0; 102],
            root_statx_commitment: [0; 102],
            root_live_statx,
            terminal_identity_digest: Blake3Digest::derive(
                BOUND_REGULAR_IDENTITY_DOMAIN_V1,
                &[b"identity"],
            ),
            content_digest: FileContentDigest::derive(
                super::super::FILE_CONTENT_DOMAIN,
                &[b"secret"],
            ),
        };
        let debug = format!("{value:?}");
        assert!(!debug.contains("secret"));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn bounded_regular_read_distinguishes_exact_short_and_growth() {
        let memory = RuntimeMemoryEscrowV1::first_checkpoint();
        assert_eq!(
            read_exact_bound_regular_size_v1(&mut io::Cursor::new(b"exact"), 5, &memory).unwrap(),
            b"exact"
        );
        assert_eq!(
            read_exact_bound_regular_size_v1(&mut io::Cursor::new(b"short"), 6, &memory)
                .unwrap_err(),
            BoundRegularReadRefusalV1::ShortRead
        );
        assert_eq!(
            read_exact_bound_regular_size_v1(&mut io::Cursor::new(b"growth"), 5, &memory)
                .unwrap_err(),
            BoundRegularReadRefusalV1::SizeMismatch
        );
        assert_eq!(
            read_exact_bound_regular_size_v1(&mut io::Cursor::new(Vec::<u8>::new()), 0, &memory,)
                .unwrap(),
            Vec::<u8>::new()
        );

        struct AlwaysInterrupted;
        impl io::Read for AlwaysInterrupted {
            fn read(&mut self, _buffer: &mut [u8]) -> io::Result<usize> {
                Err(io::Error::from(io::ErrorKind::Interrupted))
            }
        }
        assert_eq!(
            read_exact_bound_regular_size_v1(&mut AlwaysInterrupted, 1, &memory).unwrap_err(),
            BoundRegularReadRefusalV1::Io
        );
    }

    #[test]
    fn runtime_memory_escrow_is_aggregate_fallible_and_linear() {
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
        <RuntimeMemoryEscrowV1 as AmbiguousIfClone<_>>::probe();
        <RuntimeMemoryEscrowV1 as AmbiguousIfCopy<_>>::probe();

        let memory = RuntimeMemoryEscrowV1 {
            remaining: Cell::new(4),
        };
        assert_eq!(memory.try_bytes_from_slice(b"four").unwrap(), b"four");
        assert_eq!(
            memory.try_bytes_from_slice(b"x").unwrap_err(),
            BoundRegularReadRefusalV1::MemoryBudget
        );
        assert!(format!("{memory:?}").contains("redacted-budget"));

        let allocation_failure = RuntimeMemoryEscrowV1::with_limit_for_test(8);
        assert_eq!(
            allocation_failure
                .try_vec_with_injected_allocation_failure_for_test::<u8>(8)
                .unwrap_err(),
            BoundRegularReadRefusalV1::MemoryBudget
        );
        assert_eq!(allocation_failure.remaining_for_test(), 8);
        let allocated = allocation_failure.try_vec_with_capacity::<u8>(8).unwrap();
        assert_eq!(
            allocation_failure.remaining_for_test(),
            8 - allocated.capacity()
        );

        let excess_capacity = RuntimeMemoryEscrowV1::with_limit_for_test(8);
        assert_eq!(
            excess_capacity
                .try_vec_with_excess_capacity_for_test::<u8>(8, 9)
                .unwrap_err(),
            BoundRegularReadRefusalV1::MemoryBudget
        );
        assert_eq!(excess_capacity.remaining_for_test(), 8);

        let replacement_memory = RuntimeMemoryEscrowV1::with_limit_for_test(64);
        let mut bytes = replacement_memory.try_bytes_from_slice(b"four").unwrap();
        let after_first = replacement_memory.remaining_for_test();
        replacement_memory
            .try_extend_bytes(&mut bytes, b"-more-than-spare")
            .unwrap();
        assert_eq!(bytes, b"four-more-than-spare");
        assert!(replacement_memory.remaining_for_test() < after_first);
    }
}
