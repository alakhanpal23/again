//! Crash-safe publication of one already-built snapshot directory.
//!
//! This leaf owns only the publication protocol. It creates an owner-private
//! staging directory beneath a trusted directory descriptor, keeps the inode
//! pinned by an owned descriptor, requires a trusted callback to attest that
//! every descendant has been made durable, fsyncs the staging root, publishes
//! with `renameat2(RENAME_NOREPLACE)`, fsyncs the parent, and reopens the final
//! name with constrained `openat2` resolution before returning it.
//!
//! It does not enumerate, copy, hash, validate, or make a tree immutable, and
//! it is not a sandbox. The caller must finish all tree construction and
//! recursive file/directory fsync work before its readiness callback returns.
//! No mutation is permitted after that callback succeeds.
//! Physical staging directories must remain owned by the current effective
//! user; source uid/gid are logical manifest metadata, never applied by chown.
//! RAII cleanup is bounded and best-effort: limit exhaustion or uncertain
//! identity leaves the private stage for explicit scavenging rather than
//! risking deletion of a replacement object.

use std::ffi::CStr;
use std::fmt;
use std::io;
use std::num::{NonZeroU8, NonZeroU16, NonZeroU32, NonZeroU64};
use std::os::fd::{BorrowedFd, OwnedFd};

use super::snapshot_connector::{SnapshotChargedErrorV1, SnapshotPublicationSessionV1};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use super::snapshot_policy::{SnapshotChargedBytesV1, SnapshotPipelineResourceErrorV1};

const STAGING_NAME_PREFIX: &[u8] = b".again-snapshot-stage-";
const STAGING_NONCE_HEX_BYTES: usize = 32;
const MAX_STAGING_NAME_WITH_NUL: u64 =
    (STAGING_NAME_PREFIX.len() + STAGING_NONCE_HEX_BYTES + 1) as u64;
const MAX_BASENAME_BYTES: usize = 255;
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
// The private staging container and the materialized tree root sit outside
// the source walker's descendant-depth budget.
const PUBLICATION_CONTAINER_LEVELS: u16 = 2;
const HARD_MAX_CLEANUP_DEPTH: u16 = HARD_MAX_SOURCE_TREE_DEPTH + PUBLICATION_CONTAINER_LEVELS;
// One descriptor pins an unpublished staging directory. Publication briefly
// owns that descriptor plus the constrained reopen of its final name.
const MAX_LIVE_STAGED_FDS: u32 = 1;
const MAX_LIVE_PUBLICATION_FDS: u32 = 2;
// Cleanup retains the original staging descriptor and its current-name
// revalidation descriptors. Each recursive level can additionally retain a
// pinned O_PATH child and a directory descriptor. This is the leaf's frozen,
// conservative descriptor envelope; caller-owned parent descriptors are not
// included.
const CLEANUP_FDS_PER_DEPTH: u32 = 2;
const CLEANUP_FIXED_FDS: u32 = 4;

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
        Some(Self {
            openat2_attempts,
            syscall_attempts,
            max_cleanup_depth,
            max_cleanup_entries,
            max_cleanup_name_bytes,
            max_cleanup_retained_name_bytes,
            max_cleanup_getdents_attempts,
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

    /// Descriptor retained while the caller builds and seals the stage.
    pub(super) const fn max_live_staged_fds(self) -> u32 {
        MAX_LIVE_STAGED_FDS
    }

    /// Conservative leaf-owned cleanup peak for this policy's depth.
    pub(super) const fn max_live_cleanup_fds(self) -> u32 {
        cleanup_fd_peak(self.max_cleanup_depth)
    }

    /// Descriptor peak while the final published name is reopened and bound.
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
    SyncStaging,
    ValidateFinalName,
    PublishRename,
    SyncParent,
    ReopenPublished,
    BindPublishedIdentity,
}

impl SnapshotPublishStageV1 {
    #[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
    const ALL_TRANSITIONS: [Self; 12] = [
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

pub(super) type StagedSnapshotDirectoryV1<'parent> = platform::StagedSnapshotDirectoryV1<'parent>;
pub(super) type ChargedStagedSnapshotDirectoryV1<'resources> =
    platform::ChargedStagedSnapshotDirectoryV1<'resources>;
pub(super) type VerifiedReadySnapshotDirectoryV1<'parent> =
    platform::VerifiedReadySnapshotDirectoryV1<'parent>;
pub(super) type PublishedSnapshotDirectoryV1 = platform::PublishedSnapshotDirectoryV1;

pub(super) fn create_charged_staged_snapshot_directory_at<'scope>(
    parent: BorrowedFd<'scope>,
    staging_name: &CStr,
    session: SnapshotPublicationSessionV1<'scope>,
) -> Result<ChargedStagedSnapshotDirectoryV1<'scope>, SnapshotChargedErrorV1<SnapshotPublishErrorV1>>
{
    platform::create_charged_staged_snapshot_directory_at(parent, staging_name, session)
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
    use std::mem::{self, MaybeUninit};
    use std::os::fd::{AsFd, AsRawFd, FromRawFd, RawFd};

    use super::*;

    #[cfg(test)]
    std::thread_local! {
        static CHARGED_DIRECTORY_FSTAT_CALLS: std::cell::Cell<u64> = const {
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
    }

    struct KernelTransitions;

    impl TransitionHookV1 for KernelTransitions {}

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
                    session.run_cleanup_attempt(attempt)
                }
                #[cfg(test)]
                (Self::Unmetered { .. }, _) => Ok(attempt()),
            }
        }

        #[cfg(test)]
        fn remaining_attempts(&self, bucket: PublisherAttemptBucketV1) -> Option<u64> {
            match (self, bucket) {
                (Self::Charged { session }, PublisherAttemptBucketV1::Forward) => {
                    Some(session.forward_attempts_remaining())
                }
                (Self::Charged { session }, PublisherAttemptBucketV1::Cleanup) => {
                    Some(session.cleanup_attempts_remaining())
                }
                (Self::Unmetered { .. }, _) => None,
            }
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

    /// A resource-charged staging guard. This narrow checkpoint deliberately
    /// exposes no ready/publish transition: those transitions are still
    /// unmetered and must not be reachable from a charged construction path.
    pub(in crate::linux_pytest) struct ChargedStagedSnapshotDirectoryV1<'resources> {
        cleanup: StagingCleanupV1<'resources>,
    }

    pub(in crate::linux_pytest) struct VerifiedReadySnapshotDirectoryV1<'parent> {
        cleanup: StagingCleanupV1<'parent>,
    }

    pub(in crate::linux_pytest) struct PublishedSnapshotDirectoryV1 {
        directory: OwnedFd,
        identity: SnapshotDirectoryIdentityV1,
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

    impl ChargedStagedSnapshotDirectoryV1<'_> {
        pub(in crate::linux_pytest) fn directory(&self) -> BorrowedFd<'_> {
            self.cleanup.directory()
        }

        pub(in crate::linux_pytest) fn cleanup_envelope(&self) -> SnapshotCleanupEnvelopeV1 {
            self.cleanup.policy().cleanup_envelope()
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

        pub(super) const fn identity(&self) -> SnapshotDirectoryIdentityV1 {
            self.identity
        }
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
            if !valid_raw_basename(final_name) || final_name == cleanup.staging_name.as_c_str() {
                return Err(SnapshotPublishErrorV1::new(
                    SnapshotPublishErrorKindV1::InvalidFinalName,
                    SnapshotPublishStageV1::ValidateFinalName,
                    SnapshotPublicationStateV1::Unpublished,
                    None,
                ));
            }

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
                identity: reopened_identity,
            })
        }
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
        for _ in 0..cleanup.policy().syscall_attempts() {
            match transitions.rename_noreplace(
                cleanup.parent,
                cleanup.staging_name.as_c_str(),
                cleanup.parent,
                final_name,
            ) {
                Ok(()) => {
                    cleanup.disarm();
                    return Ok(());
                }
                Err(error) => {
                    let old_binding = name_binding(
                        cleanup.parent,
                        cleanup.staging_name.as_c_str(),
                        cleanup.expected_identity(),
                        cleanup.policy().openat2_attempts(),
                    );
                    let final_binding = name_binding(
                        cleanup.parent,
                        final_name,
                        cleanup.expected_identity(),
                        cleanup.policy().openat2_attempts(),
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
                            return Err(rename_error(
                                error,
                                SnapshotPublicationStateV1::Unpublished,
                            ));
                        }
                        (Ok(NameBindingV1::Expected), Ok(NameBindingV1::Missing)) => {
                            return Err(rename_error(
                                error,
                                SnapshotPublicationStateV1::Unpublished,
                            ));
                        }
                        _ => {
                            cleanup.disarm();
                            return Err(rename_error(
                                error,
                                SnapshotPublicationStateV1::PublishedDurabilityUnknown,
                            ));
                        }
                    }
                }
            }
        }
        Err(SnapshotPublishErrorV1::new(
            SnapshotPublishErrorKindV1::Io,
            SnapshotPublishStageV1::PublishRename,
            SnapshotPublicationStateV1::Unpublished,
            Some(libc::EINTR),
        ))
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

    fn name_binding(
        parent: BorrowedFd<'_>,
        name: &CStr,
        expected: SnapshotDirectoryIdentityV1,
        attempts: u8,
    ) -> io::Result<NameBindingV1> {
        let current = match open_path_at(parent, name, attempts) {
            Ok(current) => current,
            Err(error) if error.raw_os_error() == Some(libc::ENOENT) => {
                return Ok(NameBindingV1::Missing);
            }
            Err(error) => return Err(error),
        };
        let current = cleanup_identity(current.as_fd())?;
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
                || !owner_private_directory(current_identity, self.effective_uid)
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
        let fd_identity = directory_identity(cleanup.directory()).map_err(|error| {
            identity_io_failure(
                SnapshotPublishStageV1::RevalidateStaging,
                SnapshotPublicationStateV1::Unpublished,
                error,
            )
        })?;
        let reopened = open_directory_at(
            cleanup.parent,
            cleanup.staging_name.as_c_str(),
            cleanup.policy().openat2_attempts(),
        )
        .map_err(|error| {
            io_failure(
                SnapshotPublishStageV1::RevalidateStaging,
                SnapshotPublicationStateV1::Unpublished,
                error,
            )
        })?;
        let reopened_identity = directory_identity(reopened.as_fd()).map_err(|error| {
            identity_io_failure(
                SnapshotPublishStageV1::RevalidateStaging,
                SnapshotPublicationStateV1::Unpublished,
                error,
            )
        })?;
        if !same_directory_object(fd_identity, cleanup.expected_identity())
            || reopened_identity != fd_identity
            || !owner_private_directory(fd_identity, cleanup.effective_uid)
        {
            return Err(identity_failure(
                SnapshotPublishStageV1::RevalidateStaging,
                SnapshotPublicationStateV1::Unpublished,
            ));
        }
        Ok(fd_identity)
    }

    fn owner_private_directory(identity: SnapshotDirectoryIdentityV1, effective_uid: u32) -> bool {
        identity.mode & libc::S_IFMT == libc::S_IFDIR
            && identity.mode & 0o7777 == PRIVATE_DIRECTORY_MODE
            && identity.uid == effective_uid
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
        let mut stat = MaybeUninit::<libc::stat>::zeroed();
        if unsafe { libc::fstat(directory.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let stat = unsafe { stat.assume_init() };

        let mut statx = MaybeUninit::<libc::statx>::zeroed();
        let result = unsafe {
            libc::syscall(
                libc::SYS_statx,
                directory.as_raw_fd(),
                c"".as_ptr(),
                AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                REQUIRED_STATX_MASK,
                statx.as_mut_ptr(),
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
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
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
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

    fn directory_identity_charged(
        authority: &PublisherAuthorityV1<'_>,
        bucket: PublisherAttemptBucketV1,
        directory: BorrowedFd<'_>,
    ) -> Result<SnapshotDirectoryIdentityV1, SnapshotChargedErrorV1<io::Error>> {
        let mut stat = MaybeUninit::<libc::stat>::zeroed();
        let fstat_result = authority
            .run_attempt(bucket, || unsafe {
                #[cfg(test)]
                CHARGED_DIRECTORY_FSTAT_CALLS.with(|calls| calls.set(calls.get() + 1));
                libc::fstat(directory.as_raw_fd(), stat.as_mut_ptr())
            })
            .map_err(SnapshotChargedErrorV1::Resource)?;
        if fstat_result != 0 {
            return Err(SnapshotChargedErrorV1::Leaf(io::Error::last_os_error()));
        }
        let stat = unsafe { stat.assume_init() };

        let mut statx = MaybeUninit::<libc::statx>::zeroed();
        let statx_result = authority
            .run_attempt(bucket, || unsafe {
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

    const fn linux_device_major(device: libc::dev_t) -> u32 {
        (((device & 0x0000_0000_000f_ff00) >> 8) | ((device & 0xffff_f000_0000_0000) >> 32)) as u32
    }

    const fn linux_device_minor(device: libc::dev_t) -> u32 {
        ((device & 0x0000_0000_0000_00ff) | ((device & 0x0000_0fff_fff0_0000) >> 12)) as u32
    }

    fn fsync_fd(fd: BorrowedFd<'_>, attempts: u8) -> io::Result<()> {
        retry_eintr_zero(attempts, || unsafe { libc::fsync(fd.as_raw_fd()) })
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
        let mut last = io::Error::from_raw_os_error(libc::EINTR);
        for _ in 0..attempts {
            let result = operation();
            if result == 0 {
                return Ok(());
            }
            last = io::Error::last_os_error();
            if last.kind() != io::ErrorKind::Interrupted {
                return Err(last);
            }
        }
        Err(last)
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
        let mut last = io::Error::from_raw_os_error(libc::EINTR);
        for _ in 0..attempts {
            let result = authority
                .run_attempt(bucket, &mut operation)
                .map_err(SnapshotChargedErrorV1::Resource)?;
            if result == 0 {
                return Ok(());
            }
            last = io::Error::last_os_error();
            if last.kind() != io::ErrorKind::Interrupted {
                return Err(SnapshotChargedErrorV1::Leaf(last));
            }
        }
        Err(SnapshotChargedErrorV1::Leaf(last))
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
        let mut stat = MaybeUninit::<libc::stat>::zeroed();
        if unsafe { libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { stat.assume_init() })
    }

    fn fstat_raw_charged(
        authority: &PublisherAuthorityV1<'_>,
        fd: BorrowedFd<'_>,
    ) -> Result<libc::stat, SnapshotChargedErrorV1<io::Error>> {
        let mut stat = MaybeUninit::<libc::stat>::zeroed();
        let result = authority
            .run_attempt(PublisherAttemptBucketV1::Cleanup, || unsafe {
                libc::fstat(fd.as_raw_fd(), stat.as_mut_ptr())
            })
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
        let stat = fstat_raw_charged(authority, fd)?;
        Ok(CleanupIdentityV1 {
            device: stat.st_dev,
            inode: stat.st_ino,
            mode_type: stat.st_mode & libc::S_IFMT,
            mode_permissions: stat.st_mode & 0o7777,
            uid: stat.st_uid,
        })
    }

    fn open_path_at(parent: BorrowedFd<'_>, name: &CStr, attempts: u8) -> io::Result<OwnedFd> {
        openat2_owned(
            parent,
            name,
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            attempts,
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
        let how = OpenHow {
            flags: flags as u64,
            mode: 0,
            resolve: SNAPSHOT_RESOLVE,
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

    fn openat2_owned_charged(
        authority: &PublisherAuthorityV1<'_>,
        bucket: PublisherAttemptBucketV1,
        parent: BorrowedFd<'_>,
        name: &CStr,
        flags: i32,
        attempts: u8,
    ) -> Result<OwnedFd, SnapshotChargedErrorV1<io::Error>> {
        let how = OpenHow {
            flags: flags as u64,
            mode: 0,
            resolve: SNAPSHOT_RESOLVE,
        };
        let mut last = io::Error::from_raw_os_error(libc::EAGAIN);
        for _ in 0..attempts {
            let result = authority
                .run_attempt(bucket, || unsafe {
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
        use std::fs::{self, File, OpenOptions};
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
        const CLEANUP_STRESS_NAME_COUNT: usize = 65;
        const CREATE_TRANSITION_COUNT: usize = 4;
        const READY_TRANSITION_COUNT: usize = 3;

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
                transient_heap_bytes,
                NonZeroU64::new(operation_attempts).unwrap(),
                NonZeroU8::new(4).unwrap(),
                NonZeroU8::new(3).unwrap(),
                NonZeroU8::new(2).unwrap(),
            )
            .unwrap();
            let resources =
                SnapshotPipelineResourcesV1::preflight(resource_policy, 0, u64::MAX, u64::MAX)
                    .unwrap();
            connect_snapshot_pipeline(resources).unwrap()
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
            // Four entries with open=4/syscall=3 reserve 272 cleanup attempts;
            // charged creation consumes exactly seven forward attempts.
            let connector = charged_connector(279, 1024 * 1024);
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
        fn zero_forward_budget_refuses_before_the_first_kernel_attempt() {
            // Four entries with open=4/syscall=3 reserve exactly 272 cleanup
            // attempts and leave no forward attempt.
            let fixture = Fixture::new();
            let connector = charged_connector(272, 1024 * 1024);
            CHARGED_DIRECTORY_FSTAT_CALLS.with(|calls| calls.set(0));
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
            assert_eq!(CHARGED_DIRECTORY_FSTAT_CALLS.with(|calls| calls.get()), 0);
            assert!(!fixture.staging_path().exists());
        }

        #[test]
        fn exhaustion_immediately_after_mkdir_uses_only_cleanup_reserve() {
            let fixture = Fixture::new();
            // Parent fstat/statx/geteuid plus mkdir consume four forward
            // attempts. The openat2 charge then refuses before its raw hook.
            let connector = charged_connector(276, 1024 * 1024);
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
            let connector =
                charged_connector_with_entries(cleanup_reserve + 7, 1024 * 1024, ENTRIES);
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

        #[test]
        fn every_state_transition_has_a_deterministic_fail_closed_checkpoint() {
            for (index, stage) in SnapshotPublishStageV1::ALL_TRANSITIONS
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
            assert_eq!(published.identity(), ready_identity);
            assert_eq!(
                directory_identity(published.directory()).unwrap(),
                ready_identity
            );
            assert!(fixture.final_path().is_dir());
            assert!(!fixture.staging_path().exists());
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
        identity: SnapshotDirectoryIdentityV1,
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

        pub(super) const fn identity(&self) -> SnapshotDirectoryIdentityV1 {
            self.identity
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
    fn final_basename_validation_is_raw_and_strict() {
        assert!(valid_raw_basename(c"snapshot-01"));
        assert!(valid_raw_basename(c"snapshot-\xFF"));
        assert!(!valid_raw_basename(c""));
        assert!(!valid_raw_basename(c"."));
        assert!(!valid_raw_basename(c".."));
        assert!(!valid_raw_basename(c"nested/name"));
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
}
