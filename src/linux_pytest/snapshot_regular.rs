//! Descriptor-selected regular-file materialization for `linux-pytest-v1`.
//!
//! This leaf deliberately does one thing: copy one already-enumerated source
//! basename into one private destination directory without ever resolving a
//! caller-controlled absolute path.  It preserves the source filesystem's
//! API-visible sparse extent sequence, hashes destination logical bytes, and
//! reopens both names to detect replacement races.  Xattrs, hardlinks,
//! metadata application, directory traversal, publication, and fsync ordering
//! belong to the higher-level snapshot builder.
//!
//! The operation runs before Python.  Consequently every error returned here
//! is a refusal; execute-only reasons are invalid at this boundary.

use std::ffi::CStr;
use std::fmt;
use std::num::{NonZeroU8, NonZeroU32, NonZeroU64};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};

#[cfg(any(test, all(target_os = "linux", target_arch = "x86_64")))]
use super::FileContentHasherV1;
use super::{ExtentV1, FileContentDigest, RefusalCode, TimespecV1};

// These hard ceilings are defense-in-depth above the smaller values selected
// by a committed profile.  The byte ceiling matches the repository's existing
// per-file capture ceiling, the extent ceiling matches the descriptor walker's
// entry ceiling, and retry work matches that walker's bound.
const HARD_MAX_LOGICAL_BYTES: u64 = 1024 * 1024 * 1024;
const HARD_MAX_DATA_EXTENTS: u32 = 1024 * 1024;
const HARD_MAX_OPENAT2_ATTEMPTS: u8 = 32;
const HARD_MAX_SYSCALL_ATTEMPTS: u8 = 32;

/// Bounded inputs that must eventually be committed by the snapshot-policy
/// digest.  Keeping them explicit prevents this leaf from inventing ambient
/// retry or resource policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RegularCopyPolicyV1 {
    max_logical_bytes: NonZeroU64,
    max_data_extents: NonZeroU32,
    openat2_attempts: NonZeroU8,
    syscall_attempts: NonZeroU8,
}

impl RegularCopyPolicyV1 {
    /// Returns `None` before any filesystem work if a caller requests work
    /// above this leaf's fixed hard ceilings.
    pub(super) const fn checked(
        max_logical_bytes: NonZeroU64,
        max_data_extents: NonZeroU32,
        openat2_attempts: NonZeroU8,
        syscall_attempts: NonZeroU8,
    ) -> Option<Self> {
        if max_logical_bytes.get() > HARD_MAX_LOGICAL_BYTES
            || max_data_extents.get() > HARD_MAX_DATA_EXTENTS
            || openat2_attempts.get() > HARD_MAX_OPENAT2_ATTEMPTS
            || syscall_attempts.get() > HARD_MAX_SYSCALL_ATTEMPTS
        {
            return None;
        }
        Some(Self {
            max_logical_bytes,
            max_data_extents,
            openat2_attempts,
            syscall_attempts,
        })
    }

    pub(super) const fn max_logical_bytes(self) -> u64 {
        self.max_logical_bytes.get()
    }

    pub(super) const fn max_data_extents(self) -> u32 {
        self.max_data_extents.get()
    }

    pub(super) const fn openat2_attempts(self) -> u8 {
        self.openat2_attempts.get()
    }

    pub(super) const fn syscall_attempts(self) -> u8 {
        self.syscall_attempts.get()
    }
}

/// Stable source metadata needed by the later manifest/xattr/hardlink stage.
/// `ctime` and `btime` are logical source metadata; a copied inode cannot have
/// the same physical values.
#[derive(Clone, Debug, Eq, PartialEq)]
struct StableStatxV1 {
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
}

/// A staged destination that must be finalized while its descriptor is pinned.
/// The source capabilities were revalidated before this value was returned.
pub(super) struct CopiedRegularV1 {
    destination: OwnedFd,
    content_digest: FileContentDigest,
    data_extents: Vec<ExtentV1>,
}

impl fmt::Debug for CopiedRegularV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CopiedRegularV1")
            .field("extent_count", &self.data_extents.len())
            .field("destination", &"<owned-fd>")
            .finish_non_exhaustive()
    }
}

impl CopiedRegularV1 {
    /// Complete destination-only work while the staged inode is pinned, then
    /// close that descriptor before returning FD-free evidence. The callback
    /// may apply metadata and must durably sync the inode; its scoped borrow
    /// cannot be retained by safe Rust.
    pub(super) fn finalize_with<T, E>(
        self,
        finalize: impl FnOnce(BorrowedFd<'_>) -> Result<T, E>,
    ) -> Result<(T, RegularCopyEvidenceV1), E> {
        let output = finalize(self.destination.as_fd())?;
        let Self {
            destination,
            content_digest,
            data_extents,
        } = self;
        drop(destination);
        Ok((
            output,
            RegularCopyEvidenceV1 {
                content_digest,
                data_extents,
            },
        ))
    }
}

/// Copy evidence with no retained filesystem capability.
pub(super) struct RegularCopyEvidenceV1 {
    content_digest: FileContentDigest,
    data_extents: Vec<ExtentV1>,
}

impl RegularCopyEvidenceV1 {
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

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SnapshotRegularStageV1 {
    ValidateSourceName,
    ValidateDestinationName,
    InspectSource,
    OpenSourceRead,
    CreateDestination,
    EnumerateSourceExtents,
    Reflink,
    RecreateForFallback,
    SparseCopy,
    EnumerateDestinationExtents,
    HashDestination,
    RevalidateSource,
    RevalidateDestination,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SnapshotRegularFailureV1 {
    code: RefusalCode,
    stage: SnapshotRegularStageV1,
    errno: Option<i32>,
}

impl SnapshotRegularFailureV1 {
    const fn new(code: RefusalCode, stage: SnapshotRegularStageV1, errno: Option<i32>) -> Self {
        Self { code, stage, errno }
    }

    pub(super) const fn code(self) -> RefusalCode {
        self.code
    }

    pub(super) const fn stage(self) -> SnapshotRegularStageV1 {
        self.stage
    }

    pub(super) const fn errno(self) -> Option<i32> {
        self.errno
    }
}

impl fmt::Display for SnapshotRegularFailureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} during {:?}", self.code.as_str(), self.stage)?;
        if let Some(errno) = self.errno {
            write!(formatter, " (errno {errno})")?;
        }
        Ok(())
    }
}

impl std::error::Error for SnapshotRegularFailureV1 {}

/// Copy one pinned regular source child into one new destination child.
///
/// Both directory descriptors and `source_handle` must already be trusted
/// capabilities. The source handle is bound to `source_parent/source_name`
/// before and after the copy, closing name-swap ABA windows at this boundary.
/// Names are raw C basenames, not paths. No ordinary-path fallback is
/// permitted.
/// # Safety
///
/// `source_parent`, `source_name`, and `source_handle` must come from the same
/// still-live `QualifiedNoAtimeSourceViewV1` enumeration callback. That view
/// must guarantee that ordinary source reads cannot mutate host metadata for
/// this call's full duration. The destination parent must be a current-user,
/// private staging directory in the already-qualified destination view.
pub(super) unsafe fn copy_regular_from_qualified_pinned_at(
    source_parent: BorrowedFd<'_>,
    source_name: &CStr,
    source_handle: BorrowedFd<'_>,
    destination_parent: BorrowedFd<'_>,
    destination_name: &CStr,
    policy: RegularCopyPolicyV1,
) -> Result<CopiedRegularV1, SnapshotRegularFailureV1> {
    platform::copy_regular_from_pinned_at(
        source_parent,
        source_name,
        source_handle,
        destination_parent,
        destination_name,
        policy,
    )
}

fn valid_basename(name: &CStr) -> bool {
    let bytes = name.to_bytes();
    !bytes.is_empty() && bytes != b"." && bytes != b".." && !bytes.contains(&b'/')
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod platform {
    use std::io;
    use std::mem::{self, MaybeUninit};
    use std::os::fd::{AsRawFd, FromRawFd, RawFd};

    use super::*;

    const RESOLVE_NO_XDEV: u64 = 0x01;
    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    const RESOLVE_BENEATH: u64 = 0x08;
    const SOURCE_RESOLVE: u64 = RESOLVE_BENEATH | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV;
    const AT_EMPTY_PATH: i32 = 0x1000;
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
    const STATX_MNT_ID: u32 = 0x1000;
    const COPY_BUFFER_BYTES: usize = 64 * 1024;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum BoundedReserveError {
        Full,
        Allocation,
    }

    fn try_reserve_bounded_for_push<T>(
        values: &mut Vec<T>,
        max_len: usize,
    ) -> Result<(), BoundedReserveError> {
        if values.len() >= max_len {
            return Err(BoundedReserveError::Full);
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
            .map_err(|_| BoundedReserveError::Allocation)
    }

    #[repr(C)]
    #[derive(Clone, Copy, Default)]
    struct OpenHow {
        flags: u64,
        mode: u64,
        resolve: u64,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct CleanupIdentity {
        device: u64,
        inode: u64,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum CleanupState {
        Absent,
        CreatedUnverified,
        Verified(CleanupIdentity),
    }

    #[cfg(test)]
    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ExtentObservationPoint {
        SourceRecheck,
        Destination,
    }

    trait CopyHooks {
        fn clone_file(&self, destination: RawFd, source: RawFd) -> io::Result<()>;

        #[cfg(test)]
        fn test_source_read_open_flags(&self) -> i32 {
            // Unit hooks model a qualified no-atime source view with a real
            // no-atime descriptor. `KernelHooks` overrides this so the
            // production path remains an ordinary read even under `cfg(test)`.
            source_read_open_flags() | libc::O_NOATIME
        }

        #[cfg(test)]
        fn after_source_handle_opened(&self) -> io::Result<()> {
            Ok(())
        }

        #[cfg(test)]
        fn destination_cleanup_identity(
            &self,
            destination: BorrowedFd<'_>,
        ) -> io::Result<CleanupIdentity> {
            fstat_cleanup_identity(destination)
        }

        #[cfg(test)]
        fn after_materialized(&self) -> io::Result<()> {
            Ok(())
        }

        #[cfg(test)]
        fn after_extent_observed(
            &self,
            _point: ExtentObservationPoint,
            _extents: &mut Vec<ExtentV1>,
        ) -> io::Result<()> {
            Ok(())
        }

        #[cfg(test)]
        fn before_destination_reopen(&self) -> io::Result<()> {
            Ok(())
        }
    }

    struct KernelHooks;

    impl CopyHooks for KernelHooks {
        fn clone_file(&self, destination: RawFd, source: RawFd) -> io::Result<()> {
            let result = unsafe { libc::ioctl(destination, libc::FICLONE as _, source) };
            if result == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }

        #[cfg(test)]
        fn test_source_read_open_flags(&self) -> i32 {
            source_read_open_flags()
        }
    }

    pub(super) fn copy_regular_from_pinned_at(
        source_parent: BorrowedFd<'_>,
        source_name: &CStr,
        source_handle: BorrowedFd<'_>,
        destination_parent: BorrowedFd<'_>,
        destination_name: &CStr,
        policy: RegularCopyPolicyV1,
    ) -> Result<CopiedRegularV1, SnapshotRegularFailureV1> {
        copy_regular_from_pinned_at_with(
            source_parent,
            source_name,
            source_handle,
            destination_parent,
            destination_name,
            policy,
            &KernelHooks,
        )
    }

    fn copy_regular_from_pinned_at_with<H: CopyHooks>(
        source_parent: BorrowedFd<'_>,
        source_name: &CStr,
        source_handle: BorrowedFd<'_>,
        destination_parent: BorrowedFd<'_>,
        destination_name: &CStr,
        policy: RegularCopyPolicyV1,
        hooks: &H,
    ) -> Result<CopiedRegularV1, SnapshotRegularFailureV1> {
        if !valid_basename(source_name) {
            return Err(SnapshotRegularFailureV1::new(
                RefusalCode::SnapshotRequiredObjectUnsupported,
                SnapshotRegularStageV1::ValidateSourceName,
                None,
            ));
        }
        if !valid_basename(destination_name) {
            return Err(SnapshotRegularFailureV1::new(
                RefusalCode::SnapshotConstructionFailed,
                SnapshotRegularStageV1::ValidateDestinationName,
                None,
            ));
        }

        let source_identity = statx_identity(source_handle)
            .map_err(|error| map_statx_failure(SnapshotRegularStageV1::InspectSource, error))?;
        if source_identity.mode & libc::S_IFMT != libc::S_IFREG {
            return Err(SnapshotRegularFailureV1::new(
                RefusalCode::SnapshotRequiredObjectUnsupported,
                SnapshotRegularStageV1::InspectSource,
                None,
            ));
        }
        if source_identity.size > policy.max_logical_bytes() {
            return Err(SnapshotRegularFailureV1::new(
                RefusalCode::SnapshotConstructionFailed,
                SnapshotRegularStageV1::InspectSource,
                None,
            ));
        }

        #[cfg(test)]
        hooks
            .after_source_handle_opened()
            .map_err(|error| construction_io(SnapshotRegularStageV1::OpenSourceRead, error))?;

        #[cfg(not(test))]
        let source_open_flags = source_read_open_flags();
        #[cfg(test)]
        let source_open_flags = hooks.test_source_read_open_flags();
        let source_read = openat2_owned(
            source_parent,
            source_name,
            source_open_flags,
            0,
            SOURCE_RESOLVE,
            policy.openat2_attempts(),
        )
        .map_err(|error| map_source_read_open(SnapshotRegularStageV1::OpenSourceRead, error))?;
        let read_identity = statx_identity(source_read.as_fd())
            .map_err(|error| map_statx_failure(SnapshotRegularStageV1::OpenSourceRead, error))?;
        if read_identity != source_identity {
            return Err(construction_failure(
                SnapshotRegularStageV1::OpenSourceRead,
                None,
            ));
        }

        let mut cleanup = DestinationCleanup::new(
            destination_parent,
            destination_name,
            policy.openat2_attempts(),
        );
        let mut destination = create_destination(&mut cleanup, hooks).map_err(|error| {
            map_destination_error(SnapshotRegularStageV1::CreateDestination, error)
        })?;

        let initial_extents = enumerate_extents(
            source_read.as_fd(),
            source_identity.size,
            policy.max_data_extents(),
        )
        .map_err(|error| map_extent_error(SnapshotRegularStageV1::EnumerateSourceExtents, error))?;

        match hooks.clone_file(destination.as_raw_fd(), source_read.as_raw_fd()) {
            Ok(()) => {}
            Err(error) if clone_fallback_error(&error) => {
                drop(destination);
                cleanup.remove_current().map_err(|error| {
                    map_destination_error(SnapshotRegularStageV1::RecreateForFallback, error)
                })?;
                destination = create_destination(&mut cleanup, hooks).map_err(|error| {
                    map_destination_error(SnapshotRegularStageV1::RecreateForFallback, error)
                })?;
                truncate_to(destination.as_fd(), source_identity.size).map_err(|error| {
                    map_destination_error(SnapshotRegularStageV1::SparseCopy, error)
                })?;
                copy_data_extents(
                    source_read.as_fd(),
                    destination.as_fd(),
                    &initial_extents,
                    policy.syscall_attempts(),
                )
                .map_err(|error| {
                    map_destination_error(SnapshotRegularStageV1::SparseCopy, error)
                })?;
            }
            Err(error) => {
                return Err(map_destination_error(
                    SnapshotRegularStageV1::Reflink,
                    error,
                ));
            }
        }

        #[cfg(test)]
        hooks.after_materialized().map_err(|error| {
            map_destination_error(SnapshotRegularStageV1::RevalidateSource, error)
        })?;

        let source_extents_after = enumerate_extents(
            source_read.as_fd(),
            source_identity.size,
            policy.max_data_extents(),
        )
        .map_err(|error| map_extent_error(SnapshotRegularStageV1::RevalidateSource, error))?;
        #[cfg(test)]
        let source_extents_after = {
            let mut observed = source_extents_after;
            hooks
                .after_extent_observed(ExtentObservationPoint::SourceRecheck, &mut observed)
                .map_err(|error| {
                    map_extent_error(SnapshotRegularStageV1::RevalidateSource, error)
                })?;
            observed
        };
        if source_extents_after != initial_extents {
            return Err(construction_failure(
                SnapshotRegularStageV1::RevalidateSource,
                None,
            ));
        }

        let destination_identity = statx_identity(destination.as_fd()).map_err(|error| {
            map_statx_failure(SnapshotRegularStageV1::RevalidateDestination, error)
        })?;
        if destination_identity.mode & libc::S_IFMT != libc::S_IFREG
            || destination_identity.size != source_identity.size
            || destination_identity.nlink != 1
        {
            return Err(construction_failure(
                SnapshotRegularStageV1::RevalidateDestination,
                None,
            ));
        }
        let destination_extents = enumerate_extents(
            destination.as_fd(),
            destination_identity.size,
            policy.max_data_extents(),
        )
        .map_err(|error| {
            map_extent_error(SnapshotRegularStageV1::EnumerateDestinationExtents, error)
        })?;
        #[cfg(test)]
        let destination_extents = {
            let mut observed = destination_extents;
            hooks
                .after_extent_observed(ExtentObservationPoint::Destination, &mut observed)
                .map_err(|error| {
                    map_extent_error(SnapshotRegularStageV1::EnumerateDestinationExtents, error)
                })?;
            observed
        };
        if destination_extents != initial_extents {
            return Err(construction_failure(
                SnapshotRegularStageV1::EnumerateDestinationExtents,
                None,
            ));
        }

        let content_digest = hash_logical_bytes(
            destination.as_fd(),
            destination_identity.size,
            policy.syscall_attempts(),
        )
        .map_err(|error| map_destination_error(SnapshotRegularStageV1::HashDestination, error))?;

        revalidate_source(
            source_parent,
            source_name,
            source_handle,
            source_read.as_fd(),
            &source_identity,
            policy.openat2_attempts(),
        )?;
        #[cfg(test)]
        hooks.before_destination_reopen().map_err(|error| {
            construction_io(SnapshotRegularStageV1::RevalidateDestination, error)
        })?;
        revalidate_destination(
            destination_parent,
            destination_name,
            destination.as_fd(),
            &destination_identity,
            policy.openat2_attempts(),
        )?;

        cleanup.disarm();
        Ok(CopiedRegularV1 {
            destination,
            content_digest,
            data_extents: initial_extents,
        })
    }

    const fn source_read_open_flags() -> i32 {
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC
    }

    const fn destination_open_flags() -> i32 {
        libc::O_RDWR
            | libc::O_CREAT
            | libc::O_EXCL
            | libc::O_NOFOLLOW
            | libc::O_NOATIME
            | libc::O_CLOEXEC
    }

    fn revalidate_source(
        parent: BorrowedFd<'_>,
        name: &CStr,
        path_handle: BorrowedFd<'_>,
        read_handle: BorrowedFd<'_>,
        expected: &StableStatxV1,
        attempts: u8,
    ) -> Result<(), SnapshotRegularFailureV1> {
        let path_after = statx_identity(path_handle)
            .map_err(|error| map_statx_failure(SnapshotRegularStageV1::RevalidateSource, error))?;
        let read_after = statx_identity(read_handle)
            .map_err(|error| map_statx_failure(SnapshotRegularStageV1::RevalidateSource, error))?;
        let reopened = openat2_owned(
            parent,
            name,
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
            SOURCE_RESOLVE,
            attempts,
        )
        .map_err(|error| construction_io(SnapshotRegularStageV1::RevalidateSource, error))?;
        let reopened_identity = statx_identity(reopened.as_fd())
            .map_err(|error| map_statx_failure(SnapshotRegularStageV1::RevalidateSource, error))?;
        if &path_after != expected || &read_after != expected || &reopened_identity != expected {
            return Err(construction_failure(
                SnapshotRegularStageV1::RevalidateSource,
                None,
            ));
        }
        Ok(())
    }

    fn revalidate_destination(
        parent: BorrowedFd<'_>,
        name: &CStr,
        destination: BorrowedFd<'_>,
        expected: &StableStatxV1,
        attempts: u8,
    ) -> Result<(), SnapshotRegularFailureV1> {
        let fd_after = statx_identity(destination).map_err(|error| {
            map_statx_failure(SnapshotRegularStageV1::RevalidateDestination, error)
        })?;
        let reopened = openat2_owned(
            parent,
            name,
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
            SOURCE_RESOLVE,
            attempts,
        )
        .map_err(|error| construction_io(SnapshotRegularStageV1::RevalidateDestination, error))?;
        let reopened_identity = statx_identity(reopened.as_fd()).map_err(|error| {
            map_statx_failure(SnapshotRegularStageV1::RevalidateDestination, error)
        })?;
        if fd_after != *expected || reopened_identity != *expected {
            return Err(construction_failure(
                SnapshotRegularStageV1::RevalidateDestination,
                None,
            ));
        }
        Ok(())
    }

    struct DestinationCleanup<'a> {
        parent: BorrowedFd<'a>,
        name: &'a CStr,
        attempts: u8,
        state: CleanupState,
    }

    impl<'a> DestinationCleanup<'a> {
        fn new(parent: BorrowedFd<'a>, name: &'a CStr, attempts: u8) -> Self {
            Self {
                parent,
                name,
                attempts,
                state: CleanupState::Absent,
            }
        }

        fn mark_created(&mut self) {
            self.state = CleanupState::CreatedUnverified;
        }

        fn arm<H: CopyHooks>(&mut self, destination: BorrowedFd<'_>, hooks: &H) -> io::Result<()> {
            #[cfg(not(test))]
            let identity = {
                let _ = hooks;
                fstat_cleanup_identity(destination)?
            };
            #[cfg(test)]
            let identity = hooks.destination_cleanup_identity(destination)?;
            self.state = CleanupState::Verified(identity);
            Ok(())
        }

        fn disarm(&mut self) {
            self.state = CleanupState::Absent;
        }

        fn remove_current(&mut self) -> io::Result<()> {
            match self.state {
                CleanupState::Absent => return Ok(()),
                CleanupState::CreatedUnverified => {}
                CleanupState::Verified(expected) => {
                    let current = openat2_owned(
                        self.parent,
                        self.name,
                        libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                        0,
                        SOURCE_RESOLVE,
                        self.attempts,
                    )?;
                    if fstat_cleanup_identity(current.as_fd())? != expected {
                        return Err(io::Error::from_raw_os_error(libc::ESTALE));
                    }
                }
            }
            let result = unsafe { libc::unlinkat(self.parent.as_raw_fd(), self.name.as_ptr(), 0) };
            if result != 0 {
                return Err(io::Error::last_os_error());
            }
            self.disarm();
            Ok(())
        }
    }

    impl Drop for DestinationCleanup<'_> {
        fn drop(&mut self) {
            // The destination parent is required to be owner-private and the
            // same-UID hostile-peer threat is outside the profile.  Once the
            // first fstat succeeds, compare the reopened inode before
            // unlinking so ordinary path replacement never deletes the
            // replacement.  Before that fstat, the O_EXCL-created name is
            // still removed rather than leaked.
            let _ = self.remove_current();
        }
    }

    fn create_destination<H: CopyHooks>(
        cleanup: &mut DestinationCleanup<'_>,
        hooks: &H,
    ) -> io::Result<OwnedFd> {
        let destination = openat2_owned(
            cleanup.parent,
            cleanup.name,
            destination_open_flags(),
            0o600,
            SOURCE_RESOLVE,
            cleanup.attempts,
        )?;
        cleanup.mark_created();
        cleanup.arm(destination.as_fd(), hooks)?;
        let identity = statx_identity(destination.as_fd())?;
        if identity.mode & libc::S_IFMT != libc::S_IFREG
            || identity.size != 0
            || identity.nlink != 1
        {
            return Err(io::Error::from_raw_os_error(libc::EIO));
        }
        Ok(destination)
    }

    fn openat2_owned(
        parent: BorrowedFd<'_>,
        name: &CStr,
        flags: i32,
        mode: u32,
        resolve: u64,
        attempts: u8,
    ) -> io::Result<OwnedFd> {
        let how = OpenHow {
            flags: flags as u64,
            mode: mode as u64,
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

    fn statx_identity(fd: BorrowedFd<'_>) -> io::Result<StableStatxV1> {
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
        Ok(StableStatxV1 {
            mount_id: raw.stx_mnt_id,
            device_major: raw.stx_dev_major,
            device_minor: raw.stx_dev_minor,
            inode: raw.stx_ino,
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

    fn fstat_cleanup_identity(fd: BorrowedFd<'_>) -> io::Result<CleanupIdentity> {
        let mut raw = MaybeUninit::<libc::stat>::zeroed();
        if unsafe { libc::fstat(fd.as_raw_fd(), raw.as_mut_ptr()) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let raw = unsafe { raw.assume_init() };
        Ok(CleanupIdentity {
            device: raw.st_dev,
            inode: raw.st_ino,
        })
    }

    fn enumerate_extents(
        fd: BorrowedFd<'_>,
        size: u64,
        max_extents: u32,
    ) -> io::Result<Vec<ExtentV1>> {
        if size == 0 {
            return Ok(Vec::new());
        }
        let mut extents = Vec::new();
        let mut cursor = 0u64;
        while cursor < size {
            let data =
                unsafe { libc::lseek(fd.as_raw_fd(), cursor as libc::off_t, libc::SEEK_DATA) };
            if data < 0 {
                let error = io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ENXIO) {
                    break;
                }
                return Err(error);
            }
            let data = data as u64;
            if data < cursor || data >= size {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            let hole = unsafe { libc::lseek(fd.as_raw_fd(), data as libc::off_t, libc::SEEK_HOLE) };
            if hole < 0 {
                return Err(io::Error::last_os_error());
            }
            let hole = hole as u64;
            if hole <= data || hole > size {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            try_reserve_bounded_for_push(&mut extents, max_extents as usize).map_err(|error| {
                io::Error::from_raw_os_error(match error {
                    BoundedReserveError::Full => libc::EFBIG,
                    BoundedReserveError::Allocation => libc::ENOMEM,
                })
            })?;
            extents.push(ExtentV1 {
                offset: data,
                length: hole - data,
            });
            cursor = hole;
        }
        Ok(extents)
    }

    fn truncate_to(destination: BorrowedFd<'_>, size: u64) -> io::Result<()> {
        if unsafe { libc::ftruncate(destination.as_raw_fd(), size as libc::off_t) } == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }

    fn copy_data_extents(
        source: BorrowedFd<'_>,
        destination: BorrowedFd<'_>,
        extents: &[ExtentV1],
        syscall_attempts: u8,
    ) -> io::Result<()> {
        let mut buffer = [0u8; COPY_BUFFER_BYTES];
        for extent in extents {
            let end = extent
                .offset
                .checked_add(extent.length)
                .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
            let mut offset = extent.offset;
            while offset < end {
                let length = usize::try_from((end - offset).min(buffer.len() as u64))
                    .map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
                pread_exact(source, &mut buffer[..length], offset, syscall_attempts)?;
                pwrite_all(destination, &buffer[..length], offset, syscall_attempts)?;
                offset += length as u64;
            }
        }
        Ok(())
    }

    fn pread_exact(
        fd: BorrowedFd<'_>,
        output: &mut [u8],
        offset: u64,
        syscall_attempts: u8,
    ) -> io::Result<()> {
        pread_exact_with(output, offset, syscall_attempts, |output, offset| {
            let result = unsafe {
                libc::pread(
                    fd.as_raw_fd(),
                    output.as_mut_ptr().cast(),
                    output.len(),
                    offset as libc::off_t,
                )
            };
            if result < 0 {
                Err(io::Error::last_os_error())
            } else {
                usize::try_from(result).map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))
            }
        })
    }

    fn pread_exact_with(
        mut output: &mut [u8],
        mut offset: u64,
        syscall_attempts: u8,
        mut operation: impl FnMut(&mut [u8], u64) -> io::Result<usize>,
    ) -> io::Result<()> {
        if output.is_empty() {
            return Ok(());
        }
        let mut exhaustion_errno = libc::EINTR;
        for _ in 0..syscall_attempts {
            let read = match operation(output, offset) {
                Ok(0) => return Err(io::Error::from_raw_os_error(libc::EIO)),
                Ok(read) if read <= output.len() => read,
                Ok(_) => return Err(io::Error::from_raw_os_error(libc::EIO)),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                    exhaustion_errno = libc::EINTR;
                    continue;
                }
                Err(error) => return Err(error),
            };
            exhaustion_errno = libc::EIO;
            offset = offset
                .checked_add(read as u64)
                .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
            output = &mut output[read..];
            if output.is_empty() {
                return Ok(());
            }
        }
        Err(io::Error::from_raw_os_error(exhaustion_errno))
    }

    fn pwrite_all(
        fd: BorrowedFd<'_>,
        input: &[u8],
        offset: u64,
        syscall_attempts: u8,
    ) -> io::Result<()> {
        pwrite_all_with(input, offset, syscall_attempts, |input, offset| {
            let result = unsafe {
                libc::pwrite(
                    fd.as_raw_fd(),
                    input.as_ptr().cast(),
                    input.len(),
                    offset as libc::off_t,
                )
            };
            if result < 0 {
                Err(io::Error::last_os_error())
            } else {
                usize::try_from(result).map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))
            }
        })
    }

    fn pwrite_all_with(
        mut input: &[u8],
        mut offset: u64,
        syscall_attempts: u8,
        mut operation: impl FnMut(&[u8], u64) -> io::Result<usize>,
    ) -> io::Result<()> {
        if input.is_empty() {
            return Ok(());
        }
        let mut exhaustion_errno = libc::EINTR;
        for _ in 0..syscall_attempts {
            let written = match operation(input, offset) {
                Ok(0) => return Err(io::Error::from_raw_os_error(libc::EIO)),
                Ok(written) if written <= input.len() => written,
                Ok(_) => return Err(io::Error::from_raw_os_error(libc::EIO)),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {
                    exhaustion_errno = libc::EINTR;
                    continue;
                }
                Err(error) => return Err(error),
            };
            exhaustion_errno = libc::EIO;
            offset = offset
                .checked_add(written as u64)
                .ok_or_else(|| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
            input = &input[written..];
            if input.is_empty() {
                return Ok(());
            }
        }
        Err(io::Error::from_raw_os_error(exhaustion_errno))
    }

    fn hash_logical_bytes(
        fd: BorrowedFd<'_>,
        size: u64,
        syscall_attempts: u8,
    ) -> io::Result<FileContentDigest> {
        let mut hasher = FileContentHasherV1::new(size);

        let mut buffer = [0u8; COPY_BUFFER_BYTES];
        let mut offset = 0u64;
        while offset < size {
            let length = usize::try_from((size - offset).min(buffer.len() as u64))
                .map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
            pread_exact(fd, &mut buffer[..length], offset, syscall_attempts)?;
            if !hasher.update(&buffer[..length]) {
                return Err(io::Error::from_raw_os_error(libc::EOVERFLOW));
            }
            offset += length as u64;
        }
        hasher
            .finish()
            .ok_or_else(|| io::Error::from_raw_os_error(libc::EIO))
    }

    fn clone_fallback_error(error: &io::Error) -> bool {
        matches!(
            error.raw_os_error(),
            Some(libc::ENOTTY | libc::EOPNOTSUPP | libc::EXDEV | libc::EINVAL)
        )
    }

    fn map_source_read_open(
        stage: SnapshotRegularStageV1,
        error: io::Error,
    ) -> SnapshotRegularFailureV1 {
        let errno = error.raw_os_error();
        let code = match errno {
            Some(libc::ENOSYS | libc::EINVAL | libc::E2BIG) => {
                RefusalCode::RequiredKernelCapabilityMissing
            }
            Some(libc::EACCES | libc::EPERM | libc::ELOOP | libc::EXDEV) => {
                RefusalCode::SnapshotRequiredObjectUnsupported
            }
            _ => RefusalCode::SnapshotConstructionFailed,
        };
        SnapshotRegularFailureV1::new(code, stage, errno)
    }

    fn map_statx_failure(
        stage: SnapshotRegularStageV1,
        error: io::Error,
    ) -> SnapshotRegularFailureV1 {
        let errno = error.raw_os_error();
        let code = match errno {
            Some(libc::ENOSYS | libc::EOPNOTSUPP | libc::EINVAL) => {
                RefusalCode::RequiredKernelCapabilityMissing
            }
            _ => RefusalCode::SnapshotConstructionFailed,
        };
        SnapshotRegularFailureV1::new(code, stage, errno)
    }

    fn map_extent_error(
        stage: SnapshotRegularStageV1,
        error: io::Error,
    ) -> SnapshotRegularFailureV1 {
        let errno = error.raw_os_error();
        let code = if errno == Some(libc::EINVAL) {
            RefusalCode::RequiredKernelCapabilityMissing
        } else {
            RefusalCode::SnapshotConstructionFailed
        };
        SnapshotRegularFailureV1::new(code, stage, errno)
    }

    fn map_destination_error(
        stage: SnapshotRegularStageV1,
        error: io::Error,
    ) -> SnapshotRegularFailureV1 {
        let errno = error.raw_os_error();
        let code = match errno {
            Some(libc::ENOSYS | libc::EOPNOTSUPP | libc::EINVAL | libc::E2BIG)
                if matches!(
                    stage,
                    SnapshotRegularStageV1::CreateDestination
                        | SnapshotRegularStageV1::RecreateForFallback
                ) =>
            {
                RefusalCode::RequiredKernelCapabilityMissing
            }
            _ => RefusalCode::SnapshotConstructionFailed,
        };
        SnapshotRegularFailureV1::new(code, stage, errno)
    }

    fn construction_io(
        stage: SnapshotRegularStageV1,
        error: io::Error,
    ) -> SnapshotRegularFailureV1 {
        construction_failure(stage, error.raw_os_error())
    }

    fn construction_failure(
        stage: SnapshotRegularStageV1,
        errno: Option<i32>,
    ) -> SnapshotRegularFailureV1 {
        SnapshotRegularFailureV1::new(RefusalCode::SnapshotConstructionFailed, stage, errno)
    }

    #[cfg(test)]
    mod tests {
        use std::cell::Cell;
        use std::ffi::{CStr, CString, OsStr};
        use std::fs::{self, File, OpenOptions};
        use std::io::{Seek, SeekFrom, Write};
        use std::os::fd::{AsFd, AsRawFd};
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::OpenOptionsExt;
        use std::path::{Path, PathBuf};

        use tempfile::TempDir;

        use super::*;

        fn policy() -> RegularCopyPolicyV1 {
            RegularCopyPolicyV1::checked(
                NonZeroU64::new(16 * 1024 * 1024).unwrap(),
                NonZeroU32::new(4096).unwrap(),
                NonZeroU8::new(4).unwrap(),
                NonZeroU8::new(4).unwrap(),
            )
            .unwrap()
        }

        #[test]
        fn bounded_vector_growth_refuses_the_exact_ceiling() {
            let mut values = Vec::new();
            for value in 0..3 {
                try_reserve_bounded_for_push(&mut values, 3).unwrap();
                values.push(value);
            }
            assert_eq!(
                try_reserve_bounded_for_push(&mut values, 3),
                Err(BoundedReserveError::Full)
            );
            assert_eq!(values, [0, 1, 2]);
        }

        fn open_directory(path: &Path) -> File {
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
                .open(path)
                .unwrap()
        }

        fn c_name(name: &OsStr) -> CString {
            CString::new(name.as_bytes()).unwrap()
        }

        struct Fixture {
            _temp: TempDir,
            source_dir: PathBuf,
            destination_dir: PathBuf,
            source_parent: File,
            destination_parent: File,
        }

        impl Fixture {
            fn empty() -> Self {
                let temp = TempDir::new().unwrap();
                let source_dir = temp.path().join("source");
                let destination_dir = temp.path().join("destination");
                fs::create_dir(&source_dir).unwrap();
                fs::create_dir(&destination_dir).unwrap();
                let source_parent = open_directory(&source_dir);
                let destination_parent = open_directory(&destination_dir);
                Self {
                    _temp: temp,
                    source_dir,
                    destination_dir,
                    source_parent,
                    destination_parent,
                }
            }

            fn with_input(bytes: &[u8]) -> Self {
                let fixture = Self::empty();
                fs::write(fixture.source("input"), bytes).unwrap();
                fixture
            }

            fn source(&self, name: impl AsRef<Path>) -> PathBuf {
                self.source_dir.join(name)
            }

            fn destination(&self, name: impl AsRef<Path>) -> PathBuf {
                self.destination_dir.join(name)
            }

            fn copy<H: CopyHooks>(
                &self,
                source_name: &CStr,
                destination_name: &CStr,
                policy: RegularCopyPolicyV1,
                hooks: &H,
            ) -> Result<CopiedRegularV1, SnapshotRegularFailureV1> {
                if !valid_basename(source_name) {
                    return Err(SnapshotRegularFailureV1::new(
                        RefusalCode::SnapshotRequiredObjectUnsupported,
                        SnapshotRegularStageV1::ValidateSourceName,
                        None,
                    ));
                }
                let source_handle = openat2_owned(
                    self.source_parent.as_fd(),
                    source_name,
                    libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    0,
                    SOURCE_RESOLVE,
                    policy.openat2_attempts(),
                )
                .map_err(|error| {
                    map_source_read_open(SnapshotRegularStageV1::OpenSourceRead, error)
                })?;
                copy_regular_from_pinned_at_with(
                    self.source_parent.as_fd(),
                    source_name,
                    source_handle.as_fd(),
                    self.destination_parent.as_fd(),
                    destination_name,
                    policy,
                    hooks,
                )
            }

            fn copy_input<H: CopyHooks>(
                &self,
                policy: RegularCopyPolicyV1,
                hooks: &H,
            ) -> Result<CopiedRegularV1, SnapshotRegularFailureV1> {
                self.copy(c"input", c"output", policy, hooks)
            }
        }

        struct ForcedCloneError {
            errno: i32,
            calls: Cell<u32>,
        }

        impl CopyHooks for ForcedCloneError {
            fn clone_file(&self, _destination: RawFd, _source: RawFd) -> io::Result<()> {
                self.calls.set(self.calls.get() + 1);
                Err(io::Error::from_raw_os_error(self.errno))
            }
        }

        struct MutateAfterCopy {
            source: PathBuf,
            original_mtime: std::time::SystemTime,
        }

        impl CopyHooks for MutateAfterCopy {
            fn clone_file(&self, _destination: RawFd, _source: RawFd) -> io::Result<()> {
                Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
            }

            fn after_materialized(&self) -> io::Result<()> {
                // Same logical length and usually the same extent layout: the
                // final statx identity check, not size or mtime alone, must
                // catch this content drift.
                fs::write(&self.source, b"changed!")?;
                OpenOptions::new()
                    .write(true)
                    .open(&self.source)?
                    .set_times(std::fs::FileTimes::new().set_modified(self.original_mtime))
            }
        }

        struct ReplaceAfterCopy {
            path: PathBuf,
            replacement: &'static [u8],
        }

        struct ReplaceBeforeRead {
            path: PathBuf,
        }

        struct ReplaceBeforeDestinationReopen {
            path: PathBuf,
            replacement: &'static [u8],
        }

        impl CopyHooks for ReplaceBeforeDestinationReopen {
            fn clone_file(&self, _destination: RawFd, _source: RawFd) -> io::Result<()> {
                Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
            }

            fn before_destination_reopen(&self) -> io::Result<()> {
                fs::remove_file(&self.path)?;
                fs::write(&self.path, self.replacement)
            }
        }

        impl CopyHooks for ReplaceBeforeRead {
            fn clone_file(&self, _destination: RawFd, _source: RawFd) -> io::Result<()> {
                panic!("clone must not be reached after source-name replacement")
            }

            fn after_source_handle_opened(&self) -> io::Result<()> {
                fs::remove_file(&self.path)?;
                fs::write(&self.path, b"replacement-before-read")
            }
        }

        impl CopyHooks for ReplaceAfterCopy {
            fn clone_file(&self, _destination: RawFd, _source: RawFd) -> io::Result<()> {
                Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
            }

            fn after_materialized(&self) -> io::Result<()> {
                fs::remove_file(&self.path)?;
                fs::write(&self.path, self.replacement)
            }
        }

        struct FailDestinationArm {
            errno: i32,
        }

        impl CopyHooks for FailDestinationArm {
            fn clone_file(&self, _destination: RawFd, _source: RawFd) -> io::Result<()> {
                panic!("clone must not be reached after destination-arm failure")
            }

            fn destination_cleanup_identity(
                &self,
                _destination: BorrowedFd<'_>,
            ) -> io::Result<CleanupIdentity> {
                Err(io::Error::from_raw_os_error(self.errno))
            }
        }

        struct InjectExtentDrift {
            point: ExtentObservationPoint,
        }

        impl CopyHooks for InjectExtentDrift {
            fn clone_file(&self, _destination: RawFd, _source: RawFd) -> io::Result<()> {
                Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
            }

            fn after_extent_observed(
                &self,
                point: ExtentObservationPoint,
                extents: &mut Vec<ExtentV1>,
            ) -> io::Result<()> {
                if point == self.point {
                    if let Some(first) = extents.first_mut() {
                        first.length = first.length.saturating_add(1);
                    } else {
                        extents.push(ExtentV1 {
                            offset: 0,
                            length: 1,
                        });
                    }
                }
                Ok(())
            }
        }

        fn finish(copied: CopiedRegularV1) -> RegularCopyEvidenceV1 {
            copied
                .finalize_with(|_| Ok::<(), std::convert::Infallible>(()))
                .unwrap()
                .1
        }

        fn run_forced_fallback(
            source_bytes: &[u8],
            errno: i32,
        ) -> (Fixture, RegularCopyEvidenceV1) {
            let fixture = Fixture::with_input(source_bytes);
            let hooks = ForcedCloneError {
                errno,
                calls: Cell::new(0),
            };
            let copied = fixture.copy_input(policy(), &hooks).unwrap();
            assert_eq!(hooks.calls.get(), 1);
            (fixture, finish(copied))
        }

        #[test]
        fn exact_clone_fallback_errno_set_is_frozen() {
            for errno in [libc::ENOTTY, libc::EOPNOTSUPP, libc::EXDEV, libc::EINVAL] {
                assert!(clone_fallback_error(&io::Error::from_raw_os_error(errno)));
            }
            for errno in [libc::EIO, libc::ENOSPC, libc::EPERM, libc::EACCES] {
                assert!(!clone_fallback_error(&io::Error::from_raw_os_error(errno)));
            }
        }

        #[test]
        fn pread_budget_accepts_exact_n_and_refuses_n_plus_one() {
            let mut output = [0u8; 4];
            let mut success_calls = 0;
            pread_exact_with(&mut output, 11, 3, |remaining, offset| {
                success_calls += 1;
                match success_calls {
                    1 => Err(io::Error::from_raw_os_error(libc::EINTR)),
                    2 => {
                        assert_eq!(offset, 11);
                        remaining[..2].copy_from_slice(b"ab");
                        Ok(2)
                    }
                    3 => {
                        assert_eq!(offset, 13);
                        remaining.copy_from_slice(b"cd");
                        Ok(remaining.len())
                    }
                    _ => panic!("pread exceeded its committed attempt budget"),
                }
            })
            .unwrap();
            assert_eq!(output, *b"abcd");
            assert_eq!(success_calls, 3);

            let mut interrupted_calls = 0;
            let error = pread_exact_with(&mut [0u8; 1], 0, 3, |_, _| {
                interrupted_calls += 1;
                Err(io::Error::from_raw_os_error(libc::EINTR))
            })
            .unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EINTR));
            assert_eq!(interrupted_calls, 3);

            let mut partial_calls = 0;
            let error = pread_exact_with(&mut [0u8; 3], 0, 2, |remaining, _| {
                partial_calls += 1;
                remaining[0] = b'x';
                Ok(1)
            })
            .unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EIO));
            assert_eq!(partial_calls, 2);
        }

        #[test]
        fn pwrite_budget_accepts_exact_n_and_refuses_n_plus_one() {
            let mut success_calls = 0;
            pwrite_all_with(b"abcd", 17, 3, |remaining, offset| {
                success_calls += 1;
                match success_calls {
                    1 => Err(io::Error::from_raw_os_error(libc::EINTR)),
                    2 => {
                        assert_eq!(offset, 17);
                        assert_eq!(remaining, b"abcd");
                        Ok(2)
                    }
                    3 => {
                        assert_eq!(offset, 19);
                        assert_eq!(remaining, b"cd");
                        Ok(2)
                    }
                    _ => panic!("pwrite exceeded its committed attempt budget"),
                }
            })
            .unwrap();
            assert_eq!(success_calls, 3);

            let mut interrupted_calls = 0;
            let error = pwrite_all_with(b"x", 0, 3, |_, _| {
                interrupted_calls += 1;
                Err(io::Error::from_raw_os_error(libc::EINTR))
            })
            .unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EINTR));
            assert_eq!(interrupted_calls, 3);

            let mut partial_calls = 0;
            let error = pwrite_all_with(b"abc", 0, 2, |_, _| {
                partial_calls += 1;
                Ok(1)
            })
            .unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EIO));
            assert_eq!(partial_calls, 2);
        }

        #[test]
        fn source_authority_uses_ordinary_reads_but_destination_keeps_noatime() {
            assert_eq!(source_read_open_flags() & libc::O_NOATIME, 0);
            assert_ne!(destination_open_flags() & libc::O_NOATIME, 0);
            assert_ne!(source_read_open_flags() & libc::O_NOFOLLOW, 0);
            assert_ne!(destination_open_flags() & libc::O_EXCL, 0);

            let source_denied = map_source_read_open(
                SnapshotRegularStageV1::OpenSourceRead,
                io::Error::from_raw_os_error(libc::EPERM),
            );
            assert_eq!(
                source_denied.code(),
                RefusalCode::SnapshotRequiredObjectUnsupported
            );
            assert_eq!(source_denied.errno(), Some(libc::EPERM));

            let missing_destination_statx = map_destination_error(
                SnapshotRegularStageV1::CreateDestination,
                io::Error::from_raw_os_error(libc::EOPNOTSUPP),
            );
            assert_eq!(
                missing_destination_statx.code(),
                RefusalCode::RequiredKernelCapabilityMissing
            );
            let sparse_copy_io = map_destination_error(
                SnapshotRegularStageV1::SparseCopy,
                io::Error::from_raw_os_error(libc::EOPNOTSUPP),
            );
            assert_eq!(
                sparse_copy_io.code(),
                RefusalCode::SnapshotConstructionFailed
            );
        }

        #[test]
        fn test_source_view_preserves_a_stale_atime_without_forging_future_time() {
            use std::os::unix::fs::MetadataExt;
            use std::time::{Duration, UNIX_EPOCH};

            let fixture = Fixture::with_input(b"qualified fixture read");
            let source_path = fixture.source("input");
            let stale_atime = UNIX_EPOCH + Duration::from_secs(946_684_800);
            OpenOptions::new()
                .read(true)
                .open(&source_path)
                .unwrap()
                .set_times(std::fs::FileTimes::new().set_accessed(stale_atime))
                .unwrap();
            let before = fs::metadata(&source_path).unwrap();
            let before_atime = (before.atime(), before.atime_nsec());
            assert!(before.atime() <= before.mtime());

            let copied = fixture
                .copy_input(
                    policy(),
                    &ForcedCloneError {
                        errno: libc::EOPNOTSUPP,
                        calls: Cell::new(0),
                    },
                )
                .unwrap();
            let _ = finish(copied);

            let after = fs::metadata(source_path).unwrap();
            assert_eq!((after.atime(), after.atime_nsec()), before_atime);
        }

        #[test]
        fn failure_between_o_excl_create_and_arm_removes_unverified_inode() {
            let fixture = Fixture::with_input(b"content");
            let error = fixture
                .copy_input(policy(), &FailDestinationArm { errno: libc::EIO })
                .unwrap_err();
            assert_eq!(error.code(), RefusalCode::SnapshotConstructionFailed);
            assert_eq!(error.stage(), SnapshotRegularStageV1::CreateDestination);
            assert_eq!(error.errno(), Some(libc::EIO));
            assert!(!fixture.destination("output").exists());
        }

        #[test]
        fn injected_source_and_destination_extent_drift_are_exact_refusals() {
            for (point, expected_stage) in [
                (
                    ExtentObservationPoint::SourceRecheck,
                    SnapshotRegularStageV1::RevalidateSource,
                ),
                (
                    ExtentObservationPoint::Destination,
                    SnapshotRegularStageV1::EnumerateDestinationExtents,
                ),
            ] {
                let fixture = Fixture::with_input(&[0x5a; 8192]);
                let error = fixture
                    .copy_input(policy(), &InjectExtentDrift { point })
                    .unwrap_err();
                assert_eq!(error.code(), RefusalCode::SnapshotConstructionFailed);
                assert_eq!(error.stage(), expected_stage);
                assert!(!fixture.destination("output").exists());
            }
        }

        #[test]
        fn forced_fallback_copies_dense_destination_bytes_and_digest() {
            let bytes = b"descriptor selected copy";
            let (fixture, evidence) = run_forced_fallback(bytes, libc::EOPNOTSUPP);
            assert_eq!(fs::read(fixture.destination("output")).unwrap(), bytes);
            assert_eq!(
                evidence.content_digest(),
                FileContentDigest::derive(super::super::super::FILE_CONTENT_DOMAIN, &[bytes])
            );
        }

        #[test]
        fn finalize_is_scoped_and_returns_fd_free_owned_evidence() {
            let (_fixture, copied) = {
                let fixture = Fixture::with_input(b"finalize");
                let hooks = ForcedCloneError {
                    errno: libc::EOPNOTSUPP,
                    calls: Cell::new(0),
                };
                let copied = fixture.copy_input(policy(), &hooks).unwrap();
                (fixture, copied)
            };
            let raw = Cell::new(-1);
            let (marker, evidence) = copied
                .finalize_with(|fd| {
                    raw.set(fd.as_raw_fd());
                    assert!(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GETFD) } >= 0);
                    Ok::<_, std::convert::Infallible>(7u8)
                })
                .unwrap();
            assert_eq!(marker, 7);
            assert_eq!(unsafe { libc::fcntl(raw.get(), libc::F_GETFD) }, -1);
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF));
            let (digest, extents) = evidence.into_parts();
            assert_eq!(
                digest,
                FileContentDigest::derive(super::super::super::FILE_CONTENT_DOMAIN, &[b"finalize"])
            );
            assert!(!extents.is_empty());
        }

        #[test]
        fn forced_fallback_preserves_api_visible_sparse_extents() {
            let fixture = Fixture::empty();
            let source_path = fixture.source("sparse");
            let mut source = OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .open(&source_path)
                .unwrap();
            source.set_len(512 * 1024).unwrap();
            source.seek(SeekFrom::Start(64 * 1024)).unwrap();
            source.write_all(b"first-data-range").unwrap();
            source.seek(SeekFrom::Start(384 * 1024)).unwrap();
            source.write_all(b"second-data-range").unwrap();
            source.sync_all().unwrap();

            let hooks = ForcedCloneError {
                errno: libc::EOPNOTSUPP,
                calls: Cell::new(0),
            };
            let evidence = finish(fixture.copy(c"sparse", c"copy", policy(), &hooks).unwrap());
            let destination = File::open(fixture.destination("copy")).unwrap();
            let observed = enumerate_extents(destination.as_fd(), 512 * 1024, 4096).unwrap();
            assert_eq!(observed, evidence.data_extents());
            assert_eq!(
                fs::metadata(fixture.destination("copy")).unwrap().len(),
                512 * 1024
            );
        }

        #[test]
        fn written_zero_extent_remains_data_and_hashes_as_logical_bytes() {
            let fixture = Fixture::empty();
            let source_path = fixture.source("zeros");
            let mut source = OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .open(&source_path)
                .unwrap();
            source.set_len(1024 * 1024).unwrap();
            source.seek(SeekFrom::Start(512 * 1024)).unwrap();
            source.write_all(&[0; 4096]).unwrap();
            source.sync_all().unwrap();

            let evidence = finish(
                fixture
                    .copy(
                        c"zeros",
                        c"copy",
                        policy(),
                        &ForcedCloneError {
                            errno: libc::EOPNOTSUPP,
                            calls: Cell::new(0),
                        },
                    )
                    .unwrap(),
            );
            assert!(!evidence.data_extents().is_empty());
            let bytes = fs::read(fixture.destination("copy")).unwrap();
            assert_eq!(bytes, vec![0; 1024 * 1024]);
            assert_eq!(
                evidence.content_digest(),
                FileContentDigest::derive(super::super::super::FILE_CONTENT_DOMAIN, &[&bytes])
            );
        }

        #[test]
        fn empty_and_all_hole_files_keep_empty_extent_lists() {
            let (_fixture, empty) = run_forced_fallback(b"", libc::EINVAL);
            assert!(empty.data_extents().is_empty());

            let fixture = Fixture::empty();
            File::create(fixture.source("hole"))
                .unwrap()
                .set_len(1024 * 1024)
                .unwrap();
            let hooks = ForcedCloneError {
                errno: libc::EXDEV,
                calls: Cell::new(0),
            };
            let evidence = finish(fixture.copy(c"hole", c"copy", policy(), &hooks).unwrap());
            assert!(evidence.data_extents().is_empty());
            assert_eq!(
                fs::metadata(fixture.destination("copy")).unwrap().len(),
                1024 * 1024
            );
        }

        #[test]
        fn hard_clone_errors_never_fall_back_and_raii_removes_partial_destination() {
            for errno in [libc::EIO, libc::ENOSPC, libc::EPERM] {
                let fixture = Fixture::with_input(b"content");
                let hooks = ForcedCloneError {
                    errno,
                    calls: Cell::new(0),
                };
                let error = fixture.copy_input(policy(), &hooks).unwrap_err();
                assert_eq!(error.code(), RefusalCode::SnapshotConstructionFailed);
                assert_eq!(error.stage(), SnapshotRegularStageV1::Reflink);
                assert_eq!(error.errno(), Some(errno));
                assert_eq!(hooks.calls.get(), 1);
                assert!(!fixture.destination("output").exists());
            }
        }

        #[test]
        fn source_name_replacement_between_path_and_read_open_is_detected() {
            let fixture = Fixture::with_input(b"original");
            let source_path = fixture.source("input");
            let error = fixture
                .copy_input(
                    policy(),
                    &ReplaceBeforeRead {
                        path: source_path.clone(),
                    },
                )
                .unwrap_err();
            assert_eq!(error.code(), RefusalCode::SnapshotConstructionFailed);
            assert_eq!(error.stage(), SnapshotRegularStageV1::OpenSourceRead);
            assert_eq!(fs::read(source_path).unwrap(), b"replacement-before-read");
            assert!(!fixture.destination("output").exists());
        }

        #[test]
        fn deterministic_post_copy_mutation_is_refused_and_cleaned() {
            use std::os::unix::fs::MetadataExt;
            use std::time::{Duration, UNIX_EPOCH};

            let fixture = Fixture::with_input(b"original");
            let source_path = fixture.source("input");
            let original_mtime = UNIX_EPOCH + Duration::from_secs(946_684_801);
            OpenOptions::new()
                .write(true)
                .open(&source_path)
                .unwrap()
                .set_times(std::fs::FileTimes::new().set_modified(original_mtime))
                .unwrap();
            let before = fs::metadata(&source_path).unwrap();
            let before_mtime = (before.mtime(), before.mtime_nsec());
            let error = fixture
                .copy_input(
                    policy(),
                    &MutateAfterCopy {
                        source: source_path.clone(),
                        original_mtime,
                    },
                )
                .unwrap_err();
            assert_eq!(error.code(), RefusalCode::SnapshotConstructionFailed);
            assert_eq!(error.stage(), SnapshotRegularStageV1::RevalidateSource);
            let after = fs::metadata(source_path).unwrap();
            assert_eq!((after.mtime(), after.mtime_nsec()), before_mtime);
            assert!(!fixture.destination("output").exists());
        }

        #[test]
        fn source_unlink_recreate_is_detected_and_partial_destination_is_cleaned() {
            let fixture = Fixture::with_input(b"original");
            let source_path = fixture.source("input");
            let error = fixture
                .copy_input(
                    policy(),
                    &ReplaceAfterCopy {
                        path: source_path.clone(),
                        replacement: b"replacement",
                    },
                )
                .unwrap_err();
            assert_eq!(error.code(), RefusalCode::SnapshotConstructionFailed);
            assert_eq!(error.stage(), SnapshotRegularStageV1::RevalidateSource);
            assert_eq!(fs::read(source_path).unwrap(), b"replacement");
            assert!(!fixture.destination("output").exists());
        }

        #[test]
        fn destination_unlink_recreate_is_detected_without_deleting_replacement() {
            let fixture = Fixture::with_input(b"original");
            let destination_path = fixture.destination("output");
            let error = fixture
                .copy_input(
                    policy(),
                    &ReplaceBeforeDestinationReopen {
                        path: destination_path.clone(),
                        replacement: b"replacement-must-survive",
                    },
                )
                .unwrap_err();
            assert_eq!(error.code(), RefusalCode::SnapshotConstructionFailed);
            assert_eq!(error.stage(), SnapshotRegularStageV1::RevalidateDestination);
            assert_eq!(
                fs::read(destination_path).unwrap(),
                b"replacement-must-survive"
            );
        }

        #[test]
        fn source_symlink_and_destination_collision_fail_closed() {
            use std::os::unix::fs::symlink;

            let fixture = Fixture::empty();
            fs::write(fixture.source("target"), b"secret").unwrap();
            symlink("target", fixture.source("input")).unwrap();
            let source_error = fixture
                .copy_input(
                    policy(),
                    &ForcedCloneError {
                        errno: libc::EOPNOTSUPP,
                        calls: Cell::new(0),
                    },
                )
                .unwrap_err();
            assert_eq!(
                source_error.code(),
                RefusalCode::SnapshotRequiredObjectUnsupported
            );

            fs::remove_file(fixture.source("input")).unwrap();
            fs::write(fixture.source("input"), b"ordinary").unwrap();
            symlink("do-not-touch", fixture.destination("output")).unwrap();
            let destination_error = fixture
                .copy_input(
                    policy(),
                    &ForcedCloneError {
                        errno: libc::EOPNOTSUPP,
                        calls: Cell::new(0),
                    },
                )
                .unwrap_err();
            assert_eq!(
                destination_error.code(),
                RefusalCode::SnapshotConstructionFailed
            );
            assert_eq!(
                fs::read_link(fixture.destination("output")).unwrap(),
                Path::new("do-not-touch")
            );

            fs::remove_file(fixture.destination("output")).unwrap();
            fs::write(fixture.destination("output"), b"preexisting").unwrap();
            let regular_collision = fixture
                .copy_input(
                    policy(),
                    &ForcedCloneError {
                        errno: libc::EOPNOTSUPP,
                        calls: Cell::new(0),
                    },
                )
                .unwrap_err();
            assert_eq!(
                regular_collision.stage(),
                SnapshotRegularStageV1::CreateDestination
            );
            assert_eq!(regular_collision.errno(), Some(libc::EEXIST));
            assert_eq!(
                fs::read(fixture.destination("output")).unwrap(),
                b"preexisting"
            );
        }

        #[test]
        fn directories_fifos_and_unix_sockets_are_rejected_before_read_open() {
            use std::os::unix::net::UnixListener;

            let fixture = Fixture::empty();
            fs::create_dir(fixture.source("directory")).unwrap();
            let fifo_name = CString::new("fifo").unwrap();
            assert_eq!(
                unsafe {
                    libc::mkfifoat(fixture.source_parent.as_raw_fd(), fifo_name.as_ptr(), 0o600)
                },
                0
            );
            let _listener = UnixListener::bind(fixture.source("socket")).unwrap();

            for name in ["directory", "fifo", "socket"] {
                let error = fixture
                    .copy(
                        &CString::new(name).unwrap(),
                        &CString::new(format!("copy-{name}")).unwrap(),
                        policy(),
                        &ForcedCloneError {
                            errno: libc::EOPNOTSUPP,
                            calls: Cell::new(0),
                        },
                    )
                    .unwrap_err();
                assert_eq!(error.code(), RefusalCode::SnapshotRequiredObjectUnsupported);
                assert_eq!(error.stage(), SnapshotRegularStageV1::InspectSource);
                assert!(!fixture.destination(format!("copy-{name}")).exists());
            }
        }

        #[test]
        fn max_extent_count_fails_before_clone_and_cleans_destination() {
            let fixture = Fixture::empty();
            let source_path = fixture.source("fragmented");
            let mut source = OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .open(&source_path)
                .unwrap();
            source.set_len(16 * 1024 * 1024).unwrap();
            source.seek(SeekFrom::Start(0)).unwrap();
            source.write_all(&[0x11; 4096]).unwrap();
            source.seek(SeekFrom::Start(8 * 1024 * 1024)).unwrap();
            source.write_all(&[0x22; 4096]).unwrap();
            source.sync_all().unwrap();
            let observed = enumerate_extents(source.as_fd(), 16 * 1024 * 1024, 4096).unwrap();
            assert!(
                observed.len() >= 2,
                "hosted Linux qualification filesystem must expose the two sparse data ranges"
            );

            let one_extent = RegularCopyPolicyV1::checked(
                NonZeroU64::new(16 * 1024 * 1024).unwrap(),
                NonZeroU32::new(1).unwrap(),
                NonZeroU8::new(4).unwrap(),
                NonZeroU8::new(4).unwrap(),
            )
            .unwrap();
            let hooks = ForcedCloneError {
                errno: libc::EOPNOTSUPP,
                calls: Cell::new(0),
            };
            let error = fixture
                .copy(c"fragmented", c"output", one_extent, &hooks)
                .unwrap_err();
            assert_eq!(error.code(), RefusalCode::SnapshotConstructionFailed);
            assert_eq!(
                error.stage(),
                SnapshotRegularStageV1::EnumerateSourceExtents
            );
            assert_eq!(error.errno(), Some(libc::EFBIG));
            assert_eq!(hooks.calls.get(), 0);
            assert!(!fixture.destination("output").exists());
        }

        #[test]
        fn raw_non_utf8_basename_is_supported() {
            let fixture = Fixture::empty();
            let raw = OsStr::from_bytes(b"in-\xff");
            fs::write(fixture.source(raw), b"raw-name").unwrap();
            let copied = fixture
                .copy(
                    &c_name(raw),
                    c"output",
                    policy(),
                    &ForcedCloneError {
                        errno: libc::ENOTTY,
                        calls: Cell::new(0),
                    },
                )
                .unwrap();
            let _ = finish(copied);
            assert_eq!(
                fs::read(fixture.destination("output")).unwrap(),
                b"raw-name"
            );
        }

        #[test]
        fn invalid_names_and_size_limit_have_exact_refusals() {
            let fixture = Fixture::with_input(b"too-large");
            let hooks = ForcedCloneError {
                errno: libc::EOPNOTSUPP,
                calls: Cell::new(0),
            };
            let invalid_source = fixture
                .copy(c"..", c"output", policy(), &hooks)
                .unwrap_err();
            assert_eq!(
                invalid_source.code(),
                RefusalCode::SnapshotRequiredObjectUnsupported
            );
            assert_eq!(
                invalid_source.stage(),
                SnapshotRegularStageV1::ValidateSourceName
            );

            let invalid_destination = fixture
                .copy(c"input", c"bad/name", policy(), &hooks)
                .unwrap_err();
            assert_eq!(
                invalid_destination.code(),
                RefusalCode::SnapshotConstructionFailed
            );

            let tiny_policy = RegularCopyPolicyV1::checked(
                NonZeroU64::new(1).unwrap(),
                NonZeroU32::new(1).unwrap(),
                NonZeroU8::new(1).unwrap(),
                NonZeroU8::new(1).unwrap(),
            )
            .unwrap();
            let limit = fixture.copy_input(tiny_policy, &hooks).unwrap_err();
            assert_eq!(limit.code(), RefusalCode::SnapshotConstructionFailed);
            assert_eq!(limit.stage(), SnapshotRegularStageV1::InspectSource);
            assert!(!fixture.destination("output").exists());
        }
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
mod platform {
    use super::*;

    pub(super) fn copy_regular_from_pinned_at(
        _source_parent: BorrowedFd<'_>,
        _source_name: &CStr,
        _source_handle: BorrowedFd<'_>,
        _destination_parent: BorrowedFd<'_>,
        _destination_name: &CStr,
        _policy: RegularCopyPolicyV1,
    ) -> Result<CopiedRegularV1, SnapshotRegularFailureV1> {
        #[cfg(not(target_os = "linux"))]
        let code = RefusalCode::UnsupportedOs;
        #[cfg(all(target_os = "linux", not(target_arch = "x86_64")))]
        let code = RefusalCode::UnsupportedArchitecture;
        Err(SnapshotRegularFailureV1::new(
            code,
            SnapshotRegularStageV1::OpenSourceRead,
            None,
        ))
    }
}

#[cfg(test)]
mod portable_tests {
    use super::*;

    #[test]
    fn basename_validation_is_raw_and_strict() {
        assert!(valid_basename(c"ordinary"));
        assert!(valid_basename(c"raw-\xFF"));
        assert!(!valid_basename(c""));
        assert!(!valid_basename(c"."));
        assert!(!valid_basename(c".."));
        assert!(!valid_basename(c"a/b"));
    }

    #[test]
    fn policy_accessors_preserve_committed_values() {
        let policy = RegularCopyPolicyV1::checked(
            NonZeroU64::new(1024).unwrap(),
            NonZeroU32::new(32).unwrap(),
            NonZeroU8::new(4).unwrap(),
            NonZeroU8::new(3).unwrap(),
        )
        .unwrap();
        assert_eq!(policy.max_logical_bytes(), 1024);
        assert_eq!(policy.max_data_extents(), 32);
        assert_eq!(policy.openat2_attempts(), 4);
        assert_eq!(policy.syscall_attempts(), 3);
    }

    #[test]
    fn checked_policy_accepts_hard_ceilings_and_rejects_every_excess() {
        let at_ceiling = RegularCopyPolicyV1::checked(
            NonZeroU64::new(HARD_MAX_LOGICAL_BYTES).unwrap(),
            NonZeroU32::new(HARD_MAX_DATA_EXTENTS).unwrap(),
            NonZeroU8::new(HARD_MAX_OPENAT2_ATTEMPTS).unwrap(),
            NonZeroU8::new(HARD_MAX_SYSCALL_ATTEMPTS).unwrap(),
        )
        .unwrap();
        assert_eq!(at_ceiling.max_logical_bytes(), HARD_MAX_LOGICAL_BYTES);
        assert_eq!(at_ceiling.max_data_extents(), HARD_MAX_DATA_EXTENTS);
        assert_eq!(at_ceiling.openat2_attempts(), HARD_MAX_OPENAT2_ATTEMPTS);
        assert_eq!(at_ceiling.syscall_attempts(), HARD_MAX_SYSCALL_ATTEMPTS);

        assert!(
            RegularCopyPolicyV1::checked(
                NonZeroU64::new(HARD_MAX_LOGICAL_BYTES + 1).unwrap(),
                NonZeroU32::new(1).unwrap(),
                NonZeroU8::new(1).unwrap(),
                NonZeroU8::new(1).unwrap(),
            )
            .is_none()
        );
        assert!(
            RegularCopyPolicyV1::checked(
                NonZeroU64::new(1).unwrap(),
                NonZeroU32::new(HARD_MAX_DATA_EXTENTS + 1).unwrap(),
                NonZeroU8::new(1).unwrap(),
                NonZeroU8::new(1).unwrap(),
            )
            .is_none()
        );
        assert!(
            RegularCopyPolicyV1::checked(
                NonZeroU64::new(1).unwrap(),
                NonZeroU32::new(1).unwrap(),
                NonZeroU8::new(HARD_MAX_OPENAT2_ATTEMPTS + 1).unwrap(),
                NonZeroU8::new(1).unwrap(),
            )
            .is_none()
        );
        assert!(
            RegularCopyPolicyV1::checked(
                NonZeroU64::new(1).unwrap(),
                NonZeroU32::new(1).unwrap(),
                NonZeroU8::new(1).unwrap(),
                NonZeroU8::new(HARD_MAX_SYSCALL_ATTEMPTS + 1).unwrap(),
            )
            .is_none()
        );
    }

    #[test]
    fn streaming_digest_matches_frozen_parent_derivation_and_length() {
        let fixtures = [
            Vec::new(),
            vec![0x5a; 64 * 1024],
            (0..(64 * 1024 + 37))
                .map(|index| (index % 251) as u8)
                .collect::<Vec<_>>(),
            (0..(3 * 64 * 1024 + 11))
                .map(|index| (index % 239) as u8)
                .collect::<Vec<_>>(),
        ];
        for bytes in fixtures {
            let mut streaming = FileContentHasherV1::new(bytes.len() as u64);
            for chunk in bytes.chunks(8191) {
                assert!(streaming.update(chunk));
            }
            assert_eq!(
                streaming.finish().unwrap(),
                FileContentDigest::derive(super::super::FILE_CONTENT_DOMAIN, &[&bytes])
            );
        }

        let mut short = FileContentHasherV1::new(2);
        assert!(short.update(b"x"));
        assert!(short.finish().is_none());

        let mut long = FileContentHasherV1::new(1);
        assert!(!long.update(b"xx"));
        assert!(!long.update(b"x"));
        assert!(long.finish().is_none());
    }
}
