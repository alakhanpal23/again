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

use super::{ExtentV1, FileContentDigest, ProfileFailure, RefusalCode, TimespecV1};

/// Bounded inputs that must eventually be committed by the snapshot-policy
/// digest.  Keeping them explicit prevents this leaf from inventing ambient
/// retry or resource policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct RegularCopyPolicyV1 {
    max_logical_bytes: NonZeroU64,
    max_data_extents: NonZeroU32,
    openat2_attempts: NonZeroU8,
}

impl RegularCopyPolicyV1 {
    pub(super) const fn new(
        max_logical_bytes: NonZeroU64,
        max_data_extents: NonZeroU32,
        openat2_attempts: NonZeroU8,
    ) -> Self {
        Self {
            max_logical_bytes,
            max_data_extents,
            openat2_attempts,
        }
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RegularCopyMethodV1 {
    Reflink,
    SparseCopy,
}

/// Stable source metadata needed by the later manifest/xattr/hardlink stage.
/// `ctime` and `btime` are logical source metadata; a copied inode cannot have
/// the same physical values.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct StableStatxV1 {
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

impl StableStatxV1 {
    pub(super) const fn mount_id(&self) -> u64 {
        self.mount_id
    }

    pub(super) const fn device_major(&self) -> u32 {
        self.device_major
    }

    pub(super) const fn device_minor(&self) -> u32 {
        self.device_minor
    }

    pub(super) const fn inode(&self) -> u64 {
        self.inode
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

/// A staged destination plus the still-pinned source inode.  The higher-level
/// builder retains the source handle while collecting xattrs, then applies
/// metadata to `destination` and fsyncs before publication.
pub(super) struct CopiedRegularV1 {
    source_handle: OwnedFd,
    destination: OwnedFd,
    source_identity: StableStatxV1,
    content_digest: FileContentDigest,
    data_extents: Box<[ExtentV1]>,
    method: RegularCopyMethodV1,
}

impl CopiedRegularV1 {
    pub(super) fn source_handle(&self) -> BorrowedFd<'_> {
        self.source_handle.as_fd()
    }

    pub(super) fn destination(&self) -> BorrowedFd<'_> {
        self.destination.as_fd()
    }

    pub(super) fn source_identity(&self) -> &StableStatxV1 {
        &self.source_identity
    }

    pub(super) const fn content_digest(&self) -> FileContentDigest {
        self.content_digest
    }

    pub(super) fn data_extents(&self) -> &[ExtentV1] {
        &self.data_extents
    }

    pub(super) const fn method(&self) -> RegularCopyMethodV1 {
        self.method
    }

    pub(super) fn into_parts(self) -> (OwnedFd, OwnedFd) {
        (self.source_handle, self.destination)
    }
}

impl fmt::Debug for CopiedRegularV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CopiedRegularV1")
            .field("source_identity", &self.source_identity)
            .field("content_digest", &self.content_digest)
            .field("data_extents", &self.data_extents)
            .field("method", &self.method)
            .field("descriptor_capabilities", &"<owned-fds>")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SnapshotRegularStageV1 {
    ValidateSourceName,
    ValidateDestinationName,
    OpenSourceHandle,
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

    pub(super) const fn into_profile_failure(self) -> ProfileFailure {
        ProfileFailure::refused(self.code)
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

/// Copy one regular source child into one new destination child.
///
/// Both directory descriptors must already be trusted capabilities. Names are
/// raw C basenames, not paths. No ordinary-path fallback is permitted.
pub(super) fn copy_regular_at(
    source_parent: BorrowedFd<'_>,
    source_name: &CStr,
    destination_parent: BorrowedFd<'_>,
    destination_name: &CStr,
    policy: RegularCopyPolicyV1,
) -> Result<CopiedRegularV1, SnapshotRegularFailureV1> {
    platform::copy_regular_at(
        source_parent,
        source_name,
        destination_parent,
        destination_name,
        policy,
    )
}

fn valid_basename(name: &CStr) -> bool {
    let bytes = name.to_bytes();
    !bytes.is_empty() && bytes != b"." && bytes != b".." && !bytes.contains(&b'/')
}

// Temporary until the parent hash layer exposes a domain-fixed streaming
// `FileContentHasherV1`. Keep the parity tests below: this must remain exactly
// equivalent to `FileContentDigest::derive(FILE_CONTENT_DOMAIN, &[bytes])`.
fn new_file_content_hasher(logical_size: u64) -> blake3::Hasher {
    let mut hasher = blake3::Hasher::new_derive_key(super::FILE_CONTENT_DOMAIN);
    hasher.update(super::HASH_FRAME_MAGIC);
    hasher.update(&1u32.to_be_bytes());
    hasher.update(&1u16.to_be_bytes());
    hasher.update(&logical_size.to_be_bytes());
    hasher
}

fn finish_file_content_hasher(hasher: blake3::Hasher) -> FileContentDigest {
    FileContentDigest(*hasher.finalize().as_bytes())
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

    trait CopyHooks {
        fn clone_file(&self, destination: RawFd, source: RawFd) -> io::Result<()>;

        fn after_materialized(&self) -> io::Result<()> {
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
    }

    pub(super) fn copy_regular_at(
        source_parent: BorrowedFd<'_>,
        source_name: &CStr,
        destination_parent: BorrowedFd<'_>,
        destination_name: &CStr,
        policy: RegularCopyPolicyV1,
    ) -> Result<CopiedRegularV1, SnapshotRegularFailureV1> {
        copy_regular_at_with(
            source_parent,
            source_name,
            destination_parent,
            destination_name,
            policy,
            &KernelHooks,
        )
    }

    fn copy_regular_at_with<H: CopyHooks>(
        source_parent: BorrowedFd<'_>,
        source_name: &CStr,
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

        let source_handle = openat2_owned(
            source_parent,
            source_name,
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
            SOURCE_RESOLVE,
            policy.openat2_attempts(),
        )
        .map_err(|error| {
            map_initial_source_open(SnapshotRegularStageV1::OpenSourceHandle, error)
        })?;
        let source_identity = statx_identity(source_handle.as_fd())
            .map_err(|error| map_statx_failure(SnapshotRegularStageV1::InspectSource, error))?;
        if source_identity.mode & libc::S_IFMT != libc::S_IFREG {
            return Err(SnapshotRegularFailureV1::new(
                RefusalCode::SnapshotRequiredObjectUnsupported,
                SnapshotRegularStageV1::InspectSource,
                None,
            ));
        }
        if source_identity.size > policy.max_logical_bytes()
            || source_identity.size > i64::MAX as u64
        {
            return Err(SnapshotRegularFailureV1::new(
                RefusalCode::SnapshotConstructionFailed,
                SnapshotRegularStageV1::InspectSource,
                None,
            ));
        }

        let source_read = openat2_owned(
            source_parent,
            source_name,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NOATIME | libc::O_CLOEXEC,
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
        let mut destination = create_destination(&mut cleanup).map_err(|error| {
            map_destination_error(SnapshotRegularStageV1::CreateDestination, error)
        })?;

        let initial_extents = enumerate_extents(
            source_read.as_fd(),
            source_identity.size,
            policy.max_data_extents(),
        )
        .map_err(|error| map_extent_error(SnapshotRegularStageV1::EnumerateSourceExtents, error))?;

        let method = match hooks.clone_file(destination.as_raw_fd(), source_read.as_raw_fd()) {
            Ok(()) => RegularCopyMethodV1::Reflink,
            Err(error) if clone_fallback_error(&error) => {
                drop(destination);
                cleanup.remove_current().map_err(|error| {
                    map_destination_error(SnapshotRegularStageV1::RecreateForFallback, error)
                })?;
                destination = create_destination(&mut cleanup).map_err(|error| {
                    map_destination_error(SnapshotRegularStageV1::RecreateForFallback, error)
                })?;
                truncate_to(destination.as_fd(), source_identity.size).map_err(|error| {
                    map_destination_error(SnapshotRegularStageV1::SparseCopy, error)
                })?;
                copy_data_extents(source_read.as_fd(), destination.as_fd(), &initial_extents)
                    .map_err(|error| {
                        map_destination_error(SnapshotRegularStageV1::SparseCopy, error)
                    })?;
                RegularCopyMethodV1::SparseCopy
            }
            Err(error) => {
                return Err(map_destination_error(
                    SnapshotRegularStageV1::Reflink,
                    error,
                ));
            }
        };

        hooks.after_materialized().map_err(|error| {
            map_destination_error(SnapshotRegularStageV1::RevalidateSource, error)
        })?;

        let source_extents_after = enumerate_extents(
            source_read.as_fd(),
            source_identity.size,
            policy.max_data_extents(),
        )
        .map_err(|error| map_extent_error(SnapshotRegularStageV1::RevalidateSource, error))?;
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
        if destination_extents != initial_extents {
            return Err(construction_failure(
                SnapshotRegularStageV1::EnumerateDestinationExtents,
                None,
            ));
        }

        let content_digest = hash_logical_bytes(destination.as_fd(), destination_identity.size)
            .map_err(|error| {
                map_destination_error(SnapshotRegularStageV1::HashDestination, error)
            })?;

        revalidate_source(
            source_parent,
            source_name,
            source_handle.as_fd(),
            source_read.as_fd(),
            &source_identity,
            policy.openat2_attempts(),
        )?;
        revalidate_destination(
            destination_parent,
            destination_name,
            destination.as_fd(),
            &destination_identity,
            policy.openat2_attempts(),
        )?;

        cleanup.disarm();
        Ok(CopiedRegularV1 {
            source_handle,
            destination,
            source_identity,
            content_digest,
            data_extents: initial_extents.into_boxed_slice(),
            method,
        })
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

        fn arm(&mut self, destination: BorrowedFd<'_>) -> io::Result<()> {
            let identity = fstat_cleanup_identity(destination)?;
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

    fn create_destination(cleanup: &mut DestinationCleanup<'_>) -> io::Result<OwnedFd> {
        let destination = openat2_owned(
            cleanup.parent,
            cleanup.name,
            libc::O_RDWR
                | libc::O_CREAT
                | libc::O_EXCL
                | libc::O_NOFOLLOW
                | libc::O_NOATIME
                | libc::O_CLOEXEC,
            0o600,
            SOURCE_RESOLVE,
            cleanup.attempts,
        )?;
        cleanup.mark_created();
        cleanup.arm(destination.as_fd())?;
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
            if extents.len() >= max_extents as usize {
                return Err(io::Error::from_raw_os_error(libc::EFBIG));
            }
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
                pread_exact(source, &mut buffer[..length], offset)?;
                pwrite_all(destination, &buffer[..length], offset)?;
                offset += length as u64;
            }
        }
        Ok(())
    }

    fn pread_exact(fd: BorrowedFd<'_>, mut output: &mut [u8], mut offset: u64) -> io::Result<()> {
        while !output.is_empty() {
            let result = unsafe {
                libc::pread(
                    fd.as_raw_fd(),
                    output.as_mut_ptr().cast(),
                    output.len(),
                    offset as libc::off_t,
                )
            };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if result == 0 {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            let read = result as usize;
            offset += read as u64;
            output = &mut output[read..];
        }
        Ok(())
    }

    fn pwrite_all(fd: BorrowedFd<'_>, mut input: &[u8], mut offset: u64) -> io::Result<()> {
        while !input.is_empty() {
            let result = unsafe {
                libc::pwrite(
                    fd.as_raw_fd(),
                    input.as_ptr().cast(),
                    input.len(),
                    offset as libc::off_t,
                )
            };
            if result < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::Interrupted {
                    continue;
                }
                return Err(error);
            }
            if result == 0 {
                return Err(io::Error::from_raw_os_error(libc::EIO));
            }
            let written = result as usize;
            offset += written as u64;
            input = &input[written..];
        }
        Ok(())
    }

    fn hash_logical_bytes(fd: BorrowedFd<'_>, size: u64) -> io::Result<FileContentDigest> {
        let mut hasher = new_file_content_hasher(size);

        let mut buffer = [0u8; COPY_BUFFER_BYTES];
        let mut offset = 0u64;
        while offset < size {
            let length = usize::try_from((size - offset).min(buffer.len() as u64))
                .map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
            pread_exact(fd, &mut buffer[..length], offset)?;
            hasher.update(&buffer[..length]);
            offset += length as u64;
        }
        Ok(finish_file_content_hasher(hasher))
    }

    fn clone_fallback_error(error: &io::Error) -> bool {
        matches!(
            error.raw_os_error(),
            Some(libc::ENOTTY | libc::EOPNOTSUPP | libc::EXDEV | libc::EINVAL)
        )
    }

    fn map_initial_source_open(
        stage: SnapshotRegularStageV1,
        error: io::Error,
    ) -> SnapshotRegularFailureV1 {
        let errno = error.raw_os_error();
        let code = match errno {
            Some(libc::ENOSYS | libc::EINVAL | libc::E2BIG) => {
                RefusalCode::RequiredKernelCapabilityMissing
            }
            Some(libc::EACCES | libc::EPERM | libc::ELOOP | libc::EXDEV | libc::ENAMETOOLONG) => {
                RefusalCode::SnapshotRequiredObjectUnsupported
            }
            _ => RefusalCode::SnapshotConstructionFailed,
        };
        SnapshotRegularFailureV1::new(code, stage, errno)
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
            Some(libc::ENOSYS | libc::EINVAL | libc::E2BIG)
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
        use std::ffi::CString;
        use std::fs::{self, File, OpenOptions};
        use std::io::{Seek, SeekFrom, Write};
        use std::os::fd::AsFd;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::OpenOptionsExt;

        use tempfile::TempDir;

        use super::*;

        fn policy() -> RegularCopyPolicyV1 {
            RegularCopyPolicyV1::new(
                NonZeroU64::new(16 * 1024 * 1024).unwrap(),
                NonZeroU32::new(4096).unwrap(),
                NonZeroU8::new(4).unwrap(),
            )
        }

        fn open_directory(path: &std::path::Path) -> File {
            OpenOptions::new()
                .read(true)
                .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC)
                .open(path)
                .unwrap()
        }

        fn c_name(name: &std::ffi::OsStr) -> CString {
            CString::new(name.as_bytes()).unwrap()
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
            source: std::path::PathBuf,
        }

        impl CopyHooks for MutateAfterCopy {
            fn clone_file(&self, _destination: RawFd, _source: RawFd) -> io::Result<()> {
                Err(io::Error::from_raw_os_error(libc::EOPNOTSUPP))
            }

            fn after_materialized(&self) -> io::Result<()> {
                fs::write(&self.source, b"changed-after-copy")
            }
        }

        struct ReplaceAfterCopy {
            path: std::path::PathBuf,
            replacement: &'static [u8],
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

        fn run_forced_fallback(
            source_bytes: &[u8],
            errno: i32,
        ) -> (TempDir, CopiedRegularV1, std::path::PathBuf) {
            let temp = TempDir::new().unwrap();
            let source_dir = temp.path().join("source");
            let destination_dir = temp.path().join("destination");
            fs::create_dir(&source_dir).unwrap();
            fs::create_dir(&destination_dir).unwrap();
            fs::write(source_dir.join("input"), source_bytes).unwrap();
            let source_parent = open_directory(&source_dir);
            let destination_parent = open_directory(&destination_dir);
            let source_name = c_name(std::ffi::OsStr::new("input"));
            let destination_name = c_name(std::ffi::OsStr::new("output"));
            let hooks = ForcedCloneError {
                errno,
                calls: Cell::new(0),
            };
            let copied = copy_regular_at_with(
                source_parent.as_fd(),
                &source_name,
                destination_parent.as_fd(),
                &destination_name,
                policy(),
                &hooks,
            )
            .unwrap();
            assert_eq!(hooks.calls.get(), 1);
            let destination = destination_dir.join("output");
            (temp, copied, destination)
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
        fn forced_fallback_copies_dense_destination_bytes_and_digest() {
            let bytes = b"descriptor selected copy";
            let (_temp, copied, destination) = run_forced_fallback(bytes, libc::EOPNOTSUPP);
            assert_eq!(copied.method(), RegularCopyMethodV1::SparseCopy);
            assert_eq!(fs::read(destination).unwrap(), bytes);
            assert_eq!(
                copied.content_digest(),
                FileContentDigest::derive(super::super::super::FILE_CONTENT_DOMAIN, &[bytes])
            );
        }

        #[test]
        fn forced_fallback_preserves_api_visible_sparse_extents() {
            let temp = TempDir::new().unwrap();
            let source_dir = temp.path().join("source");
            let destination_dir = temp.path().join("destination");
            fs::create_dir(&source_dir).unwrap();
            fs::create_dir(&destination_dir).unwrap();
            let source_path = source_dir.join("sparse");
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

            let source_parent = open_directory(&source_dir);
            let destination_parent = open_directory(&destination_dir);
            let source_name = CString::new("sparse").unwrap();
            let destination_name = CString::new("copy").unwrap();
            let hooks = ForcedCloneError {
                errno: libc::EOPNOTSUPP,
                calls: Cell::new(0),
            };
            let copied = copy_regular_at_with(
                source_parent.as_fd(),
                &source_name,
                destination_parent.as_fd(),
                &destination_name,
                policy(),
                &hooks,
            )
            .unwrap();
            let destination = File::open(destination_dir.join("copy")).unwrap();
            let observed = enumerate_extents(destination.as_fd(), 512 * 1024, 4096).unwrap();
            assert_eq!(observed, copied.data_extents());
            assert_eq!(
                fs::metadata(destination_dir.join("copy")).unwrap().len(),
                512 * 1024
            );
        }

        #[test]
        fn written_zero_extent_remains_data_and_hashes_as_logical_bytes() {
            let temp = TempDir::new().unwrap();
            let source_dir = temp.path().join("source");
            let destination_dir = temp.path().join("destination");
            fs::create_dir(&source_dir).unwrap();
            fs::create_dir(&destination_dir).unwrap();
            let source_path = source_dir.join("zeros");
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

            let source_parent = open_directory(&source_dir);
            let destination_parent = open_directory(&destination_dir);
            let copied = copy_regular_at_with(
                source_parent.as_fd(),
                &CString::new("zeros").unwrap(),
                destination_parent.as_fd(),
                &CString::new("copy").unwrap(),
                policy(),
                &ForcedCloneError {
                    errno: libc::EOPNOTSUPP,
                    calls: Cell::new(0),
                },
            )
            .unwrap();
            assert!(!copied.data_extents().is_empty());
            let bytes = fs::read(destination_dir.join("copy")).unwrap();
            assert_eq!(bytes, vec![0; 1024 * 1024]);
            assert_eq!(
                copied.content_digest(),
                FileContentDigest::derive(super::super::super::FILE_CONTENT_DOMAIN, &[&bytes])
            );
        }

        #[test]
        fn source_atime_is_unchanged_by_fallback_reads() {
            use std::fs::FileTimes;
            use std::os::unix::fs::MetadataExt;
            use std::time::{Duration, UNIX_EPOCH};

            let temp = TempDir::new().unwrap();
            let source_dir = temp.path().join("source");
            let destination_dir = temp.path().join("destination");
            fs::create_dir(&source_dir).unwrap();
            fs::create_dir(&destination_dir).unwrap();
            let source_path = source_dir.join("input");
            let source = OpenOptions::new()
                .create_new(true)
                .read(true)
                .write(true)
                .open(&source_path)
                .unwrap();
            source.set_len(256 * 1024).unwrap();
            source
                .set_times(
                    FileTimes::new()
                        .set_accessed(UNIX_EPOCH + Duration::from_secs(946_684_800))
                        .set_modified(UNIX_EPOCH + Duration::from_secs(946_684_801)),
                )
                .unwrap();
            let before = fs::metadata(&source_path).unwrap();
            let before_atime = (before.atime(), before.atime_nsec());

            let source_parent = open_directory(&source_dir);
            let destination_parent = open_directory(&destination_dir);
            copy_regular_at_with(
                source_parent.as_fd(),
                &CString::new("input").unwrap(),
                destination_parent.as_fd(),
                &CString::new("copy").unwrap(),
                policy(),
                &ForcedCloneError {
                    errno: libc::EOPNOTSUPP,
                    calls: Cell::new(0),
                },
            )
            .unwrap();
            let after = fs::metadata(source_path).unwrap();
            assert_eq!((after.atime(), after.atime_nsec()), before_atime);
        }

        #[test]
        fn empty_and_all_hole_files_keep_empty_extent_lists() {
            let (_temp, empty, _destination) = run_forced_fallback(b"", libc::EINVAL);
            assert!(empty.data_extents().is_empty());

            let temp = TempDir::new().unwrap();
            let source_dir = temp.path().join("source");
            let destination_dir = temp.path().join("destination");
            fs::create_dir(&source_dir).unwrap();
            fs::create_dir(&destination_dir).unwrap();
            File::create(source_dir.join("hole"))
                .unwrap()
                .set_len(1024 * 1024)
                .unwrap();
            let source_parent = open_directory(&source_dir);
            let destination_parent = open_directory(&destination_dir);
            let hooks = ForcedCloneError {
                errno: libc::EXDEV,
                calls: Cell::new(0),
            };
            let copied = copy_regular_at_with(
                source_parent.as_fd(),
                &CString::new("hole").unwrap(),
                destination_parent.as_fd(),
                &CString::new("copy").unwrap(),
                policy(),
                &hooks,
            )
            .unwrap();
            assert!(copied.data_extents().is_empty());
            assert_eq!(
                fs::metadata(destination_dir.join("copy")).unwrap().len(),
                1024 * 1024
            );
        }

        #[test]
        fn hard_clone_errors_never_fall_back_and_raii_removes_partial_destination() {
            for errno in [libc::EIO, libc::ENOSPC, libc::EPERM] {
                let temp = TempDir::new().unwrap();
                let source_dir = temp.path().join("source");
                let destination_dir = temp.path().join("destination");
                fs::create_dir(&source_dir).unwrap();
                fs::create_dir(&destination_dir).unwrap();
                fs::write(source_dir.join("input"), b"content").unwrap();
                let source_parent = open_directory(&source_dir);
                let destination_parent = open_directory(&destination_dir);
                let hooks = ForcedCloneError {
                    errno,
                    calls: Cell::new(0),
                };
                let error = copy_regular_at_with(
                    source_parent.as_fd(),
                    &CString::new("input").unwrap(),
                    destination_parent.as_fd(),
                    &CString::new("output").unwrap(),
                    policy(),
                    &hooks,
                )
                .unwrap_err();
                assert_eq!(error.code(), RefusalCode::SnapshotConstructionFailed);
                assert_eq!(error.stage(), SnapshotRegularStageV1::Reflink);
                assert_eq!(error.errno(), Some(errno));
                assert_eq!(hooks.calls.get(), 1);
                assert!(!destination_dir.join("output").exists());
            }
        }

        #[test]
        fn deterministic_post_copy_mutation_is_refused_and_cleaned() {
            let temp = TempDir::new().unwrap();
            let source_dir = temp.path().join("source");
            let destination_dir = temp.path().join("destination");
            fs::create_dir(&source_dir).unwrap();
            fs::create_dir(&destination_dir).unwrap();
            let source_path = source_dir.join("input");
            fs::write(&source_path, b"original").unwrap();
            let source_parent = open_directory(&source_dir);
            let destination_parent = open_directory(&destination_dir);
            let error = copy_regular_at_with(
                source_parent.as_fd(),
                &CString::new("input").unwrap(),
                destination_parent.as_fd(),
                &CString::new("output").unwrap(),
                policy(),
                &MutateAfterCopy {
                    source: source_path,
                },
            )
            .unwrap_err();
            assert_eq!(error.code(), RefusalCode::SnapshotConstructionFailed);
            assert_eq!(error.stage(), SnapshotRegularStageV1::RevalidateSource);
            assert!(!destination_dir.join("output").exists());
        }

        #[test]
        fn source_unlink_recreate_is_detected_and_partial_destination_is_cleaned() {
            let temp = TempDir::new().unwrap();
            let source_dir = temp.path().join("source");
            let destination_dir = temp.path().join("destination");
            fs::create_dir(&source_dir).unwrap();
            fs::create_dir(&destination_dir).unwrap();
            let source_path = source_dir.join("input");
            fs::write(&source_path, b"original").unwrap();
            let source_parent = open_directory(&source_dir);
            let destination_parent = open_directory(&destination_dir);
            let error = copy_regular_at_with(
                source_parent.as_fd(),
                &CString::new("input").unwrap(),
                destination_parent.as_fd(),
                &CString::new("output").unwrap(),
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
            assert!(!destination_dir.join("output").exists());
        }

        #[test]
        fn destination_unlink_recreate_is_detected_without_deleting_replacement() {
            let temp = TempDir::new().unwrap();
            let source_dir = temp.path().join("source");
            let destination_dir = temp.path().join("destination");
            fs::create_dir(&source_dir).unwrap();
            fs::create_dir(&destination_dir).unwrap();
            fs::write(source_dir.join("input"), b"original").unwrap();
            let destination_path = destination_dir.join("output");
            let source_parent = open_directory(&source_dir);
            let destination_parent = open_directory(&destination_dir);
            let error = copy_regular_at_with(
                source_parent.as_fd(),
                &CString::new("input").unwrap(),
                destination_parent.as_fd(),
                &CString::new("output").unwrap(),
                policy(),
                &ReplaceAfterCopy {
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

            let temp = TempDir::new().unwrap();
            let source_dir = temp.path().join("source");
            let destination_dir = temp.path().join("destination");
            fs::create_dir(&source_dir).unwrap();
            fs::create_dir(&destination_dir).unwrap();
            fs::write(source_dir.join("target"), b"secret").unwrap();
            symlink("target", source_dir.join("input")).unwrap();
            let source_parent = open_directory(&source_dir);
            let destination_parent = open_directory(&destination_dir);
            let source_error = copy_regular_at_with(
                source_parent.as_fd(),
                &CString::new("input").unwrap(),
                destination_parent.as_fd(),
                &CString::new("output").unwrap(),
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

            fs::remove_file(source_dir.join("input")).unwrap();
            fs::write(source_dir.join("input"), b"ordinary").unwrap();
            symlink("do-not-touch", destination_dir.join("output")).unwrap();
            let destination_error = copy_regular_at_with(
                source_parent.as_fd(),
                &CString::new("input").unwrap(),
                destination_parent.as_fd(),
                &CString::new("output").unwrap(),
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
                fs::read_link(destination_dir.join("output")).unwrap(),
                std::path::Path::new("do-not-touch")
            );
        }

        #[test]
        fn raw_non_utf8_basename_is_supported() {
            let temp = TempDir::new().unwrap();
            let source_dir = temp.path().join("source");
            let destination_dir = temp.path().join("destination");
            fs::create_dir(&source_dir).unwrap();
            fs::create_dir(&destination_dir).unwrap();
            let raw = std::ffi::OsStr::from_bytes(b"in-\xff");
            fs::write(source_dir.join(raw), b"raw-name").unwrap();
            let source_parent = open_directory(&source_dir);
            let destination_parent = open_directory(&destination_dir);
            let copied = copy_regular_at_with(
                source_parent.as_fd(),
                &c_name(raw),
                destination_parent.as_fd(),
                &CString::new("output").unwrap(),
                policy(),
                &ForcedCloneError {
                    errno: libc::ENOTTY,
                    calls: Cell::new(0),
                },
            )
            .unwrap();
            assert_eq!(copied.method(), RegularCopyMethodV1::SparseCopy);
            assert_eq!(
                fs::read(destination_dir.join("output")).unwrap(),
                b"raw-name"
            );
        }

        #[test]
        fn invalid_names_and_size_limit_have_exact_refusals() {
            let temp = TempDir::new().unwrap();
            let source_dir = temp.path().join("source");
            let destination_dir = temp.path().join("destination");
            fs::create_dir(&source_dir).unwrap();
            fs::create_dir(&destination_dir).unwrap();
            fs::write(source_dir.join("input"), b"too-large").unwrap();
            let source_parent = open_directory(&source_dir);
            let destination_parent = open_directory(&destination_dir);
            let hooks = ForcedCloneError {
                errno: libc::EOPNOTSUPP,
                calls: Cell::new(0),
            };
            let invalid_source = copy_regular_at_with(
                source_parent.as_fd(),
                &CString::new("..").unwrap(),
                destination_parent.as_fd(),
                &CString::new("output").unwrap(),
                policy(),
                &hooks,
            )
            .unwrap_err();
            assert_eq!(
                invalid_source.code(),
                RefusalCode::SnapshotRequiredObjectUnsupported
            );
            assert_eq!(
                invalid_source.stage(),
                SnapshotRegularStageV1::ValidateSourceName
            );

            let invalid_destination = copy_regular_at_with(
                source_parent.as_fd(),
                &CString::new("input").unwrap(),
                destination_parent.as_fd(),
                &CString::new("bad/name").unwrap(),
                policy(),
                &hooks,
            )
            .unwrap_err();
            assert_eq!(
                invalid_destination.code(),
                RefusalCode::SnapshotConstructionFailed
            );

            let tiny_policy = RegularCopyPolicyV1::new(
                NonZeroU64::new(1).unwrap(),
                NonZeroU32::new(1).unwrap(),
                NonZeroU8::new(1).unwrap(),
            );
            let limit = copy_regular_at_with(
                source_parent.as_fd(),
                &CString::new("input").unwrap(),
                destination_parent.as_fd(),
                &CString::new("output").unwrap(),
                tiny_policy,
                &hooks,
            )
            .unwrap_err();
            assert_eq!(limit.code(), RefusalCode::SnapshotConstructionFailed);
            assert_eq!(limit.stage(), SnapshotRegularStageV1::InspectSource);
            assert!(!destination_dir.join("output").exists());
        }
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
mod platform {
    use super::*;

    pub(super) fn copy_regular_at(
        _source_parent: BorrowedFd<'_>,
        _source_name: &CStr,
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
            SnapshotRegularStageV1::OpenSourceHandle,
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
        let policy = RegularCopyPolicyV1::new(
            NonZeroU64::new(1024).unwrap(),
            NonZeroU32::new(32).unwrap(),
            NonZeroU8::new(4).unwrap(),
        );
        assert_eq!(policy.max_logical_bytes(), 1024);
        assert_eq!(policy.max_data_extents(), 32);
        assert_eq!(policy.openat2_attempts(), 4);
    }

    #[test]
    fn temporary_streaming_digest_matches_frozen_parent_derivation() {
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
            let mut streaming = new_file_content_hasher(bytes.len() as u64);
            for chunk in bytes.chunks(8191) {
                streaming.update(chunk);
            }
            assert_eq!(
                finish_file_content_hasher(streaming),
                FileContentDigest::derive(super::super::FILE_CONTENT_DOMAIN, &[&bytes])
            );
        }
    }
}
