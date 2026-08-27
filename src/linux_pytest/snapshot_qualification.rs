//! Functional qualification for the source view consumed by snapshot capture.
//!
//! Qualification is deliberately conservative. Before performing any
//! operation that can update access time, the exact source mount must report
//! `ST_NOATIME`. The qualifier then exercises the ordinary (non-`O_NOATIME`)
//! read surfaces used by capture: directory enumeration, regular-file bytes,
//! a symlink target, xattr-list calls on authenticated readable directory and
//! regular-file descriptors, and a descriptor-relative symlink xattr-list
//! bracketed by pinned and reopened identity checks. It proves that every
//! observed object matches its pinned `O_PATH` identity before and after the
//! operation. A mount flag alone is not enough, and an
//! `O_NOATIME` open is not accepted as a substitute: the eventual traversal
//! intentionally uses ordinary reads so that root-owned runtime files remain
//! readable without `CAP_FOWNER`.
//!
//! This module is internal and is not wired to the CLI. It exposes one safe,
//! fail-closed producer for the existing borrowed-FD capability; no second
//! authority representation and no unsafe minting API is introduced here.

use std::ffi::CStr;
use std::fmt;
use std::os::fd::BorrowedFd;

use super::{QualifiedNoAtimeSourceViewV1, RefusalCode};

const MAX_BASENAME_BYTES: usize = 255;
const MAX_XATTR_NAME_BYTES: usize = 255;

/// Immutable fixture names provisioned on the exact source view being
/// qualified. The qualifier never creates, timestamps, or repairs fixtures.
pub(super) struct SourceViewQualificationProbesV1<'a> {
    directory: &'a CStr,
    regular: &'a CStr,
    symlink: &'a CStr,
    xattr: &'a CStr,
}

impl<'a> SourceViewQualificationProbesV1<'a> {
    pub(super) fn checked(
        directory: &'a CStr,
        regular: &'a CStr,
        symlink: &'a CStr,
        xattr: &'a CStr,
    ) -> Option<Self> {
        let directory_bytes = directory.to_bytes();
        let regular_bytes = regular.to_bytes();
        let symlink_bytes = symlink.to_bytes();
        if !valid_basename(directory_bytes)
            || !valid_basename(regular_bytes)
            || !valid_basename(symlink_bytes)
            || directory_bytes == regular_bytes
            || directory_bytes == symlink_bytes
            || regular_bytes == symlink_bytes
            || xattr.to_bytes().is_empty()
            || xattr.to_bytes().len() > MAX_XATTR_NAME_BYTES
        {
            return None;
        }
        Some(Self {
            directory,
            regular,
            symlink,
            xattr,
        })
    }
}

fn valid_basename(name: &[u8]) -> bool {
    !name.is_empty()
        && name.len() <= MAX_BASENAME_BYTES
        && name != b"."
        && name != b".."
        && !name.contains(&b'/')
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SourceViewQualificationStageV1 {
    InspectMountBefore,
    InspectParentBefore,
    PinDirectory,
    PinRegular,
    PinSymlink,
    ReadDirectory,
    ReadDirectoryXattrList,
    ReadRegular,
    ReadRegularXattr,
    ReadSymlink,
    ReadSymlinkXattrList,
    RevalidateDirectory,
    RevalidateRegular,
    RevalidateSymlink,
    RevalidateParent,
    InspectMountAfter,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SourceViewQualificationReasonV1 {
    RequiredKernelCapability,
    FilesystemNotQualified,
    MountDoesNotSuppressAtime,
    MountChanged,
    MountCrossing,
    WrongObjectKind,
    EmptyProbe,
    MissingXattr,
    AtimeChanged,
    SourceChanged,
    MalformedKernelResponse,
    ProbeExceedsBound,
    Io,
}

pub(super) struct SourceViewQualificationFailureV1 {
    code: RefusalCode,
    stage: SourceViewQualificationStageV1,
    reason: SourceViewQualificationReasonV1,
    errno: Option<i32>,
}

impl SourceViewQualificationFailureV1 {
    const fn new(
        code: RefusalCode,
        stage: SourceViewQualificationStageV1,
        reason: SourceViewQualificationReasonV1,
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

    pub(super) const fn stage(&self) -> SourceViewQualificationStageV1 {
        self.stage
    }

    pub(super) const fn reason(&self) -> SourceViewQualificationReasonV1 {
        self.reason
    }

    pub(super) const fn errno(&self) -> Option<i32> {
        self.errno
    }
}

impl fmt::Debug for SourceViewQualificationFailureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SourceViewQualificationFailureV1")
            .field("code", &self.code)
            .field("stage", &self.stage)
            .field("reason", &self.reason)
            .field("errno", &self.errno)
            .finish()
    }
}

impl fmt::Display for SourceViewQualificationFailureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "source-view qualification refused: {} at {:?} ({:?}, errno={:?})",
            self.code.as_str(),
            self.stage,
            self.reason,
            self.errno
        )
    }
}

impl std::error::Error for SourceViewQualificationFailureV1 {}

/// Prove that ordinary capture reads on `trusted_parent` cannot update host
/// atime, then mint the one existing source-view capability.
///
/// The returned borrow is tied to `trusted_parent`. Callers must keep the view
/// in the same qualified mount context and consume it synchronously; a mount
/// namespace or privileged remount outside the profile threat boundary must
/// invalidate the surrounding execution attempt.
pub(super) fn qualify_no_atime_source_view_at<'source>(
    trusted_parent: BorrowedFd<'source>,
    probes: &SourceViewQualificationProbesV1<'_>,
) -> Result<QualifiedNoAtimeSourceViewV1<'source>, SourceViewQualificationFailureV1> {
    platform::qualify_no_atime_source_view_at(trusted_parent, probes)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod platform {
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
    const REQUIRED_STATX_MASK: u32 = libc::STATX_BASIC_STATS | STATX_MNT_ID;
    const REQUESTED_STATX_MASK: u32 = REQUIRED_STATX_MASK | libc::STATX_BTIME;
    const MAX_OPENAT2_ATTEMPTS: u8 = 4;
    const XATTR_BUFFER_BYTES: usize = 64 * 1024;
    const SYS_GETXATTRAT_X86_64: libc::c_long = 464;
    const SYS_LISTXATTRAT_X86_64: libc::c_long = 465;
    const EXT_FAMILY_SUPER_MAGIC: i64 = 0x0000_ef53;
    const XFS_SUPER_MAGIC: i64 = 0x5846_5342;
    const BTRFS_SUPER_MAGIC: i64 = 0x9123_683e;
    const TMPFS_SUPER_MAGIC: i64 = 0x0102_1994;

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

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct TimestampV1 {
        seconds: i64,
        nanoseconds: u32,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct NodeObservationV1 {
        mount_id: u64,
        device_major: u32,
        device_minor: u32,
        inode: u64,
        mode: u32,
        uid: u32,
        gid: u32,
        link_count: u64,
        size: u64,
        blocks: u64,
        attributes: u64,
        attributes_mask: u64,
        atime: TimestampV1,
        mtime: TimestampV1,
        ctime: TimestampV1,
        btime: Option<TimestampV1>,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    struct MountObservationV1 {
        filesystem_type: i64,
        flags: u64,
    }

    impl MountObservationV1 {
        fn is_supported_local_filesystem(self) -> bool {
            matches!(
                self.filesystem_type,
                EXT_FAMILY_SUPER_MAGIC | XFS_SUPER_MAGIC | BTRFS_SUPER_MAGIC | TMPFS_SUPER_MAGIC
            )
        }

        fn suppresses_atime(self) -> bool {
            self.flags & libc::ST_NOATIME != 0
        }
    }

    #[derive(Clone, Copy)]
    enum ProbeKindV1 {
        Directory,
        Regular,
        Symlink,
    }

    impl ProbeKindV1 {
        const fn expected_mode(self) -> u32 {
            match self {
                Self::Directory => libc::S_IFDIR,
                Self::Regular => libc::S_IFREG,
                Self::Symlink => libc::S_IFLNK,
            }
        }
    }

    struct PinnedProbeV1 {
        fd: OwnedFd,
        observation: NodeObservationV1,
    }

    #[derive(Clone, Copy)]
    struct ReadExerciseV1 {
        before: NodeObservationV1,
        after: NodeObservationV1,
    }

    trait QualificationHooksV1 {
        fn observe_mount(&self, parent: BorrowedFd<'_>) -> io::Result<MountObservationV1>;

        fn observe_parent(&self, parent: BorrowedFd<'_>) -> io::Result<NodeObservationV1>;

        fn pin_probe(
            &self,
            parent: BorrowedFd<'_>,
            name: &CStr,
            kind: ProbeKindV1,
        ) -> io::Result<PinnedProbeV1>;

        fn exercise_directory(
            &self,
            parent: BorrowedFd<'_>,
            name: &CStr,
        ) -> io::Result<ReadExerciseV1>;

        fn exercise_regular(
            &self,
            parent: BorrowedFd<'_>,
            name: &CStr,
        ) -> io::Result<ReadExerciseV1>;

        fn exercise_symlink(&self, fd: BorrowedFd<'_>) -> io::Result<()>;

        fn exercise_xattr_list(
            &self,
            parent: BorrowedFd<'_>,
            name: &CStr,
            probe: &PinnedProbeV1,
        ) -> io::Result<ReadExerciseV1>;

        fn exercise_regular_xattr(
            &self,
            parent: BorrowedFd<'_>,
            name: &CStr,
            probe: &PinnedProbeV1,
            xattr_name: &CStr,
        ) -> io::Result<ReadExerciseV1>;

        fn reobserve_probe(
            &self,
            fd: BorrowedFd<'_>,
            kind: ProbeKindV1,
        ) -> io::Result<NodeObservationV1>;

        fn reopen_probe(
            &self,
            parent: BorrowedFd<'_>,
            name: &CStr,
            kind: ProbeKindV1,
        ) -> io::Result<NodeObservationV1>;
    }

    struct KernelHooksV1;

    impl QualificationHooksV1 for KernelHooksV1 {
        fn observe_mount(&self, parent: BorrowedFd<'_>) -> io::Result<MountObservationV1> {
            raw_mount_observation(parent)
        }

        fn observe_parent(&self, parent: BorrowedFd<'_>) -> io::Result<NodeObservationV1> {
            raw_node_observation(parent)
        }

        fn pin_probe(
            &self,
            parent: BorrowedFd<'_>,
            name: &CStr,
            _kind: ProbeKindV1,
        ) -> io::Result<PinnedProbeV1> {
            let fd = openat2_owned(
                parent,
                name,
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )?;
            let observation = raw_node_observation(fd.as_fd())?;
            Ok(PinnedProbeV1 { fd, observation })
        }

        fn exercise_directory(
            &self,
            parent: BorrowedFd<'_>,
            name: &CStr,
        ) -> io::Result<ReadExerciseV1> {
            let fd = openat2_owned(
                parent,
                name,
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )?;
            let before = raw_node_observation(fd.as_fd())?;
            let mut buffer = [0u8; 4096];
            let result = unsafe {
                libc::syscall(
                    libc::SYS_getdents64,
                    fd.as_raw_fd(),
                    buffer.as_mut_ptr(),
                    buffer.len(),
                )
            };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
            let after = raw_node_observation(fd.as_fd())?;
            Ok(ReadExerciseV1 { before, after })
        }

        fn exercise_regular(
            &self,
            parent: BorrowedFd<'_>,
            name: &CStr,
        ) -> io::Result<ReadExerciseV1> {
            let fd = openat2_owned(
                parent,
                name,
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )?;
            let before = raw_node_observation(fd.as_fd())?;
            let mut byte = 0u8;
            let result =
                unsafe { libc::pread(fd.as_raw_fd(), std::ptr::from_mut(&mut byte).cast(), 1, 0) };
            if result != 1 {
                return Err(if result < 0 {
                    io::Error::last_os_error()
                } else {
                    io::Error::from_raw_os_error(libc::EIO)
                });
            }
            let after = raw_node_observation(fd.as_fd())?;
            Ok(ReadExerciseV1 { before, after })
        }

        fn exercise_symlink(&self, fd: BorrowedFd<'_>) -> io::Result<()> {
            let mut output = [0u8; 4096];
            let result = unsafe {
                libc::readlinkat(
                    fd.as_raw_fd(),
                    c"".as_ptr(),
                    output.as_mut_ptr().cast(),
                    output.len(),
                )
            };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
            let used = usize::try_from(result)
                .map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
            if used == 0 || used == output.len() || output[..used].contains(&0) {
                return Err(io::Error::from_raw_os_error(libc::EPROTO));
            }
            Ok(())
        }

        fn exercise_xattr_list(
            &self,
            parent: BorrowedFd<'_>,
            name: &CStr,
            probe: &PinnedProbeV1,
        ) -> io::Result<ReadExerciseV1> {
            match probe.observation.mode & libc::S_IFMT {
                libc::S_IFDIR => {
                    let readable = openat2_owned(
                        parent,
                        name,
                        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    )?;
                    let before = raw_node_observation(readable.as_fd())?;
                    if before != probe.observation {
                        return Err(io::Error::from_raw_os_error(libc::ESTALE));
                    }
                    let mut buffer = [0u8; XATTR_BUFFER_BYTES];
                    bounded_xattr_list(readable.as_raw_fd(), &mut buffer)?;
                    let after = raw_node_observation(readable.as_fd())?;
                    Ok(ReadExerciseV1 { before, after })
                }
                libc::S_IFLNK => {
                    let before = raw_node_observation(probe.fd.as_fd())?;
                    if before != probe.observation {
                        return Err(io::Error::from_raw_os_error(libc::ESTALE));
                    }
                    require_reopened_probe_identity_v1(parent, name, probe.observation)?;
                    let mut buffer = [0u8; XATTR_BUFFER_BYTES];
                    bounded_xattr_list_at(parent.as_raw_fd(), name, &mut buffer)?;
                    require_reopened_probe_identity_v1(parent, name, probe.observation)?;
                    let after = raw_node_observation(probe.fd.as_fd())?;
                    Ok(ReadExerciseV1 { before, after })
                }
                _ => Err(io::Error::from_raw_os_error(libc::EINVAL)),
            }
        }

        fn exercise_regular_xattr(
            &self,
            parent: BorrowedFd<'_>,
            name: &CStr,
            probe: &PinnedProbeV1,
            xattr_name: &CStr,
        ) -> io::Result<ReadExerciseV1> {
            let fd = openat2_owned(
                parent,
                name,
                libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )?;
            let before = raw_node_observation(fd.as_fd())?;
            if before != probe.observation {
                return Err(io::Error::from_raw_os_error(libc::ESTALE));
            }
            let mut buffer = [0u8; XATTR_BUFFER_BYTES];
            let listed = bounded_xattr_list(fd.as_raw_fd(), &mut buffer)?;
            if listed == 0 {
                return Err(io::Error::from_raw_os_error(libc::ENODATA));
            }
            if !xattr_list_contains(&buffer[..listed], xattr_name.to_bytes()) {
                return Err(io::Error::from_raw_os_error(libc::ENODATA));
            }

            let value_bytes = raw_get_xattr(fd.as_raw_fd(), xattr_name, None)?;
            if value_bytes > XATTR_BUFFER_BYTES {
                return Err(io::Error::from_raw_os_error(libc::E2BIG));
            }
            let output_len = value_bytes.max(1);
            let observed =
                raw_get_xattr(fd.as_raw_fd(), xattr_name, Some(&mut buffer[..output_len]))?;
            if observed != value_bytes {
                return Err(io::Error::from_raw_os_error(libc::ESTALE));
            }
            let after = raw_node_observation(fd.as_fd())?;
            Ok(ReadExerciseV1 { before, after })
        }

        fn reobserve_probe(
            &self,
            fd: BorrowedFd<'_>,
            _kind: ProbeKindV1,
        ) -> io::Result<NodeObservationV1> {
            raw_node_observation(fd)
        }

        fn reopen_probe(
            &self,
            parent: BorrowedFd<'_>,
            name: &CStr,
            _kind: ProbeKindV1,
        ) -> io::Result<NodeObservationV1> {
            let fd = openat2_owned(
                parent,
                name,
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )?;
            raw_node_observation(fd.as_fd())
        }
    }

    pub(super) fn qualify_no_atime_source_view_at<'source>(
        trusted_parent: BorrowedFd<'source>,
        probes: &SourceViewQualificationProbesV1<'_>,
    ) -> Result<QualifiedNoAtimeSourceViewV1<'source>, SourceViewQualificationFailureV1> {
        qualify_with_hooks(trusted_parent, probes, &KernelHooksV1)
    }

    fn qualify_with_hooks<'source, H: QualificationHooksV1>(
        trusted_parent: BorrowedFd<'source>,
        probes: &SourceViewQualificationProbesV1<'_>,
        hooks: &H,
    ) -> Result<QualifiedNoAtimeSourceViewV1<'source>, SourceViewQualificationFailureV1> {
        // This check must remain before every operation that can update atime.
        let mount_before = hooks.observe_mount(trusted_parent).map_err(|error| {
            io_failure(SourceViewQualificationStageV1::InspectMountBefore, error)
        })?;
        if !mount_before.is_supported_local_filesystem() {
            return Err(failure(
                RefusalCode::RequiredKernelCapabilityMissing,
                SourceViewQualificationStageV1::InspectMountBefore,
                SourceViewQualificationReasonV1::FilesystemNotQualified,
            ));
        }
        if !mount_before.suppresses_atime() {
            return Err(failure(
                RefusalCode::RequiredKernelCapabilityMissing,
                SourceViewQualificationStageV1::InspectMountBefore,
                SourceViewQualificationReasonV1::MountDoesNotSuppressAtime,
            ));
        }

        let parent_before = hooks.observe_parent(trusted_parent).map_err(|error| {
            io_failure(SourceViewQualificationStageV1::InspectParentBefore, error)
        })?;
        require_kind(
            parent_before,
            ProbeKindV1::Directory,
            SourceViewQualificationStageV1::InspectParentBefore,
        )?;

        let directory = pin_probe(
            hooks,
            trusted_parent,
            probes.directory,
            ProbeKindV1::Directory,
            parent_before.mount_id,
            SourceViewQualificationStageV1::PinDirectory,
        )?;
        let regular = pin_probe(
            hooks,
            trusted_parent,
            probes.regular,
            ProbeKindV1::Regular,
            parent_before.mount_id,
            SourceViewQualificationStageV1::PinRegular,
        )?;
        if regular.observation.size == 0 {
            return Err(failure(
                RefusalCode::SnapshotRequiredObjectUnsupported,
                SourceViewQualificationStageV1::PinRegular,
                SourceViewQualificationReasonV1::EmptyProbe,
            ));
        }
        let symlink = pin_probe(
            hooks,
            trusted_parent,
            probes.symlink,
            ProbeKindV1::Symlink,
            parent_before.mount_id,
            SourceViewQualificationStageV1::PinSymlink,
        )?;
        if symlink.observation.size == 0 {
            return Err(failure(
                RefusalCode::SnapshotRequiredObjectUnsupported,
                SourceViewQualificationStageV1::PinSymlink,
                SourceViewQualificationReasonV1::EmptyProbe,
            ));
        }

        let directory_read = hooks
            .exercise_directory(trusted_parent, probes.directory)
            .map_err(|error| io_failure(SourceViewQualificationStageV1::ReadDirectory, error))?;
        require_unchanged(
            directory.observation,
            directory_read.before,
            SourceViewQualificationStageV1::ReadDirectory,
        )?;
        require_unchanged(
            directory.observation,
            directory_read.after,
            SourceViewQualificationStageV1::ReadDirectory,
        )?;
        let directory_xattr = hooks
            .exercise_xattr_list(trusted_parent, probes.directory, &directory)
            .map_err(|error| {
                io_failure(
                    SourceViewQualificationStageV1::ReadDirectoryXattrList,
                    error,
                )
            })?;
        require_unchanged(
            directory.observation,
            directory_xattr.before,
            SourceViewQualificationStageV1::ReadDirectoryXattrList,
        )?;
        require_unchanged(
            directory.observation,
            directory_xattr.after,
            SourceViewQualificationStageV1::ReadDirectoryXattrList,
        )?;

        let regular_read = hooks
            .exercise_regular(trusted_parent, probes.regular)
            .map_err(|error| io_failure(SourceViewQualificationStageV1::ReadRegular, error))?;
        require_unchanged(
            regular.observation,
            regular_read.before,
            SourceViewQualificationStageV1::ReadRegular,
        )?;
        require_unchanged(
            regular.observation,
            regular_read.after,
            SourceViewQualificationStageV1::ReadRegular,
        )?;
        let regular_xattr = hooks
            .exercise_regular_xattr(trusted_parent, probes.regular, &regular, probes.xattr)
            .map_err(|error| io_failure(SourceViewQualificationStageV1::ReadRegularXattr, error))?;
        require_unchanged(
            regular.observation,
            regular_xattr.before,
            SourceViewQualificationStageV1::ReadRegularXattr,
        )?;
        require_unchanged(
            regular.observation,
            regular_xattr.after,
            SourceViewQualificationStageV1::ReadRegularXattr,
        )?;

        hooks
            .exercise_symlink(symlink.fd.as_fd())
            .map_err(|error| io_failure(SourceViewQualificationStageV1::ReadSymlink, error))?;
        let symlink_xattr = hooks
            .exercise_xattr_list(trusted_parent, probes.symlink, &symlink)
            .map_err(|error| {
                io_failure(SourceViewQualificationStageV1::ReadSymlinkXattrList, error)
            })?;
        require_unchanged(
            symlink.observation,
            symlink_xattr.before,
            SourceViewQualificationStageV1::ReadSymlinkXattrList,
        )?;
        require_unchanged(
            symlink.observation,
            symlink_xattr.after,
            SourceViewQualificationStageV1::ReadSymlinkXattrList,
        )?;

        revalidate_probe(
            hooks,
            trusted_parent,
            probes.directory,
            ProbeKindV1::Directory,
            &directory,
            SourceViewQualificationStageV1::RevalidateDirectory,
        )?;
        revalidate_probe(
            hooks,
            trusted_parent,
            probes.regular,
            ProbeKindV1::Regular,
            &regular,
            SourceViewQualificationStageV1::RevalidateRegular,
        )?;
        revalidate_probe(
            hooks,
            trusted_parent,
            probes.symlink,
            ProbeKindV1::Symlink,
            &symlink,
            SourceViewQualificationStageV1::RevalidateSymlink,
        )?;

        let parent_after = hooks
            .observe_parent(trusted_parent)
            .map_err(|error| io_failure(SourceViewQualificationStageV1::RevalidateParent, error))?;
        require_unchanged(
            parent_before,
            parent_after,
            SourceViewQualificationStageV1::RevalidateParent,
        )?;

        // Recheck immediately before minting so a remount cannot silently turn
        // a formerly qualified view into an ordinary atime-updating view.
        let mount_after = hooks.observe_mount(trusted_parent).map_err(|error| {
            io_failure(SourceViewQualificationStageV1::InspectMountAfter, error)
        })?;
        if mount_after != mount_before
            || !mount_after.is_supported_local_filesystem()
            || !mount_after.suppresses_atime()
        {
            return Err(failure(
                RefusalCode::SnapshotConstructionFailed,
                SourceViewQualificationStageV1::InspectMountAfter,
                SourceViewQualificationReasonV1::MountChanged,
            ));
        }

        // This nested module alone reaches the parent-private production
        // constructor after proving the exact mount advertised ST_NOATIME,
        // exercising the admitted representative read forms, revalidating pinned and
        // reopened identities, and checking the mount again before mint.
        Ok(QualifiedNoAtimeSourceViewV1::from_functionally_verified_mount(trusted_parent))
    }

    fn pin_probe<H: QualificationHooksV1>(
        hooks: &H,
        parent: BorrowedFd<'_>,
        name: &CStr,
        kind: ProbeKindV1,
        expected_mount: u64,
        stage: SourceViewQualificationStageV1,
    ) -> Result<PinnedProbeV1, SourceViewQualificationFailureV1> {
        let probe = hooks
            .pin_probe(parent, name, kind)
            .map_err(|error| io_failure(stage, error))?;
        require_kind(probe.observation, kind, stage)?;
        if probe.observation.mount_id != expected_mount {
            return Err(failure(
                RefusalCode::SnapshotRequiredObjectUnsupported,
                stage,
                SourceViewQualificationReasonV1::MountCrossing,
            ));
        }
        Ok(probe)
    }

    fn revalidate_probe<H: QualificationHooksV1>(
        hooks: &H,
        parent: BorrowedFd<'_>,
        name: &CStr,
        kind: ProbeKindV1,
        pinned: &PinnedProbeV1,
        stage: SourceViewQualificationStageV1,
    ) -> Result<(), SourceViewQualificationFailureV1> {
        let pinned_after = hooks
            .reobserve_probe(pinned.fd.as_fd(), kind)
            .map_err(|error| io_failure(stage, error))?;
        require_unchanged(pinned.observation, pinned_after, stage)?;
        let reopened = hooks
            .reopen_probe(parent, name, kind)
            .map_err(|error| io_failure(stage, error))?;
        require_unchanged(pinned.observation, reopened, stage)
    }

    fn require_kind(
        observation: NodeObservationV1,
        kind: ProbeKindV1,
        stage: SourceViewQualificationStageV1,
    ) -> Result<(), SourceViewQualificationFailureV1> {
        if observation.mode & libc::S_IFMT == kind.expected_mode() {
            Ok(())
        } else {
            Err(failure(
                RefusalCode::SnapshotRequiredObjectUnsupported,
                stage,
                SourceViewQualificationReasonV1::WrongObjectKind,
            ))
        }
    }

    fn require_unchanged(
        before: NodeObservationV1,
        after: NodeObservationV1,
        stage: SourceViewQualificationStageV1,
    ) -> Result<(), SourceViewQualificationFailureV1> {
        if before == after {
            Ok(())
        } else if before.atime != after.atime {
            Err(failure(
                RefusalCode::SnapshotConstructionFailed,
                stage,
                SourceViewQualificationReasonV1::AtimeChanged,
            ))
        } else {
            Err(failure(
                RefusalCode::SnapshotConstructionFailed,
                stage,
                SourceViewQualificationReasonV1::SourceChanged,
            ))
        }
    }

    fn failure(
        code: RefusalCode,
        stage: SourceViewQualificationStageV1,
        reason: SourceViewQualificationReasonV1,
    ) -> SourceViewQualificationFailureV1 {
        SourceViewQualificationFailureV1::new(code, stage, reason, None)
    }

    fn io_failure(
        stage: SourceViewQualificationStageV1,
        error: io::Error,
    ) -> SourceViewQualificationFailureV1 {
        let errno = error.raw_os_error();
        let (code, reason) = if errno == Some(libc::EXDEV) {
            (
                RefusalCode::SnapshotRequiredObjectUnsupported,
                SourceViewQualificationReasonV1::MountCrossing,
            )
        } else if stage == SourceViewQualificationStageV1::ReadRegularXattr
            && errno == Some(libc::ENODATA)
        {
            (
                RefusalCode::SnapshotRequiredObjectUnsupported,
                SourceViewQualificationReasonV1::MissingXattr,
            )
        } else if matches!(
            stage,
            SourceViewQualificationStageV1::ReadDirectoryXattrList
                | SourceViewQualificationStageV1::ReadRegularXattr
                | SourceViewQualificationStageV1::ReadSymlinkXattrList
        ) && errno == Some(libc::E2BIG)
        {
            (
                RefusalCode::SnapshotRequiredObjectUnsupported,
                SourceViewQualificationReasonV1::ProbeExceedsBound,
            )
        } else if matches!(
            errno,
            Some(libc::ENOSYS | libc::EINVAL | libc::E2BIG | libc::EOPNOTSUPP)
        ) {
            (
                RefusalCode::RequiredKernelCapabilityMissing,
                SourceViewQualificationReasonV1::RequiredKernelCapability,
            )
        } else if errno == Some(libc::EPROTO) {
            (
                RefusalCode::SnapshotConstructionFailed,
                SourceViewQualificationReasonV1::MalformedKernelResponse,
            )
        } else if matches!(errno, Some(libc::ESTALE | libc::ENOENT | libc::ELOOP)) {
            (
                RefusalCode::SnapshotConstructionFailed,
                SourceViewQualificationReasonV1::SourceChanged,
            )
        } else {
            (
                RefusalCode::SnapshotConstructionFailed,
                SourceViewQualificationReasonV1::Io,
            )
        };
        SourceViewQualificationFailureV1::new(code, stage, reason, errno)
    }

    fn raw_mount_observation(parent: BorrowedFd<'_>) -> io::Result<MountObservationV1> {
        let mut raw = MaybeUninit::<libc::statfs64>::zeroed();
        let result = unsafe { libc::fstatfs64(parent.as_raw_fd(), raw.as_mut_ptr()) };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        let raw = unsafe { raw.assume_init() };
        let flags = u64::try_from(raw.f_flags)
            .map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))?;
        Ok(MountObservationV1 {
            filesystem_type: raw.f_type,
            flags,
        })
    }

    fn raw_node_observation(fd: BorrowedFd<'_>) -> io::Result<NodeObservationV1> {
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
        let timestamp = |value: libc::statx_timestamp| TimestampV1 {
            seconds: value.tv_sec,
            nanoseconds: value.tv_nsec,
        };
        Ok(NodeObservationV1 {
            mount_id: raw.stx_mnt_id,
            device_major: raw.stx_dev_major,
            device_minor: raw.stx_dev_minor,
            inode: raw.stx_ino,
            mode: u32::from(raw.stx_mode),
            uid: raw.stx_uid,
            gid: raw.stx_gid,
            link_count: u64::from(raw.stx_nlink),
            size: raw.stx_size,
            blocks: raw.stx_blocks,
            attributes: raw.stx_attributes,
            attributes_mask: raw.stx_attributes_mask,
            atime: timestamp(raw.stx_atime),
            mtime: timestamp(raw.stx_mtime),
            ctime: timestamp(raw.stx_ctime),
            btime: (raw.stx_mask & libc::STATX_BTIME != 0).then(|| timestamp(raw.stx_btime)),
        })
    }

    fn openat2_owned(parent: BorrowedFd<'_>, name: &CStr, flags: i32) -> io::Result<OwnedFd> {
        let how = OpenHow {
            flags: flags as u64,
            mode: 0,
            resolve: SOURCE_RESOLVE,
        };
        let mut last = io::Error::from_raw_os_error(libc::EAGAIN);
        for _ in 0..MAX_OPENAT2_ATTEMPTS {
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

    fn require_reopened_probe_identity_v1(
        parent: BorrowedFd<'_>,
        name: &CStr,
        expected: NodeObservationV1,
    ) -> io::Result<()> {
        let reopened = openat2_owned(
            parent,
            name,
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )?;
        if raw_node_observation(reopened.as_fd())? != expected {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        Ok(())
    }

    fn raw_list_xattrs_at(
        fd: RawFd,
        path: &CStr,
        flags: i32,
        output: Option<&mut [u8]>,
    ) -> io::Result<usize> {
        let (pointer, length) = output
            .map(|buffer| (buffer.as_mut_ptr().cast::<libc::c_char>(), buffer.len()))
            .unwrap_or((std::ptr::null_mut(), 0));
        let result = unsafe {
            libc::syscall(
                SYS_LISTXATTRAT_X86_64,
                fd,
                path.as_ptr(),
                flags,
                pointer,
                length,
            )
        };
        syscall_size(result)
    }

    fn raw_list_xattrs(fd: RawFd, output: Option<&mut [u8]>) -> io::Result<usize> {
        raw_list_xattrs_at(fd, c"", AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW, output)
    }

    fn bounded_xattr_list(fd: RawFd, buffer: &mut [u8; XATTR_BUFFER_BYTES]) -> io::Result<usize> {
        bounded_xattr_list_with_v1(buffer, |output| raw_list_xattrs(fd, output))
    }

    fn bounded_xattr_list_at(
        parent: RawFd,
        name: &CStr,
        buffer: &mut [u8; XATTR_BUFFER_BYTES],
    ) -> io::Result<usize> {
        bounded_xattr_list_with_v1(buffer, |output| {
            raw_list_xattrs_at(parent, name, libc::AT_SYMLINK_NOFOLLOW, output)
        })
    }

    fn bounded_xattr_list_with_v1(
        buffer: &mut [u8; XATTR_BUFFER_BYTES],
        mut list: impl FnMut(Option<&mut [u8]>) -> io::Result<usize>,
    ) -> io::Result<usize> {
        let required = list(None)?;
        if required > buffer.len() {
            return Err(io::Error::from_raw_os_error(libc::E2BIG));
        }
        if required == 0 {
            return Ok(0);
        }
        let listed = list(Some(&mut buffer[..required]))?;
        if listed != required {
            return Err(io::Error::from_raw_os_error(libc::ESTALE));
        }
        if buffer[..listed].last() != Some(&0) {
            return Err(io::Error::from_raw_os_error(libc::EPROTO));
        }
        Ok(listed)
    }

    fn raw_get_xattr(fd: RawFd, name: &CStr, output: Option<&mut [u8]>) -> io::Result<usize> {
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

    fn syscall_size(result: libc::c_long) -> io::Result<usize> {
        if result < 0 {
            Err(io::Error::last_os_error())
        } else {
            usize::try_from(result).map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))
        }
    }

    fn xattr_list_contains(list: &[u8], expected: &[u8]) -> bool {
        if list.last() != Some(&0) {
            return false;
        }
        list[..list.len() - 1]
            .split(|byte| *byte == 0)
            .any(|name| name == expected)
    }

    #[cfg(test)]
    mod tests {
        use std::cell::{Cell, RefCell};
        use std::fs::File;
        use std::os::fd::AsFd;

        use super::*;

        const MOUNT_NOATIME: MountObservationV1 = MountObservationV1 {
            filesystem_type: TMPFS_SUPER_MAGIC,
            flags: libc::ST_NOATIME,
        };

        fn observation(kind: ProbeKindV1, inode: u64) -> NodeObservationV1 {
            NodeObservationV1 {
                mount_id: 7,
                device_major: 8,
                device_minor: 1,
                inode,
                mode: kind.expected_mode() | 0o444,
                uid: 1000,
                gid: 1000,
                link_count: 1,
                size: 8,
                blocks: 1,
                attributes: 0,
                attributes_mask: 0,
                atime: TimestampV1 {
                    seconds: 10,
                    nanoseconds: 11,
                },
                mtime: TimestampV1 {
                    seconds: 12,
                    nanoseconds: 13,
                },
                ctime: TimestampV1 {
                    seconds: 14,
                    nanoseconds: 15,
                },
                btime: None,
            }
        }

        fn parent_observation() -> NodeObservationV1 {
            observation(ProbeKindV1::Directory, 1)
        }

        fn probes() -> SourceViewQualificationProbesV1<'static> {
            SourceViewQualificationProbesV1::checked(
                c"directory",
                c"regular",
                c"symlink",
                c"user.again-noatime-probe",
            )
            .unwrap()
        }

        struct MockHooksV1 {
            calls: RefCell<Vec<&'static str>>,
            mount_calls: Cell<u8>,
            first_mount: MountObservationV1,
            second_mount: MountObservationV1,
            regular_read_after: Cell<NodeObservationV1>,
            directory_xattr_after: Cell<NodeObservationV1>,
            regular_xattr_after: Cell<NodeObservationV1>,
            symlink_xattr_after: Cell<NodeObservationV1>,
            directory_xattr_list_errno: Cell<Option<i32>>,
            regular_xattr_errno: Cell<Option<i32>>,
            symlink_xattr_list_errno: Cell<Option<i32>>,
        }

        impl MockHooksV1 {
            fn stable() -> Self {
                Self {
                    calls: RefCell::new(Vec::new()),
                    mount_calls: Cell::new(0),
                    first_mount: MOUNT_NOATIME,
                    second_mount: MOUNT_NOATIME,
                    regular_read_after: Cell::new(observation(ProbeKindV1::Regular, 3)),
                    directory_xattr_after: Cell::new(observation(ProbeKindV1::Directory, 2)),
                    regular_xattr_after: Cell::new(observation(ProbeKindV1::Regular, 3)),
                    symlink_xattr_after: Cell::new(observation(ProbeKindV1::Symlink, 4)),
                    directory_xattr_list_errno: Cell::new(None),
                    regular_xattr_errno: Cell::new(None),
                    symlink_xattr_list_errno: Cell::new(None),
                }
            }

            fn record(&self, call: &'static str) {
                self.calls.borrow_mut().push(call);
            }

            fn duplicate(parent: BorrowedFd<'_>) -> io::Result<OwnedFd> {
                let result = unsafe { libc::fcntl(parent.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 3) };
                if result < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    Ok(unsafe { OwnedFd::from_raw_fd(result) })
                }
            }
        }

        impl QualificationHooksV1 for MockHooksV1 {
            fn observe_mount(&self, _parent: BorrowedFd<'_>) -> io::Result<MountObservationV1> {
                self.record("mount");
                let call = self.mount_calls.get();
                self.mount_calls.set(call + 1);
                Ok(if call == 0 {
                    self.first_mount
                } else {
                    self.second_mount
                })
            }

            fn observe_parent(&self, _parent: BorrowedFd<'_>) -> io::Result<NodeObservationV1> {
                self.record("parent");
                Ok(parent_observation())
            }

            fn pin_probe(
                &self,
                parent: BorrowedFd<'_>,
                _name: &CStr,
                kind: ProbeKindV1,
            ) -> io::Result<PinnedProbeV1> {
                self.record("pin");
                let inode = match kind {
                    ProbeKindV1::Directory => 2,
                    ProbeKindV1::Regular => 3,
                    ProbeKindV1::Symlink => 4,
                };
                Ok(PinnedProbeV1 {
                    fd: Self::duplicate(parent)?,
                    observation: observation(kind, inode),
                })
            }

            fn exercise_directory(
                &self,
                _parent: BorrowedFd<'_>,
                _name: &CStr,
            ) -> io::Result<ReadExerciseV1> {
                self.record("read_directory");
                let value = observation(ProbeKindV1::Directory, 2);
                Ok(ReadExerciseV1 {
                    before: value,
                    after: value,
                })
            }

            fn exercise_regular(
                &self,
                _parent: BorrowedFd<'_>,
                _name: &CStr,
            ) -> io::Result<ReadExerciseV1> {
                self.record("read_regular");
                Ok(ReadExerciseV1 {
                    before: observation(ProbeKindV1::Regular, 3),
                    after: self.regular_read_after.get(),
                })
            }

            fn exercise_symlink(&self, _fd: BorrowedFd<'_>) -> io::Result<()> {
                self.record("read_symlink");
                Ok(())
            }

            fn exercise_xattr_list(
                &self,
                _parent: BorrowedFd<'_>,
                _name: &CStr,
                probe: &PinnedProbeV1,
            ) -> io::Result<ReadExerciseV1> {
                let errno = match probe.observation.mode & libc::S_IFMT {
                    libc::S_IFDIR => {
                        self.record("list_directory_xattrs");
                        self.directory_xattr_list_errno.get()
                    }
                    libc::S_IFLNK => {
                        self.record("list_symlink_xattrs");
                        self.symlink_xattr_list_errno.get()
                    }
                    _ => return Err(io::Error::from_raw_os_error(libc::EINVAL)),
                };
                match errno {
                    Some(errno) => Err(io::Error::from_raw_os_error(errno)),
                    None => Ok(ReadExerciseV1 {
                        before: probe.observation,
                        after: match probe.observation.mode & libc::S_IFMT {
                            libc::S_IFDIR => self.directory_xattr_after.get(),
                            libc::S_IFLNK => self.symlink_xattr_after.get(),
                            _ => unreachable!("object kind was validated above"),
                        },
                    }),
                }
            }

            fn exercise_regular_xattr(
                &self,
                _parent: BorrowedFd<'_>,
                _name: &CStr,
                probe: &PinnedProbeV1,
                _xattr_name: &CStr,
            ) -> io::Result<ReadExerciseV1> {
                self.record("list_get_regular_xattr");
                match self.regular_xattr_errno.get() {
                    Some(errno) => Err(io::Error::from_raw_os_error(errno)),
                    None => Ok(ReadExerciseV1 {
                        before: probe.observation,
                        after: self.regular_xattr_after.get(),
                    }),
                }
            }

            fn reobserve_probe(
                &self,
                _fd: BorrowedFd<'_>,
                kind: ProbeKindV1,
            ) -> io::Result<NodeObservationV1> {
                self.record("reobserve");
                let inode = match kind {
                    ProbeKindV1::Directory => 2,
                    ProbeKindV1::Regular => 3,
                    ProbeKindV1::Symlink => 4,
                };
                Ok(observation(kind, inode))
            }

            fn reopen_probe(
                &self,
                _parent: BorrowedFd<'_>,
                _name: &CStr,
                kind: ProbeKindV1,
            ) -> io::Result<NodeObservationV1> {
                self.record("reopen");
                let inode = match kind {
                    ProbeKindV1::Directory => 2,
                    ProbeKindV1::Regular => 3,
                    ProbeKindV1::Symlink => 4,
                };
                Ok(observation(kind, inode))
            }
        }

        #[test]
        fn noatime_gate_precedes_reads_and_all_xattr_object_forms_run_in_order() {
            let file = File::open("/dev/null").unwrap();
            let hooks = MockHooksV1::stable();
            let qualified = qualify_with_hooks(file.as_fd(), &probes(), &hooks);
            assert!(qualified.is_ok());

            let calls = hooks.calls.borrow();
            assert_eq!(
                &*calls,
                &[
                    "mount",
                    "parent",
                    "pin",
                    "pin",
                    "pin",
                    "read_directory",
                    "list_directory_xattrs",
                    "read_regular",
                    "list_get_regular_xattr",
                    "read_symlink",
                    "list_symlink_xattrs",
                    "reobserve",
                    "reopen",
                    "reobserve",
                    "reopen",
                    "reobserve",
                    "reopen",
                    "parent",
                    "mount",
                ]
            );
        }

        #[test]
        fn missing_noatime_flag_refuses_before_any_probe_or_read() {
            let file = File::open("/dev/null").unwrap();
            let mut hooks = MockHooksV1::stable();
            hooks.first_mount.flags = 0;
            let failure = qualify_with_hooks(file.as_fd(), &probes(), &hooks)
                .err()
                .unwrap();

            assert_eq!(failure.code(), RefusalCode::RequiredKernelCapabilityMissing);
            assert_eq!(
                failure.reason(),
                SourceViewQualificationReasonV1::MountDoesNotSuppressAtime
            );
            assert_eq!(&*hooks.calls.borrow(), &["mount"]);
        }

        #[test]
        fn unqualified_filesystem_refuses_before_any_probe_or_read() {
            let file = File::open("/dev/null").unwrap();
            let mut hooks = MockHooksV1::stable();
            hooks.first_mount.filesystem_type = libc::NFS_SUPER_MAGIC;
            let failure = qualify_with_hooks(file.as_fd(), &probes(), &hooks)
                .err()
                .unwrap();

            assert_eq!(failure.code(), RefusalCode::RequiredKernelCapabilityMissing);
            assert_eq!(
                failure.reason(),
                SourceViewQualificationReasonV1::FilesystemNotQualified
            );
            assert_eq!(&*hooks.calls.borrow(), &["mount"]);
        }

        #[test]
        fn observed_atime_change_refuses_in_the_exact_read_stage() {
            let file = File::open("/dev/null").unwrap();
            let hooks = MockHooksV1::stable();
            let mut changed = observation(ProbeKindV1::Regular, 3);
            changed.atime.nanoseconds += 1;
            hooks.regular_read_after.set(changed);

            let failure = qualify_with_hooks(file.as_fd(), &probes(), &hooks)
                .err()
                .unwrap();
            assert_eq!(failure.code(), RefusalCode::SnapshotConstructionFailed);
            assert_eq!(failure.stage(), SourceViewQualificationStageV1::ReadRegular);
            assert_eq!(
                failure.reason(),
                SourceViewQualificationReasonV1::AtimeChanged
            );
        }

        #[test]
        fn mount_change_after_reads_refuses_before_mint() {
            let file = File::open("/dev/null").unwrap();
            let mut hooks = MockHooksV1::stable();
            hooks.second_mount.flags |= libc::ST_RDONLY;

            let failure = qualify_with_hooks(file.as_fd(), &probes(), &hooks)
                .err()
                .unwrap();
            assert_eq!(
                failure.stage(),
                SourceViewQualificationStageV1::InspectMountAfter
            );
            assert_eq!(
                failure.reason(),
                SourceViewQualificationReasonV1::MountChanged
            );
        }

        #[test]
        fn missing_xattr_is_a_typed_object_refusal() {
            let file = File::open("/dev/null").unwrap();
            let hooks = MockHooksV1::stable();
            hooks.regular_xattr_errno.set(Some(libc::ENODATA));

            let failure = qualify_with_hooks(file.as_fd(), &probes(), &hooks)
                .err()
                .unwrap();
            assert_eq!(
                failure.code(),
                RefusalCode::SnapshotRequiredObjectUnsupported
            );
            assert_eq!(
                failure.reason(),
                SourceViewQualificationReasonV1::MissingXattr
            );
            assert_eq!(failure.errno(), Some(libc::ENODATA));
            assert_eq!(
                failure.stage(),
                SourceViewQualificationStageV1::ReadRegularXattr
            );
        }

        #[test]
        fn oversized_xattr_probe_is_not_misreported_as_a_kernel_gap() {
            let file = File::open("/dev/null").unwrap();
            let hooks = MockHooksV1::stable();
            hooks.regular_xattr_errno.set(Some(libc::E2BIG));

            let failure = qualify_with_hooks(file.as_fd(), &probes(), &hooks)
                .err()
                .unwrap();
            assert_eq!(
                failure.code(),
                RefusalCode::SnapshotRequiredObjectUnsupported
            );
            assert_eq!(
                failure.reason(),
                SourceViewQualificationReasonV1::ProbeExceedsBound
            );
            assert_eq!(failure.errno(), Some(libc::E2BIG));
        }

        #[test]
        fn directory_xattr_list_failure_is_typed_before_regular_or_symlink_reads() {
            let file = File::open("/dev/null").unwrap();
            let hooks = MockHooksV1::stable();
            hooks.directory_xattr_list_errno.set(Some(libc::E2BIG));

            let failure = qualify_with_hooks(file.as_fd(), &probes(), &hooks)
                .err()
                .unwrap();
            assert_eq!(
                failure.stage(),
                SourceViewQualificationStageV1::ReadDirectoryXattrList
            );
            assert_eq!(
                failure.reason(),
                SourceViewQualificationReasonV1::ProbeExceedsBound
            );
            assert_eq!(
                &*hooks.calls.borrow(),
                &[
                    "mount",
                    "parent",
                    "pin",
                    "pin",
                    "pin",
                    "read_directory",
                    "list_directory_xattrs",
                ]
            );
        }

        #[test]
        fn readable_xattr_descriptor_drift_refuses_before_qualification() {
            let file = File::open("/dev/null").unwrap();
            let directory_hooks = MockHooksV1::stable();
            let mut changed_directory = observation(ProbeKindV1::Directory, 2);
            changed_directory.ctime.nanoseconds += 1;
            directory_hooks.directory_xattr_after.set(changed_directory);
            let failure = qualify_with_hooks(file.as_fd(), &probes(), &directory_hooks)
                .err()
                .unwrap();
            assert_eq!(
                failure.stage(),
                SourceViewQualificationStageV1::ReadDirectoryXattrList
            );
            assert_eq!(
                failure.reason(),
                SourceViewQualificationReasonV1::SourceChanged
            );

            let regular_hooks = MockHooksV1::stable();
            let mut changed_regular = observation(ProbeKindV1::Regular, 3);
            changed_regular.ctime.nanoseconds += 1;
            regular_hooks.regular_xattr_after.set(changed_regular);
            let failure = qualify_with_hooks(file.as_fd(), &probes(), &regular_hooks)
                .err()
                .unwrap();
            assert_eq!(
                failure.stage(),
                SourceViewQualificationStageV1::ReadRegularXattr
            );
            assert_eq!(
                failure.reason(),
                SourceViewQualificationReasonV1::SourceChanged
            );
        }

        #[test]
        fn xattr_list_ebadf_is_an_io_refusal_for_every_object_kind() {
            let file = File::open("/dev/null").unwrap();
            let directory_hooks = MockHooksV1::stable();
            directory_hooks
                .directory_xattr_list_errno
                .set(Some(libc::EBADF));
            let failure = qualify_with_hooks(file.as_fd(), &probes(), &directory_hooks)
                .err()
                .unwrap();
            assert_eq!(failure.reason(), SourceViewQualificationReasonV1::Io);
            assert_eq!(failure.code(), RefusalCode::SnapshotConstructionFailed);

            let symlink_hooks = MockHooksV1::stable();
            symlink_hooks
                .symlink_xattr_list_errno
                .set(Some(libc::EBADF));
            let failure = qualify_with_hooks(file.as_fd(), &probes(), &symlink_hooks)
                .err()
                .unwrap();
            assert_eq!(
                failure.stage(),
                SourceViewQualificationStageV1::ReadSymlinkXattrList
            );
            assert_eq!(failure.reason(), SourceViewQualificationReasonV1::Io);
            assert_eq!(failure.code(), RefusalCode::SnapshotConstructionFailed);
        }

        #[test]
        fn symlink_xattr_list_failure_follows_positive_regular_list_get() {
            let file = File::open("/dev/null").unwrap();
            let hooks = MockHooksV1::stable();
            hooks.symlink_xattr_list_errno.set(Some(libc::E2BIG));

            let failure = qualify_with_hooks(file.as_fd(), &probes(), &hooks)
                .err()
                .unwrap();
            assert_eq!(
                failure.stage(),
                SourceViewQualificationStageV1::ReadSymlinkXattrList
            );
            assert_eq!(
                failure.reason(),
                SourceViewQualificationReasonV1::ProbeExceedsBound
            );
            assert_eq!(
                &*hooks.calls.borrow(),
                &[
                    "mount",
                    "parent",
                    "pin",
                    "pin",
                    "pin",
                    "read_directory",
                    "list_directory_xattrs",
                    "read_regular",
                    "list_get_regular_xattr",
                    "read_symlink",
                    "list_symlink_xattrs",
                ]
            );
        }

        #[test]
        fn xattr_list_parser_requires_a_complete_nul_terminated_exact_name() {
            assert!(xattr_list_contains(
                b"user.a\0user.again-noatime-probe\0",
                b"user.again-noatime-probe"
            ));
            assert!(!xattr_list_contains(
                b"user.again-noatime-probe",
                b"user.again-noatime-probe"
            ));
            assert!(!xattr_list_contains(
                b"user.again-noatime-probe-extra\0",
                b"user.again-noatime-probe"
            ));
        }
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
mod platform {
    use super::*;

    pub(super) fn qualify_no_atime_source_view_at<'source>(
        _trusted_parent: BorrowedFd<'source>,
        _probes: &SourceViewQualificationProbesV1<'_>,
    ) -> Result<QualifiedNoAtimeSourceViewV1<'source>, SourceViewQualificationFailureV1> {
        let code = if cfg!(target_os = "linux") {
            RefusalCode::UnsupportedArchitecture
        } else {
            RefusalCode::UnsupportedOs
        };
        Err(SourceViewQualificationFailureV1::new(
            code,
            SourceViewQualificationStageV1::InspectMountBefore,
            SourceViewQualificationReasonV1::RequiredKernelCapability,
            None,
        ))
    }
}

#[cfg(test)]
mod portable_tests {
    use std::fs::File;
    use std::os::fd::AsFd;

    use super::*;

    #[test]
    fn probe_names_are_strictly_validated() {
        assert!(
            SourceViewQualificationProbesV1::checked(
                c"directory",
                c"regular",
                c"symlink",
                c"user.again-probe"
            )
            .is_some()
        );
        assert!(
            SourceViewQualificationProbesV1::checked(
                c"same",
                c"same",
                c"symlink",
                c"user.again-probe"
            )
            .is_none()
        );
        assert!(
            SourceViewQualificationProbesV1::checked(
                c"../escape",
                c"regular",
                c"symlink",
                c"user.again-probe"
            )
            .is_none()
        );
        assert!(
            SourceViewQualificationProbesV1::checked(c"directory", c"regular", c"symlink", c"")
                .is_none()
        );
    }

    #[test]
    fn safe_portable_entrypoint_compiles_and_fails_closed_for_a_non_directory() {
        let file = File::open("/dev/null").unwrap();
        let probes = SourceViewQualificationProbesV1::checked(
            c"directory",
            c"regular",
            c"symlink",
            c"user.again-probe",
        )
        .unwrap();
        assert!(qualify_no_atime_source_view_at(file.as_fd(), &probes).is_err());
    }
}
