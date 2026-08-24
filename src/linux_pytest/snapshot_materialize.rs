//! Descriptor-relative staging-tree materialization for `linux-pytest-v1`.
//!
//! The materializer owns the publisher's private staging container while it
//! is active. It always creates the source root as a child of that container,
//! keeps only the active destination-directory stack open, and returns an
//! opaque publisher-ready authority only after hardlinks, metadata, xattrs,
//! timestamps, and recursive durability are complete. Dropping the
//! materializer delegates bounded, best-effort recursive cleanup to the
//! publisher's inode-bound RAII guard. Cleanup is not immediate while a
//! caller retains the materializer, and an uncleanable owner-private stage is
//! left for explicit scavenging rather than deleted without identity proof.
//! Symlinks fail closed until staging is bound to a qualified dedicated
//! filesystem whose filesystem-wide durability operation is safe to invoke.

use std::fmt;
use std::num::{NonZeroU8, NonZeroU16, NonZeroU32, NonZeroU64};

use super::RefusalCode;
use super::snapshot_publish::{
    SnapshotCleanupEnvelopeV1, SnapshotPublishErrorV1, StagedSnapshotDirectoryV1,
    VerifiedReadySnapshotDirectoryV1,
};
use super::snapshot_regular::SnapshotRegularStageV1;
use super::snapshot_tree::{
    SourceDirectoryVisitV1, SourceEnumerationPolicyV1, SourceRegularEvidenceV1,
    SourceRegularVisitV1, SourceSymlinkVisitV1, SourceTreePlanV1, SourceTreeVisitorV1,
};

const HARD_MAX_DEPTH: u16 = 256;
const HARD_MAX_BASENAME_BYTES: u16 = 255;
const HARD_MAX_ENTRIES: u32 = 1024 * 1024;
const HARD_MAX_TOTAL_XATTR_BYTES: u64 = 256 * 1024 * 1024;
const HARD_MAX_TOTAL_XATTRS: u64 = 4 * 1024 * 1024;
const HARD_MAX_XATTR_OPERATIONS: u64 = 32 * 1024 * 1024;
const HARD_MAX_PLAN_OPEN_COMPONENTS: u64 = 16 * 1024 * 1024;
const HARD_MAX_PLAN_BYTES: u64 = 512 * 1024 * 1024;
const HARD_MAX_OPENAT2_ATTEMPTS: u8 = 32;
const EVENT_COMMITMENT_BYTES: u64 = 32;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SnapshotMaterializePolicyV1 {
    max_depth: u16,
    max_basename_bytes: NonZeroU16,
    max_entries: NonZeroU32,
    max_total_xattr_bytes: NonZeroU64,
    max_total_xattrs: NonZeroU64,
    max_xattr_operations: NonZeroU64,
    max_plan_open_components: NonZeroU64,
    max_plan_bytes: NonZeroU64,
    openat2_attempts: NonZeroU8,
    syscall_attempts: NonZeroU8,
}

impl SnapshotMaterializePolicyV1 {
    /// Derive the materializer's only production policy from the exact source
    /// enumeration policy. Generic EINTR work uses the source policy's
    /// distinct bounded syscall-attempt count; the profile may therefore not
    /// silently grant the destination more retry work than source acquisition.
    pub(super) fn from_source_policy(source: SourceEnumerationPolicyV1) -> Option<Self> {
        Self::checked_derived(
            source.max_depth(),
            NonZeroU16::new(source.max_basename_bytes())?,
            NonZeroU32::new(source.max_entries())?,
            NonZeroU64::new(source.max_total_xattr_bytes())?,
            NonZeroU64::new(source.max_total_xattrs())?,
            NonZeroU64::new(source.max_plan_bytes())?,
            NonZeroU8::new(source.openat2_attempts())?,
            NonZeroU8::new(source.syscall_attempts())?,
        )
    }

    #[cfg(test)]
    fn checked(
        max_depth: u16,
        max_entries: NonZeroU32,
        max_total_xattr_bytes: NonZeroU64,
        openat2_attempts: NonZeroU8,
        syscall_attempts: NonZeroU8,
    ) -> Option<Self> {
        Self::checked_derived(
            max_depth,
            NonZeroU16::new(HARD_MAX_BASENAME_BYTES)?,
            max_entries,
            max_total_xattr_bytes,
            NonZeroU64::new(max_entries.get() as u64)?,
            NonZeroU64::new(HARD_MAX_PLAN_BYTES)?,
            openat2_attempts,
            syscall_attempts,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn checked_derived(
        max_depth: u16,
        max_basename_bytes: NonZeroU16,
        max_entries: NonZeroU32,
        max_total_xattr_bytes: NonZeroU64,
        max_total_xattrs: NonZeroU64,
        max_plan_bytes: NonZeroU64,
        openat2_attempts: NonZeroU8,
        syscall_attempts: NonZeroU8,
    ) -> Option<Self> {
        let xattr_value_operations = max_total_xattrs.get().checked_mul(6)?;
        let entry_operations = (max_entries.get() as u64) * 8;
        let max_xattr_operations =
            NonZeroU64::new(xattr_value_operations.checked_add(entry_operations)?)?;
        let plan_open_limit = if max_plan_bytes.get() < HARD_MAX_PLAN_OPEN_COMPONENTS {
            max_plan_bytes.get()
        } else {
            HARD_MAX_PLAN_OPEN_COMPONENTS
        };
        let max_plan_open_components = NonZeroU64::new(plan_open_limit)?;
        let event_commitment_bytes =
            (max_entries.get() as u64).checked_mul(EVENT_COMMITMENT_BYTES)?;
        if max_depth > HARD_MAX_DEPTH
            || max_basename_bytes.get() > HARD_MAX_BASENAME_BYTES
            || max_entries.get() > HARD_MAX_ENTRIES
            || max_total_xattr_bytes.get() > HARD_MAX_TOTAL_XATTR_BYTES
            || max_total_xattrs.get() > HARD_MAX_TOTAL_XATTRS
            || max_xattr_operations.get() > HARD_MAX_XATTR_OPERATIONS
            || max_plan_bytes.get() > HARD_MAX_PLAN_BYTES
            || event_commitment_bytes > max_plan_bytes.get()
            || openat2_attempts.get() > HARD_MAX_OPENAT2_ATTEMPTS
            || syscall_attempts.get() > HARD_MAX_OPENAT2_ATTEMPTS
        {
            return None;
        }
        Some(Self {
            max_depth,
            max_basename_bytes,
            max_entries,
            max_total_xattr_bytes,
            max_total_xattrs,
            max_xattr_operations,
            max_plan_open_components,
            max_plan_bytes,
            openat2_attempts,
            syscall_attempts,
        })
    }

    /// Destination descriptors owned by the walker itself. The regular-copy
    /// leaf and publisher each expose their own additive preflight bounds.
    pub(super) const fn max_live_destination_fds(self) -> u32 {
        let depth_bound = self.max_depth as u32 + 1;
        if depth_bound > 4 { depth_bound } else { 4 }
    }
}

fn cleanup_envelope_covers(
    cleanup: SnapshotCleanupEnvelopeV1,
    materialize: SnapshotMaterializePolicyV1,
) -> bool {
    cleanup.max_source_tree_depth() >= materialize.max_depth
        && cleanup.max_entries() >= materialize.max_entries.get()
        && cleanup.max_basename_bytes() >= materialize.max_basename_bytes.get()
        && cleanup.openat2_attempts() >= materialize.openat2_attempts.get()
        && cleanup.generic_syscall_attempts() >= materialize.syscall_attempts.get()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SnapshotMaterializeStageV1 {
    ValidateCleanupAuthority,
    ValidateEvent,
    ValidatePlan,
    ValidateDurability,
    CreateRoot,
    CreateDirectory,
    CopyRegular,
    ConsolidateHardlinks,
    OpenDestination,
    ApplyMode,
    ApplyXattrs,
    ApplyTimes,
    VerifyMetadata,
    SyncRegular,
    FinalizeDirectory,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SnapshotMaterializeLimitV1 {
    Depth,
    Entries,
    TotalXattrBytes,
    TotalXattrs,
    XattrOperations,
    XattrListBytes,
    PlanBytes,
    PlanOpenComponents,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SnapshotMaterializeFailureKindV1 {
    CleanupAuthorityInsufficient,
    InvalidEventSequence,
    PlanMismatch,
    SymlinkDurabilityRequiresQualifiedFilesystem,
    ResourceLimit(SnapshotMaterializeLimitV1),
    VisibleXattrUnrepresentable,
    RequiredKernelCapability,
    DestinationCollision,
    DestinationIdentityMismatch,
    UnsupportedMetadata,
    RegularCopy,
    Io,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SnapshotMaterializePathCaptureV1 {
    Exact,
    OmittedAllocationFailure,
}

#[derive(Debug)]
pub(super) struct SnapshotMaterializeFailureV1 {
    code: RefusalCode,
    stage: SnapshotMaterializeStageV1,
    kind: SnapshotMaterializeFailureKindV1,
    regular_stage: Option<SnapshotRegularStageV1>,
    errno: Option<i32>,
    relative_path: Vec<u8>,
    relative_path_capture: SnapshotMaterializePathCaptureV1,
}

impl SnapshotMaterializeFailureV1 {
    fn new(
        code: RefusalCode,
        stage: SnapshotMaterializeStageV1,
        kind: SnapshotMaterializeFailureKindV1,
        regular_stage: Option<SnapshotRegularStageV1>,
        errno: Option<i32>,
        relative_path: &[u8],
    ) -> Self {
        let (relative_path, relative_path_capture) = capture_diagnostic_path(relative_path);
        Self {
            code,
            stage,
            kind,
            regular_stage,
            errno,
            relative_path,
            relative_path_capture,
        }
    }

    pub(super) const fn code(&self) -> RefusalCode {
        self.code
    }

    pub(super) const fn stage(&self) -> SnapshotMaterializeStageV1 {
        self.stage
    }

    pub(super) const fn kind(&self) -> SnapshotMaterializeFailureKindV1 {
        self.kind
    }

    pub(super) const fn regular_stage(&self) -> Option<SnapshotRegularStageV1> {
        self.regular_stage
    }

    pub(super) const fn errno(&self) -> Option<i32> {
        self.errno
    }

    pub(super) fn relative_path(&self) -> &[u8] {
        &self.relative_path
    }

    pub(super) const fn relative_path_capture(&self) -> SnapshotMaterializePathCaptureV1 {
        self.relative_path_capture
    }
}

fn capture_diagnostic_path(relative_path: &[u8]) -> (Vec<u8>, SnapshotMaterializePathCaptureV1) {
    capture_diagnostic_path_with(relative_path, |retained, length| {
        retained.try_reserve_exact(length).map_err(|_| ())
    })
}

fn capture_diagnostic_path_with(
    relative_path: &[u8],
    reserve: impl FnOnce(&mut Vec<u8>, usize) -> Result<(), ()>,
) -> (Vec<u8>, SnapshotMaterializePathCaptureV1) {
    let mut retained = Vec::new();
    if reserve(&mut retained, relative_path.len()).is_err() {
        return (
            retained,
            SnapshotMaterializePathCaptureV1::OmittedAllocationFailure,
        );
    }
    retained.extend_from_slice(relative_path);
    (retained, SnapshotMaterializePathCaptureV1::Exact)
}

impl fmt::Display for SnapshotMaterializeFailureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} ({:?}) during {:?}",
            self.code.as_str(),
            self.kind,
            self.stage
        )?;
        match self.relative_path_capture {
            SnapshotMaterializePathCaptureV1::Exact if !self.relative_path.is_empty() => {
                write!(formatter, " at {:?}", self.relative_path)?;
            }
            SnapshotMaterializePathCaptureV1::Exact => {}
            SnapshotMaterializePathCaptureV1::OmittedAllocationFailure => {
                write!(formatter, " (relative path omitted: allocation failure)")?;
            }
        }
        if let Some(stage) = self.regular_stage {
            write!(formatter, " (regular stage {stage:?})")?;
        }
        if let Some(errno) = self.errno {
            write!(formatter, " (errno {errno})")?;
        }
        Ok(())
    }
}

impl std::error::Error for SnapshotMaterializeFailureV1 {}

fn cleanup_authority_failure() -> SnapshotMaterializeFailureV1 {
    SnapshotMaterializeFailureV1::new(
        RefusalCode::SnapshotConstructionFailed,
        SnapshotMaterializeStageV1::ValidateCleanupAuthority,
        SnapshotMaterializeFailureKindV1::CleanupAuthorityInsufficient,
        None,
        None,
        b"",
    )
}

#[derive(Debug)]
pub(super) enum SnapshotMaterializeFinishErrorV1 {
    Materialize(SnapshotMaterializeFailureV1),
    Publisher(SnapshotPublishErrorV1),
}

impl fmt::Display for SnapshotMaterializeFinishErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Materialize(error) => write!(formatter, "materializer readiness failed: {error}"),
            Self::Publisher(error) => write!(formatter, "publisher readiness failed: {error}"),
        }
    }
}

impl std::error::Error for SnapshotMaterializeFinishErrorV1 {}

impl From<SnapshotMaterializeFailureV1> for SnapshotMaterializeFinishErrorV1 {
    fn from(error: SnapshotMaterializeFailureV1) -> Self {
        Self::Materialize(error)
    }
}

impl From<SnapshotPublishErrorV1> for SnapshotMaterializeFinishErrorV1 {
    fn from(error: SnapshotPublishErrorV1) -> Self {
        Self::Publisher(error)
    }
}

pub(super) type SnapshotMaterializerV1<'parent> = platform::SnapshotMaterializerV1<'parent>;

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod platform {
    use std::cell::Cell;
    use std::ffi::CStr;
    use std::io;
    use std::mem::{self, MaybeUninit};
    use std::os::fd::{AsFd, AsRawFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

    use super::*;
    use crate::linux_pytest::snapshot_tree::{
        CapturedXattrV1, CapturedXattrValueV1, SourceNodeKindV1, SourcePlanPayloadV1,
        SourceStatxV1, SourceVisitCommonV1,
    };

    const RESOLVE_NO_XDEV: u64 = 0x01;
    const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
    const RESOLVE_BENEATH: u64 = 0x08;
    const DESTINATION_RESOLVE: u64 = RESOLVE_NO_XDEV | RESOLVE_NO_MAGICLINKS | RESOLVE_BENEATH;
    const AT_EMPTY_PATH: i32 = 0x1000;
    const STATX_MNT_ID: u32 = 0x1000;
    const SYS_FCHMODAT2_X86_64: libc::c_long = 452;
    const SYS_SETXATTRAT_X86_64: libc::c_long = 463;
    const SYS_GETXATTRAT_X86_64: libc::c_long = 464;
    const SYS_LISTXATTRAT_X86_64: libc::c_long = 465;
    const SYS_REMOVEXATTRAT_X86_64: libc::c_long = 466;
    const MAX_XATTR_LIST_BYTES: usize = 64 * 1024;
    const PRIVATE_DIRECTORY_MODE: u32 = 0o700;
    const REQUIRED_STATX_MASK: u32 = libc::STATX_TYPE
        | libc::STATX_MODE
        | libc::STATX_NLINK
        | libc::STATX_UID
        | libc::STATX_ATIME
        | libc::STATX_MTIME
        | libc::STATX_INO
        | libc::STATX_SIZE
        | STATX_MNT_ID;

    #[repr(C)]
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

    struct RetainedCStringV1 {
        bytes_with_nul: Vec<u8>,
    }

    impl RetainedCStringV1 {
        fn as_c_str(&self) -> &CStr {
            // SAFETY: the only constructor rejects interior NUL bytes and
            // appends exactly one terminator. The backing vector is private
            // and never mutated after construction.
            unsafe { CStr::from_bytes_with_nul_unchecked(&self.bytes_with_nul) }
        }

        fn as_bytes(&self) -> &[u8] {
            &self.bytes_with_nul[..self.bytes_with_nul.len() - 1]
        }
    }

    impl fmt::Debug for RetainedCStringV1 {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("RetainedCStringV1")
                .field("byte_len", &self.as_bytes().len())
                .finish()
        }
    }

    impl std::ops::Deref for RetainedCStringV1 {
        type Target = CStr;

        fn deref(&self) -> &Self::Target {
            self.as_c_str()
        }
    }

    pub(in crate::linux_pytest) trait MaterializeHooks {
        fn checkpoint(
            &self,
            _stage: SnapshotMaterializeStageV1,
            _relative_path: &[u8],
        ) -> io::Result<()> {
            Ok(())
        }

        fn list_xattrs(&self, fd: RawFd, output: Option<&mut [u8]>) -> io::Result<usize>;

        fn get_xattr(&self, fd: RawFd, name: &CStr, output: Option<&mut [u8]>)
        -> io::Result<usize>;

        fn set_xattr(&self, fd: RawFd, name: &CStr, value: &[u8]) -> io::Result<()>;

        fn remove_xattr(&self, fd: RawFd, name: &CStr) -> io::Result<()>;
    }

    pub(in crate::linux_pytest) struct KernelHooks {
        syscall_attempts: u8,
    }

    impl MaterializeHooks for KernelHooks {
        fn list_xattrs(&self, fd: RawFd, output: Option<&mut [u8]>) -> io::Result<usize> {
            let (pointer, length) = output
                .map(|buffer| (buffer.as_mut_ptr().cast::<libc::c_char>(), buffer.len()))
                .unwrap_or((std::ptr::null_mut(), 0));
            retry_eintr_size(self.syscall_attempts, || unsafe {
                libc::syscall(
                    SYS_LISTXATTRAT_X86_64,
                    fd,
                    c"".as_ptr(),
                    AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                    pointer,
                    length,
                )
            })
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
            let mut args = XattrArgs {
                value: pointer,
                size: u32::try_from(length)
                    .map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))?,
                flags: 0,
            };
            retry_eintr_size(self.syscall_attempts, || unsafe {
                libc::syscall(
                    SYS_GETXATTRAT_X86_64,
                    fd,
                    c"".as_ptr(),
                    AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                    name.as_ptr(),
                    &mut args,
                    mem::size_of::<XattrArgs>(),
                )
            })
        }

        fn set_xattr(&self, fd: RawFd, name: &CStr, value: &[u8]) -> io::Result<()> {
            let mut args = XattrArgs {
                value: value.as_ptr() as usize as u64,
                size: u32::try_from(value.len())
                    .map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))?,
                flags: 0,
            };
            retry_eintr_zero(self.syscall_attempts, || unsafe {
                libc::syscall(
                    SYS_SETXATTRAT_X86_64,
                    fd,
                    c"".as_ptr(),
                    AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                    name.as_ptr(),
                    &mut args,
                    mem::size_of::<XattrArgs>(),
                ) as libc::c_int
            })
        }

        fn remove_xattr(&self, fd: RawFd, name: &CStr) -> io::Result<()> {
            retry_eintr_zero(self.syscall_attempts, || unsafe {
                libc::syscall(
                    SYS_REMOVEXATTRAT_X86_64,
                    fd,
                    c"".as_ptr(),
                    AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                    name.as_ptr(),
                ) as libc::c_int
            })
        }
    }

    struct ActiveDirectoryV1 {
        /// `None` is the source root, whose basename is outside relative paths.
        basename: Option<Vec<u8>>,
        directory: OwnedFd,
        event_index: usize,
    }

    struct XattrOperationBudgetV1 {
        used: Cell<u64>,
        limit: u64,
    }

    impl XattrOperationBudgetV1 {
        const fn new(limit: u64) -> Self {
            Self {
                used: Cell::new(0),
                limit,
            }
        }

        fn charge(
            &self,
            operations: u64,
            stage: SnapshotMaterializeStageV1,
            relative_path: &[u8],
        ) -> Result<(), SnapshotMaterializeFailureV1> {
            let next = self.used.get().checked_add(operations).ok_or_else(|| {
                resource_failure_at(
                    stage,
                    SnapshotMaterializeLimitV1::XattrOperations,
                    relative_path,
                )
            })?;
            if next > self.limit {
                return Err(resource_failure_at(
                    stage,
                    SnapshotMaterializeLimitV1::XattrOperations,
                    relative_path,
                ));
            }
            self.used.set(next);
            Ok(())
        }
    }

    pub(in crate::linux_pytest) struct SnapshotMaterializerWithHooksV1<'parent, H> {
        staging: StagedSnapshotDirectoryV1<'parent>,
        policy: SnapshotMaterializePolicyV1,
        hooks: H,
        xattr_operations: XattrOperationBudgetV1,
        stack: Vec<ActiveDirectoryV1>,
        event_commitments: Vec<[u8; 32]>,
        root_name: Option<Vec<u8>>,
        total_xattr_bytes: u64,
        total_xattrs: u64,
        stack_name_bytes: u32,
    }

    pub(in crate::linux_pytest) type SnapshotMaterializerV1<'parent> =
        SnapshotMaterializerWithHooksV1<'parent, KernelHooks>;

    impl<'parent> SnapshotMaterializerWithHooksV1<'parent, KernelHooks> {
        pub(super) fn new(
            staging: StagedSnapshotDirectoryV1<'parent>,
            policy: SnapshotMaterializePolicyV1,
        ) -> Result<Self, SnapshotMaterializeFailureV1> {
            Self::new_with_hooks(
                staging,
                policy,
                KernelHooks {
                    syscall_attempts: policy.syscall_attempts.get(),
                },
            )
        }
    }

    impl<'parent, H: MaterializeHooks> SnapshotMaterializerWithHooksV1<'parent, H> {
        fn new_with_hooks(
            staging: StagedSnapshotDirectoryV1<'parent>,
            policy: SnapshotMaterializePolicyV1,
            hooks: H,
        ) -> Result<Self, SnapshotMaterializeFailureV1> {
            if !cleanup_envelope_covers(staging.cleanup_envelope(), policy) {
                return Err(cleanup_authority_failure());
            }
            Ok(Self {
                staging,
                policy,
                hooks,
                xattr_operations: XattrOperationBudgetV1::new(policy.max_xattr_operations.get()),
                stack: Vec::new(),
                event_commitments: Vec::new(),
                root_name: None,
                total_xattr_bytes: 0,
                total_xattrs: 0,
                stack_name_bytes: 0,
            })
        }

        pub(super) fn finish(
            mut self,
            plan: &SourceTreePlanV1,
        ) -> Result<VerifiedReadySnapshotDirectoryV1<'parent>, SnapshotMaterializeFinishErrorV1>
        {
            refuse_unqualified_plan_symlinks(plan)?;
            self.validate_finished_plan(plan)?;
            self.consolidate_hardlinks(plan)?;
            self.refinalize_hardlink_anchors(plan)?;
            self.finalize_directories(plan)?;
            let Self { staging, .. } = self;
            Ok(staging.verify_ready_with(|_| Ok(()))?)
        }

        fn staging_directory(&self) -> BorrowedFd<'_> {
            self.staging.directory()
        }

        fn validate_event(
            &mut self,
            common: SourceVisitCommonV1<'_>,
            expected_kind: SourceNodeKindV1,
        ) -> Result<(), SnapshotMaterializeFailureV1> {
            checkpoint(
                &self.hooks,
                SnapshotMaterializeStageV1::ValidateEvent,
                common.relative_path(),
            )?;
            if (self.root_name.is_some() && self.stack.is_empty())
                || kind_from_mode(common.statx().mode()) != Some(expected_kind)
            {
                return Err(event_failure(common.relative_path()));
            }
            let next_entries = self.event_commitments.len().checked_add(1).ok_or_else(|| {
                resource_failure(SnapshotMaterializeLimitV1::Entries, common.relative_path())
            })?;
            if next_entries > self.policy.max_entries.get() as usize {
                return Err(resource_failure(
                    SnapshotMaterializeLimitV1::Entries,
                    common.relative_path(),
                ));
            }
            reserve_plan_vector_slot(
                &mut self.event_commitments,
                self.policy.max_entries.get() as usize,
                common.relative_path(),
            )?;
            let depth = if common.relative_path().is_empty() {
                0
            } else {
                common
                    .relative_path()
                    .iter()
                    .filter(|byte| **byte == b'/')
                    .count()
                    .checked_add(1)
                    .ok_or_else(|| {
                        resource_failure(SnapshotMaterializeLimitV1::Depth, common.relative_path())
                    })?
            };
            if depth > usize::from(self.policy.max_depth) {
                return Err(resource_failure(
                    SnapshotMaterializeLimitV1::Depth,
                    common.relative_path(),
                ));
            }
            let xattr_bytes = checked_xattr_bytes(common.xattrs(), common.relative_path())?;
            let next_xattr_bytes =
                self.total_xattr_bytes
                    .checked_add(xattr_bytes)
                    .ok_or_else(|| {
                        resource_failure(
                            SnapshotMaterializeLimitV1::TotalXattrBytes,
                            common.relative_path(),
                        )
                    })?;
            if next_xattr_bytes > self.policy.max_total_xattr_bytes.get() {
                return Err(resource_failure(
                    SnapshotMaterializeLimitV1::TotalXattrBytes,
                    common.relative_path(),
                ));
            }
            let next_xattrs = self
                .total_xattrs
                .checked_add(common.xattrs().len() as u64)
                .ok_or_else(|| {
                    resource_failure(
                        SnapshotMaterializeLimitV1::TotalXattrs,
                        common.relative_path(),
                    )
                })?;
            if next_xattrs > self.policy.max_total_xattrs.get() {
                return Err(resource_failure(
                    SnapshotMaterializeLimitV1::TotalXattrs,
                    common.relative_path(),
                ));
            }
            validate_common_path(&self.stack, common)?;
            self.total_xattr_bytes = next_xattr_bytes;
            self.total_xattrs = next_xattrs;
            Ok(())
        }

        fn active_parent(
            &self,
            relative_path: &[u8],
            name: &CStr,
        ) -> Result<BorrowedFd<'_>, SnapshotMaterializeFailureV1> {
            let parent = self
                .stack
                .last()
                .ok_or_else(|| event_failure(relative_path))?;
            if !path_matches_stack(&self.stack, Some(name.to_bytes()), relative_path) {
                return Err(event_failure(relative_path));
            }
            Ok(parent.directory.as_fd())
        }

        fn validate_finished_plan(
            &mut self,
            plan: &SourceTreePlanV1,
        ) -> Result<(), SnapshotMaterializeFailureV1> {
            checkpoint(&self.hooks, SnapshotMaterializeStageV1::ValidatePlan, b"")?;
            if !self.stack.is_empty()
                || plan.entries().is_empty()
                || plan.entries().len() != self.event_commitments.len()
                || self.root_name.as_deref() != Some(plan.root_name())
                || plan.has_unsettable_xattrs()
                || !valid_raw_name_bytes(plan.root_name())
                || (plan.entries().len() as u64).saturating_mul(EVENT_COMMITMENT_BYTES)
                    > self.policy.max_plan_bytes.get()
            {
                return Err(plan_failure(b""));
            }
            let root = &plan.entries()[0];
            if !root.relative_path().is_empty()
                || root.parent_index().is_some()
                || root.basename() != plan.root_name()
                || root.payload().kind() != SourceNodeKindV1::Directory
            {
                return Err(plan_failure(root.relative_path()));
            }
            let mut observed_xattr_bytes = 0u64;
            let mut observed_xattrs = 0u64;
            let mut plan_commitments = Vec::new();
            plan_commitments
                .try_reserve_exact(plan.entries().len())
                .map_err(|_| resource_failure(SnapshotMaterializeLimitV1::PlanBytes, b""))?;
            for (index, entry) in plan.entries().iter().enumerate() {
                if kind_from_mode(entry.statx().mode()) != Some(entry.payload().kind())
                    || (index != 0 && !valid_plan_parent(plan, index))
                    || entry_depth(entry.relative_path()) > usize::from(self.policy.max_depth)
                    || (index > 1
                        && plan.entries()[index - 1].relative_path() >= entry.relative_path())
                {
                    return Err(plan_failure(entry.relative_path()));
                }
                observed_xattr_bytes = observed_xattr_bytes
                    .checked_add(checked_xattr_bytes(entry.xattrs(), entry.relative_path())?)
                    .ok_or_else(|| {
                        resource_failure(
                            SnapshotMaterializeLimitV1::TotalXattrBytes,
                            entry.relative_path(),
                        )
                    })?;
                observed_xattrs = observed_xattrs
                    .checked_add(entry.xattrs().len() as u64)
                    .ok_or_else(|| {
                        resource_failure(
                            SnapshotMaterializeLimitV1::TotalXattrs,
                            entry.relative_path(),
                        )
                    })?;
                if observed_xattrs > self.policy.max_total_xattrs.get() {
                    return Err(resource_failure(
                        SnapshotMaterializeLimitV1::TotalXattrs,
                        entry.relative_path(),
                    ));
                }
                plan_commitments.push(commit_plan_entry(plan, index)?);
            }
            if observed_xattr_bytes != self.total_xattr_bytes
                || observed_xattrs != self.total_xattrs
            {
                return Err(plan_failure(b""));
            }
            validate_hardlink_groups(plan)?;
            validate_plan_open_work(plan, self.policy)?;
            self.event_commitments.sort_unstable();
            plan_commitments.sort_unstable();
            if self.event_commitments != plan_commitments {
                return Err(plan_failure(b""));
            }
            Ok(())
        }

        fn consolidate_hardlinks(
            &self,
            plan: &SourceTreePlanV1,
        ) -> Result<(), SnapshotMaterializeFailureV1> {
            for group in plan.hardlink_groups() {
                let Some((&first, remaining)) = group.member_indices().split_first() else {
                    return Err(plan_failure(b""));
                };
                let first_index = first as usize;
                let first_entry = plan
                    .entries()
                    .get(first_index)
                    .ok_or_else(|| plan_failure(b""))?;
                require_materializable_regular(first_entry.payload(), first_entry.relative_path())?;
                checkpoint(
                    &self.hooks,
                    SnapshotMaterializeStageV1::ConsolidateHardlinks,
                    first_entry.relative_path(),
                )?;
                let (first_parent, first_name) = open_plan_parent(
                    self.staging_directory(),
                    plan,
                    first_index,
                    self.policy.max_depth,
                    self.policy.openat2_attempts.get(),
                )?;
                let first_handle = open_path_at(
                    first_parent.as_fd(),
                    &first_name,
                    self.policy.openat2_attempts.get(),
                )
                .map_err(|error| open_io(first_entry.relative_path(), error))?;
                let first_identity = destination_identity(first_handle.as_fd())
                    .map_err(|error| map_identity_error(first_entry.relative_path(), error))?;
                for member in remaining {
                    let member_index = *member as usize;
                    let entry = plan
                        .entries()
                        .get(member_index)
                        .ok_or_else(|| plan_failure(first_entry.relative_path()))?;
                    require_materializable_regular(entry.payload(), entry.relative_path())?;
                    let (parent, name) = open_plan_parent(
                        self.staging_directory(),
                        plan,
                        member_index,
                        self.policy.max_depth,
                        self.policy.openat2_attempts.get(),
                    )?;
                    let replaced =
                        open_path_at(parent.as_fd(), &name, self.policy.openat2_attempts.get())
                            .map_err(|error| open_io(entry.relative_path(), error))?;
                    let replaced_identity = destination_identity(replaced.as_fd())
                        .map_err(|error| map_identity_error(entry.relative_path(), error))?;
                    if replaced_identity.same_object(&first_identity) {
                        return Err(metadata_mismatch(entry.relative_path()));
                    }
                    drop(replaced);
                    retry_eintr_zero(self.policy.syscall_attempts.get(), || unsafe {
                        libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0)
                    })
                    .map_err(|error| {
                        mutation_io(
                            SnapshotMaterializeStageV1::ConsolidateHardlinks,
                            entry.relative_path(),
                            error,
                        )
                    })?;
                    retry_eintr_zero(self.policy.syscall_attempts.get(), || unsafe {
                        libc::linkat(
                            first_parent.as_raw_fd(),
                            first_name.as_ptr(),
                            parent.as_raw_fd(),
                            name.as_ptr(),
                            0,
                        )
                    })
                    .map_err(|error| {
                        mutation_io(
                            SnapshotMaterializeStageV1::ConsolidateHardlinks,
                            entry.relative_path(),
                            error,
                        )
                    })?;
                    let linked =
                        open_path_at(parent.as_fd(), &name, self.policy.openat2_attempts.get())
                            .map_err(|error| open_io(entry.relative_path(), error))?;
                    let linked_identity = destination_identity(linked.as_fd())
                        .map_err(|error| map_identity_error(entry.relative_path(), error))?;
                    if !linked_identity.same_object(&first_identity) {
                        return Err(metadata_mismatch(entry.relative_path()));
                    }
                }
                let rebound = open_path_at(
                    first_parent.as_fd(),
                    &first_name,
                    self.policy.openat2_attempts.get(),
                )
                .map_err(|error| open_io(first_entry.relative_path(), error))?;
                let rebound_identity = destination_identity(rebound.as_fd())
                    .map_err(|error| map_identity_error(first_entry.relative_path(), error))?;
                if !rebound_identity.same_object(&first_identity)
                    || rebound_identity.nlink != first_entry.statx().nlink()
                {
                    return Err(metadata_mismatch(first_entry.relative_path()));
                }
            }
            Ok(())
        }

        fn refinalize_hardlink_anchors(
            &self,
            plan: &SourceTreePlanV1,
        ) -> Result<(), SnapshotMaterializeFailureV1> {
            for group in plan.hardlink_groups() {
                let Some(first) = group.member_indices().first() else {
                    return Err(plan_failure(b""));
                };
                let index = *first as usize;
                let entry = plan.entries().get(index).ok_or_else(|| plan_failure(b""))?;
                require_materializable_regular(entry.payload(), entry.relative_path())?;
                let (parent, name) = open_plan_parent(
                    self.staging_directory(),
                    plan,
                    index,
                    self.policy.max_depth,
                    self.policy.openat2_attempts.get(),
                )?;
                let handle =
                    open_path_at(parent.as_fd(), &name, self.policy.openat2_attempts.get())
                        .map_err(|error| open_io(entry.relative_path(), error))?;
                let pinned = destination_identity(handle.as_fd())
                    .map_err(|error| map_identity_error(entry.relative_path(), error))?;
                chmod_empty_path(handle.as_fd(), 0o600, self.policy.syscall_attempts.get())
                    .map_err(|error| {
                        metadata_io(
                            SnapshotMaterializeStageV1::ApplyMode,
                            entry.relative_path(),
                            error,
                        )
                    })?;
                let writable =
                    open_regular_at(parent.as_fd(), &name, self.policy.openat2_attempts.get())
                        .map_err(|error| open_io(entry.relative_path(), error))?;
                let rebound = destination_identity(writable.as_fd())
                    .map_err(|error| map_identity_error(entry.relative_path(), error))?;
                if !rebound.same_object(&pinned) {
                    return Err(metadata_mismatch(entry.relative_path()));
                }
                self.finalize_regular(
                    writable.as_fd(),
                    entry.statx(),
                    entry.xattrs(),
                    entry.relative_path(),
                )?;
                let rebound = destination_identity(handle.as_fd())
                    .map_err(|error| map_identity_error(entry.relative_path(), error))?;
                if !rebound.same_object(&pinned) || rebound.nlink != entry.statx().nlink() {
                    return Err(metadata_mismatch(entry.relative_path()));
                }
            }
            Ok(())
        }

        fn finalize_directories(
            &self,
            plan: &SourceTreePlanV1,
        ) -> Result<(), SnapshotMaterializeFailureV1> {
            for (index, entry) in plan.entries().iter().enumerate().rev() {
                if entry.payload().kind() != SourceNodeKindV1::Directory {
                    continue;
                }
                checkpoint(
                    &self.hooks,
                    SnapshotMaterializeStageV1::FinalizeDirectory,
                    entry.relative_path(),
                )?;
                let directory = open_plan_entry_directory(
                    self.staging_directory(),
                    plan,
                    index,
                    self.policy.max_depth,
                    self.policy.openat2_attempts.get(),
                )?;
                let projected_nlink = match entry.payload() {
                    SourcePlanPayloadV1::Directory { children } => {
                        children.iter().try_fold(2u64, |count, child| {
                            let child = plan
                                .entries()
                                .get(*child as usize)
                                .ok_or_else(|| plan_failure(entry.relative_path()))?;
                            if child.parent_index() != Some(index as u32) {
                                return Err(plan_failure(child.relative_path()));
                            }
                            if child.payload().kind() == SourceNodeKindV1::Directory {
                                count
                                    .checked_add(1)
                                    .ok_or_else(|| plan_failure(entry.relative_path()))
                            } else {
                                Ok(count)
                            }
                        })?
                    }
                    _ => return Err(plan_failure(entry.relative_path())),
                };
                self.finalize_directory(
                    directory.as_fd(),
                    entry.statx(),
                    entry.xattrs(),
                    projected_nlink,
                    entry.relative_path(),
                )?;
            }
            Ok(())
        }
    }

    impl<H: MaterializeHooks> SourceTreeVisitorV1 for SnapshotMaterializerWithHooksV1<'_, H> {
        type Error = SnapshotMaterializeFailureV1;

        fn directory_enter(
            &mut self,
            visit: SourceDirectoryVisitV1<'_>,
        ) -> Result<(), Self::Error> {
            self.validate_event(visit.common(), SourceNodeKindV1::Directory)?;
            let common = visit.common();
            let event_commitment = commit_directory_event(common, visit.membership())?;
            reserve_plan_vector_slot(
                &mut self.stack,
                usize::from(self.policy.max_depth) + 1,
                common.relative_path(),
            )?;
            let retained_basename =
                fallible_plan_bytes(common.name().to_bytes(), common.relative_path())?;
            let stage = if common.relative_path().is_empty() {
                SnapshotMaterializeStageV1::CreateRoot
            } else {
                SnapshotMaterializeStageV1::CreateDirectory
            };
            checkpoint(&self.hooks, stage, common.relative_path())?;
            let parent = if common.relative_path().is_empty() {
                if !self.stack.is_empty() || self.root_name.is_some() {
                    return Err(event_failure(common.relative_path()));
                }
                self.staging_directory()
            } else {
                self.active_parent(common.relative_path(), common.name())?
            };
            mkdir_private_at(parent, common.name(), self.policy.syscall_attempts.get())
                .map_err(|error| mutation_io(stage, common.relative_path(), error))?;
            let directory =
                open_directory_at(parent, common.name(), self.policy.openat2_attempts.get())
                    .map_err(|error| mutation_io(stage, common.relative_path(), error))?;
            validate_new_directory(directory.as_fd(), common.relative_path())?;
            if common.relative_path().is_empty() {
                self.root_name = Some(retained_basename);
                let event_index = self.event_commitments.len();
                self.stack.push(ActiveDirectoryV1 {
                    basename: None,
                    directory,
                    event_index,
                });
            } else {
                let next_stack_name_bytes = self
                    .stack_name_bytes
                    .checked_add(retained_basename.len() as u32)
                    .ok_or_else(|| {
                        resource_failure(
                            SnapshotMaterializeLimitV1::PlanBytes,
                            common.relative_path(),
                        )
                    })?;
                let maximum = u32::from(self.policy.max_depth).saturating_mul(255);
                if next_stack_name_bytes > maximum {
                    return Err(resource_failure(
                        SnapshotMaterializeLimitV1::PlanBytes,
                        common.relative_path(),
                    ));
                }
                self.stack_name_bytes = next_stack_name_bytes;
                let event_index = self.event_commitments.len();
                self.stack.push(ActiveDirectoryV1 {
                    basename: Some(retained_basename),
                    directory,
                    event_index,
                });
            }
            self.event_commitments.push(event_commitment);
            Ok(())
        }

        fn regular(
            &mut self,
            visit: SourceRegularVisitV1<'_>,
        ) -> Result<SourceRegularEvidenceV1, Self::Error> {
            self.validate_event(visit.common(), SourceNodeKindV1::Regular)?;
            let common = visit.common();
            checkpoint(
                &self.hooks,
                SnapshotMaterializeStageV1::CopyRegular,
                common.relative_path(),
            )?;
            let parent = self.active_parent(common.relative_path(), common.name())?;
            let copied = visit.copy_to(parent, common.name()).map_err(|error| {
                SnapshotMaterializeFailureV1::new(
                    error.code(),
                    SnapshotMaterializeStageV1::CopyRegular,
                    SnapshotMaterializeFailureKindV1::RegularCopy,
                    Some(error.stage()),
                    error.errno(),
                    common.relative_path(),
                )
            })?;
            let (_, evidence) = copied.finalize_with(|destination| {
                self.finalize_regular(
                    destination,
                    common.statx(),
                    common.xattrs(),
                    common.relative_path(),
                )
            })?;
            let (digest, extents) = evidence.into_parts();
            let evidence = SourceRegularEvidenceV1::checked(digest, extents, common.statx().size())
                .ok_or_else(|| metadata_mismatch(common.relative_path()))?;
            self.event_commitments
                .push(commit_regular_event(common, &evidence)?);
            Ok(evidence)
        }

        fn symlink(&mut self, visit: SourceSymlinkVisitV1<'_>) -> Result<(), Self::Error> {
            self.validate_event(visit.common(), SourceNodeKindV1::Symlink)?;
            let common = visit.common();
            refuse_unqualified_symlink_event(common.relative_path())
        }

        fn directory_leave(
            &mut self,
            visit: SourceDirectoryVisitV1<'_>,
        ) -> Result<(), Self::Error> {
            let common = visit.common();
            let Some(active) = self.stack.last() else {
                return Err(event_failure(common.relative_path()));
            };
            let expected_name = active.basename.as_deref().or(self.root_name.as_deref());
            if kind_from_mode(common.statx().mode()) != Some(SourceNodeKindV1::Directory)
                || expected_name != Some(common.name().to_bytes())
                || !path_matches_stack(&self.stack, None, common.relative_path())
                || self.event_commitments.get(active.event_index)
                    != Some(&commit_directory_event(common, visit.membership())?)
            {
                return Err(event_failure(common.relative_path()));
            }
            let Some(active) = self.stack.pop() else {
                return Err(event_failure(common.relative_path()));
            };
            if let Some(basename) = active.basename {
                self.stack_name_bytes = self
                    .stack_name_bytes
                    .checked_sub(basename.len() as u32)
                    .ok_or_else(|| event_failure(common.relative_path()))?;
            }
            if common.relative_path().is_empty() && !self.stack.is_empty() {
                return Err(event_failure(common.relative_path()));
            }
            Ok(())
        }
    }

    struct DestinationIdentityV1 {
        mount_id: u64,
        device_major: u32,
        device_minor: u32,
        inode: u64,
        mode: u32,
        uid: u32,
        nlink: u64,
        size: u64,
        atime_seconds: i64,
        atime_nanoseconds: u32,
        mtime_seconds: i64,
        mtime_nanoseconds: u32,
    }

    impl DestinationIdentityV1 {
        fn same_object(&self, other: &Self) -> bool {
            self.mount_id == other.mount_id
                && self.device_major == other.device_major
                && self.device_minor == other.device_minor
                && self.inode == other.inode
        }
    }

    fn kind_from_mode(mode: u32) -> Option<SourceNodeKindV1> {
        match mode & libc::S_IFMT {
            libc::S_IFDIR => Some(SourceNodeKindV1::Directory),
            libc::S_IFREG => Some(SourceNodeKindV1::Regular),
            libc::S_IFLNK => Some(SourceNodeKindV1::Symlink),
            _ => None,
        }
    }

    fn commit_directory_event(
        common: SourceVisitCommonV1<'_>,
        membership: &[Box<[u8]>],
    ) -> Result<[u8; 32], SnapshotMaterializeFailureV1> {
        let payload = commit_name_sequence(
            membership.iter().map(|name| name.as_ref()),
            membership.len(),
            common.relative_path(),
        )?;
        commit_event_common(common, SourceNodeKindV1::Directory, &payload)
    }

    fn commit_regular_event(
        common: SourceVisitCommonV1<'_>,
        evidence: &SourceRegularEvidenceV1,
    ) -> Result<[u8; 32], SnapshotMaterializeFailureV1> {
        let payload = commit_regular_evidence(evidence);
        commit_event_common(common, SourceNodeKindV1::Regular, &payload)
    }

    fn commit_event_common(
        common: SourceVisitCommonV1<'_>,
        kind: SourceNodeKindV1,
        payload: &[u8; 32],
    ) -> Result<[u8; 32], SnapshotMaterializeFailureV1> {
        commit_entry_parts(
            common.relative_path(),
            common.name().to_bytes(),
            common.statx(),
            common.xattrs(),
            kind,
            payload,
        )
    }

    fn commit_plan_entry(
        plan: &SourceTreePlanV1,
        index: usize,
    ) -> Result<[u8; 32], SnapshotMaterializeFailureV1> {
        let entry = plan.entries().get(index).ok_or_else(|| plan_failure(b""))?;
        let (kind, payload) = match entry.payload() {
            SourcePlanPayloadV1::Directory { children } => {
                let mut previous: Option<&[u8]> = None;
                let mut hasher = blake3::Hasher::new_derive_key(
                    "again linux pytest materialize directory membership v1",
                );
                hasher.update(b"AGNMATD1");
                hasher.update(&(children.len() as u64).to_be_bytes());
                for child in children {
                    let child = plan
                        .entries()
                        .get(*child as usize)
                        .ok_or_else(|| plan_failure(entry.relative_path()))?;
                    if child.parent_index() != Some(index as u32)
                        || previous.is_some_and(|name| name >= child.basename())
                        || !valid_raw_name_bytes(child.basename())
                    {
                        return Err(plan_failure(child.relative_path()));
                    }
                    hash_put_sequence_item(&mut hasher, child.basename());
                    previous = Some(child.basename());
                }
                (SourceNodeKindV1::Directory, *hasher.finalize().as_bytes())
            }
            SourcePlanPayloadV1::Regular { evidence } => {
                (SourceNodeKindV1::Regular, commit_regular_evidence(evidence))
            }
            SourcePlanPayloadV1::Symlink { target } => (
                SourceNodeKindV1::Symlink,
                commit_single_payload(b"AGNMATS1", target),
            ),
        };
        commit_entry_parts(
            entry.relative_path(),
            entry.basename(),
            entry.statx(),
            entry.xattrs(),
            kind,
            &payload,
        )
    }

    fn commit_entry_parts(
        relative_path: &[u8],
        basename: &[u8],
        statx: &SourceStatxV1,
        xattrs: &[CapturedXattrV1],
        kind: SourceNodeKindV1,
        payload: &[u8; 32],
    ) -> Result<[u8; 32], SnapshotMaterializeFailureV1> {
        checked_xattr_bytes(xattrs, relative_path)?;
        let xattrs = commit_xattrs(xattrs);
        let statx = statx.commitment_bytes_v1();
        let kind = match kind {
            SourceNodeKindV1::Directory => [1],
            SourceNodeKindV1::Regular => [2],
            SourceNodeKindV1::Symlink => [3],
        };
        let mut hasher = blake3::Hasher::new_derive_key("again linux pytest materialize event v1");
        hasher.update(b"AGNMATE1");
        hash_put_field(&mut hasher, 1, &[1]);
        hash_put_field(&mut hasher, 2, &kind);
        hash_put_field(&mut hasher, 3, relative_path);
        hash_put_field(&mut hasher, 4, basename);
        hash_put_field(&mut hasher, 5, &statx);
        hash_put_field(&mut hasher, 6, &xattrs);
        hash_put_field(&mut hasher, 7, payload);
        Ok(*hasher.finalize().as_bytes())
    }

    fn commit_xattrs(xattrs: &[CapturedXattrV1]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key("again linux pytest materialize xattrs v1");
        hasher.update(b"AGNMATX1");
        hasher.update(&(xattrs.len() as u64).to_be_bytes());
        for xattr in xattrs {
            hash_put_sequence_item(&mut hasher, xattr.name());
            match xattr.value() {
                CapturedXattrValueV1::Bytes(value) => {
                    hasher.update(&[1]);
                    hash_put_sequence_item(&mut hasher, value);
                }
                CapturedXattrValueV1::VisibleButUnsettable { errno } => {
                    hasher.update(&[2]);
                    hasher.update(&errno.to_be_bytes());
                }
            }
        }
        *hasher.finalize().as_bytes()
    }

    fn commit_regular_evidence(evidence: &SourceRegularEvidenceV1) -> [u8; 32] {
        let mut hasher =
            blake3::Hasher::new_derive_key("again linux pytest materialize regular evidence v1");
        hasher.update(b"AGNMATR1");
        hash_put_sequence_item(&mut hasher, evidence.content_digest().as_bytes());
        hasher.update(&(evidence.data_extents().len() as u64).to_be_bytes());
        for extent in evidence.data_extents() {
            hasher.update(&extent.offset.to_be_bytes());
            hasher.update(&extent.length.to_be_bytes());
        }
        *hasher.finalize().as_bytes()
    }

    fn commit_name_sequence<'a>(
        names: impl Iterator<Item = &'a [u8]>,
        count: usize,
        relative_path: &[u8],
    ) -> Result<[u8; 32], SnapshotMaterializeFailureV1> {
        let mut previous: Option<&[u8]> = None;
        let mut hasher = blake3::Hasher::new_derive_key(
            "again linux pytest materialize directory membership v1",
        );
        hasher.update(b"AGNMATD1");
        hasher.update(&(count as u64).to_be_bytes());
        for name in names {
            if previous.is_some_and(|prior| prior >= name) || !valid_raw_name_bytes(name) {
                return Err(event_failure(relative_path));
            }
            hash_put_sequence_item(&mut hasher, name);
            previous = Some(name);
        }
        Ok(*hasher.finalize().as_bytes())
    }

    fn commit_single_payload(magic: &[u8; 8], value: &[u8]) -> [u8; 32] {
        let mut hasher =
            blake3::Hasher::new_derive_key("again linux pytest materialize leaf payload v1");
        hasher.update(magic);
        hash_put_sequence_item(&mut hasher, value);
        *hasher.finalize().as_bytes()
    }

    fn hash_put_field(hasher: &mut blake3::Hasher, tag: u16, value: &[u8]) {
        hasher.update(&tag.to_be_bytes());
        hash_put_sequence_item(hasher, value);
    }

    fn hash_put_sequence_item(hasher: &mut blake3::Hasher, value: &[u8]) {
        hasher.update(&(value.len() as u64).to_be_bytes());
        hasher.update(value);
    }

    fn valid_raw_name_bytes(bytes: &[u8]) -> bool {
        !bytes.is_empty()
            && bytes.len() <= 255
            && bytes != b"."
            && bytes != b".."
            && !bytes.contains(&b'/')
            && !bytes.contains(&0)
    }

    fn validate_common_path(
        stack: &[ActiveDirectoryV1],
        common: SourceVisitCommonV1<'_>,
    ) -> Result<(), SnapshotMaterializeFailureV1> {
        if !valid_raw_basename(common.name()) {
            return Err(event_failure(common.relative_path()));
        }
        if common.relative_path().is_empty() {
            if !stack.is_empty() {
                return Err(event_failure(common.relative_path()));
            }
            return Ok(());
        }
        if stack.is_empty()
            || !path_matches_stack(
                stack,
                Some(common.name().to_bytes()),
                common.relative_path(),
            )
        {
            return Err(event_failure(common.relative_path()));
        }
        Ok(())
    }

    fn path_matches_stack(stack: &[ActiveDirectoryV1], leaf: Option<&[u8]>, path: &[u8]) -> bool {
        if stack.is_empty() {
            return false;
        }
        let mut cursor = 0usize;
        for expected in stack
            .iter()
            .skip(1)
            .filter_map(|entry| entry.basename.as_deref())
        {
            if !consume_path_component(path, &mut cursor, expected) {
                return false;
            }
        }
        if let Some(leaf) = leaf
            && !consume_path_component(path, &mut cursor, leaf)
        {
            return false;
        }
        cursor == path.len()
    }

    fn consume_path_component(path: &[u8], cursor: &mut usize, expected: &[u8]) -> bool {
        if *cursor != 0 {
            if path.get(*cursor) != Some(&b'/') {
                return false;
            }
            *cursor += 1;
        }
        let Some(end) = cursor.checked_add(expected.len()) else {
            return false;
        };
        if path.get(*cursor..end) != Some(expected) {
            return false;
        }
        *cursor = end;
        true
    }

    fn path_is_child_of(parent: &[u8], basename: &[u8], path: &[u8]) -> bool {
        if parent.is_empty() {
            path == basename
        } else {
            path.len() == parent.len() + 1 + basename.len()
                && path.starts_with(parent)
                && path[parent.len()] == b'/'
                && &path[parent.len() + 1..] == basename
        }
    }

    fn valid_raw_basename(name: &CStr) -> bool {
        valid_raw_name_bytes(name.to_bytes())
    }

    fn checked_xattr_bytes(
        xattrs: &[CapturedXattrV1],
        relative_path: &[u8],
    ) -> Result<u64, SnapshotMaterializeFailureV1> {
        let mut total = 0u64;
        let mut previous: Option<&[u8]> = None;
        for xattr in xattrs {
            if xattr.name().is_empty()
                || xattr.name().contains(&0)
                || previous.is_some_and(|name| name >= xattr.name())
            {
                return Err(plan_failure(relative_path));
            }
            let value_len = match xattr.value() {
                CapturedXattrValueV1::Bytes(value) => value.len(),
                CapturedXattrValueV1::VisibleButUnsettable { .. } => {
                    return Err(SnapshotMaterializeFailureV1::new(
                        RefusalCode::SnapshotRequiredObjectUnsupported,
                        SnapshotMaterializeStageV1::ValidateEvent,
                        SnapshotMaterializeFailureKindV1::VisibleXattrUnrepresentable,
                        None,
                        None,
                        relative_path,
                    ));
                }
            };
            total = total
                .checked_add(xattr.name().len() as u64)
                .and_then(|value| value.checked_add(value_len as u64))
                .ok_or_else(|| {
                    resource_failure(SnapshotMaterializeLimitV1::TotalXattrBytes, relative_path)
                })?;
            previous = Some(xattr.name());
        }
        Ok(total)
    }

    fn valid_plan_parent(plan: &SourceTreePlanV1, index: usize) -> bool {
        let entry = &plan.entries()[index];
        let Some(parent_index) = entry.parent_index().map(|value| value as usize) else {
            return false;
        };
        if parent_index >= index || parent_index >= plan.entries().len() {
            return false;
        }
        let parent = &plan.entries()[parent_index];
        parent.payload().kind() == SourceNodeKindV1::Directory
            && path_is_child_of(
                parent.relative_path(),
                entry.basename(),
                entry.relative_path(),
            )
    }

    fn entry_depth(relative_path: &[u8]) -> usize {
        if relative_path.is_empty() {
            0
        } else {
            relative_path.iter().filter(|byte| **byte == b'/').count() + 1
        }
    }

    fn validate_plan_open_work(
        plan: &SourceTreePlanV1,
        policy: SnapshotMaterializePolicyV1,
    ) -> Result<(), SnapshotMaterializeFailureV1> {
        let mut components = 0u64;
        let mut charge = |count: u64, relative_path: &[u8]| {
            charge_plan_open_work(&mut components, count, policy, relative_path)
        };
        for entry in plan.entries() {
            if entry.payload().kind() == SourceNodeKindV1::Directory {
                charge(
                    entry_depth(entry.relative_path()) as u64 + 1,
                    entry.relative_path(),
                )?;
            }
        }
        for group in plan.hardlink_groups() {
            let Some((first, remaining)) = group.member_indices().split_first() else {
                return Err(plan_failure(b""));
            };
            let first = plan
                .entries()
                .get(*first as usize)
                .ok_or_else(|| plan_failure(b""))?;
            // Parent chain plus pinned anchor handle.
            charge(
                entry_depth(first.relative_path()) as u64 + 1,
                first.relative_path(),
            )?;
            for member in remaining {
                let entry = plan
                    .entries()
                    .get(*member as usize)
                    .ok_or_else(|| plan_failure(first.relative_path()))?;
                // Parent chain plus the replaced and rebound leaf handles.
                charge(
                    entry_depth(entry.relative_path()) as u64 + 2,
                    entry.relative_path(),
                )?;
            }
            // Final anchor rebound, then its exact post-link re-finalization.
            charge(1, first.relative_path())?;
            require_materializable_regular(first.payload(), first.relative_path())?;
            let anchor_leaf_opens = 2;
            charge(
                entry_depth(first.relative_path()) as u64 + anchor_leaf_opens,
                first.relative_path(),
            )?;
        }
        Ok(())
    }

    fn charge_plan_open_work(
        components: &mut u64,
        count: u64,
        policy: SnapshotMaterializePolicyV1,
        relative_path: &[u8],
    ) -> Result<(), SnapshotMaterializeFailureV1> {
        *components = components.checked_add(count).ok_or_else(|| {
            resource_failure_at(
                SnapshotMaterializeStageV1::ValidatePlan,
                SnapshotMaterializeLimitV1::PlanOpenComponents,
                relative_path,
            )
        })?;
        if *components > policy.max_plan_open_components.get() {
            return Err(resource_failure_at(
                SnapshotMaterializeStageV1::ValidatePlan,
                SnapshotMaterializeLimitV1::PlanOpenComponents,
                relative_path,
            ));
        }
        Ok(())
    }

    fn validate_hardlink_groups(
        plan: &SourceTreePlanV1,
    ) -> Result<(), SnapshotMaterializeFailureV1> {
        let mut group_keys = Vec::new();
        group_keys
            .try_reserve_exact(plan.hardlink_groups().len())
            .map_err(|_| resource_failure(SnapshotMaterializeLimitV1::PlanBytes, b""))?;
        group_keys.extend(plan.hardlink_groups().iter().map(|group| group.inode_key()));
        group_keys.sort_unstable();
        if group_keys.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(plan_failure(b""));
        }
        let mut seen = Vec::new();
        seen.try_reserve_exact(plan.entries().len())
            .map_err(|_| resource_failure(SnapshotMaterializeLimitV1::PlanBytes, b""))?;
        seen.resize(plan.entries().len(), false);
        for (group_index, group) in plan.hardlink_groups().iter().enumerate() {
            if group.member_indices().len() < 2 {
                return Err(plan_failure(b""));
            }
            if group
                .member_indices()
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
            {
                return Err(plan_failure(b""));
            }
            let mut reference_index: Option<usize> = None;
            for member in group.member_indices() {
                let index = *member as usize;
                let entry = plan.entries().get(index).ok_or_else(|| plan_failure(b""))?;
                require_materializable_regular(entry.payload(), entry.relative_path())?;
                if seen.get(index).copied().unwrap_or(true)
                    || entry.hardlink_group() != Some(group_index as u32)
                    || entry.statx().inode_key() != group.inode_key()
                    || entry.statx().nlink() != group.member_indices().len() as u64
                {
                    return Err(plan_failure(entry.relative_path()));
                }
                seen[index] = true;
                if let Some(reference_index) = reference_index {
                    let reference = &plan.entries()[reference_index];
                    if reference.statx() != entry.statx()
                        || reference.payload() != entry.payload()
                        || reference.xattrs() != entry.xattrs()
                    {
                        return Err(plan_failure(entry.relative_path()));
                    }
                } else {
                    reference_index = Some(index);
                }
            }
        }
        for (index, entry) in plan.entries().iter().enumerate() {
            if entry.hardlink_group().is_some() != seen[index] {
                return Err(plan_failure(entry.relative_path()));
            }
            if entry.hardlink_group().is_none()
                && entry.payload().kind() != SourceNodeKindV1::Directory
                && entry.statx().nlink() != 1
            {
                return Err(plan_failure(entry.relative_path()));
            }
        }
        Ok(())
    }

    fn open_plan_parent(
        container: BorrowedFd<'_>,
        plan: &SourceTreePlanV1,
        index: usize,
        max_depth: u16,
        attempts: u8,
    ) -> Result<(OwnedFd, RetainedCStringV1), SnapshotMaterializeFailureV1> {
        let entry = plan.entries().get(index).ok_or_else(|| plan_failure(b""))?;
        let parent_index = entry
            .parent_index()
            .map(|value| value as usize)
            .ok_or_else(|| plan_failure(entry.relative_path()))?;
        let name = fallible_plan_basename(entry.basename(), entry.relative_path())?;
        let parent = open_plan_entry_directory(container, plan, parent_index, max_depth, attempts)?;
        Ok((parent, name))
    }

    fn open_plan_entry_directory(
        container: BorrowedFd<'_>,
        plan: &SourceTreePlanV1,
        index: usize,
        max_depth: u16,
        attempts: u8,
    ) -> Result<OwnedFd, SnapshotMaterializeFailureV1> {
        let mut chain = [0usize; HARD_MAX_DEPTH as usize + 1];
        let mut chain_len = 0usize;
        let mut cursor = index;
        loop {
            if chain_len > usize::from(max_depth) {
                return Err(plan_failure(
                    plan.entries()
                        .get(index)
                        .map_or(b"".as_slice(), |entry| entry.relative_path()),
                ));
            }
            chain[chain_len] = cursor;
            chain_len += 1;
            let entry = plan
                .entries()
                .get(cursor)
                .ok_or_else(|| plan_failure(b""))?;
            if entry.payload().kind() != SourceNodeKindV1::Directory {
                return Err(plan_failure(entry.relative_path()));
            }
            match entry.parent_index() {
                Some(parent) => cursor = parent as usize,
                None if cursor == 0 => break,
                None => return Err(plan_failure(entry.relative_path())),
            }
        }
        let mut current: Option<OwnedFd> = None;
        for &entry_index in chain[..chain_len].iter().rev() {
            let entry = &plan.entries()[entry_index];
            let name = fallible_plan_basename(entry.basename(), entry.relative_path())?;
            let parent = current
                .as_ref()
                .map_or(container, |directory| directory.as_fd());
            let next = open_directory_at(parent, &name, attempts)
                .map_err(|error| open_io(entry.relative_path(), error))?;
            current = Some(next);
        }
        current.ok_or_else(|| plan_failure(b""))
    }

    fn mkdir_private_at(parent: BorrowedFd<'_>, name: &CStr, attempts: u8) -> io::Result<()> {
        if !valid_raw_basename(name) {
            return Err(io::Error::from_raw_os_error(libc::EINVAL));
        }
        retry_eintr_zero(attempts, || unsafe {
            libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), PRIVATE_DIRECTORY_MODE)
        })
    }

    fn open_directory_at(parent: BorrowedFd<'_>, name: &CStr, attempts: u8) -> io::Result<OwnedFd> {
        openat2_owned(
            parent,
            name,
            libc::O_RDONLY
                | libc::O_DIRECTORY
                | libc::O_NOFOLLOW
                | libc::O_NOATIME
                | libc::O_CLOEXEC,
            0,
            DESTINATION_RESOLVE,
            attempts,
        )
    }

    fn open_path_at(parent: BorrowedFd<'_>, name: &CStr, attempts: u8) -> io::Result<OwnedFd> {
        openat2_owned(
            parent,
            name,
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            0,
            DESTINATION_RESOLVE,
            attempts,
        )
    }

    fn open_regular_at(parent: BorrowedFd<'_>, name: &CStr, attempts: u8) -> io::Result<OwnedFd> {
        openat2_owned(
            parent,
            name,
            libc::O_RDWR | libc::O_NOFOLLOW | libc::O_NOATIME | libc::O_CLOEXEC,
            0,
            DESTINATION_RESOLVE,
            attempts,
        )
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

    fn destination_identity(fd: BorrowedFd<'_>) -> io::Result<DestinationIdentityV1> {
        let mut raw = MaybeUninit::<libc::statx>::zeroed();
        let result = unsafe {
            libc::syscall(
                libc::SYS_statx,
                fd.as_raw_fd(),
                c"".as_ptr(),
                AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
                libc::STATX_BASIC_STATS | STATX_MNT_ID,
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
        Ok(DestinationIdentityV1 {
            mount_id: raw.stx_mnt_id,
            device_major: raw.stx_dev_major,
            device_minor: raw.stx_dev_minor,
            inode: raw.stx_ino,
            mode: u32::from(raw.stx_mode),
            uid: raw.stx_uid,
            nlink: u64::from(raw.stx_nlink),
            size: raw.stx_size,
            atime_seconds: raw.stx_atime.tv_sec,
            atime_nanoseconds: raw.stx_atime.tv_nsec,
            mtime_seconds: raw.stx_mtime.tv_sec,
            mtime_nanoseconds: raw.stx_mtime.tv_nsec,
        })
    }

    fn validate_new_directory(
        fd: BorrowedFd<'_>,
        relative_path: &[u8],
    ) -> Result<(), SnapshotMaterializeFailureV1> {
        let identity =
            destination_identity(fd).map_err(|error| map_identity_error(relative_path, error))?;
        if identity.mode & libc::S_IFMT != libc::S_IFDIR
            || identity.mode & 0o7777 != PRIVATE_DIRECTORY_MODE
            || identity.uid != unsafe { libc::geteuid() }
            || identity.nlink < 2
        {
            return Err(metadata_mismatch(relative_path));
        }
        Ok(())
    }

    impl<H: MaterializeHooks> SnapshotMaterializerWithHooksV1<'_, H> {
        fn finalize_regular(
            &self,
            fd: BorrowedFd<'_>,
            expected: &SourceStatxV1,
            xattrs: &[CapturedXattrV1],
            relative_path: &[u8],
        ) -> Result<(), SnapshotMaterializeFailureV1> {
            let kind = SourceNodeKindV1::Regular;
            validate_builder_mode(fd, kind, relative_path)?;
            let xattr_names = apply_xattrs(
                &self.hooks,
                &self.xattr_operations,
                fd,
                xattrs,
                self.policy,
                relative_path,
            )?;
            apply_mode(
                fd,
                projected_regular_mode(expected.mode()),
                self.policy.syscall_attempts.get(),
                relative_path,
            )?;
            apply_times(
                fd,
                expected,
                self.policy.syscall_attempts.get(),
                relative_path,
            )?;
            verify_metadata(fd, expected, xattrs, kind, None, relative_path)?;
            verify_xattrs(
                &self.hooks,
                &self.xattr_operations,
                fd,
                xattrs,
                &xattr_names,
                self.policy,
                relative_path,
            )?;
            checkpoint(
                &self.hooks,
                SnapshotMaterializeStageV1::SyncRegular,
                relative_path,
            )?;
            retry_eintr_zero(self.policy.syscall_attempts.get(), || unsafe {
                libc::fsync(fd.as_raw_fd())
            })
            .map_err(|error| {
                metadata_io(
                    SnapshotMaterializeStageV1::SyncRegular,
                    relative_path,
                    error,
                )
            })?;
            Ok(())
        }

        fn finalize_directory(
            &self,
            fd: BorrowedFd<'_>,
            expected: &SourceStatxV1,
            xattrs: &[CapturedXattrV1],
            projected_nlink: u64,
            relative_path: &[u8],
        ) -> Result<(), SnapshotMaterializeFailureV1> {
            validate_builder_mode(fd, SourceNodeKindV1::Directory, relative_path)?;
            let xattr_names = apply_xattrs(
                &self.hooks,
                &self.xattr_operations,
                fd,
                xattrs,
                self.policy,
                relative_path,
            )?;
            apply_mode(
                fd,
                projected_directory_mode(expected.mode()),
                self.policy.syscall_attempts.get(),
                relative_path,
            )?;
            apply_times(
                fd,
                expected,
                self.policy.syscall_attempts.get(),
                relative_path,
            )?;
            verify_metadata(
                fd,
                expected,
                xattrs,
                SourceNodeKindV1::Directory,
                Some(projected_nlink),
                relative_path,
            )?;
            verify_xattrs(
                &self.hooks,
                &self.xattr_operations,
                fd,
                xattrs,
                &xattr_names,
                self.policy,
                relative_path,
            )?;
            retry_eintr_zero(self.policy.syscall_attempts.get(), || unsafe {
                libc::fsync(fd.as_raw_fd())
            })
            .map_err(|error| {
                metadata_io(
                    SnapshotMaterializeStageV1::FinalizeDirectory,
                    relative_path,
                    error,
                )
            })
        }
    }

    fn apply_mode(
        fd: BorrowedFd<'_>,
        physical_mode: u32,
        attempts: u8,
        relative_path: &[u8],
    ) -> Result<(), SnapshotMaterializeFailureV1> {
        retry_eintr_zero(attempts, || unsafe {
            libc::fchmod(fd.as_raw_fd(), physical_mode & 0o7777)
        })
        .map_err(|error| metadata_io(SnapshotMaterializeStageV1::ApplyMode, relative_path, error))
    }

    fn validate_builder_mode(
        fd: BorrowedFd<'_>,
        kind: SourceNodeKindV1,
        relative_path: &[u8],
    ) -> Result<(), SnapshotMaterializeFailureV1> {
        let observed =
            destination_identity(fd).map_err(|error| map_identity_error(relative_path, error))?;
        let expected_mode = match kind {
            SourceNodeKindV1::Directory => PRIVATE_DIRECTORY_MODE,
            SourceNodeKindV1::Regular => 0o600,
            SourceNodeKindV1::Symlink => {
                return Err(unqualified_symlink_durability(relative_path));
            }
        };
        if kind_from_mode(observed.mode) != Some(kind)
            || observed.mode & 0o7777 != expected_mode
            || observed.uid != unsafe { libc::geteuid() }
        {
            return Err(metadata_mismatch(relative_path));
        }
        Ok(())
    }

    fn chmod_empty_path(fd: BorrowedFd<'_>, mode: u32, attempts: u8) -> io::Result<()> {
        retry_eintr_zero(attempts, || unsafe {
            libc::syscall(
                SYS_FCHMODAT2_X86_64,
                fd.as_raw_fd(),
                c"".as_ptr(),
                mode,
                AT_EMPTY_PATH,
            ) as libc::c_int
        })
    }

    fn apply_times(
        fd: BorrowedFd<'_>,
        expected: &SourceStatxV1,
        attempts: u8,
        relative_path: &[u8],
    ) -> Result<(), SnapshotMaterializeFailureV1> {
        if expected.atime().nanoseconds >= 1_000_000_000
            || expected.mtime().nanoseconds >= 1_000_000_000
        {
            return Err(SnapshotMaterializeFailureV1::new(
                RefusalCode::SnapshotRequiredObjectUnsupported,
                SnapshotMaterializeStageV1::ApplyTimes,
                SnapshotMaterializeFailureKindV1::UnsupportedMetadata,
                None,
                None,
                relative_path,
            ));
        }
        let times = [
            libc::timespec {
                tv_sec: expected.atime().seconds,
                tv_nsec: libc::c_long::from(expected.atime().nanoseconds),
            },
            libc::timespec {
                tv_sec: expected.mtime().seconds,
                tv_nsec: libc::c_long::from(expected.mtime().nanoseconds),
            },
        ];
        retry_eintr_zero(attempts, || unsafe {
            libc::utimensat(
                fd.as_raw_fd(),
                c"".as_ptr(),
                times.as_ptr(),
                AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW,
            )
        })
        .map_err(|error| metadata_io(SnapshotMaterializeStageV1::ApplyTimes, relative_path, error))
    }

    fn verify_metadata(
        fd: BorrowedFd<'_>,
        expected: &SourceStatxV1,
        xattrs: &[CapturedXattrV1],
        kind: SourceNodeKindV1,
        projected_directory_nlink: Option<u64>,
        relative_path: &[u8],
    ) -> Result<(), SnapshotMaterializeFailureV1> {
        let expected_physical_mode = match kind {
            SourceNodeKindV1::Directory => projected_directory_mode(expected.mode()),
            SourceNodeKindV1::Regular => projected_regular_mode(expected.mode()),
            SourceNodeKindV1::Symlink => return Err(unqualified_symlink_durability(relative_path)),
        };
        let observed =
            destination_identity(fd).map_err(|error| map_identity_error(relative_path, error))?;
        let euid = unsafe { libc::geteuid() };
        let mode_mismatch = observed.mode & 0o7777 != expected_physical_mode;
        if mode_mismatch && contains_access_acl(xattrs) {
            return Err(unsupported_metadata(
                SnapshotMaterializeStageV1::VerifyMetadata,
                relative_path,
                None,
            ));
        }
        if !metadata_projection_matches(&observed, expected, kind, projected_directory_nlink, euid)
        {
            return Err(metadata_mismatch(relative_path));
        }
        Ok(())
    }

    fn metadata_projection_matches(
        observed: &DestinationIdentityV1,
        expected: &SourceStatxV1,
        kind: SourceNodeKindV1,
        projected_directory_nlink: Option<u64>,
        euid: u32,
    ) -> bool {
        let expected_physical_mode = match kind {
            SourceNodeKindV1::Directory => projected_directory_mode(expected.mode()),
            SourceNodeKindV1::Regular => projected_regular_mode(expected.mode()),
            SourceNodeKindV1::Symlink => return false,
        };
        let object_metadata_matches = match kind {
            SourceNodeKindV1::Directory => projected_directory_nlink == Some(observed.nlink),
            SourceNodeKindV1::Regular => {
                observed.size == expected.size()
                    && observed.nlink != 0
                    && observed.nlink <= expected.nlink()
            }
            SourceNodeKindV1::Symlink => return false,
        };
        kind_from_mode(observed.mode) == Some(kind)
            && observed.mode & 0o7777 == expected_physical_mode
            && observed.uid == euid
            && observed.atime_seconds == expected.atime().seconds
            && observed.atime_nanoseconds == expected.atime().nanoseconds
            && observed.mtime_seconds == expected.mtime().seconds
            && observed.mtime_nanoseconds == expected.mtime().nanoseconds
            && object_metadata_matches
    }

    fn apply_xattrs<H: MaterializeHooks>(
        hooks: &H,
        xattr_operations: &XattrOperationBudgetV1,
        fd: BorrowedFd<'_>,
        expected: &[CapturedXattrV1],
        policy: SnapshotMaterializePolicyV1,
        relative_path: &[u8],
    ) -> Result<Vec<RetainedCStringV1>, SnapshotMaterializeFailureV1> {
        checkpoint(
            hooks,
            SnapshotMaterializeStageV1::ApplyXattrs,
            relative_path,
        )?;
        checked_xattr_bytes(expected, relative_path)?;
        let expected_names = xattr_names(
            expected,
            SnapshotMaterializeStageV1::ApplyXattrs,
            relative_path,
        )?;
        let existing = list_xattr_names(
            hooks,
            xattr_operations,
            fd,
            policy,
            SnapshotMaterializeStageV1::ApplyXattrs,
            relative_path,
        )?;
        for name in &existing {
            if expected_names
                .binary_search_by(|expected| expected.as_bytes().cmp(name.as_bytes()))
                .is_err()
            {
                xattr_operations.charge(
                    1,
                    SnapshotMaterializeStageV1::ApplyXattrs,
                    relative_path,
                )?;
                hooks.remove_xattr(fd.as_raw_fd(), name).map_err(|error| {
                    xattr_io(
                        SnapshotMaterializeStageV1::ApplyXattrs,
                        relative_path,
                        error,
                    )
                })?;
            }
        }
        for (xattr, name) in expected.iter().zip(&expected_names) {
            let CapturedXattrValueV1::Bytes(value) = xattr.value() else {
                return Err(SnapshotMaterializeFailureV1::new(
                    RefusalCode::SnapshotRequiredObjectUnsupported,
                    SnapshotMaterializeStageV1::ApplyXattrs,
                    SnapshotMaterializeFailureKindV1::VisibleXattrUnrepresentable,
                    None,
                    None,
                    relative_path,
                ));
            };
            xattr_operations.charge(1, SnapshotMaterializeStageV1::ApplyXattrs, relative_path)?;
            hooks
                .set_xattr(fd.as_raw_fd(), name, value)
                .map_err(|error| {
                    xattr_io(
                        SnapshotMaterializeStageV1::ApplyXattrs,
                        relative_path,
                        error,
                    )
                })?;
        }
        Ok(expected_names)
    }

    fn verify_xattrs<H: MaterializeHooks>(
        hooks: &H,
        xattr_operations: &XattrOperationBudgetV1,
        fd: BorrowedFd<'_>,
        expected: &[CapturedXattrV1],
        expected_names: &[RetainedCStringV1],
        policy: SnapshotMaterializePolicyV1,
        relative_path: &[u8],
    ) -> Result<(), SnapshotMaterializeFailureV1> {
        let observed = list_xattr_names(
            hooks,
            xattr_operations,
            fd,
            policy,
            SnapshotMaterializeStageV1::VerifyMetadata,
            relative_path,
        )?;
        if observed.len() != expected_names.len()
            || observed
                .iter()
                .zip(expected_names)
                .any(|(left, right)| left.as_bytes() != right.as_bytes())
        {
            return Err(xattr_mismatch(expected, relative_path));
        }
        for (xattr, name) in expected.iter().zip(expected_names) {
            let CapturedXattrValueV1::Bytes(value) = xattr.value() else {
                return Err(xattr_mismatch(expected, relative_path));
            };
            xattr_operations.charge(
                1,
                SnapshotMaterializeStageV1::VerifyMetadata,
                relative_path,
            )?;
            let length = hooks
                .get_xattr(fd.as_raw_fd(), name, None)
                .map_err(|error| {
                    xattr_io(
                        SnapshotMaterializeStageV1::VerifyMetadata,
                        relative_path,
                        error,
                    )
                })?;
            if length != value.len() || length as u64 > policy.max_total_xattr_bytes.get() {
                return Err(xattr_mismatch(expected, relative_path));
            }
            let mut observed_value = allocate_zeroed_at(
                length,
                SnapshotMaterializeLimitV1::TotalXattrBytes,
                SnapshotMaterializeStageV1::VerifyMetadata,
                relative_path,
            )?;
            xattr_operations.charge(
                1,
                SnapshotMaterializeStageV1::VerifyMetadata,
                relative_path,
            )?;
            let returned = hooks
                .get_xattr(fd.as_raw_fd(), name, Some(&mut observed_value))
                .map_err(|error| {
                    xattr_io(
                        SnapshotMaterializeStageV1::VerifyMetadata,
                        relative_path,
                        error,
                    )
                })?;
            if returned != length || observed_value.as_slice() != value.as_ref() {
                return Err(xattr_mismatch(expected, relative_path));
            }
        }
        Ok(())
    }

    fn xattr_names(
        expected: &[CapturedXattrV1],
        stage: SnapshotMaterializeStageV1,
        relative_path: &[u8],
    ) -> Result<Vec<RetainedCStringV1>, SnapshotMaterializeFailureV1> {
        let mut names = Vec::new();
        names.try_reserve_exact(expected.len()).map_err(|_| {
            resource_failure_at(
                stage,
                SnapshotMaterializeLimitV1::TotalXattrBytes,
                relative_path,
            )
        })?;
        for xattr in expected {
            names.push(fallible_cstring(xattr.name(), stage, relative_path)?);
        }
        Ok(names)
    }

    fn list_xattr_names<H: MaterializeHooks>(
        hooks: &H,
        xattr_operations: &XattrOperationBudgetV1,
        fd: BorrowedFd<'_>,
        policy: SnapshotMaterializePolicyV1,
        stage: SnapshotMaterializeStageV1,
        relative_path: &[u8],
    ) -> Result<Vec<RetainedCStringV1>, SnapshotMaterializeFailureV1> {
        xattr_operations.charge(1, stage, relative_path)?;
        let length = hooks
            .list_xattrs(fd.as_raw_fd(), None)
            .map_err(|error| xattr_io(stage, relative_path, error))?;
        if length > MAX_XATTR_LIST_BYTES || length as u64 > policy.max_total_xattr_bytes.get() {
            return Err(resource_failure_at(
                stage,
                SnapshotMaterializeLimitV1::XattrListBytes,
                relative_path,
            ));
        }
        if length == 0 {
            return Ok(Vec::new());
        }
        let mut bytes = allocate_zeroed_at(
            length,
            SnapshotMaterializeLimitV1::XattrListBytes,
            stage,
            relative_path,
        )?;
        xattr_operations.charge(1, stage, relative_path)?;
        let returned = hooks
            .list_xattrs(fd.as_raw_fd(), Some(&mut bytes))
            .map_err(|error| xattr_io(stage, relative_path, error))?;
        if returned != length {
            return Err(metadata_mismatch_at(stage, relative_path));
        }
        let name_count = bytes.iter().filter(|byte| **byte == 0).count();
        let mut names = Vec::new();
        names.try_reserve_exact(name_count).map_err(|_| {
            resource_failure_at(
                stage,
                SnapshotMaterializeLimitV1::XattrListBytes,
                relative_path,
            )
        })?;
        let mut start = 0usize;
        for (index, byte) in bytes.iter().enumerate() {
            if *byte != 0 {
                continue;
            }
            if index == start {
                return Err(metadata_mismatch_at(stage, relative_path));
            }
            names.push(fallible_cstring(
                &bytes[start..index],
                stage,
                relative_path,
            )?);
            start = index + 1;
        }
        if start != bytes.len() {
            return Err(metadata_mismatch_at(stage, relative_path));
        }
        names.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
        if names
            .windows(2)
            .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
        {
            return Err(metadata_mismatch_at(stage, relative_path));
        }
        Ok(names)
    }

    fn projected_directory_mode(logical_mode: u32) -> u32 {
        // Logical special bits remain manifest data. Physical ownership is
        // remapped to the builder EUID, so setuid/setgid/sticky are neither
        // equivalent nor safe and are stripped from the sealed projection.
        (logical_mode & 0o777 & !0o222) | 0o500
    }

    fn projected_regular_mode(logical_mode: u32) -> u32 {
        let sealed = logical_mode & 0o777 & !0o222;
        sealed | 0o400 | if logical_mode & 0o111 != 0 { 0o100 } else { 0 }
    }

    fn allocate_zeroed_at(
        length: usize,
        limit: SnapshotMaterializeLimitV1,
        stage: SnapshotMaterializeStageV1,
        relative_path: &[u8],
    ) -> Result<Vec<u8>, SnapshotMaterializeFailureV1> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| resource_failure_at(stage, limit, relative_path))?;
        bytes.resize(length, 0);
        Ok(bytes)
    }

    fn fallible_cstring(
        bytes: &[u8],
        stage: SnapshotMaterializeStageV1,
        relative_path: &[u8],
    ) -> Result<RetainedCStringV1, SnapshotMaterializeFailureV1> {
        fallible_cstring_with_limit(
            bytes,
            SnapshotMaterializeLimitV1::TotalXattrBytes,
            stage,
            relative_path,
        )
    }

    fn fallible_cstring_with_limit(
        bytes: &[u8],
        limit: SnapshotMaterializeLimitV1,
        stage: SnapshotMaterializeStageV1,
        relative_path: &[u8],
    ) -> Result<RetainedCStringV1, SnapshotMaterializeFailureV1> {
        if bytes.contains(&0) {
            return Err(metadata_mismatch_at(stage, relative_path));
        }
        let capacity = bytes
            .len()
            .checked_add(1)
            .ok_or_else(|| metadata_mismatch_at(stage, relative_path))?;
        let mut terminated = Vec::new();
        terminated
            .try_reserve_exact(capacity)
            .map_err(|_| resource_failure_at(stage, limit, relative_path))?;
        terminated.extend_from_slice(bytes);
        terminated.push(0);
        Ok(RetainedCStringV1 {
            bytes_with_nul: terminated,
        })
    }

    fn fallible_plan_basename(
        bytes: &[u8],
        relative_path: &[u8],
    ) -> Result<RetainedCStringV1, SnapshotMaterializeFailureV1> {
        if !valid_raw_name_bytes(bytes) {
            return Err(plan_failure(relative_path));
        }
        fallible_cstring_with_limit(
            bytes,
            SnapshotMaterializeLimitV1::PlanBytes,
            SnapshotMaterializeStageV1::ValidatePlan,
            relative_path,
        )
    }

    fn fallible_plan_bytes(
        bytes: &[u8],
        relative_path: &[u8],
    ) -> Result<Vec<u8>, SnapshotMaterializeFailureV1> {
        let mut retained = Vec::new();
        retained
            .try_reserve_exact(bytes.len())
            .map_err(|_| resource_failure(SnapshotMaterializeLimitV1::PlanBytes, relative_path))?;
        retained.extend_from_slice(bytes);
        Ok(retained)
    }

    fn reserve_plan_vector_slot<T>(
        values: &mut Vec<T>,
        ceiling: usize,
        relative_path: &[u8],
    ) -> Result<(), SnapshotMaterializeFailureV1> {
        if values.len() >= ceiling {
            return Err(resource_failure(
                SnapshotMaterializeLimitV1::PlanBytes,
                relative_path,
            ));
        }
        if values.len() < values.capacity() {
            return Ok(());
        }
        let required = values.len() + 1;
        let target = values
            .capacity()
            .checked_mul(2)
            .unwrap_or(ceiling)
            .max(required)
            .min(ceiling);
        values
            .try_reserve_exact(target - values.len())
            .map_err(|_| resource_failure(SnapshotMaterializeLimitV1::PlanBytes, relative_path))
    }

    fn retry_eintr_zero(
        attempts: u8,
        mut operation: impl FnMut() -> libc::c_int,
    ) -> io::Result<()> {
        for _ in 0..attempts {
            if operation() == 0 {
                return Ok(());
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
        Err(io::Error::from_raw_os_error(libc::EINTR))
    }

    fn retry_eintr_size(
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

    fn checkpoint<H: MaterializeHooks>(
        hooks: &H,
        stage: SnapshotMaterializeStageV1,
        relative_path: &[u8],
    ) -> Result<(), SnapshotMaterializeFailureV1> {
        hooks
            .checkpoint(stage, relative_path)
            .map_err(|error| mutation_io(stage, relative_path, error))
    }

    fn capability_errno(errno: Option<i32>) -> bool {
        matches!(
            errno,
            Some(libc::ENOSYS | libc::EINVAL | libc::E2BIG | libc::EOPNOTSUPP)
        )
    }

    fn event_failure(relative_path: &[u8]) -> SnapshotMaterializeFailureV1 {
        SnapshotMaterializeFailureV1::new(
            RefusalCode::SnapshotConstructionFailed,
            SnapshotMaterializeStageV1::ValidateEvent,
            SnapshotMaterializeFailureKindV1::InvalidEventSequence,
            None,
            None,
            relative_path,
        )
    }

    fn plan_failure(relative_path: &[u8]) -> SnapshotMaterializeFailureV1 {
        SnapshotMaterializeFailureV1::new(
            RefusalCode::SnapshotConstructionFailed,
            SnapshotMaterializeStageV1::ValidatePlan,
            SnapshotMaterializeFailureKindV1::PlanMismatch,
            None,
            None,
            relative_path,
        )
    }

    fn resource_failure(
        limit: SnapshotMaterializeLimitV1,
        relative_path: &[u8],
    ) -> SnapshotMaterializeFailureV1 {
        resource_failure_at(
            SnapshotMaterializeStageV1::ValidateEvent,
            limit,
            relative_path,
        )
    }

    fn resource_failure_at(
        stage: SnapshotMaterializeStageV1,
        limit: SnapshotMaterializeLimitV1,
        relative_path: &[u8],
    ) -> SnapshotMaterializeFailureV1 {
        SnapshotMaterializeFailureV1::new(
            RefusalCode::SnapshotConstructionFailed,
            stage,
            SnapshotMaterializeFailureKindV1::ResourceLimit(limit),
            None,
            None,
            relative_path,
        )
    }

    fn refuse_unqualified_plan_symlinks(
        plan: &SourceTreePlanV1,
    ) -> Result<(), SnapshotMaterializeFailureV1> {
        match plan
            .entries()
            .iter()
            .find(|entry| matches!(entry.payload(), SourcePlanPayloadV1::Symlink { .. }))
        {
            Some(entry) => Err(unqualified_symlink_durability(entry.relative_path())),
            None => Ok(()),
        }
    }

    fn refuse_unqualified_symlink_event(
        relative_path: &[u8],
    ) -> Result<(), SnapshotMaterializeFailureV1> {
        Err(unqualified_symlink_durability(relative_path))
    }

    fn require_materializable_regular(
        payload: &SourcePlanPayloadV1,
        relative_path: &[u8],
    ) -> Result<(), SnapshotMaterializeFailureV1> {
        match payload {
            SourcePlanPayloadV1::Regular { .. } => Ok(()),
            SourcePlanPayloadV1::Symlink { .. } => {
                Err(unqualified_symlink_durability(relative_path))
            }
            SourcePlanPayloadV1::Directory { .. } => Err(plan_failure(relative_path)),
        }
    }

    fn unqualified_symlink_durability(relative_path: &[u8]) -> SnapshotMaterializeFailureV1 {
        SnapshotMaterializeFailureV1::new(
            RefusalCode::RequiredKernelCapabilityMissing,
            SnapshotMaterializeStageV1::ValidateDurability,
            SnapshotMaterializeFailureKindV1::SymlinkDurabilityRequiresQualifiedFilesystem,
            None,
            None,
            relative_path,
        )
    }

    fn metadata_mismatch(relative_path: &[u8]) -> SnapshotMaterializeFailureV1 {
        metadata_mismatch_at(SnapshotMaterializeStageV1::VerifyMetadata, relative_path)
    }

    fn metadata_mismatch_at(
        stage: SnapshotMaterializeStageV1,
        relative_path: &[u8],
    ) -> SnapshotMaterializeFailureV1 {
        SnapshotMaterializeFailureV1::new(
            RefusalCode::SnapshotConstructionFailed,
            stage,
            SnapshotMaterializeFailureKindV1::DestinationIdentityMismatch,
            None,
            None,
            relative_path,
        )
    }

    fn unsupported_metadata(
        stage: SnapshotMaterializeStageV1,
        relative_path: &[u8],
        errno: Option<i32>,
    ) -> SnapshotMaterializeFailureV1 {
        SnapshotMaterializeFailureV1::new(
            RefusalCode::SnapshotRequiredObjectUnsupported,
            stage,
            SnapshotMaterializeFailureKindV1::UnsupportedMetadata,
            None,
            errno,
            relative_path,
        )
    }

    fn contains_access_acl(xattrs: &[CapturedXattrV1]) -> bool {
        xattrs
            .iter()
            .any(|xattr| xattr.name() == b"system.posix_acl_access")
    }

    fn xattr_mismatch(
        expected: &[CapturedXattrV1],
        relative_path: &[u8],
    ) -> SnapshotMaterializeFailureV1 {
        if contains_access_acl(expected) {
            unsupported_metadata(
                SnapshotMaterializeStageV1::VerifyMetadata,
                relative_path,
                None,
            )
        } else {
            metadata_mismatch(relative_path)
        }
    }

    fn mutation_io(
        stage: SnapshotMaterializeStageV1,
        relative_path: &[u8],
        error: io::Error,
    ) -> SnapshotMaterializeFailureV1 {
        let errno = error.raw_os_error();
        let collision = errno == Some(libc::EEXIST);
        SnapshotMaterializeFailureV1::new(
            RefusalCode::SnapshotConstructionFailed,
            stage,
            if collision {
                SnapshotMaterializeFailureKindV1::DestinationCollision
            } else {
                SnapshotMaterializeFailureKindV1::Io
            },
            None,
            errno,
            relative_path,
        )
    }

    fn metadata_io(
        stage: SnapshotMaterializeStageV1,
        relative_path: &[u8],
        error: io::Error,
    ) -> SnapshotMaterializeFailureV1 {
        let errno = error.raw_os_error();
        let capability = capability_errno(errno);
        SnapshotMaterializeFailureV1::new(
            if capability {
                RefusalCode::RequiredKernelCapabilityMissing
            } else {
                RefusalCode::SnapshotConstructionFailed
            },
            stage,
            if capability {
                SnapshotMaterializeFailureKindV1::RequiredKernelCapability
            } else {
                SnapshotMaterializeFailureKindV1::Io
            },
            None,
            errno,
            relative_path,
        )
    }

    fn open_io(relative_path: &[u8], error: io::Error) -> SnapshotMaterializeFailureV1 {
        metadata_io(
            SnapshotMaterializeStageV1::OpenDestination,
            relative_path,
            error,
        )
    }

    fn map_identity_error(relative_path: &[u8], error: io::Error) -> SnapshotMaterializeFailureV1 {
        metadata_io(
            SnapshotMaterializeStageV1::VerifyMetadata,
            relative_path,
            error,
        )
    }

    fn xattr_io(
        stage: SnapshotMaterializeStageV1,
        relative_path: &[u8],
        error: io::Error,
    ) -> SnapshotMaterializeFailureV1 {
        if matches!(error.raw_os_error(), Some(libc::EPERM | libc::EACCES)) {
            unsupported_metadata(stage, relative_path, error.raw_os_error())
        } else {
            metadata_io(stage, relative_path, error)
        }
    }

    #[cfg(test)]
    mod tests {
        use std::cell::RefCell;
        use std::collections::BTreeMap;
        use std::ffi::{CString, OsStr};
        use std::fs::{self, File};
        use std::num::NonZeroU16;
        use std::os::unix::ffi::OsStrExt;
        use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
        use std::path::Path;
        use std::time::{SystemTime, UNIX_EPOCH};

        use super::*;
        use crate::linux_pytest::snapshot_publish::{
            SnapshotPublishPolicyV1, create_staged_snapshot_directory_at,
        };
        use crate::linux_pytest::snapshot_tree::{
            QualifiedNoAtimeSourceViewV1, SourceEnumerationPolicyV1, SourceTraversalLimitsV1,
            SourceTreeAcquireFailureV1, SourceXattrLimitsV1, enumerate_source_tree_view_at,
        };

        #[derive(Default)]
        struct FakeHooks {
            list_payload: RefCell<Vec<u8>>,
            list_error: RefCell<Option<i32>>,
            checkpoints: RefCell<Vec<SnapshotMaterializeStageV1>>,
            fail_checkpoint: Option<SnapshotMaterializeStageV1>,
        }

        #[derive(Default)]
        struct StatefulXattrHooks {
            values: RefCell<BTreeMap<Vec<u8>, Vec<u8>>>,
            operations: RefCell<Vec<&'static str>>,
        }

        impl StatefulXattrHooks {
            fn response(bytes: &[u8], output: Option<&mut [u8]>) -> io::Result<usize> {
                if let Some(output) = output {
                    if output.len() < bytes.len() {
                        return Err(io::Error::from_raw_os_error(libc::ERANGE));
                    }
                    output[..bytes.len()].copy_from_slice(bytes);
                }
                Ok(bytes.len())
            }
        }

        impl MaterializeHooks for StatefulXattrHooks {
            fn checkpoint(
                &self,
                _stage: SnapshotMaterializeStageV1,
                _relative_path: &[u8],
            ) -> io::Result<()> {
                self.operations.borrow_mut().push("checkpoint");
                Ok(())
            }

            fn list_xattrs(&self, _fd: RawFd, output: Option<&mut [u8]>) -> io::Result<usize> {
                self.operations.borrow_mut().push("list");
                let mut payload = Vec::new();
                for name in self.values.borrow().keys() {
                    payload.extend_from_slice(name);
                    payload.push(0);
                }
                Self::response(&payload, output)
            }

            fn get_xattr(
                &self,
                _fd: RawFd,
                name: &CStr,
                output: Option<&mut [u8]>,
            ) -> io::Result<usize> {
                self.operations.borrow_mut().push("get");
                let values = self.values.borrow();
                let value = values
                    .get(name.to_bytes())
                    .ok_or_else(|| io::Error::from_raw_os_error(libc::ENODATA))?;
                Self::response(value, output)
            }

            fn set_xattr(&self, _fd: RawFd, name: &CStr, value: &[u8]) -> io::Result<()> {
                self.operations.borrow_mut().push("set");
                self.values
                    .borrow_mut()
                    .insert(name.to_bytes().to_vec(), value.to_vec());
                Ok(())
            }

            fn remove_xattr(&self, _fd: RawFd, name: &CStr) -> io::Result<()> {
                self.operations.borrow_mut().push("remove");
                self.values.borrow_mut().remove(name.to_bytes());
                Ok(())
            }
        }

        impl MaterializeHooks for FakeHooks {
            fn checkpoint(
                &self,
                stage: SnapshotMaterializeStageV1,
                _relative_path: &[u8],
            ) -> io::Result<()> {
                self.checkpoints.borrow_mut().push(stage);
                if self.fail_checkpoint == Some(stage) {
                    return Err(io::Error::from_raw_os_error(libc::EIO));
                }
                Ok(())
            }

            fn list_xattrs(&self, _fd: RawFd, output: Option<&mut [u8]>) -> io::Result<usize> {
                if let Some(errno) = self.list_error.borrow_mut().take() {
                    return Err(io::Error::from_raw_os_error(errno));
                }
                let payload = self.list_payload.borrow();
                if let Some(output) = output {
                    if output.len() < payload.len() {
                        return Err(io::Error::from_raw_os_error(libc::ERANGE));
                    }
                    output[..payload.len()].copy_from_slice(&payload);
                }
                Ok(payload.len())
            }

            fn get_xattr(
                &self,
                _fd: RawFd,
                _name: &CStr,
                _output: Option<&mut [u8]>,
            ) -> io::Result<usize> {
                Err(io::Error::from_raw_os_error(libc::ENODATA))
            }

            fn set_xattr(&self, _fd: RawFd, _name: &CStr, _value: &[u8]) -> io::Result<()> {
                Ok(())
            }

            fn remove_xattr(&self, _fd: RawFd, _name: &CStr) -> io::Result<()> {
                Ok(())
            }
        }

        struct PlanOnlyVisitor;

        impl SourceTreeVisitorV1 for PlanOnlyVisitor {
            type Error = SnapshotMaterializeFailureV1;

            fn directory_enter(
                &mut self,
                _visit: SourceDirectoryVisitV1<'_>,
            ) -> Result<(), Self::Error> {
                Ok(())
            }

            fn regular(
                &mut self,
                visit: SourceRegularVisitV1<'_>,
            ) -> Result<SourceRegularEvidenceV1, Self::Error> {
                Err(event_failure(visit.common().relative_path()))
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

        fn test_policy() -> SnapshotMaterializePolicyV1 {
            SnapshotMaterializePolicyV1::checked(
                8,
                NonZeroU32::new(32).unwrap(),
                NonZeroU64::new(128 * 1024).unwrap(),
                NonZeroU8::new(4).unwrap(),
                NonZeroU8::new(3).unwrap(),
            )
            .unwrap()
        }

        fn test_publish_policy() -> SnapshotPublishPolicyV1 {
            test_publish_policy_with_cleanup_limits(4, 4, 8, 32, 255)
        }

        fn test_publish_policy_with_cleanup_limits(
            openat2_attempts: u8,
            syscall_attempts: u8,
            max_source_tree_depth: u16,
            max_entries: u32,
            max_basename_bytes: u16,
        ) -> SnapshotPublishPolicyV1 {
            SnapshotPublishPolicyV1::checked(
                NonZeroU8::new(openat2_attempts).unwrap(),
                NonZeroU8::new(syscall_attempts).unwrap(),
                max_source_tree_depth,
                NonZeroU32::new(max_entries).unwrap(),
                NonZeroU16::new(max_basename_bytes).unwrap(),
                NonZeroU64::new(256 * 1024).unwrap(),
            )
            .unwrap()
        }

        fn test_fd() -> File {
            File::open("/dev/null").unwrap()
        }

        fn test_xattr_budget() -> XattrOperationBudgetV1 {
            XattrOperationBudgetV1::new(test_policy().max_xattr_operations.get())
        }

        fn test_stat(mode: u32, nlink: u64, size: u64) -> SourceStatxV1 {
            let timestamp = crate::linux_pytest::TimespecV1 {
                seconds: 17,
                nanoseconds: 23,
            };
            SourceStatxV1::for_test(
                1,
                8,
                1,
                55,
                mode,
                1000,
                1000,
                nlink,
                size,
                timestamp.clone(),
                timestamp.clone(),
                timestamp,
                None,
            )
        }

        #[test]
        fn bounded_eintr_retry_accepts_n_and_never_attempts_n_plus_one() {
            let mut calls = 0;
            retry_eintr_zero(3, || {
                calls += 1;
                if calls == 3 {
                    0
                } else {
                    unsafe { *libc::__errno_location() = libc::EINTR };
                    -1
                }
            })
            .unwrap();
            assert_eq!(calls, 3);

            let mut exhausted_calls = 0;
            let error = retry_eintr_zero(3, || {
                exhausted_calls += 1;
                unsafe { *libc::__errno_location() = libc::EINTR };
                -1
            })
            .unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EINTR));
            assert_eq!(exhausted_calls, 3);
        }

        #[test]
        fn bounded_size_retry_accepts_n_and_never_attempts_n_plus_one() {
            let mut calls = 0;
            let size = retry_eintr_size(3, || {
                calls += 1;
                if calls == 3 {
                    17
                } else {
                    unsafe { *libc::__errno_location() = libc::EINTR };
                    -1
                }
            })
            .unwrap();
            assert_eq!(size, 17);
            assert_eq!(calls, 3);

            let mut exhausted_calls = 0;
            let error = retry_eintr_size(3, || {
                exhausted_calls += 1;
                unsafe { *libc::__errno_location() = libc::EINTR };
                -1
            })
            .unwrap_err();
            assert_eq!(error.raw_os_error(), Some(libc::EINTR));
            assert_eq!(exhausted_calls, 3);
        }

        #[test]
        fn exact_cleanup_envelope_is_accepted_before_population() {
            let publication_parent = tempfile::tempdir().unwrap();
            let publication_parent_fd = File::open(publication_parent.path()).unwrap();
            let staging_name = c".again-snapshot-stage-0123456789abcdef0123456789abcde0";
            let staging_path = publication_parent
                .path()
                .join(OsStr::from_bytes(staging_name.to_bytes()));
            let staged = create_staged_snapshot_directory_at(
                publication_parent_fd.as_fd(),
                staging_name,
                test_publish_policy_with_cleanup_limits(4, 3, 8, 32, 255),
            )
            .unwrap();

            let materializer = match SnapshotMaterializerV1::new(staged, test_policy()) {
                Ok(materializer) => materializer,
                Err(failure) => panic!("exact cleanup envelope must be accepted: {failure}"),
            };
            drop(materializer);
            assert!(!staging_path.exists());
        }

        #[test]
        fn every_short_cleanup_envelope_dimension_refuses_and_cleans_controlled_fixture() {
            let deficient_policies = [
                (
                    c".again-snapshot-stage-0123456789abcdef0123456789abcde1",
                    test_publish_policy_with_cleanup_limits(4, 3, 7, 32, 255),
                ),
                (
                    c".again-snapshot-stage-0123456789abcdef0123456789abcde2",
                    test_publish_policy_with_cleanup_limits(4, 3, 8, 31, 255),
                ),
                (
                    c".again-snapshot-stage-0123456789abcdef0123456789abcde3",
                    test_publish_policy_with_cleanup_limits(4, 3, 8, 32, 254),
                ),
                (
                    c".again-snapshot-stage-0123456789abcdef0123456789abcde4",
                    test_publish_policy_with_cleanup_limits(3, 3, 8, 32, 255),
                ),
                (
                    c".again-snapshot-stage-0123456789abcdef0123456789abcde5",
                    test_publish_policy_with_cleanup_limits(4, 2, 8, 32, 255),
                ),
            ];

            for (staging_name, cleanup_policy) in deficient_policies {
                let publication_parent = tempfile::tempdir().unwrap();
                let publication_parent_fd = File::open(publication_parent.path()).unwrap();
                let staging_path = publication_parent
                    .path()
                    .join(OsStr::from_bytes(staging_name.to_bytes()));
                let staged = create_staged_snapshot_directory_at(
                    publication_parent_fd.as_fd(),
                    staging_name,
                    cleanup_policy,
                )
                .unwrap();

                let failure = match SnapshotMaterializerV1::new(staged, test_policy()) {
                    Ok(_) => panic!("every insufficient cleanup dimension must fail closed"),
                    Err(failure) => failure,
                };
                assert_eq!(
                    failure.stage(),
                    SnapshotMaterializeStageV1::ValidateCleanupAuthority
                );
                assert_eq!(
                    failure.kind(),
                    SnapshotMaterializeFailureKindV1::CleanupAuthorityInsufficient
                );
                assert!(failure.relative_path().is_empty());
                assert!(!staging_path.exists());
            }
        }

        #[test]
        fn symlink_event_refusal_helper_creates_no_symlink_or_final_and_raii_cleans_prior_root() {
            let publication_parent = tempfile::tempdir().unwrap();
            let publication_parent_fd = File::open(publication_parent.path()).unwrap();
            let staging_name = c".again-snapshot-stage-0123456789abcdef0123456789abcdea";
            let staging_path = publication_parent
                .path()
                .join(OsStr::from_bytes(staging_name.to_bytes()));
            let final_path = publication_parent.path().join("final");
            let staged = create_staged_snapshot_directory_at(
                publication_parent_fd.as_fd(),
                staging_name,
                test_publish_policy(),
            )
            .unwrap();
            let materializer = SnapshotMaterializerV1::new(staged, test_policy()).unwrap();
            mkdir_private_at(
                materializer.staging_directory(),
                c"tree",
                test_policy().syscall_attempts.get(),
            )
            .unwrap();
            let private_root = staging_path.join("tree");
            assert!(private_root.is_dir());

            let failure = refuse_unqualified_symlink_event(b"link").unwrap_err();
            assert_eq!(failure.code(), RefusalCode::RequiredKernelCapabilityMissing);
            assert_eq!(
                failure.stage(),
                SnapshotMaterializeStageV1::ValidateDurability
            );
            assert_eq!(
                failure.kind(),
                SnapshotMaterializeFailureKindV1::SymlinkDurabilityRequiresQualifiedFilesystem
            );
            assert_eq!(failure.relative_path(), b"link");
            assert_eq!(fs::read_dir(&private_root).unwrap().count(), 0);
            assert_eq!(
                fs::symlink_metadata(private_root.join("link"))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::NotFound
            );
            assert!(!final_path.exists());

            drop(materializer);
            assert!(!staging_path.exists());
            assert!(!final_path.exists());
            assert_eq!(fs::read_dir(publication_parent.path()).unwrap().count(), 0);
        }

        #[test]
        fn bounded_vector_growth_stops_at_the_exact_ceiling() {
            let mut values = Vec::new();
            for value in 0..3 {
                reserve_plan_vector_slot(&mut values, 3, b"bounded").unwrap();
                values.push(value);
            }
            let failure = reserve_plan_vector_slot(&mut values, 3, b"bounded").unwrap_err();
            assert_eq!(values, [0, 1, 2]);
            assert_eq!(failure.relative_path(), b"bounded");
            assert_eq!(
                failure.kind(),
                SnapshotMaterializeFailureKindV1::ResourceLimit(
                    SnapshotMaterializeLimitV1::PlanBytes
                )
            );
        }

        #[test]
        fn retained_plan_bytes_keep_the_fallibly_reserved_vector_capacity() {
            let retained = fallible_plan_bytes(b"raw-\xff-name", b"parent/raw-\xff-name").unwrap();
            assert_eq!(retained, b"raw-\xff-name");
            assert!(retained.capacity() >= retained.len());
        }

        #[test]
        fn physical_projection_is_read_only_and_preserves_builder_owner_access() {
            assert_eq!(projected_regular_mode(libc::S_IFREG | 0o7777), 0o555);
            assert_eq!(projected_directory_mode(libc::S_IFDIR | 0o2642), 0o540);
            assert_eq!(projected_regular_mode(libc::S_IFREG | 0o400), 0o400);
            assert_eq!(projected_regular_mode(libc::S_IFREG | 0o222), 0o400);
            assert_eq!(projected_directory_mode(libc::S_IFDIR), 0o500);
            assert_eq!(projected_regular_mode(libc::S_IFREG | 0o064), 0o444);
            assert_eq!(projected_directory_mode(libc::S_IFDIR | 0o001), 0o501);
        }

        #[test]
        fn directory_size_is_not_part_of_the_physical_projection() {
            let expected = test_stat(libc::S_IFDIR | 0o755, 9, 1);
            let observed = DestinationIdentityV1 {
                mount_id: 1,
                device_major: 8,
                device_minor: 1,
                inode: 99,
                mode: libc::S_IFDIR | 0o555,
                uid: 42,
                nlink: 3,
                size: u64::MAX,
                atime_seconds: 17,
                atime_nanoseconds: 23,
                mtime_seconds: 17,
                mtime_nanoseconds: 23,
            };
            assert!(metadata_projection_matches(
                &observed,
                &expected,
                SourceNodeKindV1::Directory,
                Some(3),
                42,
            ));
            assert!(!metadata_projection_matches(
                &DestinationIdentityV1 {
                    mode: libc::S_IFREG | 0o555,
                    ..observed
                },
                &test_stat(libc::S_IFREG | 0o755, 1, 1),
                SourceNodeKindV1::Regular,
                None,
                42,
            ));
        }

        #[test]
        fn same_count_plan_swap_changes_the_exact_event_commitment() {
            let root_stat = test_stat(libc::S_IFDIR | 0o755, 2, 0);
            let leaf_stat = test_stat(libc::S_IFLNK | 0o777, 1, 1);
            let root_a = commit_name_sequence(std::iter::once(b"a".as_slice()), 1, b"").unwrap();
            let root_b = commit_name_sequence(std::iter::once(b"b".as_slice()), 1, b"").unwrap();
            let target = commit_single_payload(b"AGNMATS1", b"x");
            let mut observed = vec![
                commit_entry_parts(
                    b"",
                    b"tree",
                    &root_stat,
                    &[],
                    SourceNodeKindV1::Directory,
                    &root_a,
                )
                .unwrap(),
                commit_entry_parts(
                    b"a",
                    b"a",
                    &leaf_stat,
                    &[],
                    SourceNodeKindV1::Symlink,
                    &target,
                )
                .unwrap(),
            ];
            let mut swapped_plan = vec![
                commit_entry_parts(
                    b"",
                    b"tree",
                    &root_stat,
                    &[],
                    SourceNodeKindV1::Directory,
                    &root_b,
                )
                .unwrap(),
                commit_entry_parts(
                    b"b",
                    b"b",
                    &leaf_stat,
                    &[],
                    SourceNodeKindV1::Symlink,
                    &target,
                )
                .unwrap(),
            ];
            observed.sort_unstable();
            swapped_plan.sort_unstable();
            assert_eq!(observed.len(), swapped_plan.len());
            assert_ne!(observed, swapped_plan);
        }

        #[test]
        fn xattr_and_deep_parent_work_stop_at_the_exact_budget() {
            let budget = XattrOperationBudgetV1::new(2);
            budget
                .charge(1, SnapshotMaterializeStageV1::ApplyXattrs, b"a")
                .unwrap();
            budget
                .charge(1, SnapshotMaterializeStageV1::VerifyMetadata, b"a")
                .unwrap();
            let failure = budget
                .charge(1, SnapshotMaterializeStageV1::VerifyMetadata, b"a")
                .unwrap_err();
            assert_eq!(
                failure.kind(),
                SnapshotMaterializeFailureKindV1::ResourceLimit(
                    SnapshotMaterializeLimitV1::XattrOperations
                )
            );

            let mut policy = test_policy();
            policy.max_plan_open_components = NonZeroU64::new(3).unwrap();
            let mut components = 0;
            charge_plan_open_work(&mut components, 3, policy, b"a/b/c").unwrap();
            let mut overflow = 0;
            let failure = charge_plan_open_work(&mut overflow, 4, policy, b"a/b/c/d").unwrap_err();
            assert_eq!(
                failure.kind(),
                SnapshotMaterializeFailureKindV1::ResourceLimit(
                    SnapshotMaterializeLimitV1::PlanOpenComponents
                )
            );
            assert_eq!(entry_depth(b"a/b/c/d"), 4);
        }

        #[test]
        fn acl_and_permission_xattr_failures_are_typed_unsupported_metadata() {
            let acl = [CapturedXattrV1::bytes_for_test(
                b"system.posix_acl_access",
                b"acl",
            )];
            assert_eq!(
                xattr_mismatch(&acl, b"file").kind(),
                SnapshotMaterializeFailureKindV1::UnsupportedMetadata
            );
            let failure = xattr_io(
                SnapshotMaterializeStageV1::VerifyMetadata,
                b"file",
                io::Error::from_raw_os_error(libc::EACCES),
            );
            assert_eq!(failure.stage(), SnapshotMaterializeStageV1::VerifyMetadata);
            assert_eq!(
                failure.code(),
                RefusalCode::SnapshotRequiredObjectUnsupported
            );
            assert_eq!(
                failure.kind(),
                SnapshotMaterializeFailureKindV1::UnsupportedMetadata
            );
        }

        #[test]
        fn raw_xattr_names_are_normalized_by_byte_order() {
            let hooks = FakeHooks {
                list_payload: RefCell::new(b"user.\xff\0user.a\0".to_vec()),
                ..FakeHooks::default()
            };
            let file = test_fd();
            let budget = test_xattr_budget();
            let names = list_xattr_names(
                &hooks,
                &budget,
                file.as_fd(),
                test_policy(),
                SnapshotMaterializeStageV1::VerifyMetadata,
                b"raw",
            )
            .unwrap();
            assert_eq!(
                names.iter().map(|name| name.as_bytes()).collect::<Vec<_>>(),
                vec![b"user.a".as_slice(), b"user.\xff".as_slice()]
            );
        }

        #[test]
        fn xattr_replay_removes_extras_sets_values_and_verifies_exactly() {
            let hooks = StatefulXattrHooks {
                values: RefCell::new(BTreeMap::from([(b"user.old".to_vec(), b"old".to_vec())])),
                ..StatefulXattrHooks::default()
            };
            let expected = [CapturedXattrV1::bytes_for_test(b"user.a", b"value")];
            let file = test_fd();
            let budget = test_xattr_budget();
            let names = apply_xattrs(
                &hooks,
                &budget,
                file.as_fd(),
                &expected,
                test_policy(),
                b"file",
            )
            .unwrap();
            verify_xattrs(
                &hooks,
                &budget,
                file.as_fd(),
                &expected,
                &names,
                test_policy(),
                b"file",
            )
            .unwrap();
            assert_eq!(
                &*hooks.values.borrow(),
                &BTreeMap::from([(b"user.a".to_vec(), b"value".to_vec())])
            );
            let operations = hooks.operations.borrow();
            assert!(operations.windows(2).any(|pair| pair == ["remove", "set"]));
            assert_eq!(operations.last(), Some(&"get"));
        }

        #[test]
        fn visible_but_unsettable_xattr_is_refused_before_mutation() {
            let hooks = StatefulXattrHooks::default();
            let expected = [CapturedXattrV1::unsettable_for_test(
                b"security.unreadable",
                libc::EACCES,
            )];
            let file = test_fd();
            let budget = test_xattr_budget();
            let failure = apply_xattrs(
                &hooks,
                &budget,
                file.as_fd(),
                &expected,
                test_policy(),
                b"file",
            )
            .unwrap_err();
            assert_eq!(
                failure.kind(),
                SnapshotMaterializeFailureKindV1::VisibleXattrUnrepresentable
            );
            assert!(hooks.values.borrow().is_empty());
            assert_eq!(hooks.operations.borrow().as_slice(), &["checkpoint"]);
        }

        #[test]
        fn malformed_xattr_lists_fail_closed() {
            let file = test_fd();
            for payload in [
                b"no-trailing-nul".to_vec(),
                b"a\0\0".to_vec(),
                b"a\0a\0".to_vec(),
            ] {
                let hooks = FakeHooks {
                    list_payload: RefCell::new(payload),
                    ..FakeHooks::default()
                };
                let budget = test_xattr_budget();
                let failure = list_xattr_names(
                    &hooks,
                    &budget,
                    file.as_fd(),
                    test_policy(),
                    SnapshotMaterializeStageV1::VerifyMetadata,
                    b"bad",
                )
                .unwrap_err();
                assert_eq!(
                    failure.kind(),
                    SnapshotMaterializeFailureKindV1::DestinationIdentityMismatch
                );
            }
        }

        #[test]
        fn xattr_list_cap_and_missing_syscall_are_typed() {
            let file = test_fd();
            let oversized = FakeHooks {
                list_payload: RefCell::new(vec![b'a'; MAX_XATTR_LIST_BYTES + 1]),
                ..FakeHooks::default()
            };
            let budget = test_xattr_budget();
            let failure = list_xattr_names(
                &oversized,
                &budget,
                file.as_fd(),
                test_policy(),
                SnapshotMaterializeStageV1::VerifyMetadata,
                b"large",
            )
            .unwrap_err();
            assert_eq!(
                failure.kind(),
                SnapshotMaterializeFailureKindV1::ResourceLimit(
                    SnapshotMaterializeLimitV1::XattrListBytes
                )
            );

            let missing = FakeHooks {
                list_error: RefCell::new(Some(libc::ENOSYS)),
                ..FakeHooks::default()
            };
            let budget = test_xattr_budget();
            let failure = list_xattr_names(
                &missing,
                &budget,
                file.as_fd(),
                test_policy(),
                SnapshotMaterializeStageV1::VerifyMetadata,
                b"missing",
            )
            .unwrap_err();
            assert_eq!(failure.code(), RefusalCode::RequiredKernelCapabilityMissing);
        }

        #[test]
        fn injected_checkpoint_failure_preserves_exact_stage_and_path() {
            let hooks = FakeHooks {
                fail_checkpoint: Some(SnapshotMaterializeStageV1::ApplyXattrs),
                ..FakeHooks::default()
            };
            let failure = checkpoint(&hooks, SnapshotMaterializeStageV1::ApplyXattrs, b"dir/file")
                .unwrap_err();
            assert_eq!(failure.stage(), SnapshotMaterializeStageV1::ApplyXattrs);
            assert_eq!(failure.relative_path(), b"dir/file");
            assert_eq!(
                hooks.checkpoints.borrow().as_slice(),
                &[SnapshotMaterializeStageV1::ApplyXattrs]
            );
        }

        #[test]
        fn raw_child_path_validation_never_requires_utf8() {
            assert!(path_is_child_of(b"dir", b"\xff", b"dir/\xff"));
            assert!(path_is_child_of(b"", b"\xfe", b"\xfe"));
            assert!(!path_is_child_of(b"dir", b"x", b"dir/x/y"));
        }

        #[test]
        fn special_modes_never_coerce_to_directory() {
            for mode in [
                libc::S_IFIFO,
                libc::S_IFSOCK,
                libc::S_IFCHR,
                libc::S_IFBLK,
                0,
            ] {
                assert_eq!(kind_from_mode(mode | 0o755), None);
            }
        }

        fn enumeration_policy() -> SourceEnumerationPolicyV1 {
            let traversal = SourceTraversalLimitsV1::checked(
                8,
                NonZeroU16::new(255).unwrap(),
                NonZeroU32::new(1024).unwrap(),
                NonZeroU32::new(32).unwrap(),
                NonZeroU32::new(1024).unwrap(),
                NonZeroU64::new(1024 * 1024).unwrap(),
                NonZeroU64::new(4 * 1024 * 1024).unwrap(),
            )
            .unwrap();
            let xattrs = SourceXattrLimitsV1::checked(
                NonZeroU16::new(16).unwrap(),
                NonZeroU16::new(255).unwrap(),
                NonZeroU32::new(64 * 1024).unwrap(),
                NonZeroU32::new(64 * 1024).unwrap(),
                NonZeroU64::new(128 * 1024).unwrap(),
            )
            .unwrap();
            SourceEnumerationPolicyV1::checked(
                traversal,
                xattrs,
                NonZeroU64::new(8 * 1024 * 1024).unwrap(),
                NonZeroU32::new(128).unwrap(),
                NonZeroU8::new(4).unwrap(),
                NonZeroU8::new(3).unwrap(),
                NonZeroU8::new(2).unwrap(),
            )
            .unwrap()
        }

        #[test]
        fn materializer_uses_the_distinct_source_syscall_retry_authority() {
            let source = enumeration_policy();
            assert_eq!(source.openat2_attempts(), 4);
            assert_eq!(source.syscall_attempts(), 3);
            assert_eq!(source.xattr_stability_attempts(), 2);

            let materialize = SnapshotMaterializePolicyV1::from_source_policy(source)
                .expect("valid source policy must project into materialization");
            assert_eq!(materialize.openat2_attempts.get(), 4);
            assert_eq!(materialize.syscall_attempts.get(), 3);
        }

        fn raw_path(path: &Path) -> CString {
            CString::new(path.as_os_str().as_bytes()).unwrap()
        }

        fn set_forced_update_probe_atime(path: &Path) {
            let metadata = fs::symlink_metadata(path).unwrap();
            // `relatime` must update an atime this old (and older than the
            // preserved mtime/just-updated ctime), while a real no-atime view
            // must leave it unchanged. A future atime would be a false-positive
            // probe because ordinary `relatime` deliberately preserves it.
            let stale = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
                .saturating_sub(3 * 86_400) as i64;
            let times = [
                libc::timespec {
                    tv_sec: stale,
                    tv_nsec: 123_456_789,
                },
                libc::timespec {
                    tv_sec: metadata.mtime(),
                    tv_nsec: metadata.mtime_nsec(),
                },
            ];
            let flags = if metadata.file_type().is_symlink() {
                libc::AT_SYMLINK_NOFOLLOW
            } else {
                0
            };
            let result = unsafe {
                libc::utimensat(
                    libc::AT_FDCWD,
                    raw_path(path).as_ptr(),
                    times.as_ptr(),
                    flags,
                )
            };
            assert_eq!(result, 0, "utimensat: {}", io::Error::last_os_error());
        }

        fn atime(path: &Path) -> (i64, i64) {
            let metadata = fs::symlink_metadata(path).unwrap();
            (metadata.atime(), metadata.atime_nsec())
        }

        fn get_path_xattr(path: &Path, name: &CStr) -> io::Result<Vec<u8>> {
            let path = raw_path(path);
            let length =
                unsafe { libc::lgetxattr(path.as_ptr(), name.as_ptr(), std::ptr::null_mut(), 0) };
            if length < 0 {
                return Err(io::Error::last_os_error());
            }
            let mut value = vec![0u8; length as usize];
            let returned = unsafe {
                libc::lgetxattr(
                    path.as_ptr(),
                    name.as_ptr(),
                    value.as_mut_ptr().cast::<libc::c_void>(),
                    value.len(),
                )
            };
            if returned < 0 {
                return Err(io::Error::last_os_error());
            }
            value.truncate(returned as usize);
            Ok(value)
        }

        fn set_path_xattr(path: &Path, name: &CStr, value: &[u8]) -> io::Result<()> {
            let path = raw_path(path);
            let result = unsafe {
                libc::lsetxattr(
                    path.as_ptr(),
                    name.as_ptr(),
                    value.as_ptr().cast::<libc::c_void>(),
                    value.len(),
                    0,
                )
            };
            if result == 0 {
                Ok(())
            } else {
                Err(io::Error::last_os_error())
            }
        }

        fn functionally_qualifies_test_view(entries: &[&Path]) -> bool {
            let before = entries.iter().map(|path| atime(path)).collect::<Vec<_>>();
            for path in entries {
                let metadata = fs::symlink_metadata(path).unwrap();
                if metadata.file_type().is_dir() {
                    let _ = fs::read_dir(path).unwrap().count();
                } else if metadata.file_type().is_symlink() {
                    let _ = fs::read_link(path).unwrap();
                } else {
                    let _ = fs::read(path).unwrap();
                }
                let _ = get_path_xattr(path, c"user.again");
            }
            let after = entries.iter().map(|path| atime(path)).collect::<Vec<_>>();
            before == after
        }

        fn open_fd_count() -> usize {
            fs::read_dir("/proc/self/fd").unwrap().count()
        }

        #[test]
        #[ignore = "requires the provisioned linux-pytest-v1 profile kernel and no-atime view"]
        fn real_tree_materializes_when_profile_capabilities_are_present() {
            let source_parent = tempfile::tempdir().unwrap();
            let root = source_parent.path().join("tree");
            let directory = root.join("dir");
            fs::create_dir(&root).unwrap();
            fs::create_dir(&directory).unwrap();
            fs::write(directory.join("file"), b"exact logical bytes").unwrap();
            fs::hard_link(directory.join("file"), directory.join("twin")).unwrap();
            let symlink_root = source_parent.path().join("symlink-tree");
            fs::create_dir(&symlink_root).unwrap();
            symlink(OsStr::from_bytes(b"target"), symlink_root.join("link")).unwrap();
            fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
            fs::set_permissions(&directory, fs::Permissions::from_mode(0o777)).unwrap();
            fs::set_permissions(directory.join("file"), fs::Permissions::from_mode(0o644)).unwrap();
            set_path_xattr(&directory.join("file"), c"user.again", b"exact-xattr").unwrap();
            // Keep these owned paths alive while borrowing them in `entries`.
            let file_path = directory.join("file");
            let twin_path = directory.join("twin");
            let link_path = symlink_root.join("link");
            let entries = [
                root.as_path(),
                directory.as_path(),
                file_path.as_path(),
                twin_path.as_path(),
                symlink_root.as_path(),
                link_path.as_path(),
            ];
            for path in entries {
                set_forced_update_probe_atime(path);
            }
            assert!(
                functionally_qualifies_test_view(&entries),
                "test mount must provide the profile's functionally qualified no-atime view"
            );
            let qualified_atimes = entries.iter().map(|path| atime(path)).collect::<Vec<_>>();
            let source_parent_fd = File::open(source_parent.path()).unwrap();
            // SAFETY: every object kind used below was probed immediately
            // above and retained its atime; the private tree is not mutated
            // again for the duration of this borrow.
            let source_view = unsafe {
                QualifiedNoAtimeSourceViewV1::from_functionally_verified_mount(
                    source_parent_fd.as_fd(),
                )
            };

            let publication_parent = tempfile::tempdir().unwrap();
            let publication_parent_fd = File::open(publication_parent.path()).unwrap();

            let mut plan_only = PlanOnlyVisitor;
            let symlink_plan = enumerate_source_tree_view_at(
                source_view,
                c"symlink-tree",
                enumeration_policy(),
                &mut plan_only,
            )
            .unwrap();
            let plan_staging_name = c".again-snapshot-stage-0123456789abcdef0123456789abceef";
            let plan_staging_path = publication_parent
                .path()
                .join(OsStr::from_bytes(plan_staging_name.to_bytes()));
            let plan_staged = create_staged_snapshot_directory_at(
                publication_parent_fd.as_fd(),
                plan_staging_name,
                test_publish_policy(),
            )
            .unwrap();
            let mut plan_materializer =
                SnapshotMaterializerV1::new(plan_staged, test_policy()).unwrap();
            plan_materializer.root_name =
                Some(fallible_plan_bytes(symlink_plan.root_name(), b"").unwrap());
            plan_materializer.event_commitments = (0..symlink_plan.entries().len())
                .map(|index| commit_plan_entry(&symlink_plan, index))
                .collect::<Result<_, _>>()
                .unwrap();
            let failure = plan_materializer.finish(&symlink_plan).unwrap_err();
            let SnapshotMaterializeFinishErrorV1::Materialize(failure) = failure else {
                panic!("unqualified immutable symlink plan must fail in the materializer")
            };
            assert_eq!(failure.code(), RefusalCode::RequiredKernelCapabilityMissing);
            assert_eq!(
                failure.stage(),
                SnapshotMaterializeStageV1::ValidateDurability
            );
            assert_eq!(
                failure.kind(),
                SnapshotMaterializeFailureKindV1::SymlinkDurabilityRequiresQualifiedFilesystem
            );
            assert_eq!(failure.relative_path(), b"link");
            assert!(
                !plan_staging_path.exists(),
                "immutable-plan refusal must clean the still-empty publisher stage"
            );

            let symlink_staging_name = c".again-snapshot-stage-0123456789abcdef0123456789abceee";
            let symlink_staging_path = publication_parent
                .path()
                .join(OsStr::from_bytes(symlink_staging_name.to_bytes()));
            let symlink_staged = create_staged_snapshot_directory_at(
                publication_parent_fd.as_fd(),
                symlink_staging_name,
                test_publish_policy(),
            )
            .unwrap();
            let mut symlink_materializer =
                SnapshotMaterializerV1::new(symlink_staged, test_policy()).unwrap();
            let failure = match enumerate_source_tree_view_at(
                source_view,
                c"symlink-tree",
                enumeration_policy(),
                &mut symlink_materializer,
            ) {
                Err(SourceTreeAcquireFailureV1::Visitor { source, .. }) => source,
                result => panic!("expected symlink durability refusal, got {result:?}"),
            };
            assert_eq!(failure.code(), RefusalCode::RequiredKernelCapabilityMissing);
            assert_eq!(
                failure.stage(),
                SnapshotMaterializeStageV1::ValidateDurability
            );
            assert_eq!(failure.relative_path(), b"link");
            let private_root = symlink_staging_path.join("symlink-tree");
            assert!(private_root.is_dir());
            assert_eq!(fs::read_dir(&private_root).unwrap().count(), 0);
            assert_eq!(
                fs::symlink_metadata(private_root.join("link"))
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::NotFound
            );
            drop(symlink_materializer);
            assert!(
                !symlink_staging_path.exists(),
                "event-time refusal must clean prior private staging mutations"
            );

            let failing_staging_name = c".again-snapshot-stage-0123456789abcdef0123456789abcdee";
            let failing_staging_path = publication_parent
                .path()
                .join(OsStr::from_bytes(failing_staging_name.to_bytes()));
            let failing_staged = create_staged_snapshot_directory_at(
                publication_parent_fd.as_fd(),
                failing_staging_name,
                test_publish_policy(),
            )
            .unwrap();
            let mut failing_materializer = SnapshotMaterializerWithHooksV1::new_with_hooks(
                failing_staged,
                test_policy(),
                FakeHooks {
                    fail_checkpoint: Some(SnapshotMaterializeStageV1::CreateDirectory),
                    ..FakeHooks::default()
                },
            )
            .unwrap();
            let failure = match enumerate_source_tree_view_at(
                source_view,
                c"tree",
                enumeration_policy(),
                &mut failing_materializer,
            ) {
                Err(SourceTreeAcquireFailureV1::Visitor { source, .. }) => source,
                result => panic!("expected injected visitor failure, got {result:?}"),
            };
            assert_eq!(failure.stage(), SnapshotMaterializeStageV1::CreateDirectory);
            assert_eq!(failure.relative_path(), b"dir");
            drop(failing_materializer);
            assert!(
                !failing_staging_path.exists(),
                "mid-tree materializer failure must delegate recursive cleanup to publisher RAII"
            );

            let swapped_staging_name = c".again-snapshot-stage-0123456789abcdef0123456789abcded";
            let swapped_staging_path = publication_parent
                .path()
                .join(OsStr::from_bytes(swapped_staging_name.to_bytes()));
            let swapped_staged = create_staged_snapshot_directory_at(
                publication_parent_fd.as_fd(),
                swapped_staging_name,
                test_publish_policy(),
            )
            .unwrap();
            let mut swapped_materializer =
                SnapshotMaterializerV1::new(swapped_staged, test_policy()).unwrap();
            let swapped_plan = enumerate_source_tree_view_at(
                source_view,
                c"tree",
                enumeration_policy(),
                &mut swapped_materializer,
            )
            .unwrap();
            swapped_materializer.event_commitments[1][0] ^= 1;
            let failure = swapped_materializer.finish(&swapped_plan).unwrap_err();
            let SnapshotMaterializeFinishErrorV1::Materialize(failure) = failure else {
                panic!("event/plan mismatch must fail in the materializer")
            };
            assert_eq!(failure.stage(), SnapshotMaterializeStageV1::ValidatePlan);
            assert_eq!(
                failure.kind(),
                SnapshotMaterializeFailureKindV1::PlanMismatch
            );
            drop(swapped_plan);
            assert!(
                !swapped_staging_path.exists(),
                "plan-swap refusal must happen before publisher readiness and clean staging"
            );

            let staging_name = c".again-snapshot-stage-0123456789abcdef0123456789abcdef";
            let staging_path = publication_parent
                .path()
                .join(OsStr::from_bytes(staging_name.to_bytes()));
            let staged = create_staged_snapshot_directory_at(
                publication_parent_fd.as_fd(),
                staging_name,
                test_publish_policy(),
            )
            .unwrap();
            let mut materializer = SnapshotMaterializerV1::new(staged, test_policy()).unwrap();
            let fd_baseline = open_fd_count();
            let plan = enumerate_source_tree_view_at(
                source_view,
                c"tree",
                enumeration_policy(),
                &mut materializer,
            )
            .unwrap();
            assert_eq!(plan.entries().len(), 4);
            assert_eq!(plan.hardlink_groups().len(), 1);
            let ready = materializer.finish(&plan).unwrap();
            assert_eq!(open_fd_count(), fd_baseline);
            assert_eq!(
                entries.iter().map(|path| atime(path)).collect::<Vec<_>>(),
                qualified_atimes,
                "enumeration and materialization must not mutate source atime"
            );

            let staged_root = staging_path.join("tree");
            let staged_directory = staged_root.join("dir");
            let staged_file = staged_directory.join("file");
            let staged_twin = staged_directory.join("twin");
            assert_eq!(fs::read(&staged_file).unwrap(), b"exact logical bytes");
            assert_eq!(
                fs::symlink_metadata(&staged_root)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777,
                0o555
            );
            assert_eq!(
                fs::symlink_metadata(&staged_directory)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777,
                0o555
            );
            let file_metadata = fs::symlink_metadata(&staged_file).unwrap();
            let twin_metadata = fs::symlink_metadata(&staged_twin).unwrap();
            assert_eq!(file_metadata.permissions().mode() & 0o7777, 0o444);
            assert_eq!(file_metadata.ino(), twin_metadata.ino());
            assert_eq!(file_metadata.dev(), twin_metadata.dev());
            assert_eq!(file_metadata.nlink(), 2);
            assert_eq!(
                get_path_xattr(&staged_file, c"user.again").unwrap(),
                b"exact-xattr"
            );
            assert!(staging_path.exists());
            drop(plan);
            let forced_failure: io::Result<()> = {
                // The ready token intentionally exposes no mutable staging FD.
                // The only available failure-path action here is to drop it.
                drop(ready);
                Err(io::Error::from_raw_os_error(libc::EIO))
            };
            assert_eq!(forced_failure.unwrap_err().raw_os_error(), Some(libc::EIO));
            assert!(
                !staging_path.exists(),
                "publisher RAII must remove the full stage"
            );
        }
    }
}

#[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
mod platform {
    use super::*;

    pub(in crate::linux_pytest) struct SnapshotMaterializerV1<'parent> {
        staging: StagedSnapshotDirectoryV1<'parent>,
    }

    impl<'parent> SnapshotMaterializerV1<'parent> {
        pub(super) fn new(
            staging: StagedSnapshotDirectoryV1<'parent>,
            policy: SnapshotMaterializePolicyV1,
        ) -> Result<Self, SnapshotMaterializeFailureV1> {
            if !cleanup_envelope_covers(staging.cleanup_envelope(), policy) {
                return Err(cleanup_authority_failure());
            }
            Ok(Self { staging })
        }

        pub(super) fn finish(
            self,
            _plan: &SourceTreePlanV1,
        ) -> Result<VerifiedReadySnapshotDirectoryV1<'parent>, SnapshotMaterializeFinishErrorV1>
        {
            Err(SnapshotMaterializeFinishErrorV1::Materialize(unsupported()))
        }
    }

    impl SourceTreeVisitorV1 for SnapshotMaterializerV1<'_> {
        type Error = SnapshotMaterializeFailureV1;

        fn directory_enter(
            &mut self,
            _visit: SourceDirectoryVisitV1<'_>,
        ) -> Result<(), Self::Error> {
            Err(unsupported())
        }

        fn regular(
            &mut self,
            _visit: SourceRegularVisitV1<'_>,
        ) -> Result<SourceRegularEvidenceV1, Self::Error> {
            Err(unsupported())
        }

        fn symlink(&mut self, _visit: SourceSymlinkVisitV1<'_>) -> Result<(), Self::Error> {
            Err(unsupported())
        }

        fn directory_leave(
            &mut self,
            _visit: SourceDirectoryVisitV1<'_>,
        ) -> Result<(), Self::Error> {
            Err(unsupported())
        }
    }

    fn unsupported() -> SnapshotMaterializeFailureV1 {
        SnapshotMaterializeFailureV1::new(
            if cfg!(target_os = "linux") {
                RefusalCode::UnsupportedArchitecture
            } else {
                RefusalCode::UnsupportedOs
            },
            SnapshotMaterializeStageV1::ValidateEvent,
            SnapshotMaterializeFailureKindV1::RequiredKernelCapability,
            None,
            None,
            b"",
        )
    }

    #[cfg(test)]
    pub(super) fn unsupported_for_test() -> SnapshotMaterializeFailureV1 {
        unsupported()
    }
}

#[cfg(test)]
mod portable_tests {
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

    #[test]
    fn diagnostic_path_capture_is_exact_or_explicitly_omitted_without_panicking() {
        let (exact, exact_capture) = capture_diagnostic_path(b"raw/\xff");
        assert_eq!(exact, b"raw/\xff");
        assert_eq!(exact_capture, SnapshotMaterializePathCaptureV1::Exact);

        let (omitted, omitted_capture) =
            capture_diagnostic_path_with(b"secret/path", |_, _| Err(()));
        assert!(omitted.is_empty());
        assert_eq!(
            omitted_capture,
            SnapshotMaterializePathCaptureV1::OmittedAllocationFailure
        );
        let failure = SnapshotMaterializeFailureV1 {
            code: RefusalCode::SnapshotConstructionFailed,
            stage: SnapshotMaterializeStageV1::ValidatePlan,
            kind: SnapshotMaterializeFailureKindV1::PlanMismatch,
            regular_stage: None,
            errno: None,
            relative_path: omitted,
            relative_path_capture: omitted_capture,
        };
        assert!(failure.relative_path().is_empty());
        assert_eq!(failure.relative_path_capture(), omitted_capture);
        assert!(failure.to_string().contains("relative path omitted"));
        assert!(!failure.to_string().contains("secret/path"));
    }

    #[test]
    fn materialize_policy_accepts_exact_hard_boundaries() {
        let policy = SnapshotMaterializePolicyV1::checked(
            HARD_MAX_DEPTH,
            nz32(HARD_MAX_ENTRIES),
            nz64(HARD_MAX_TOTAL_XATTR_BYTES),
            nz8(HARD_MAX_OPENAT2_ATTEMPTS),
            nz8(HARD_MAX_OPENAT2_ATTEMPTS),
        )
        .unwrap();
        assert_eq!(
            policy.max_live_destination_fds(),
            u32::from(HARD_MAX_DEPTH) + 1
        );
    }

    #[test]
    fn materialize_policy_rejects_each_hard_boundary_plus_one() {
        let valid = || (1, nz32(1), nz64(1), nz8(1), nz8(1));
        let (_, entries, xattrs, open, syscall) = valid();
        assert!(
            SnapshotMaterializePolicyV1::checked(
                HARD_MAX_DEPTH + 1,
                entries,
                xattrs,
                open,
                syscall
            )
            .is_none()
        );
        let (depth, _, xattrs, open, syscall) = valid();
        assert!(
            SnapshotMaterializePolicyV1::checked(
                depth,
                nz32(HARD_MAX_ENTRIES + 1),
                xattrs,
                open,
                syscall
            )
            .is_none()
        );
        let (depth, entries, _, open, syscall) = valid();
        assert!(
            SnapshotMaterializePolicyV1::checked(
                depth,
                entries,
                nz64(HARD_MAX_TOTAL_XATTR_BYTES + 1),
                open,
                syscall
            )
            .is_none()
        );
        let (depth, entries, xattrs, _, syscall) = valid();
        assert!(
            SnapshotMaterializePolicyV1::checked(
                depth,
                entries,
                xattrs,
                nz8(HARD_MAX_OPENAT2_ATTEMPTS + 1),
                syscall
            )
            .is_none()
        );
        let (depth, entries, xattrs, open, _) = valid();
        assert!(
            SnapshotMaterializePolicyV1::checked(
                depth,
                entries,
                xattrs,
                open,
                nz8(HARD_MAX_OPENAT2_ATTEMPTS + 1),
            )
            .is_none()
        );
    }

    #[test]
    fn derived_total_xattr_and_operation_ceiling_is_exact() {
        let exact = SnapshotMaterializePolicyV1::checked_derived(
            HARD_MAX_DEPTH,
            nz16(HARD_MAX_BASENAME_BYTES),
            nz32(HARD_MAX_ENTRIES),
            nz64(HARD_MAX_TOTAL_XATTR_BYTES),
            nz64(HARD_MAX_TOTAL_XATTRS),
            nz64(HARD_MAX_PLAN_BYTES),
            nz8(HARD_MAX_OPENAT2_ATTEMPTS),
            nz8(HARD_MAX_OPENAT2_ATTEMPTS),
        )
        .unwrap();
        assert_eq!(exact.max_basename_bytes.get(), HARD_MAX_BASENAME_BYTES);
        assert_eq!(exact.max_xattr_operations.get(), HARD_MAX_XATTR_OPERATIONS);
        assert!(
            SnapshotMaterializePolicyV1::checked_derived(
                HARD_MAX_DEPTH,
                nz16(HARD_MAX_BASENAME_BYTES + 1),
                nz32(HARD_MAX_ENTRIES),
                nz64(HARD_MAX_TOTAL_XATTR_BYTES),
                nz64(HARD_MAX_TOTAL_XATTRS),
                nz64(HARD_MAX_PLAN_BYTES),
                nz8(HARD_MAX_OPENAT2_ATTEMPTS),
                nz8(HARD_MAX_OPENAT2_ATTEMPTS),
            )
            .is_none()
        );
        assert!(
            SnapshotMaterializePolicyV1::checked_derived(
                HARD_MAX_DEPTH,
                nz16(HARD_MAX_BASENAME_BYTES),
                nz32(HARD_MAX_ENTRIES),
                nz64(HARD_MAX_TOTAL_XATTR_BYTES),
                nz64(HARD_MAX_TOTAL_XATTRS + 1),
                nz64(HARD_MAX_PLAN_BYTES),
                nz8(HARD_MAX_OPENAT2_ATTEMPTS),
                nz8(HARD_MAX_OPENAT2_ATTEMPTS),
            )
            .is_none()
        );
    }

    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    #[test]
    fn unsupported_platform_is_typed_and_fail_closed() {
        let failure = platform::unsupported_for_test();
        assert_eq!(failure.stage(), SnapshotMaterializeStageV1::ValidateEvent);
        assert_eq!(
            failure.kind(),
            SnapshotMaterializeFailureKindV1::RequiredKernelCapability
        );
        assert!(matches!(
            failure.code(),
            RefusalCode::UnsupportedOs | RefusalCode::UnsupportedArchitecture
        ));
    }
}
