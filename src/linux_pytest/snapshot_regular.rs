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
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use super::snapshot_connector::{
    SnapshotDestinationObservationErrorV1, SnapshotDestinationObservationSessionV1,
};
use super::snapshot_connector::{
    SnapshotMaterializationSessionV1, SnapshotSourceObservationErrorV1,
    SnapshotSourceObservationSessionV1,
};
use super::snapshot_policy::SnapshotPipelineResourceErrorV1;
use super::{ExtentV1, FileContentDigest, RefusalCode, TimespecV1};

// These hard ceilings are defense-in-depth above the smaller values selected
// by a committed profile.  The byte ceiling matches the repository's existing
// per-file capture ceiling, the extent ceiling matches the descriptor walker's
// entry ceiling, and retry work matches that walker's bound.
const HARD_MAX_LOGICAL_BYTES: u64 = 1024 * 1024 * 1024;
const HARD_MAX_DATA_EXTENTS: u32 = 1024 * 1024;
const HARD_MAX_OPENAT2_ATTEMPTS: u8 = 32;
const HARD_MAX_SYSCALL_ATTEMPTS: u8 = 32;
// The leaf owns at most the source read descriptor and destination descriptor,
// plus one name-reopen descriptor during either (sequential) identity check.
// Caller-owned source/destination parent and pinned-source descriptors are not
// included and remain the connector's additive responsibility.
const MAX_LIVE_TRANSIENT_FDS: u32 = 3;

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
    /// Exact leaf-owned descriptor peak, excluding caller-owned capabilities.
    pub(super) const fn max_live_transient_fds() -> u32 {
        MAX_LIVE_TRANSIENT_FDS
    }

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

    /// Exact fixed reserve needed to remove the one active regular-copy
    /// destination after a fatal forward error: destination-name reopen,
    /// destination `fstat`, then `unlinkat`, each at its committed retry bound.
    pub(super) fn local_cleanup_attempt_bound(self) -> u64 {
        u64::from(self.openat2_attempts.get()) + 2 * u64::from(self.syscall_attempts.get())
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
    HashSource,
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

/// A charged regular-copy refusal. The connector's resource ledger and leaf
/// correctness failures remain structurally distinguishable.
#[derive(Debug, Eq, PartialEq)]
pub(super) enum SnapshotRegularMaterializationErrorV1 {
    Resource(SnapshotPipelineResourceErrorV1),
    Leaf(SnapshotRegularFailureV1),
}

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
#[cfg(test)]
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

/// Copy one pinned regular source child through the connector's non-forgeable
/// regular-copy session. The session supplies both the committed leaf policy
/// and the shared forward/local-cleanup ledgers; callers cannot splice either.
///
/// # Safety
///
/// `source_parent`, `source_name`, and `source_handle` must come from one
/// still-live qualified source-view callback. The destination parent must be
/// a current-user private staging directory in the already-qualified
/// destination view.
pub(super) unsafe fn copy_regular_from_qualified_pinned_charged_at(
    source_parent: BorrowedFd<'_>,
    source_name: &CStr,
    source_handle: BorrowedFd<'_>,
    destination_parent: BorrowedFd<'_>,
    destination_name: &CStr,
    session: &SnapshotMaterializationSessionV1<'_>,
) -> Result<CopiedRegularV1, SnapshotRegularMaterializationErrorV1> {
    platform::copy_regular_from_pinned_charged_at(
        source_parent,
        source_name,
        source_handle,
        destination_parent,
        destination_name,
        session,
    )
}

/// Observe one pinned regular source without creating a destination inode.
///
/// The connector-minted session binds the source policy, forward-attempt
/// ledger, and `SourceObservation` stage. There is deliberately no separate
/// policy or stage argument that a caller could splice into this operation.
/// The returned extent count is bounded by the committed leaf policy, but the
/// allocator-observed capacity is not yet attached to the shared transient-heap
/// ledger. This API therefore claims charged kernel attempts, not a charged
/// observation allocation boundary.
///
/// # Safety
///
/// `source_parent`, `source_name`, and `source_handle` must come from the same
/// still-live `QualifiedNoAtimeSourceViewV1` enumeration callback. That view
/// must guarantee that ordinary source reads cannot mutate host metadata for
/// this call's full duration.
pub(super) unsafe fn observe_regular_from_qualified_pinned_at(
    source_parent: BorrowedFd<'_>,
    source_name: &CStr,
    source_handle: BorrowedFd<'_>,
    session: &SnapshotSourceObservationSessionV1<'_>,
) -> Result<RegularCopyEvidenceV1, SnapshotSourceObservationErrorV1<SnapshotRegularFailureV1>> {
    platform::observe_regular_from_pinned_at(source_parent, source_name, source_handle, session)
}

/// Observe one pinned regular file in the owner-private staged destination.
///
/// The connector-minted session binds the committed regular policy, the
/// shared forward-attempt ledger, and the distinct `DestinationObservation`
/// stage. The descriptor is reopened with `O_NOATIME`; no copy, readiness,
/// publication, or reuse authority is returned.
///
/// # Safety
///
/// `destination_parent`, `destination_name`, and `destination_handle` must
/// come from the same still-live descriptor-stable traversal callback over the
/// connector-owned private staging tree.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) unsafe fn observe_destination_regular_from_private_pinned_at(
    destination_parent: BorrowedFd<'_>,
    destination_name: &CStr,
    destination_handle: BorrowedFd<'_>,
    session: &SnapshotDestinationObservationSessionV1<'_>,
) -> Result<RegularCopyEvidenceV1, SnapshotDestinationObservationErrorV1<SnapshotRegularFailureV1>>
{
    platform::observe_destination_regular_from_private_pinned_at(
        destination_parent,
        destination_name,
        destination_handle,
        session,
    )
}

fn valid_basename(name: &CStr) -> bool {
    let bytes = name.to_bytes();
    !bytes.is_empty() && bytes != b"." && bytes != b".." && !bytes.contains(&b'/')
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod platform {
    #[cfg(test)]
    use std::convert::Infallible;
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

    /// Private raw-attempt seam shared by charged paths and legacy unit tests.
    /// Production callers always supply an exact connector session;
    /// `DirectGateV1` does not exist outside test builds.
    trait KernelAttemptGateV1 {
        type ChargeError;

        fn run<T>(&self, attempt: impl FnOnce() -> T) -> Result<T, Self::ChargeError>;
    }

    /// A regular-copy authority has a second, non-fungible reserve for
    /// best-effort removal of its one active private destination. Traversal is
    /// sequential and aborts on its first fatal leaf, so two such cleanups can
    /// never overlap. Normal fallback removal remains forward work and never
    /// spends this reserve.
    trait MaterializationAttemptGateV1: KernelAttemptGateV1 {
        fn run_cleanup<T>(&self, attempt: impl FnOnce() -> T) -> Result<T, Self::ChargeError>;
    }

    #[derive(Debug)]
    enum MeteredIoV1<E> {
        Charge(E),
        Io(io::Error),
    }

    #[cfg(test)]
    struct DirectGateV1;

    #[cfg(test)]
    impl KernelAttemptGateV1 for DirectGateV1 {
        type ChargeError = Infallible;

        fn run<T>(&self, attempt: impl FnOnce() -> T) -> Result<T, Self::ChargeError> {
            Ok(attempt())
        }
    }

    #[cfg(test)]
    impl MaterializationAttemptGateV1 for DirectGateV1 {
        fn run_cleanup<T>(&self, attempt: impl FnOnce() -> T) -> Result<T, Self::ChargeError> {
            Ok(attempt())
        }
    }

    impl KernelAttemptGateV1 for SnapshotSourceObservationSessionV1<'_> {
        type ChargeError = SnapshotPipelineResourceErrorV1;

        fn run<T>(&self, attempt: impl FnOnce() -> T) -> Result<T, Self::ChargeError> {
            SnapshotSourceObservationSessionV1::run_attempt(self, attempt)
        }
    }

    impl KernelAttemptGateV1 for SnapshotDestinationObservationSessionV1<'_> {
        type ChargeError = SnapshotPipelineResourceErrorV1;

        fn run<T>(&self, attempt: impl FnOnce() -> T) -> Result<T, Self::ChargeError> {
            SnapshotDestinationObservationSessionV1::run_attempt(self, attempt)
        }
    }

    impl KernelAttemptGateV1 for SnapshotMaterializationSessionV1<'_> {
        type ChargeError = SnapshotPipelineResourceErrorV1;

        fn run<T>(&self, attempt: impl FnOnce() -> T) -> Result<T, Self::ChargeError> {
            SnapshotMaterializationSessionV1::run_regular_copy_attempt(self, attempt)
        }
    }

    impl MaterializationAttemptGateV1 for SnapshotMaterializationSessionV1<'_> {
        fn run_cleanup<T>(&self, attempt: impl FnOnce() -> T) -> Result<T, Self::ChargeError> {
            SnapshotMaterializationSessionV1::run_local_cleanup_attempt(self, attempt)
        }
    }

    fn run_io_attempt<G: KernelAttemptGateV1, T>(
        gate: &G,
        attempt: impl FnOnce() -> io::Result<T>,
    ) -> Result<T, MeteredIoV1<G::ChargeError>> {
        gate.run(attempt)
            .map_err(MeteredIoV1::Charge)?
            .map_err(MeteredIoV1::Io)
    }

    /// Run one bounded retry class while charging immediately before every raw
    /// operation.
    fn run_retryable_io_attempts<G: KernelAttemptGateV1, T>(
        gate: &G,
        attempts: u8,
        exhausted_errno: i32,
        retryable: impl Fn(&io::Error) -> bool,
        mut attempt: impl FnMut() -> io::Result<T>,
    ) -> Result<T, MeteredIoV1<G::ChargeError>> {
        let mut last = io::Error::from_raw_os_error(exhausted_errno);
        for _ in 0..attempts {
            match run_io_attempt(gate, &mut attempt) {
                Ok(value) => return Ok(value),
                Err(MeteredIoV1::Io(error)) if retryable(&error) => last = error,
                Err(error) => return Err(error),
            }
        }
        Err(MeteredIoV1::Io(last))
    }

    #[cfg(test)]
    fn into_direct_io<T>(result: Result<T, MeteredIoV1<Infallible>>) -> io::Result<T> {
        match result {
            Ok(value) => Ok(value),
            Err(MeteredIoV1::Io(error)) => Err(error),
            Err(MeteredIoV1::Charge(never)) => match never {},
        }
    }

    #[derive(Debug)]
    enum GatedRegularFailureV1<E> {
        Charge(E),
        Leaf(SnapshotRegularFailureV1),
    }

    fn map_gated_result<T, E>(
        result: Result<T, MeteredIoV1<E>>,
        map_io: impl FnOnce(io::Error) -> SnapshotRegularFailureV1,
    ) -> Result<T, GatedRegularFailureV1<E>> {
        result.map_err(|error| match error {
            MeteredIoV1::Charge(error) => GatedRegularFailureV1::Charge(error),
            MeteredIoV1::Io(error) => GatedRegularFailureV1::Leaf(map_io(error)),
        })
    }

    #[cfg(test)]
    fn into_direct_regular<T>(
        result: Result<T, GatedRegularFailureV1<Infallible>>,
    ) -> Result<T, SnapshotRegularFailureV1> {
        match result {
            Ok(value) => Ok(value),
            Err(GatedRegularFailureV1::Leaf(error)) => Err(error),
            Err(GatedRegularFailureV1::Charge(never)) => match never {},
        }
    }

    fn into_observation_regular<T>(
        result: Result<T, GatedRegularFailureV1<SnapshotPipelineResourceErrorV1>>,
    ) -> Result<T, SnapshotSourceObservationErrorV1<SnapshotRegularFailureV1>> {
        match result {
            Ok(value) => Ok(value),
            Err(GatedRegularFailureV1::Charge(error)) => {
                Err(SnapshotSourceObservationErrorV1::Resource(error))
            }
            Err(GatedRegularFailureV1::Leaf(error)) => {
                Err(SnapshotSourceObservationErrorV1::Leaf(error))
            }
        }
    }

    fn into_materialization_regular<T>(
        result: Result<T, GatedRegularFailureV1<SnapshotPipelineResourceErrorV1>>,
    ) -> Result<T, SnapshotRegularMaterializationErrorV1> {
        match result {
            Ok(value) => Ok(value),
            Err(GatedRegularFailureV1::Charge(error)) => {
                Err(SnapshotRegularMaterializationErrorV1::Resource(error))
            }
            Err(GatedRegularFailureV1::Leaf(error)) => {
                Err(SnapshotRegularMaterializationErrorV1::Leaf(error))
            }
        }
    }

    #[derive(Debug, Eq, PartialEq)]
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
        fn before_destination_arm(&self) -> io::Result<()> {
            Ok(())
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

    #[cfg(test)]
    pub(super) fn copy_regular_from_pinned_at(
        source_parent: BorrowedFd<'_>,
        source_name: &CStr,
        source_handle: BorrowedFd<'_>,
        destination_parent: BorrowedFd<'_>,
        destination_name: &CStr,
        policy: RegularCopyPolicyV1,
    ) -> Result<CopiedRegularV1, SnapshotRegularFailureV1> {
        into_direct_regular(copy_regular_from_pinned_at_with_gate(
            source_parent,
            source_name,
            source_handle,
            destination_parent,
            destination_name,
            policy,
            &KernelHooks,
            &DirectGateV1,
        ))
    }

    pub(super) fn copy_regular_from_pinned_charged_at(
        source_parent: BorrowedFd<'_>,
        source_name: &CStr,
        source_handle: BorrowedFd<'_>,
        destination_parent: BorrowedFd<'_>,
        destination_name: &CStr,
        session: &SnapshotMaterializationSessionV1<'_>,
    ) -> Result<CopiedRegularV1, SnapshotRegularMaterializationErrorV1> {
        into_materialization_regular(copy_regular_from_pinned_at_with_gate(
            source_parent,
            source_name,
            source_handle,
            destination_parent,
            destination_name,
            session.regular_copy_policy(),
            &KernelHooks,
            session,
        ))
    }

    pub(super) fn observe_regular_from_pinned_at(
        source_parent: BorrowedFd<'_>,
        source_name: &CStr,
        source_handle: BorrowedFd<'_>,
        session: &SnapshotSourceObservationSessionV1<'_>,
    ) -> Result<RegularCopyEvidenceV1, SnapshotSourceObservationErrorV1<SnapshotRegularFailureV1>>
    {
        let result = observe_regular_from_pinned_at_with_gate(
            source_parent,
            source_name,
            source_handle,
            session.regular_copy_policy(),
            source_read_open_flags(),
            session,
        );
        into_observation_regular(result)
    }

    pub(super) fn observe_destination_regular_from_private_pinned_at(
        destination_parent: BorrowedFd<'_>,
        destination_name: &CStr,
        destination_handle: BorrowedFd<'_>,
        session: &SnapshotDestinationObservationSessionV1<'_>,
    ) -> Result<
        RegularCopyEvidenceV1,
        SnapshotDestinationObservationErrorV1<SnapshotRegularFailureV1>,
    > {
        let result = observe_regular_from_pinned_at_with_gate(
            destination_parent,
            destination_name,
            destination_handle,
            session.regular_copy_policy(),
            destination_observation_open_flags(),
            session,
        );
        into_observation_regular(result)
    }

    fn observe_regular_from_pinned_at_with_gate<G: KernelAttemptGateV1>(
        source_parent: BorrowedFd<'_>,
        source_name: &CStr,
        source_handle: BorrowedFd<'_>,
        policy: RegularCopyPolicyV1,
        source_open_flags: i32,
        gate: &G,
    ) -> Result<RegularCopyEvidenceV1, GatedRegularFailureV1<G::ChargeError>> {
        if !valid_basename(source_name) {
            return Err(GatedRegularFailureV1::Leaf(SnapshotRegularFailureV1::new(
                RefusalCode::SnapshotRequiredObjectUnsupported,
                SnapshotRegularStageV1::ValidateSourceName,
                None,
            )));
        }

        let source_identity =
            map_gated_result(statx_identity_with_gate(source_handle, gate), |error| {
                map_statx_failure(SnapshotRegularStageV1::InspectSource, error)
            })?;
        if source_identity.mode & libc::S_IFMT != libc::S_IFREG {
            return Err(GatedRegularFailureV1::Leaf(SnapshotRegularFailureV1::new(
                RefusalCode::SnapshotRequiredObjectUnsupported,
                SnapshotRegularStageV1::InspectSource,
                None,
            )));
        }
        if source_identity.size > policy.max_logical_bytes() {
            return Err(GatedRegularFailureV1::Leaf(construction_failure(
                SnapshotRegularStageV1::InspectSource,
                None,
            )));
        }

        let source_read = map_gated_result(
            openat2_owned_with_gate(
                source_parent,
                source_name,
                source_open_flags,
                0,
                SOURCE_RESOLVE,
                policy.openat2_attempts(),
                gate,
            ),
            |error| map_source_read_open(SnapshotRegularStageV1::OpenSourceRead, error),
        )?;
        let read_identity = map_gated_result(
            statx_identity_with_gate(source_read.as_fd(), gate),
            |error| map_statx_failure(SnapshotRegularStageV1::OpenSourceRead, error),
        )?;
        if read_identity != source_identity {
            return Err(GatedRegularFailureV1::Leaf(construction_failure(
                SnapshotRegularStageV1::OpenSourceRead,
                None,
            )));
        }

        let initial_extents = map_gated_result(
            enumerate_extents_with_gate(
                source_read.as_fd(),
                source_identity.size,
                policy.max_data_extents(),
                policy.syscall_attempts(),
                gate,
            ),
            |error| map_extent_error(SnapshotRegularStageV1::EnumerateSourceExtents, error),
        )?;
        let content_digest = map_gated_result(
            hash_logical_bytes_with_gate(
                source_read.as_fd(),
                source_identity.size,
                policy.syscall_attempts(),
                gate,
            ),
            |error| construction_io(SnapshotRegularStageV1::HashSource, error),
        )?;
        let source_extents_after = map_gated_result(
            enumerate_extents_with_gate(
                source_read.as_fd(),
                source_identity.size,
                policy.max_data_extents(),
                policy.syscall_attempts(),
                gate,
            ),
            |error| map_extent_error(SnapshotRegularStageV1::RevalidateSource, error),
        )?;
        if source_extents_after != initial_extents {
            return Err(GatedRegularFailureV1::Leaf(construction_failure(
                SnapshotRegularStageV1::RevalidateSource,
                None,
            )));
        }
        revalidate_source_with_gate(
            source_parent,
            source_name,
            source_handle,
            source_read.as_fd(),
            &source_identity,
            policy.openat2_attempts(),
            gate,
        )?;

        Ok(RegularCopyEvidenceV1 {
            content_digest,
            data_extents: initial_extents,
        })
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the private leaf must bind both descriptor-selected names/handles, policy, hooks, and one gate without an argument bag that adds no semantic authority"
    )]
    fn copy_regular_from_pinned_at_with_gate<H: CopyHooks, G: MaterializationAttemptGateV1>(
        source_parent: BorrowedFd<'_>,
        source_name: &CStr,
        source_handle: BorrowedFd<'_>,
        destination_parent: BorrowedFd<'_>,
        destination_name: &CStr,
        policy: RegularCopyPolicyV1,
        hooks: &H,
        gate: &G,
    ) -> Result<CopiedRegularV1, GatedRegularFailureV1<G::ChargeError>> {
        if !valid_basename(source_name) {
            return Err(GatedRegularFailureV1::Leaf(SnapshotRegularFailureV1::new(
                RefusalCode::SnapshotRequiredObjectUnsupported,
                SnapshotRegularStageV1::ValidateSourceName,
                None,
            )));
        }
        if !valid_basename(destination_name) {
            return Err(GatedRegularFailureV1::Leaf(SnapshotRegularFailureV1::new(
                RefusalCode::SnapshotConstructionFailed,
                SnapshotRegularStageV1::ValidateDestinationName,
                None,
            )));
        }

        let source_identity =
            map_gated_result(statx_identity_with_gate(source_handle, gate), |error| {
                map_statx_failure(SnapshotRegularStageV1::InspectSource, error)
            })?;
        if source_identity.mode & libc::S_IFMT != libc::S_IFREG {
            return Err(GatedRegularFailureV1::Leaf(SnapshotRegularFailureV1::new(
                RefusalCode::SnapshotRequiredObjectUnsupported,
                SnapshotRegularStageV1::InspectSource,
                None,
            )));
        }
        if source_identity.size > policy.max_logical_bytes() {
            return Err(GatedRegularFailureV1::Leaf(SnapshotRegularFailureV1::new(
                RefusalCode::SnapshotConstructionFailed,
                SnapshotRegularStageV1::InspectSource,
                None,
            )));
        }

        #[cfg(test)]
        hooks.after_source_handle_opened().map_err(|error| {
            GatedRegularFailureV1::Leaf(construction_io(
                SnapshotRegularStageV1::OpenSourceRead,
                error,
            ))
        })?;

        #[cfg(not(test))]
        let source_open_flags = source_read_open_flags();
        #[cfg(test)]
        let source_open_flags = hooks.test_source_read_open_flags();
        let source_read = map_gated_result(
            openat2_owned_with_gate(
                source_parent,
                source_name,
                source_open_flags,
                0,
                SOURCE_RESOLVE,
                policy.openat2_attempts(),
                gate,
            ),
            |error| map_source_read_open(SnapshotRegularStageV1::OpenSourceRead, error),
        )?;
        let read_identity = map_gated_result(
            statx_identity_with_gate(source_read.as_fd(), gate),
            |error| map_statx_failure(SnapshotRegularStageV1::OpenSourceRead, error),
        )?;
        if read_identity != source_identity {
            return Err(GatedRegularFailureV1::Leaf(construction_failure(
                SnapshotRegularStageV1::OpenSourceRead,
                None,
            )));
        }

        let mut cleanup = DestinationCleanup::new(
            destination_parent,
            destination_name,
            policy.openat2_attempts(),
            policy.syscall_attempts(),
            gate,
        );
        let mut destination =
            map_gated_result(create_destination_with_gate(&mut cleanup, hooks), |error| {
                map_destination_error(SnapshotRegularStageV1::CreateDestination, error)
            })?;

        let initial_extents = map_gated_result(
            enumerate_extents_with_gate(
                source_read.as_fd(),
                source_identity.size,
                policy.max_data_extents(),
                policy.syscall_attempts(),
                gate,
            ),
            |error| map_extent_error(SnapshotRegularStageV1::EnumerateSourceExtents, error),
        )?;

        match run_io_attempt(gate, || {
            hooks.clone_file(destination.as_raw_fd(), source_read.as_raw_fd())
        }) {
            Ok(()) => {}
            Err(MeteredIoV1::Io(error)) if clone_fallback_error(&error) => {
                drop(destination);
                map_gated_result(cleanup.remove_current_forward(), |error| {
                    map_destination_error(SnapshotRegularStageV1::RecreateForFallback, error)
                })?;
                destination =
                    map_gated_result(create_destination_with_gate(&mut cleanup, hooks), |error| {
                        map_destination_error(SnapshotRegularStageV1::RecreateForFallback, error)
                    })?;
                map_gated_result(
                    truncate_to_with_gate(
                        destination.as_fd(),
                        source_identity.size,
                        policy.syscall_attempts(),
                        gate,
                    ),
                    |error| map_destination_error(SnapshotRegularStageV1::SparseCopy, error),
                )?;
                map_gated_result(
                    copy_data_extents_with_gate(
                        source_read.as_fd(),
                        destination.as_fd(),
                        &initial_extents,
                        policy.syscall_attempts(),
                        gate,
                    ),
                    |error| map_destination_error(SnapshotRegularStageV1::SparseCopy, error),
                )?;
            }
            Err(MeteredIoV1::Io(error)) => {
                return Err(GatedRegularFailureV1::Leaf(map_destination_error(
                    SnapshotRegularStageV1::Reflink,
                    error,
                )));
            }
            Err(MeteredIoV1::Charge(error)) => {
                return Err(GatedRegularFailureV1::Charge(error));
            }
        }

        #[cfg(test)]
        hooks.after_materialized().map_err(|error| {
            GatedRegularFailureV1::Leaf(map_destination_error(
                SnapshotRegularStageV1::RevalidateSource,
                error,
            ))
        })?;

        let source_extents_after = map_gated_result(
            enumerate_extents_with_gate(
                source_read.as_fd(),
                source_identity.size,
                policy.max_data_extents(),
                policy.syscall_attempts(),
                gate,
            ),
            |error| map_extent_error(SnapshotRegularStageV1::RevalidateSource, error),
        )?;
        #[cfg(test)]
        let source_extents_after = {
            let mut observed = source_extents_after;
            hooks
                .after_extent_observed(ExtentObservationPoint::SourceRecheck, &mut observed)
                .map_err(|error| {
                    GatedRegularFailureV1::Leaf(map_extent_error(
                        SnapshotRegularStageV1::RevalidateSource,
                        error,
                    ))
                })?;
            observed
        };
        if source_extents_after != initial_extents {
            return Err(GatedRegularFailureV1::Leaf(construction_failure(
                SnapshotRegularStageV1::RevalidateSource,
                None,
            )));
        }

        let destination_identity = map_gated_result(
            statx_identity_with_gate(destination.as_fd(), gate),
            |error| map_statx_failure(SnapshotRegularStageV1::RevalidateDestination, error),
        )?;
        if destination_identity.mode & libc::S_IFMT != libc::S_IFREG
            || destination_identity.size != source_identity.size
            || destination_identity.nlink != 1
        {
            return Err(GatedRegularFailureV1::Leaf(construction_failure(
                SnapshotRegularStageV1::RevalidateDestination,
                None,
            )));
        }
        let destination_extents = map_gated_result(
            enumerate_extents_with_gate(
                destination.as_fd(),
                destination_identity.size,
                policy.max_data_extents(),
                policy.syscall_attempts(),
                gate,
            ),
            |error| map_extent_error(SnapshotRegularStageV1::EnumerateDestinationExtents, error),
        )?;
        #[cfg(test)]
        let destination_extents = {
            let mut observed = destination_extents;
            hooks
                .after_extent_observed(ExtentObservationPoint::Destination, &mut observed)
                .map_err(|error| {
                    GatedRegularFailureV1::Leaf(map_extent_error(
                        SnapshotRegularStageV1::EnumerateDestinationExtents,
                        error,
                    ))
                })?;
            observed
        };
        if destination_extents != initial_extents {
            return Err(GatedRegularFailureV1::Leaf(construction_failure(
                SnapshotRegularStageV1::EnumerateDestinationExtents,
                None,
            )));
        }

        let content_digest = map_gated_result(
            hash_logical_bytes_with_gate(
                destination.as_fd(),
                destination_identity.size,
                policy.syscall_attempts(),
                gate,
            ),
            |error| map_destination_error(SnapshotRegularStageV1::HashDestination, error),
        )?;

        revalidate_source_with_gate(
            source_parent,
            source_name,
            source_handle,
            source_read.as_fd(),
            &source_identity,
            policy.openat2_attempts(),
            gate,
        )?;
        #[cfg(test)]
        hooks.before_destination_reopen().map_err(|error| {
            GatedRegularFailureV1::Leaf(construction_io(
                SnapshotRegularStageV1::RevalidateDestination,
                error,
            ))
        })?;
        revalidate_destination_with_gate(
            destination_parent,
            destination_name,
            destination.as_fd(),
            &destination_identity,
            policy.openat2_attempts(),
            gate,
        )?;

        cleanup.disarm();
        Ok(CopiedRegularV1 {
            destination,
            content_digest,
            data_extents: initial_extents,
        })
    }

    const fn source_read_open_flags() -> i32 {
        // `O_NONBLOCK` is ignored for regular files, but prevents a pathname
        // replacement with a FIFO from blocking before identity comparison.
        libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC
    }

    const fn destination_observation_open_flags() -> i32 {
        source_read_open_flags() | libc::O_NOATIME
    }

    const fn destination_open_flags() -> i32 {
        libc::O_RDWR
            | libc::O_CREAT
            | libc::O_EXCL
            | libc::O_NOFOLLOW
            | libc::O_NOATIME
            | libc::O_CLOEXEC
    }

    fn revalidate_source_with_gate<G: KernelAttemptGateV1>(
        parent: BorrowedFd<'_>,
        name: &CStr,
        path_handle: BorrowedFd<'_>,
        read_handle: BorrowedFd<'_>,
        expected: &StableStatxV1,
        attempts: u8,
        gate: &G,
    ) -> Result<(), GatedRegularFailureV1<G::ChargeError>> {
        let path_after = map_gated_result(statx_identity_with_gate(path_handle, gate), |error| {
            map_statx_failure(SnapshotRegularStageV1::RevalidateSource, error)
        })?;
        let read_after = map_gated_result(statx_identity_with_gate(read_handle, gate), |error| {
            map_statx_failure(SnapshotRegularStageV1::RevalidateSource, error)
        })?;
        let reopened = map_gated_result(
            openat2_owned_with_gate(
                parent,
                name,
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0,
                SOURCE_RESOLVE,
                attempts,
                gate,
            ),
            |error| construction_io(SnapshotRegularStageV1::RevalidateSource, error),
        )?;
        let reopened_identity =
            map_gated_result(statx_identity_with_gate(reopened.as_fd(), gate), |error| {
                map_statx_failure(SnapshotRegularStageV1::RevalidateSource, error)
            })?;
        if &path_after != expected || &read_after != expected || &reopened_identity != expected {
            return Err(GatedRegularFailureV1::Leaf(construction_failure(
                SnapshotRegularStageV1::RevalidateSource,
                None,
            )));
        }
        Ok(())
    }

    fn revalidate_destination_with_gate<G: KernelAttemptGateV1>(
        parent: BorrowedFd<'_>,
        name: &CStr,
        destination: BorrowedFd<'_>,
        expected: &StableStatxV1,
        attempts: u8,
        gate: &G,
    ) -> Result<(), GatedRegularFailureV1<G::ChargeError>> {
        let fd_after = map_gated_result(statx_identity_with_gate(destination, gate), |error| {
            map_statx_failure(SnapshotRegularStageV1::RevalidateDestination, error)
        })?;
        let reopened = map_gated_result(
            openat2_owned_with_gate(
                parent,
                name,
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0,
                SOURCE_RESOLVE,
                attempts,
                gate,
            ),
            |error| construction_io(SnapshotRegularStageV1::RevalidateDestination, error),
        )?;
        let reopened_identity =
            map_gated_result(statx_identity_with_gate(reopened.as_fd(), gate), |error| {
                map_statx_failure(SnapshotRegularStageV1::RevalidateDestination, error)
            })?;
        if fd_after != *expected || reopened_identity != *expected {
            return Err(GatedRegularFailureV1::Leaf(construction_failure(
                SnapshotRegularStageV1::RevalidateDestination,
                None,
            )));
        }
        Ok(())
    }

    struct CleanupGateV1<'gate, G: MaterializationAttemptGateV1>(&'gate G);

    impl<G: MaterializationAttemptGateV1> KernelAttemptGateV1 for CleanupGateV1<'_, G> {
        type ChargeError = G::ChargeError;

        fn run<T>(&self, attempt: impl FnOnce() -> T) -> Result<T, Self::ChargeError> {
            self.0.run_cleanup(attempt)
        }
    }

    struct DestinationCleanup<'destination, 'gate, G: MaterializationAttemptGateV1> {
        parent: BorrowedFd<'destination>,
        name: &'destination CStr,
        openat2_attempts: u8,
        syscall_attempts: u8,
        state: CleanupState,
        gate: &'gate G,
    }

    impl<'destination, 'gate, G: MaterializationAttemptGateV1>
        DestinationCleanup<'destination, 'gate, G>
    {
        fn new(
            parent: BorrowedFd<'destination>,
            name: &'destination CStr,
            openat2_attempts: u8,
            syscall_attempts: u8,
            gate: &'gate G,
        ) -> Self {
            Self {
                parent,
                name,
                openat2_attempts,
                syscall_attempts,
                state: CleanupState::Absent,
                gate,
            }
        }

        fn mark_created(&mut self) {
            self.state = CleanupState::CreatedUnverified;
        }

        fn arm(&mut self, identity: CleanupIdentity) {
            self.state = CleanupState::Verified(identity);
        }

        fn disarm(&mut self) {
            self.state = CleanupState::Absent;
        }

        fn remove_current_with_gate<A: KernelAttemptGateV1<ChargeError = G::ChargeError>>(
            &mut self,
            gate: &A,
        ) -> Result<(), MeteredIoV1<G::ChargeError>> {
            remove_destination_with_gate(
                self.parent,
                self.name,
                self.openat2_attempts,
                self.syscall_attempts,
                self.state,
                gate,
            )?;
            self.disarm();
            Ok(())
        }

        fn remove_current_forward(&mut self) -> Result<(), MeteredIoV1<G::ChargeError>> {
            let gate = self.gate;
            self.remove_current_with_gate(gate)
        }

        fn remove_current_cleanup(&mut self) -> Result<(), MeteredIoV1<G::ChargeError>> {
            let gate = CleanupGateV1(self.gate);
            self.remove_current_with_gate(&gate)
        }
    }

    fn remove_destination_with_gate<G: KernelAttemptGateV1>(
        parent: BorrowedFd<'_>,
        name: &CStr,
        openat2_attempts: u8,
        syscall_attempts: u8,
        state: CleanupState,
        gate: &G,
    ) -> Result<(), MeteredIoV1<G::ChargeError>> {
        match state {
            CleanupState::Absent => return Ok(()),
            CleanupState::CreatedUnverified => {}
            CleanupState::Verified(expected) => {
                let current = openat2_owned_with_gate(
                    parent,
                    name,
                    libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    0,
                    SOURCE_RESOLVE,
                    openat2_attempts,
                    gate,
                )?;
                if fstat_cleanup_identity_with_gate(current.as_fd(), syscall_attempts, gate)?
                    != expected
                {
                    return Err(MeteredIoV1::Io(io::Error::from_raw_os_error(libc::ESTALE)));
                }
            }
        }
        unlinkat_with_gate(parent, name, syscall_attempts, gate)
    }

    impl<G: MaterializationAttemptGateV1> Drop for DestinationCleanup<'_, '_, G> {
        fn drop(&mut self) {
            // The destination parent is required to be owner-private and the
            // same-UID hostile-peer threat is outside the profile.  Once the
            // first fstat succeeds, compare the reopened inode before
            // unlinking so ordinary path replacement never deletes the
            // replacement.  Before that fstat, the O_EXCL-created name is
            // still removed rather than leaked.
            let _ = self.remove_current_cleanup();
        }
    }

    fn create_destination_with_gate<H: CopyHooks, G: MaterializationAttemptGateV1>(
        cleanup: &mut DestinationCleanup<'_, '_, G>,
        hooks: &H,
    ) -> Result<OwnedFd, MeteredIoV1<G::ChargeError>> {
        let destination = openat2_owned_with_gate(
            cleanup.parent,
            cleanup.name,
            destination_open_flags(),
            0o600,
            SOURCE_RESOLVE,
            cleanup.openat2_attempts,
            cleanup.gate,
        )?;
        cleanup.mark_created();
        #[cfg(test)]
        hooks.before_destination_arm().map_err(MeteredIoV1::Io)?;
        #[cfg(not(test))]
        let _ = hooks;
        let cleanup_identity = fstat_cleanup_identity_with_gate(
            destination.as_fd(),
            cleanup.syscall_attempts,
            cleanup.gate,
        )?;
        cleanup.arm(cleanup_identity);
        let identity = statx_identity_with_gate(destination.as_fd(), cleanup.gate)?;
        if identity.mode & libc::S_IFMT != libc::S_IFREG
            || identity.size != 0
            || identity.nlink != 1
        {
            return Err(MeteredIoV1::Io(io::Error::from_raw_os_error(libc::EIO)));
        }
        Ok(destination)
    }

    #[cfg(test)]
    fn openat2_owned(
        parent: BorrowedFd<'_>,
        name: &CStr,
        flags: i32,
        mode: u32,
        resolve: u64,
        attempts: u8,
    ) -> io::Result<OwnedFd> {
        into_direct_io(openat2_owned_with_gate(
            parent,
            name,
            flags,
            mode,
            resolve,
            attempts,
            &DirectGateV1,
        ))
    }

    fn openat2_owned_with_gate<G: KernelAttemptGateV1>(
        parent: BorrowedFd<'_>,
        name: &CStr,
        flags: i32,
        mode: u32,
        resolve: u64,
        attempts: u8,
        gate: &G,
    ) -> Result<OwnedFd, MeteredIoV1<G::ChargeError>> {
        let how = OpenHow {
            flags: flags as u64,
            mode: mode as u64,
            resolve,
        };
        run_retryable_io_attempts(
            gate,
            attempts,
            libc::EAGAIN,
            |error| error.raw_os_error() == Some(libc::EAGAIN),
            || {
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
            },
        )
    }

    fn statx_identity_with_gate<G: KernelAttemptGateV1>(
        fd: BorrowedFd<'_>,
        gate: &G,
    ) -> Result<StableStatxV1, MeteredIoV1<G::ChargeError>> {
        let raw = run_io_attempt(gate, || {
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
            Ok(unsafe { raw.assume_init() })
        })?;
        if raw.stx_mask & REQUIRED_STATX_MASK != REQUIRED_STATX_MASK {
            return Err(MeteredIoV1::Io(io::Error::from_raw_os_error(
                libc::EOPNOTSUPP,
            )));
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

    fn fstat_cleanup_identity_with_gate<G: KernelAttemptGateV1>(
        fd: BorrowedFd<'_>,
        syscall_attempts: u8,
        gate: &G,
    ) -> Result<CleanupIdentity, MeteredIoV1<G::ChargeError>> {
        run_retryable_io_attempts(
            gate,
            syscall_attempts,
            libc::EINTR,
            |error| error.kind() == io::ErrorKind::Interrupted,
            || {
                let mut raw = MaybeUninit::<libc::stat>::zeroed();
                if unsafe { libc::fstat(fd.as_raw_fd(), raw.as_mut_ptr()) } != 0 {
                    return Err(io::Error::last_os_error());
                }
                let raw = unsafe { raw.assume_init() };
                Ok(CleanupIdentity {
                    device: raw.st_dev,
                    inode: raw.st_ino,
                })
            },
        )
    }

    fn unlinkat_with_gate<G: KernelAttemptGateV1>(
        parent: BorrowedFd<'_>,
        name: &CStr,
        syscall_attempts: u8,
        gate: &G,
    ) -> Result<(), MeteredIoV1<G::ChargeError>> {
        run_retryable_io_attempts(
            gate,
            syscall_attempts,
            libc::EINTR,
            |error| error.kind() == io::ErrorKind::Interrupted,
            || {
                let result = unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), 0) };
                if result == 0 {
                    Ok(())
                } else {
                    Err(io::Error::last_os_error())
                }
            },
        )
    }

    #[cfg(test)]
    fn enumerate_extents_direct_with_attempts(
        fd: BorrowedFd<'_>,
        size: u64,
        max_extents: u32,
        syscall_attempts: u8,
    ) -> io::Result<Vec<ExtentV1>> {
        into_direct_io(enumerate_extents_with_gate(
            fd,
            size,
            max_extents,
            syscall_attempts,
            &DirectGateV1,
        ))
    }

    fn enumerate_extents_with_gate<G: KernelAttemptGateV1>(
        fd: BorrowedFd<'_>,
        size: u64,
        max_extents: u32,
        syscall_attempts: u8,
        gate: &G,
    ) -> Result<Vec<ExtentV1>, MeteredIoV1<G::ChargeError>> {
        if size == 0 {
            return Ok(Vec::new());
        }
        let mut extents = Vec::new();
        let mut cursor = 0u64;
        while cursor < size {
            let data = match lseek_with_gate(fd, cursor, libc::SEEK_DATA, syscall_attempts, gate) {
                Err(MeteredIoV1::Io(error)) if error.raw_os_error() == Some(libc::ENXIO) => {
                    break;
                }
                result => result?,
            };
            if data < cursor || data >= size {
                return Err(MeteredIoV1::Io(io::Error::from_raw_os_error(libc::EIO)));
            }
            let hole = lseek_with_gate(fd, data, libc::SEEK_HOLE, syscall_attempts, gate)?;
            if hole <= data || hole > size {
                return Err(MeteredIoV1::Io(io::Error::from_raw_os_error(libc::EIO)));
            }
            try_reserve_bounded_for_push(&mut extents, max_extents as usize).map_err(|error| {
                MeteredIoV1::Io(io::Error::from_raw_os_error(match error {
                    BoundedReserveError::Full => libc::EFBIG,
                    BoundedReserveError::Allocation => libc::ENOMEM,
                }))
            })?;
            extents.push(ExtentV1 {
                offset: data,
                length: hole - data,
            });
            cursor = hole;
        }
        Ok(extents)
    }

    fn lseek_with_gate<G: KernelAttemptGateV1>(
        fd: BorrowedFd<'_>,
        offset: u64,
        whence: i32,
        syscall_attempts: u8,
        gate: &G,
    ) -> Result<u64, MeteredIoV1<G::ChargeError>> {
        let offset = libc::off_t::try_from(offset)
            .map_err(|_| MeteredIoV1::Io(io::Error::from_raw_os_error(libc::EOVERFLOW)))?;
        let mut last = io::Error::from_raw_os_error(libc::EINTR);
        for _ in 0..syscall_attempts {
            match run_io_attempt(gate, || {
                let result = unsafe { libc::lseek(fd.as_raw_fd(), offset, whence) };
                if result < 0 {
                    Err(io::Error::last_os_error())
                } else {
                    u64::try_from(result).map_err(|_| io::Error::from_raw_os_error(libc::EOVERFLOW))
                }
            }) {
                Ok(result) => return Ok(result),
                Err(MeteredIoV1::Io(error)) if error.kind() == io::ErrorKind::Interrupted => {
                    last = error;
                }
                Err(error) => return Err(error),
            }
        }
        Err(MeteredIoV1::Io(last))
    }

    fn truncate_to_with_gate<G: KernelAttemptGateV1>(
        destination: BorrowedFd<'_>,
        size: u64,
        syscall_attempts: u8,
        gate: &G,
    ) -> Result<(), MeteredIoV1<G::ChargeError>> {
        let size = libc::off_t::try_from(size)
            .map_err(|_| MeteredIoV1::Io(io::Error::from_raw_os_error(libc::EOVERFLOW)))?;
        let mut last = io::Error::from_raw_os_error(libc::EINTR);
        for _ in 0..syscall_attempts {
            match run_io_attempt(gate, || {
                if unsafe { libc::ftruncate(destination.as_raw_fd(), size) } == 0 {
                    Ok(())
                } else {
                    Err(io::Error::last_os_error())
                }
            }) {
                Ok(()) => return Ok(()),
                Err(MeteredIoV1::Io(error)) if error.kind() == io::ErrorKind::Interrupted => {
                    last = error;
                }
                Err(error) => return Err(error),
            }
        }
        Err(MeteredIoV1::Io(last))
    }

    fn copy_data_extents_with_gate<G: KernelAttemptGateV1>(
        source: BorrowedFd<'_>,
        destination: BorrowedFd<'_>,
        extents: &[ExtentV1],
        syscall_attempts: u8,
        gate: &G,
    ) -> Result<(), MeteredIoV1<G::ChargeError>> {
        let mut buffer = [0u8; COPY_BUFFER_BYTES];
        for extent in extents {
            let end = extent
                .offset
                .checked_add(extent.length)
                .ok_or_else(|| MeteredIoV1::Io(io::Error::from_raw_os_error(libc::EOVERFLOW)))?;
            let mut offset = extent.offset;
            while offset < end {
                let length = usize::try_from((end - offset).min(buffer.len() as u64))
                    .map_err(|_| MeteredIoV1::Io(io::Error::from_raw_os_error(libc::EOVERFLOW)))?;
                pread_exact_raw_with_gate(
                    source,
                    &mut buffer[..length],
                    offset,
                    syscall_attempts,
                    gate,
                )?;
                pwrite_all_raw_with_gate(
                    destination,
                    &buffer[..length],
                    offset,
                    syscall_attempts,
                    gate,
                )?;
                offset += length as u64;
            }
        }
        Ok(())
    }

    fn pread_exact_raw_with_gate<G: KernelAttemptGateV1>(
        fd: BorrowedFd<'_>,
        output: &mut [u8],
        offset: u64,
        syscall_attempts: u8,
        gate: &G,
    ) -> Result<(), MeteredIoV1<G::ChargeError>> {
        pread_exact_operation_with_gate(output, offset, syscall_attempts, gate, |output, offset| {
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

    #[cfg(test)]
    fn pread_exact_with(
        output: &mut [u8],
        offset: u64,
        syscall_attempts: u8,
        operation: impl FnMut(&mut [u8], u64) -> io::Result<usize>,
    ) -> io::Result<()> {
        into_direct_io(pread_exact_operation_with_gate(
            output,
            offset,
            syscall_attempts,
            &DirectGateV1,
            operation,
        ))
    }

    fn pread_exact_operation_with_gate<G: KernelAttemptGateV1>(
        mut output: &mut [u8],
        mut offset: u64,
        syscall_attempts: u8,
        gate: &G,
        mut operation: impl FnMut(&mut [u8], u64) -> io::Result<usize>,
    ) -> Result<(), MeteredIoV1<G::ChargeError>> {
        if output.is_empty() {
            return Ok(());
        }
        let mut exhaustion_errno = libc::EINTR;
        for _ in 0..syscall_attempts {
            let read = match run_io_attempt(gate, || operation(output, offset)) {
                Ok(0) => return Err(MeteredIoV1::Io(io::Error::from_raw_os_error(libc::EIO))),
                Ok(read) if read <= output.len() => read,
                Ok(_) => return Err(MeteredIoV1::Io(io::Error::from_raw_os_error(libc::EIO))),
                Err(MeteredIoV1::Io(error)) if error.kind() == io::ErrorKind::Interrupted => {
                    exhaustion_errno = libc::EINTR;
                    continue;
                }
                Err(error) => return Err(error),
            };
            exhaustion_errno = libc::EIO;
            offset = offset
                .checked_add(read as u64)
                .ok_or_else(|| MeteredIoV1::Io(io::Error::from_raw_os_error(libc::EOVERFLOW)))?;
            output = &mut output[read..];
            if output.is_empty() {
                return Ok(());
            }
        }
        Err(MeteredIoV1::Io(io::Error::from_raw_os_error(
            exhaustion_errno,
        )))
    }

    fn pwrite_all_raw_with_gate<G: KernelAttemptGateV1>(
        fd: BorrowedFd<'_>,
        input: &[u8],
        offset: u64,
        syscall_attempts: u8,
        gate: &G,
    ) -> Result<(), MeteredIoV1<G::ChargeError>> {
        pwrite_all_operation_with_gate(input, offset, syscall_attempts, gate, |input, offset| {
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

    #[cfg(test)]
    fn pwrite_all_with(
        input: &[u8],
        offset: u64,
        syscall_attempts: u8,
        operation: impl FnMut(&[u8], u64) -> io::Result<usize>,
    ) -> io::Result<()> {
        into_direct_io(pwrite_all_operation_with_gate(
            input,
            offset,
            syscall_attempts,
            &DirectGateV1,
            operation,
        ))
    }

    fn pwrite_all_operation_with_gate<G: KernelAttemptGateV1>(
        mut input: &[u8],
        mut offset: u64,
        syscall_attempts: u8,
        gate: &G,
        mut operation: impl FnMut(&[u8], u64) -> io::Result<usize>,
    ) -> Result<(), MeteredIoV1<G::ChargeError>> {
        if input.is_empty() {
            return Ok(());
        }
        let mut exhaustion_errno = libc::EINTR;
        for _ in 0..syscall_attempts {
            let written = match run_io_attempt(gate, || operation(input, offset)) {
                Ok(0) => {
                    return Err(MeteredIoV1::Io(io::Error::from_raw_os_error(libc::EIO)));
                }
                Ok(written) if written <= input.len() => written,
                Ok(_) => {
                    return Err(MeteredIoV1::Io(io::Error::from_raw_os_error(libc::EIO)));
                }
                Err(MeteredIoV1::Io(error)) if error.kind() == io::ErrorKind::Interrupted => {
                    exhaustion_errno = libc::EINTR;
                    continue;
                }
                Err(error) => return Err(error),
            };
            exhaustion_errno = libc::EIO;
            offset = offset
                .checked_add(written as u64)
                .ok_or_else(|| MeteredIoV1::Io(io::Error::from_raw_os_error(libc::EOVERFLOW)))?;
            input = &input[written..];
            if input.is_empty() {
                return Ok(());
            }
        }
        Err(MeteredIoV1::Io(io::Error::from_raw_os_error(
            exhaustion_errno,
        )))
    }

    fn hash_logical_bytes_with_gate<G: KernelAttemptGateV1>(
        fd: BorrowedFd<'_>,
        size: u64,
        syscall_attempts: u8,
        gate: &G,
    ) -> Result<FileContentDigest, MeteredIoV1<G::ChargeError>> {
        let mut hasher = FileContentHasherV1::new(size);

        let mut buffer = [0u8; COPY_BUFFER_BYTES];
        let mut offset = 0u64;
        while offset < size {
            let length = usize::try_from((size - offset).min(buffer.len() as u64))
                .map_err(|_| MeteredIoV1::Io(io::Error::from_raw_os_error(libc::EOVERFLOW)))?;
            pread_exact_raw_with_gate(fd, &mut buffer[..length], offset, syscall_attempts, gate)?;
            if !hasher.update(&buffer[..length]) {
                return Err(MeteredIoV1::Io(io::Error::from_raw_os_error(
                    libc::EOVERFLOW,
                )));
            }
            offset += length as u64;
        }
        hasher
            .finish()
            .ok_or_else(|| MeteredIoV1::Io(io::Error::from_raw_os_error(libc::EIO)))
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
        use std::os::unix::fs::{FileTypeExt, OpenOptionsExt, PermissionsExt};
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
                into_direct_regular(self.copy_with_gate(
                    source_name,
                    destination_name,
                    policy,
                    hooks,
                    &DirectGateV1,
                ))
            }

            fn copy_with_gate<H: CopyHooks, G: MaterializationAttemptGateV1>(
                &self,
                source_name: &CStr,
                destination_name: &CStr,
                policy: RegularCopyPolicyV1,
                hooks: &H,
                gate: &G,
            ) -> Result<CopiedRegularV1, GatedRegularFailureV1<G::ChargeError>> {
                if !valid_basename(source_name) {
                    return Err(GatedRegularFailureV1::Leaf(SnapshotRegularFailureV1::new(
                        RefusalCode::SnapshotRequiredObjectUnsupported,
                        SnapshotRegularStageV1::ValidateSourceName,
                        None,
                    )));
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
                    GatedRegularFailureV1::Leaf(map_source_read_open(
                        SnapshotRegularStageV1::OpenSourceRead,
                        error,
                    ))
                })?;
                copy_regular_from_pinned_at_with_gate(
                    self.source_parent.as_fd(),
                    source_name,
                    source_handle.as_fd(),
                    self.destination_parent.as_fd(),
                    destination_name,
                    policy,
                    hooks,
                    gate,
                )
            }

            fn copy_input<H: CopyHooks>(
                &self,
                policy: RegularCopyPolicyV1,
                hooks: &H,
            ) -> Result<CopiedRegularV1, SnapshotRegularFailureV1> {
                self.copy(c"input", c"output", policy, hooks)
            }

            fn copy_input_with_gate<H: CopyHooks, G: MaterializationAttemptGateV1>(
                &self,
                policy: RegularCopyPolicyV1,
                hooks: &H,
                gate: &G,
            ) -> Result<CopiedRegularV1, GatedRegularFailureV1<G::ChargeError>> {
                self.copy_with_gate(c"input", c"output", policy, hooks, gate)
            }

            fn observe_input<G: KernelAttemptGateV1>(
                &self,
                policy: RegularCopyPolicyV1,
                gate: &G,
            ) -> Result<RegularCopyEvidenceV1, GatedRegularFailureV1<G::ChargeError>> {
                let source_handle = openat2_owned(
                    self.source_parent.as_fd(),
                    c"input",
                    libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                    0,
                    SOURCE_RESOLVE,
                    policy.openat2_attempts(),
                )
                .unwrap();
                observe_regular_from_pinned_at_with_gate(
                    self.source_parent.as_fd(),
                    c"input",
                    source_handle.as_fd(),
                    policy,
                    destination_observation_open_flags(),
                    gate,
                )
            }
        }

        #[derive(Debug)]
        struct GateExhausted;

        enum TestReplacement {
            Regular,
            Fifo,
            InPlace(Vec<u8>),
        }

        struct TestGate {
            remaining: Cell<u64>,
            raw_calls: Cell<u64>,
            cleanup_remaining: Cell<u64>,
            cleanup_raw_calls: Cell<u64>,
            mutation: Option<(u64, PathBuf, TestReplacement)>,
        }

        impl TestGate {
            fn bounded(attempts: u64) -> Self {
                Self {
                    remaining: Cell::new(attempts),
                    raw_calls: Cell::new(0),
                    cleanup_remaining: Cell::new(u64::MAX),
                    cleanup_raw_calls: Cell::new(0),
                    mutation: None,
                }
            }

            fn bounded_with_cleanup(forward_attempts: u64, cleanup_attempts: u64) -> Self {
                Self {
                    remaining: Cell::new(forward_attempts),
                    raw_calls: Cell::new(0),
                    cleanup_remaining: Cell::new(cleanup_attempts),
                    cleanup_raw_calls: Cell::new(0),
                    mutation: None,
                }
            }

            fn mutating(attempts: u64, mutate_at: u64, path: PathBuf) -> Self {
                Self {
                    remaining: Cell::new(attempts),
                    raw_calls: Cell::new(0),
                    cleanup_remaining: Cell::new(u64::MAX),
                    cleanup_raw_calls: Cell::new(0),
                    mutation: Some((mutate_at, path, TestReplacement::Regular)),
                }
            }

            fn mutating_to_fifo(attempts: u64, mutate_at: u64, path: PathBuf) -> Self {
                Self {
                    remaining: Cell::new(attempts),
                    raw_calls: Cell::new(0),
                    cleanup_remaining: Cell::new(u64::MAX),
                    cleanup_raw_calls: Cell::new(0),
                    mutation: Some((mutate_at, path, TestReplacement::Fifo)),
                }
            }

            fn mutating_in_place(
                attempts: u64,
                mutate_at: u64,
                path: PathBuf,
                bytes: Vec<u8>,
            ) -> Self {
                Self {
                    remaining: Cell::new(attempts),
                    raw_calls: Cell::new(0),
                    cleanup_remaining: Cell::new(u64::MAX),
                    cleanup_raw_calls: Cell::new(0),
                    mutation: Some((mutate_at, path, TestReplacement::InPlace(bytes))),
                }
            }
        }

        impl KernelAttemptGateV1 for TestGate {
            type ChargeError = GateExhausted;

            fn run<T>(&self, attempt: impl FnOnce() -> T) -> Result<T, Self::ChargeError> {
                let Some(remaining) = self.remaining.get().checked_sub(1) else {
                    return Err(GateExhausted);
                };
                self.remaining.set(remaining);
                let call = self.raw_calls.get() + 1;
                if let Some((mutate_at, path, replacement)) = &self.mutation {
                    if call == *mutate_at {
                        match replacement {
                            TestReplacement::Regular => {
                                fs::remove_file(path).unwrap();
                                fs::write(path, b"replacement-observer-bytes").unwrap();
                            }
                            TestReplacement::Fifo => {
                                fs::remove_file(path).unwrap();
                                let path = c_name(path.as_os_str());
                                let result = unsafe { libc::mkfifo(path.as_ptr(), 0o600) };
                                assert_eq!(
                                    result,
                                    0,
                                    "mkfifo failed: {}",
                                    io::Error::last_os_error()
                                );
                            }
                            TestReplacement::InPlace(bytes) => {
                                fs::write(path, bytes).unwrap();
                                let mut permissions = fs::metadata(path).unwrap().permissions();
                                permissions.set_mode(0o400);
                                fs::set_permissions(path, permissions).unwrap();
                            }
                        }
                    }
                }
                self.raw_calls.set(call);
                Ok(attempt())
            }
        }

        impl MaterializationAttemptGateV1 for TestGate {
            fn run_cleanup<T>(&self, attempt: impl FnOnce() -> T) -> Result<T, Self::ChargeError> {
                let Some(remaining) = self.cleanup_remaining.get().checked_sub(1) else {
                    return Err(GateExhausted);
                };
                self.cleanup_remaining.set(remaining);
                self.cleanup_raw_calls.set(self.cleanup_raw_calls.get() + 1);
                Ok(attempt())
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

            fn before_destination_arm(&self) -> io::Result<()> {
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
        fn gate_accepts_exact_partial_preads_and_refuses_before_n_plus_one() {
            let exact = TestGate::bounded(2);
            let mut exact_output = [0u8; 2];
            let exact_result =
                pread_exact_operation_with_gate(&mut exact_output, 0, 2, &exact, |remaining, _| {
                    remaining[0] = b'x';
                    Ok(1)
                });
            assert!(exact_result.is_ok());
            assert_eq!(exact_output, *b"xx");
            assert_eq!(exact.raw_calls.get(), 2);
            assert_eq!(exact.remaining.get(), 0);

            let short = TestGate::bounded(1);
            let mut short_output = [0u8; 2];
            let short_result =
                pread_exact_operation_with_gate(&mut short_output, 0, 2, &short, |remaining, _| {
                    remaining[0] = b'y';
                    Ok(1)
                });
            assert!(matches!(
                short_result,
                Err(MeteredIoV1::Charge(GateExhausted))
            ));
            assert_eq!(short_output, [b'y', 0]);
            assert_eq!(short.raw_calls.get(), 1);
        }

        #[test]
        fn destination_observer_core_returns_exact_evidence_charges_and_revalidates_identity() {
            let bytes = (0..(COPY_BUFFER_BYTES + 37))
                .map(|index| (index % 251) as u8)
                .collect::<Vec<_>>();
            let fixture = Fixture::with_input(&bytes);

            let zero = TestGate::bounded(0);
            assert!(matches!(
                fixture.observe_input(policy(), &zero),
                Err(GatedRegularFailureV1::Charge(GateExhausted))
            ));
            assert_eq!(zero.raw_calls.get(), 0);

            let discovery = TestGate::bounded(u64::MAX);
            let evidence = fixture.observe_input(policy(), &discovery).unwrap();
            let required = discovery.raw_calls.get();
            assert!(
                required > 4,
                "observer must include final source revalidation"
            );
            assert_eq!(
                evidence.content_digest(),
                FileContentDigest::derive(super::super::super::FILE_CONTENT_DOMAIN, &[&bytes])
            );

            let exact = TestGate::bounded(required);
            let exact_evidence = fixture.observe_input(policy(), &exact).unwrap();
            assert_eq!(exact_evidence.content_digest(), evidence.content_digest());
            assert_eq!(exact_evidence.data_extents(), evidence.data_extents());
            assert_eq!(exact.raw_calls.get(), required);

            let short = TestGate::bounded(required - 1);
            assert!(matches!(
                fixture.observe_input(policy(), &short),
                Err(GatedRegularFailureV1::Charge(GateExhausted))
            ));
            assert_eq!(short.raw_calls.get(), required - 1);

            let mutate_at = required - 3;
            let swapping = TestGate::mutating(required, mutate_at, fixture.source("input"));
            let failure = match fixture.observe_input(policy(), &swapping) {
                Ok(_) => panic!("source replacement must fail observation"),
                Err(failure) => failure,
            };
            match failure {
                GatedRegularFailureV1::Leaf(failure) => {
                    assert_eq!(failure.stage(), SnapshotRegularStageV1::RevalidateSource);
                    assert_eq!(failure.code(), RefusalCode::SnapshotConstructionFailed);
                }
                GatedRegularFailureV1::Charge(_) => {
                    panic!("the exact gate must reach semantic revalidation")
                }
            }
            assert_eq!(
                fs::read(fixture.source("input")).unwrap(),
                b"replacement-observer-bytes"
            );

            let in_place_fixture = Fixture::with_input(&bytes);
            let replacement = vec![b'Z'; bytes.len()];
            let in_place = TestGate::mutating_in_place(
                required,
                required - 3,
                in_place_fixture.source("input"),
                replacement,
            );
            let failure = match in_place_fixture.observe_input(policy(), &in_place) {
                Ok(_) => panic!("same-inode post-hash mutation must fail observation"),
                Err(failure) => failure,
            };
            let GatedRegularFailureV1::Leaf(failure) = failure else {
                panic!("the exact gate must reach semantic revalidation")
            };
            assert_eq!(failure.stage(), SnapshotRegularStageV1::RevalidateSource);
            assert_eq!(failure.code(), RefusalCode::SnapshotConstructionFailed);
        }

        #[test]
        fn charged_copy_accepts_exact_forward_n_and_n_minus_one_cleans() {
            let bytes = (0..(COPY_BUFFER_BYTES + 37))
                .map(|index| (index % 251) as u8)
                .collect::<Vec<_>>();

            let discovery_fixture = Fixture::with_input(&bytes);
            let discovery_hooks = ForcedCloneError {
                errno: libc::EOPNOTSUPP,
                calls: Cell::new(0),
            };
            let discovery = TestGate::bounded_with_cleanup(u64::MAX, u64::MAX);
            let evidence = finish(
                discovery_fixture
                    .copy_input_with_gate(policy(), &discovery_hooks, &discovery)
                    .unwrap(),
            );
            let required = discovery.raw_calls.get();
            assert!(
                required > 10,
                "the whole copy and revalidation must be gated"
            );
            assert_eq!(discovery.cleanup_raw_calls.get(), 0);
            assert_eq!(
                evidence.content_digest(),
                FileContentDigest::derive(super::super::super::FILE_CONTENT_DOMAIN, &[&bytes])
            );

            let exact_fixture = Fixture::with_input(&bytes);
            let exact_hooks = ForcedCloneError {
                errno: libc::EOPNOTSUPP,
                calls: Cell::new(0),
            };
            let exact = TestGate::bounded_with_cleanup(required, u64::MAX);
            let exact_evidence = finish(
                exact_fixture
                    .copy_input_with_gate(policy(), &exact_hooks, &exact)
                    .unwrap(),
            );
            assert_eq!(exact.raw_calls.get(), required);
            assert_eq!(exact.remaining.get(), 0);
            assert_eq!(exact.cleanup_raw_calls.get(), 0);
            assert_eq!(exact_evidence.content_digest(), evidence.content_digest());
            assert_eq!(exact_evidence.data_extents(), evidence.data_extents());

            let short_fixture = Fixture::with_input(&bytes);
            let short_hooks = ForcedCloneError {
                errno: libc::EOPNOTSUPP,
                calls: Cell::new(0),
            };
            let short = TestGate::bounded_with_cleanup(required - 1, u64::MAX);
            assert!(matches!(
                short_fixture.copy_input_with_gate(policy(), &short_hooks, &short),
                Err(GatedRegularFailureV1::Charge(GateExhausted))
            ));
            assert_eq!(short.raw_calls.get(), required - 1);
            assert_eq!(short.cleanup_raw_calls.get(), 3);
            assert!(!short_fixture.destination("output").exists());
        }

        #[test]
        fn fatal_copy_uses_exact_local_cleanup_and_short_gate_never_unlinks() {
            let exact_fixture = Fixture::with_input(b"cleanup-on-fatal-clone");
            let exact_hooks = ForcedCloneError {
                errno: libc::EIO,
                calls: Cell::new(0),
            };
            let exact = TestGate::bounded_with_cleanup(u64::MAX, 3);
            assert!(matches!(
                exact_fixture.copy_input_with_gate(policy(), &exact_hooks, &exact),
                Err(GatedRegularFailureV1::Leaf(_))
            ));
            assert_eq!(exact.cleanup_raw_calls.get(), 3);
            assert_eq!(exact.cleanup_remaining.get(), 0);
            assert!(!exact_fixture.destination("output").exists());

            let short_fixture = Fixture::with_input(b"cleanup-gate-is-linear");
            let short_hooks = ForcedCloneError {
                errno: libc::EIO,
                calls: Cell::new(0),
            };
            let short = TestGate::bounded_with_cleanup(u64::MAX, 2);
            assert!(matches!(
                short_fixture.copy_input_with_gate(policy(), &short_hooks, &short),
                Err(GatedRegularFailureV1::Leaf(_))
            ));
            assert_eq!(short.cleanup_raw_calls.get(), 2);
            assert_eq!(short.cleanup_remaining.get(), 0);
            assert!(
                short_fixture.destination("output").exists(),
                "the N+1 unlink must not run after cleanup authority is exhausted"
            );
            fs::remove_file(short_fixture.destination("output")).unwrap();
        }

        #[test]
        fn every_forward_budget_cutpoint_in_reflink_fallback_refuses_before_next_gated_closure() {
            let bytes = b"deterministic-fallback-prefix-matrix";
            let policy = policy();
            let discovery_fixture = Fixture::with_input(bytes);
            let discovery_hooks = ForcedCloneError {
                errno: libc::EOPNOTSUPP,
                calls: Cell::new(0),
            };
            let discovery = TestGate::bounded_with_cleanup(u64::MAX, u64::MAX);
            finish(
                discovery_fixture
                    .copy_input_with_gate(policy, &discovery_hooks, &discovery)
                    .unwrap(),
            );
            let required = discovery.raw_calls.get();
            assert_eq!(discovery_hooks.calls.get(), 1);
            assert!(required > 10, "the matrix must span the fallback path");

            for budget in 0..required {
                let fixture = Fixture::with_input(bytes);
                let hooks = ForcedCloneError {
                    errno: libc::EOPNOTSUPP,
                    calls: Cell::new(0),
                };
                let gate =
                    TestGate::bounded_with_cleanup(budget, policy.local_cleanup_attempt_bound());
                assert!(matches!(
                    fixture.copy_input_with_gate(policy, &hooks, &gate),
                    Err(GatedRegularFailureV1::Charge(GateExhausted))
                ));
                assert_eq!(
                    gate.raw_calls.get(),
                    budget,
                    "budget {budget} invoked the N+1 gated closure"
                );
                assert_eq!(gate.remaining.get(), 0);
                assert!(
                    !fixture.destination("output").exists(),
                    "budget {budget} left a partial fallback destination"
                );
            }
        }

        #[test]
        fn destination_observer_regular_to_fifo_swap_refuses_without_blocking() {
            let fixture = Fixture::with_input(b"ordinary-regular-file");
            // Attempt 1 inspects the pinned regular handle. Replace its name
            // immediately before attempt 2 opens the readable descriptor.
            let gate = TestGate::mutating_to_fifo(3, 2, fixture.source("input"));

            let failure = match fixture.observe_input(policy(), &gate) {
                Err(failure) => failure,
                Ok(_) => panic!("FIFO replacement must fail observation"),
            };
            let GatedRegularFailureV1::Leaf(failure) = failure else {
                panic!("three attempts must reach the post-open identity check")
            };
            assert_eq!(failure.stage(), SnapshotRegularStageV1::OpenSourceRead);
            assert_eq!(failure.code(), RefusalCode::SnapshotConstructionFailed);
            assert_eq!(gate.raw_calls.get(), 3);
            assert_eq!(gate.remaining.get(), 0);
            assert!(
                fs::metadata(fixture.source("input"))
                    .unwrap()
                    .file_type()
                    .is_fifo()
            );
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
        fn gate_accepts_exact_partial_pwrites_and_refuses_before_n_plus_one() {
            let exact = TestGate::bounded(2);
            let mut exact_calls = 0usize;
            pwrite_all_operation_with_gate(b"xy", 7, 2, &exact, |remaining, offset| {
                exact_calls += 1;
                assert_eq!(offset, 6 + u64::try_from(exact_calls).unwrap());
                assert_eq!(remaining.len(), 3 - exact_calls);
                Ok(1)
            })
            .unwrap();
            assert_eq!(exact_calls, 2);
            assert_eq!(exact.raw_calls.get(), 2);
            assert_eq!(exact.remaining.get(), 0);

            let short = TestGate::bounded(1);
            let mut short_calls = 0;
            assert!(matches!(
                pwrite_all_operation_with_gate(b"xy", 7, 2, &short, |_, _| {
                    short_calls += 1;
                    Ok(1)
                }),
                Err(MeteredIoV1::Charge(GateExhausted))
            ));
            assert_eq!(short_calls, 1);
            assert_eq!(short.raw_calls.get(), 1);
        }

        #[test]
        fn source_authority_uses_ordinary_reads_while_destination_paths_keep_noatime() {
            assert_eq!(source_read_open_flags() & libc::O_NOATIME, 0);
            assert_ne!(source_read_open_flags() & libc::O_NONBLOCK, 0);
            assert_ne!(destination_observation_open_flags() & libc::O_NOATIME, 0);
            assert_ne!(destination_observation_open_flags() & libc::O_NONBLOCK, 0);
            assert_ne!(destination_observation_open_flags() & libc::O_NOFOLLOW, 0);
            assert_eq!(
                destination_observation_open_flags()
                    & (libc::O_WRONLY | libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC),
                0
            );
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
        fn destination_observer_preserves_stale_atime_and_returns_exact_evidence() {
            use std::os::unix::fs::MetadataExt;
            use std::time::{Duration, UNIX_EPOCH};

            let bytes = b"destination observation exact bytes";
            let fixture = Fixture::with_input(bytes);
            let destination_path = fixture.source("input");
            let stale_atime = UNIX_EPOCH + Duration::from_secs(946_684_800);
            OpenOptions::new()
                .read(true)
                .open(&destination_path)
                .unwrap()
                .set_times(std::fs::FileTimes::new().set_accessed(stale_atime))
                .unwrap();
            let before = fs::metadata(&destination_path).unwrap();
            let before_atime = (before.atime(), before.atime_nsec());
            assert!(before.atime() <= before.mtime());

            let gate = TestGate::bounded(u64::MAX);
            let evidence = fixture.observe_input(policy(), &gate).unwrap();

            assert_eq!(
                evidence.content_digest(),
                FileContentDigest::derive(super::super::super::FILE_CONTENT_DOMAIN, &[bytes])
            );
            assert!(!evidence.data_extents().is_empty());
            let after = fs::metadata(destination_path).unwrap();
            assert_eq!((after.atime(), after.atime_nsec()), before_atime);
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
        fn failure_between_o_excl_create_and_arm_spends_one_cleanup_attempt() {
            let fixture = Fixture::with_input(b"content");
            let gate = TestGate::bounded_with_cleanup(u64::MAX, 1);
            let error = fixture
                .copy_input_with_gate(policy(), &FailDestinationArm { errno: libc::EIO }, &gate)
                .unwrap_err();
            let GatedRegularFailureV1::Leaf(error) = error else {
                panic!("the forward ledger is intentionally unbounded")
            };
            assert_eq!(error.code(), RefusalCode::SnapshotConstructionFailed);
            assert_eq!(error.stage(), SnapshotRegularStageV1::CreateDestination);
            assert_eq!(error.errno(), Some(libc::EIO));
            assert_eq!(gate.cleanup_raw_calls.get(), 1);
            assert_eq!(gate.cleanup_remaining.get(), 0);
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
            let observed =
                enumerate_extents_direct_with_attempts(destination.as_fd(), 512 * 1024, 4096, 1)
                    .unwrap();
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
            let observed =
                enumerate_extents_direct_with_attempts(source.as_fd(), 16 * 1024 * 1024, 4096, 1)
                    .unwrap();
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

    pub(super) fn observe_regular_from_pinned_at(
        _source_parent: BorrowedFd<'_>,
        _source_name: &CStr,
        _source_handle: BorrowedFd<'_>,
        _session: &SnapshotSourceObservationSessionV1<'_>,
    ) -> Result<RegularCopyEvidenceV1, SnapshotSourceObservationErrorV1<SnapshotRegularFailureV1>>
    {
        #[cfg(not(target_os = "linux"))]
        let code = RefusalCode::UnsupportedOs;
        #[cfg(all(target_os = "linux", not(target_arch = "x86_64")))]
        let code = RefusalCode::UnsupportedArchitecture;
        Err(SnapshotSourceObservationErrorV1::Leaf(
            SnapshotRegularFailureV1::new(code, SnapshotRegularStageV1::OpenSourceRead, None),
        ))
    }

    pub(super) fn copy_regular_from_pinned_charged_at(
        _source_parent: BorrowedFd<'_>,
        _source_name: &CStr,
        _source_handle: BorrowedFd<'_>,
        _destination_parent: BorrowedFd<'_>,
        _destination_name: &CStr,
        _session: &SnapshotMaterializationSessionV1<'_>,
    ) -> Result<CopiedRegularV1, SnapshotRegularMaterializationErrorV1> {
        #[cfg(not(target_os = "linux"))]
        let code = RefusalCode::UnsupportedOs;
        #[cfg(all(target_os = "linux", not(target_arch = "x86_64")))]
        let code = RefusalCode::UnsupportedArchitecture;
        Err(SnapshotRegularMaterializationErrorV1::Leaf(
            SnapshotRegularFailureV1::new(code, SnapshotRegularStageV1::OpenSourceRead, None),
        ))
    }

    #[cfg(test)]
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
        assert_eq!(policy.local_cleanup_attempt_bound(), 10);
    }

    #[test]
    fn leaf_owned_transient_fd_peak_is_exact() {
        assert_eq!(RegularCopyPolicyV1::max_live_transient_fds(), 3);
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
