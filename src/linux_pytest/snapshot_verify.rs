//! Bounded semantic comparison for the four snapshot observations.
//!
//! Connector orchestration must retain at most two policy-bounded plans at
//! once and drives this typestate in order: S1/S2, S1/D1, then D1/D2. After
//! S1/D1, an exact raw witness retains only the destination-only physical
//! fields needed to compare D2, so the full D1 plan can be released while S1
//! remains available for logical manifest projection. The witness is charged
//! to transient heap and is neither a hash nor a retained stability view.
//! Successful comparison grants no manifest or publication authority and is
//! not a substitute for canonical verification.

use super::snapshot_connector::SnapshotDestinationWitnessBytesV1;
use super::snapshot_materialize::projected_materialized_permissions;
use super::snapshot_policy::{
    SnapshotPipelineForwardStageV1, SnapshotPipelineResourceErrorV1, SnapshotPipelineStageV1,
};
use super::snapshot_tree::{
    CapturedXattrV1, SourceNodeKindV1, SourcePlanPayloadV1, SourceStatxV1, SourceTreeEntryV1,
    SourceTreePlanV1,
};

const DESTINATION_WITNESS_ENTRY_BYTES_V1: usize = 57;
const DESTINATION_WITNESS_HARDLINK_BYTES_V1: usize = 24;

const DESTINATION_STABILITY_INODE_RANGE_V1: std::ops::Range<usize> = 0..24;
const DESTINATION_STABILITY_DIRECTORY_SIZE_RANGE_V1: std::ops::Range<usize> = 24..32;
const DESTINATION_STABILITY_CTIME_RANGE_V1: std::ops::Range<usize> = 32..44;
const DESTINATION_STABILITY_BTIME_RANGE_V1: std::ops::Range<usize> = 44..57;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct DestinationPhysicalIdentityV1 {
    uid: u32,
    gid: u32,
}

impl DestinationPhysicalIdentityV1 {
    pub(super) const fn new(uid: u32, gid: u32) -> Self {
        Self { uid, gid }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SnapshotViewPairV1 {
    S1S2,
    S1D1,
    D1D2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SnapshotMismatchFieldV1 {
    RootName,
    EntryCount,
    HardlinkGroupCount,
    UnsettableXattrState,
    RelativePath,
    Basename,
    ParentIndex,
    NodeKind,
    InodeIdentity,
    Mode,
    Ownership,
    LinkCount,
    Size,
    Atime,
    Mtime,
    Ctime,
    Btime,
    XattrCount,
    XattrName,
    XattrValue,
    DirectoryChildren,
    RegularContentDigest,
    RegularExtents,
    SymlinkTarget,
    HardlinkInodeIdentity,
    HardlinkMembers,
    DestinationPhysicalMode,
    DestinationPhysicalOwner,
    VisibleXattrUnrepresentable,
    SymlinkMaterializationUnsupported,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SnapshotVerifyLocationV1 {
    Header,
    Entry(u32),
    HardlinkGroup(u32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SnapshotVerifyErrorV1 {
    pub(super) pair: SnapshotViewPairV1,
    pub(super) field: SnapshotMismatchFieldV1,
    pub(super) location: SnapshotVerifyLocationV1,
}

/// S1 is retained until an independently produced S2 has compared equal.
pub(super) struct AwaitingSourceViewS2V1<'source> {
    source_s1: &'source SourceTreePlanV1,
}

pub(super) const fn begin_four_view_comparison(
    source_s1: &SourceTreePlanV1,
) -> AwaitingSourceViewS2V1<'_> {
    AwaitingSourceViewS2V1 { source_s1 }
}

impl<'source> AwaitingSourceViewS2V1<'source> {
    /// The returned state no longer borrows S2, allowing its retained-plan
    /// lease to be dropped before D1 is acquired.
    pub(super) fn compare_source_s2(
        self,
        source_s2: &SourceTreePlanV1,
    ) -> Result<SourceViewsStableV1<'source>, SnapshotVerifyErrorV1> {
        compare_same_plan(self.source_s1, source_s2, SnapshotViewPairV1::S1S2)?;
        Ok(SourceViewsStableV1 {
            source_s1: self.source_s1,
        })
    }
}

/// S1/S2 equality is proven; S1 remains borrowed through both destination
/// comparisons so it can later be projected into logical manifest metadata.
pub(super) struct SourceViewsStableV1<'source> {
    source_s1: &'source SourceTreePlanV1,
}

impl<'source> SourceViewsStableV1<'source> {
    /// Equality under the source-to-destination materialization projection is
    /// proven here. The returned short-lived state still borrows D1 so its
    /// exact destination-only fields can be copied into a charged raw witness.
    pub(super) fn compare_destination_d1<'destination>(
        self,
        destination_d1: &'destination SourceTreePlanV1,
        physical_identity: DestinationPhysicalIdentityV1,
    ) -> Result<DestinationViewD1MatchedV1<'source, 'destination>, SnapshotVerifyErrorV1> {
        compare_source_destination(self.source_s1, destination_d1, physical_identity)?;
        Ok(DestinationViewD1MatchedV1 {
            source_s1: self.source_s1,
            destination_d1,
            exact_physical_identity: physical_identity,
        })
    }
}

/// A short-lived state proving S1/D1 projection equality while borrowing the
/// exact D1 plan. It intentionally cannot be cloned or used for publication.
pub(super) struct DestinationViewD1MatchedV1<'source, 'destination> {
    source_s1: &'source SourceTreePlanV1,
    destination_d1: &'destination SourceTreePlanV1,
    exact_physical_identity: DestinationPhysicalIdentityV1,
}

impl<'source, 'destination> DestinationViewD1MatchedV1<'source, 'destination> {
    /// Captures the exact D1-only equality fields into one charged raw buffer.
    /// Consuming this state ends its D1 borrow; the returned state owns no
    /// retained-view lease and keeps only its transient charge plus S1. The
    /// allocator is intentionally narrow: connector orchestration must lend a
    /// destination-observation-session allocator rather than exposing or
    /// substituting the pipeline's raw resource authority here.
    pub(super) fn capture_stability_witness<'resources>(
        self,
        allocate_destination_observation_bytes: impl FnOnce(
            usize,
        ) -> Result<
            SnapshotDestinationWitnessBytesV1<'resources>,
            SnapshotPipelineResourceErrorV1,
        >,
    ) -> Result<AwaitingDestinationViewD2V1<'source, 'resources>, SnapshotPipelineResourceErrorV1>
    {
        let witness = DestinationStabilityWitnessV1::capture(
            self.destination_d1,
            allocate_destination_observation_bytes,
        )?;
        Ok(AwaitingDestinationViewD2V1 {
            source_s1: self.source_s1,
            witness,
            exact_physical_identity: self.exact_physical_identity,
        })
    }
}

/// S1 plus a compact exact D1 witness are retained until an independently
/// produced D2 has compared equal. This state owns no D1 borrow.
pub(super) struct AwaitingDestinationViewD2V1<'source, 'resources> {
    source_s1: &'source SourceTreePlanV1,
    witness: DestinationStabilityWitnessV1<'resources>,
    exact_physical_identity: DestinationPhysicalIdentityV1,
}

impl AwaitingDestinationViewD2V1<'_, '_> {
    /// Success completes comparison only; it grants no publication authority.
    pub(super) fn compare_destination_d2(
        self,
        destination_d2: &SourceTreePlanV1,
    ) -> Result<(), SnapshotVerifyErrorV1> {
        compare_destination_from_witness(
            self.source_s1,
            &self.witness,
            destination_d2,
            self.exact_physical_identity,
        )
    }
}

/// Exact, fixed-width D1 fields omitted by the source-to-destination logical
/// projection. The charged byte container is deliberately opaque and neither
/// this type nor its owning typestate implements `Clone`.
struct DestinationStabilityWitnessV1<'resources> {
    bytes: SnapshotDestinationWitnessBytesV1<'resources>,
    entry_count: u32,
    hardlink_group_count: u32,
}

impl<'resources> DestinationStabilityWitnessV1<'resources> {
    fn capture(
        destination_d1: &SourceTreePlanV1,
        allocate_destination_observation_bytes: impl FnOnce(
            usize,
        ) -> Result<
            SnapshotDestinationWitnessBytesV1<'resources>,
            SnapshotPipelineResourceErrorV1,
        >,
    ) -> Result<Self, SnapshotPipelineResourceErrorV1> {
        let entry_count_usize = destination_d1.entries().len();
        let hardlink_group_count_usize = destination_d1.hardlink_groups().len();
        let capacity =
            checked_destination_witness_capacity(entry_count_usize, hardlink_group_count_usize)?;
        let mut bytes = allocate_destination_observation_bytes(capacity)?;
        let entry_count = u32::try_from(entry_count_usize)
            .expect("successful witness capacity validation bounds entries to u32");
        let hardlink_group_count = u32::try_from(hardlink_group_count_usize)
            .expect("successful witness capacity validation bounds hardlink groups to u32");
        for entry in destination_d1.entries() {
            bytes.try_extend_from_slice(&entry.destination_stability_bytes_v1())?;
        }
        for group in destination_d1.hardlink_groups() {
            bytes.try_extend_from_slice(&group.destination_stability_bytes_v1())?;
        }
        debug_assert_eq!(bytes.as_slice().len(), capacity);
        Ok(Self {
            bytes,
            entry_count,
            hardlink_group_count,
        })
    }

    const fn entry_count(&self) -> u32 {
        self.entry_count
    }

    const fn hardlink_group_count(&self) -> u32 {
        self.hardlink_group_count
    }

    fn entry(&self, index: usize) -> &[u8] {
        let start = index * DESTINATION_WITNESS_ENTRY_BYTES_V1;
        &self.bytes.as_slice()[start..start + DESTINATION_WITNESS_ENTRY_BYTES_V1]
    }

    fn hardlink_group(&self, index: usize) -> &[u8] {
        let entries_bytes = usize::try_from(self.entry_count())
            .expect("u32 entry count fits usize on supported targets")
            * DESTINATION_WITNESS_ENTRY_BYTES_V1;
        let start = entries_bytes + index * DESTINATION_WITNESS_HARDLINK_BYTES_V1;
        &self.bytes.as_slice()[start..start + DESTINATION_WITNESS_HARDLINK_BYTES_V1]
    }
}

fn checked_destination_witness_capacity(
    entry_count: usize,
    hardlink_group_count: usize,
) -> Result<usize, SnapshotPipelineResourceErrorV1> {
    if u32::try_from(entry_count).is_err() || u32::try_from(hardlink_group_count).is_err() {
        return Err(witness_arithmetic_error());
    }
    checked_destination_witness_payload_bytes(entry_count, hardlink_group_count)
}

fn checked_destination_witness_payload_bytes(
    entry_count: usize,
    hardlink_group_count: usize,
) -> Result<usize, SnapshotPipelineResourceErrorV1> {
    entry_count
        .checked_mul(DESTINATION_WITNESS_ENTRY_BYTES_V1)
        .and_then(|entries| {
            hardlink_group_count
                .checked_mul(DESTINATION_WITNESS_HARDLINK_BYTES_V1)
                .and_then(|groups| entries.checked_add(groups))
        })
        .ok_or_else(witness_arithmetic_error)
}

const fn witness_arithmetic_error() -> SnapshotPipelineResourceErrorV1 {
    SnapshotPipelineResourceErrorV1::ContainerCapacityArithmeticOverflow {
        stage: SnapshotPipelineStageV1::Forward(
            SnapshotPipelineForwardStageV1::DestinationObservation,
        ),
    }
}

fn compare_same_plan(
    expected: &SourceTreePlanV1,
    observed: &SourceTreePlanV1,
    pair: SnapshotViewPairV1,
) -> Result<(), SnapshotVerifyErrorV1> {
    if expected.root_name() != observed.root_name() {
        return Err(mismatch(pair, SnapshotMismatchFieldV1::RootName));
    }
    if expected.entries().len() != observed.entries().len() {
        return Err(mismatch(pair, SnapshotMismatchFieldV1::EntryCount));
    }
    if expected.hardlink_groups().len() != observed.hardlink_groups().len() {
        return Err(mismatch(pair, SnapshotMismatchFieldV1::HardlinkGroupCount));
    }
    if expected.has_unsettable_xattrs() != observed.has_unsettable_xattrs() {
        return Err(mismatch(
            pair,
            SnapshotMismatchFieldV1::UnsettableXattrState,
        ));
    }

    for (index, (expected_entry, observed_entry)) in expected
        .entries()
        .iter()
        .zip(observed.entries())
        .enumerate()
    {
        if expected_entry.relative_path() != observed_entry.relative_path() {
            return Err(SnapshotVerifyErrorV1 {
                pair,
                field: SnapshotMismatchFieldV1::RelativePath,
                location: SnapshotVerifyLocationV1::Entry(plan_index(index)),
            });
        }
        if let Some(field) = same_entry_mismatch(expected_entry, observed_entry) {
            return Err(SnapshotVerifyErrorV1 {
                pair,
                field,
                location: SnapshotVerifyLocationV1::Entry(plan_index(index)),
            });
        }
    }

    for (index, (expected_group, observed_group)) in expected
        .hardlink_groups()
        .iter()
        .zip(observed.hardlink_groups())
        .enumerate()
    {
        let field = if expected_group.inode_key() != observed_group.inode_key() {
            Some(SnapshotMismatchFieldV1::HardlinkInodeIdentity)
        } else if expected_group.member_indices() != observed_group.member_indices() {
            Some(SnapshotMismatchFieldV1::HardlinkMembers)
        } else {
            None
        };
        if let Some(field) = field {
            return Err(SnapshotVerifyErrorV1 {
                pair,
                field,
                location: SnapshotVerifyLocationV1::HardlinkGroup(plan_index(index)),
            });
        }
    }
    Ok(())
}

fn compare_destination_from_witness(
    source_s1: &SourceTreePlanV1,
    destination_d1: &DestinationStabilityWitnessV1<'_>,
    destination_d2: &SourceTreePlanV1,
    exact_physical_identity: DestinationPhysicalIdentityV1,
) -> Result<(), SnapshotVerifyErrorV1> {
    let pair = SnapshotViewPairV1::D1D2;
    if source_s1.root_name() != destination_d2.root_name() {
        return Err(mismatch(pair, SnapshotMismatchFieldV1::RootName));
    }
    if u64::from(destination_d1.entry_count())
        != u64::try_from(destination_d2.entries().len()).unwrap_or(u64::MAX)
    {
        return Err(mismatch(pair, SnapshotMismatchFieldV1::EntryCount));
    }
    if u64::from(destination_d1.hardlink_group_count())
        != u64::try_from(destination_d2.hardlink_groups().len()).unwrap_or(u64::MAX)
    {
        return Err(mismatch(pair, SnapshotMismatchFieldV1::HardlinkGroupCount));
    }
    // S1/D1 succeeds only when neither view has unsettable visible xattrs, so
    // D1's exact value at this point is known to be false.
    if destination_d2.has_unsettable_xattrs() {
        return Err(mismatch(
            pair,
            SnapshotMismatchFieldV1::UnsettableXattrState,
        ));
    }

    for (index, (source_entry, destination_entry)) in source_s1
        .entries()
        .iter()
        .zip(destination_d2.entries())
        .enumerate()
    {
        if source_entry.relative_path() != destination_entry.relative_path() {
            return Err(SnapshotVerifyErrorV1 {
                pair,
                field: SnapshotMismatchFieldV1::RelativePath,
                location: SnapshotVerifyLocationV1::Entry(plan_index(index)),
            });
        }
        let witness_entry = destination_d1.entry(index);
        if let Some(field) = destination_witness_entry_mismatch(
            source_entry,
            witness_entry,
            destination_entry,
            exact_physical_identity,
        ) {
            return Err(SnapshotVerifyErrorV1 {
                pair,
                field,
                location: SnapshotVerifyLocationV1::Entry(plan_index(index)),
            });
        }
    }

    for (index, (source_group, destination_group)) in source_s1
        .hardlink_groups()
        .iter()
        .zip(destination_d2.hardlink_groups())
        .enumerate()
    {
        let witness_inode = destination_d1.hardlink_group(index);
        let field = if witness_inode != destination_group.destination_stability_bytes_v1() {
            Some(SnapshotMismatchFieldV1::HardlinkInodeIdentity)
        } else if source_group.member_indices() != destination_group.member_indices() {
            Some(SnapshotMismatchFieldV1::HardlinkMembers)
        } else {
            None
        };
        if let Some(field) = field {
            return Err(SnapshotVerifyErrorV1 {
                pair,
                field,
                location: SnapshotVerifyLocationV1::HardlinkGroup(plan_index(index)),
            });
        }
    }
    Ok(())
}

fn destination_witness_entry_mismatch(
    source_s1: &SourceTreeEntryV1,
    destination_d1: &[u8],
    destination_d2: &SourceTreeEntryV1,
    exact_physical_identity: DestinationPhysicalIdentityV1,
) -> Option<SnapshotMismatchFieldV1> {
    let kind = source_s1.payload().kind();
    let destination_d2_stability = destination_d2.destination_stability_bytes_v1();
    if source_s1.basename() != destination_d2.basename() {
        Some(SnapshotMismatchFieldV1::Basename)
    } else if source_s1.parent_index() != destination_d2.parent_index() {
        Some(SnapshotMismatchFieldV1::ParentIndex)
    } else if kind != destination_d2.payload().kind() {
        Some(SnapshotMismatchFieldV1::NodeKind)
    } else if destination_d1[DESTINATION_STABILITY_INODE_RANGE_V1]
        != destination_d2_stability[DESTINATION_STABILITY_INODE_RANGE_V1]
    {
        Some(SnapshotMismatchFieldV1::InodeIdentity)
    } else if projected_materialized_permissions(source_s1.statx().mode(), kind)
        != Some(destination_d2.statx().mode() & 0o7777)
    {
        Some(SnapshotMismatchFieldV1::Mode)
    } else if destination_d2.statx().uid() != exact_physical_identity.uid
        || destination_d2.statx().gid() != exact_physical_identity.gid
    {
        Some(SnapshotMismatchFieldV1::Ownership)
    } else if source_s1.statx().nlink() != destination_d2.statx().nlink() {
        Some(SnapshotMismatchFieldV1::LinkCount)
    } else if if kind == SourceNodeKindV1::Directory {
        destination_d1[DESTINATION_STABILITY_DIRECTORY_SIZE_RANGE_V1]
            != destination_d2_stability[DESTINATION_STABILITY_DIRECTORY_SIZE_RANGE_V1]
    } else {
        source_s1.statx().size() != destination_d2.statx().size()
    } {
        Some(SnapshotMismatchFieldV1::Size)
    } else if source_s1.statx().atime() != destination_d2.statx().atime() {
        Some(SnapshotMismatchFieldV1::Atime)
    } else if source_s1.statx().mtime() != destination_d2.statx().mtime() {
        Some(SnapshotMismatchFieldV1::Mtime)
    } else if destination_d1[DESTINATION_STABILITY_CTIME_RANGE_V1]
        != destination_d2_stability[DESTINATION_STABILITY_CTIME_RANGE_V1]
    {
        Some(SnapshotMismatchFieldV1::Ctime)
    } else if destination_d1[DESTINATION_STABILITY_BTIME_RANGE_V1]
        != destination_d2_stability[DESTINATION_STABILITY_BTIME_RANGE_V1]
    {
        Some(SnapshotMismatchFieldV1::Btime)
    } else {
        xattr_mismatch(source_s1.xattrs(), destination_d2.xattrs())
            .or_else(|| payload_mismatch(source_s1.payload(), destination_d2.payload()))
    }
}

fn compare_source_destination(
    source: &SourceTreePlanV1,
    destination: &SourceTreePlanV1,
    physical_identity: DestinationPhysicalIdentityV1,
) -> Result<(), SnapshotVerifyErrorV1> {
    let pair = SnapshotViewPairV1::S1D1;
    if source.root_name() != destination.root_name() {
        return Err(mismatch(pair, SnapshotMismatchFieldV1::RootName));
    }
    if source.entries().len() != destination.entries().len() {
        return Err(mismatch(pair, SnapshotMismatchFieldV1::EntryCount));
    }
    if source.hardlink_groups().len() != destination.hardlink_groups().len() {
        return Err(mismatch(pair, SnapshotMismatchFieldV1::HardlinkGroupCount));
    }
    if source.has_unsettable_xattrs() || destination.has_unsettable_xattrs() {
        return Err(mismatch(
            pair,
            SnapshotMismatchFieldV1::VisibleXattrUnrepresentable,
        ));
    }

    for (index, (source_entry, destination_entry)) in source
        .entries()
        .iter()
        .zip(destination.entries())
        .enumerate()
    {
        if source_entry.relative_path() != destination_entry.relative_path() {
            return Err(SnapshotVerifyErrorV1 {
                pair,
                field: SnapshotMismatchFieldV1::RelativePath,
                location: SnapshotVerifyLocationV1::Entry(plan_index(index)),
            });
        }
        if let Some(field) =
            source_destination_entry_mismatch(source_entry, destination_entry, physical_identity)
        {
            return Err(SnapshotVerifyErrorV1 {
                pair,
                field,
                location: SnapshotVerifyLocationV1::Entry(plan_index(index)),
            });
        }
    }

    for (index, (source_group, destination_group)) in source
        .hardlink_groups()
        .iter()
        .zip(destination.hardlink_groups())
        .enumerate()
    {
        if source_group.member_indices() != destination_group.member_indices() {
            return Err(SnapshotVerifyErrorV1 {
                pair,
                field: SnapshotMismatchFieldV1::HardlinkMembers,
                location: SnapshotVerifyLocationV1::HardlinkGroup(plan_index(index)),
            });
        }
    }
    Ok(())
}

fn same_entry_mismatch(
    expected: &SourceTreeEntryV1,
    observed: &SourceTreeEntryV1,
) -> Option<SnapshotMismatchFieldV1> {
    if expected.basename() != observed.basename() {
        Some(SnapshotMismatchFieldV1::Basename)
    } else if expected.parent_index() != observed.parent_index() {
        Some(SnapshotMismatchFieldV1::ParentIndex)
    } else if expected.payload().kind() != observed.payload().kind() {
        Some(SnapshotMismatchFieldV1::NodeKind)
    } else {
        same_statx_mismatch(expected.statx(), observed.statx())
            .or_else(|| xattr_mismatch(expected.xattrs(), observed.xattrs()))
            .or_else(|| payload_mismatch(expected.payload(), observed.payload()))
    }
}

fn same_statx_mismatch(
    expected: &SourceStatxV1,
    observed: &SourceStatxV1,
) -> Option<SnapshotMismatchFieldV1> {
    if expected.inode_key() != observed.inode_key() {
        Some(SnapshotMismatchFieldV1::InodeIdentity)
    } else if expected.mode() != observed.mode() {
        Some(SnapshotMismatchFieldV1::Mode)
    } else if expected.uid() != observed.uid() || expected.gid() != observed.gid() {
        Some(SnapshotMismatchFieldV1::Ownership)
    } else if expected.nlink() != observed.nlink() {
        Some(SnapshotMismatchFieldV1::LinkCount)
    } else if expected.size() != observed.size() {
        Some(SnapshotMismatchFieldV1::Size)
    } else if expected.atime() != observed.atime() {
        Some(SnapshotMismatchFieldV1::Atime)
    } else if expected.mtime() != observed.mtime() {
        Some(SnapshotMismatchFieldV1::Mtime)
    } else if expected.ctime() != observed.ctime() {
        Some(SnapshotMismatchFieldV1::Ctime)
    } else if expected.btime() != observed.btime() {
        Some(SnapshotMismatchFieldV1::Btime)
    } else {
        None
    }
}

fn source_destination_entry_mismatch(
    source: &SourceTreeEntryV1,
    destination: &SourceTreeEntryV1,
    physical_identity: DestinationPhysicalIdentityV1,
) -> Option<SnapshotMismatchFieldV1> {
    let kind = source.payload().kind();
    if source.basename() != destination.basename() {
        Some(SnapshotMismatchFieldV1::Basename)
    } else if source.parent_index() != destination.parent_index() {
        Some(SnapshotMismatchFieldV1::ParentIndex)
    } else if kind != destination.payload().kind() {
        Some(SnapshotMismatchFieldV1::NodeKind)
    } else if kind == SourceNodeKindV1::Symlink {
        Some(SnapshotMismatchFieldV1::SymlinkMaterializationUnsupported)
    } else if projected_materialized_permissions(source.statx().mode(), kind)
        != Some(destination.statx().mode() & 0o7777)
    {
        Some(SnapshotMismatchFieldV1::DestinationPhysicalMode)
    } else if destination.statx().uid() != physical_identity.uid
        || destination.statx().gid() != physical_identity.gid
    {
        Some(SnapshotMismatchFieldV1::DestinationPhysicalOwner)
    } else if source.statx().nlink() != destination.statx().nlink() {
        Some(SnapshotMismatchFieldV1::LinkCount)
    } else if kind != SourceNodeKindV1::Directory
        && source.statx().size() != destination.statx().size()
    {
        Some(SnapshotMismatchFieldV1::Size)
    } else if source.statx().atime() != destination.statx().atime() {
        Some(SnapshotMismatchFieldV1::Atime)
    } else if source.statx().mtime() != destination.statx().mtime() {
        Some(SnapshotMismatchFieldV1::Mtime)
    } else {
        xattr_mismatch(source.xattrs(), destination.xattrs())
            .or_else(|| payload_mismatch(source.payload(), destination.payload()))
    }
}

fn xattr_mismatch(
    expected: &[CapturedXattrV1],
    observed: &[CapturedXattrV1],
) -> Option<SnapshotMismatchFieldV1> {
    if expected.len() != observed.len() {
        return Some(SnapshotMismatchFieldV1::XattrCount);
    }
    for (expected, observed) in expected.iter().zip(observed) {
        if expected.name() != observed.name() {
            return Some(SnapshotMismatchFieldV1::XattrName);
        }
        if expected.value() != observed.value() {
            return Some(SnapshotMismatchFieldV1::XattrValue);
        }
    }
    None
}

fn payload_mismatch(
    expected: &SourcePlanPayloadV1,
    observed: &SourcePlanPayloadV1,
) -> Option<SnapshotMismatchFieldV1> {
    match (expected, observed) {
        (
            SourcePlanPayloadV1::Directory { children: expected },
            SourcePlanPayloadV1::Directory { children: observed },
        ) => (expected != observed).then_some(SnapshotMismatchFieldV1::DirectoryChildren),
        (
            SourcePlanPayloadV1::Regular { evidence: expected },
            SourcePlanPayloadV1::Regular { evidence: observed },
        ) => {
            if expected.content_digest() != observed.content_digest() {
                Some(SnapshotMismatchFieldV1::RegularContentDigest)
            } else if expected.data_extents() != observed.data_extents() {
                Some(SnapshotMismatchFieldV1::RegularExtents)
            } else {
                None
            }
        }
        (
            SourcePlanPayloadV1::Symlink { target: expected },
            SourcePlanPayloadV1::Symlink { target: observed },
        ) => (expected != observed).then_some(SnapshotMismatchFieldV1::SymlinkTarget),
        _ => Some(SnapshotMismatchFieldV1::NodeKind),
    }
}

const fn mismatch(
    pair: SnapshotViewPairV1,
    field: SnapshotMismatchFieldV1,
) -> SnapshotVerifyErrorV1 {
    SnapshotVerifyErrorV1 {
        pair,
        field,
        location: SnapshotVerifyLocationV1::Header,
    }
}

fn plan_index(index: usize) -> u32 {
    u32::try_from(index).expect("normalized snapshot plans are bounded to u32 entries")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux_pytest::snapshot_connector::mint_destination_witness_bytes_for_test;
    use crate::linux_pytest::snapshot_policy::{
        SnapshotPipelineResourcesV1, SnapshotResourcePolicyV1,
    };
    use crate::linux_pytest::snapshot_tree::{
        CapturedXattrV1, SourceHardlinkGroupV1, SourceRegularEvidenceV1, SourceStatxV1,
        SourceTreeEntryV1,
    };
    use crate::linux_pytest::{ExtentV1, FILE_CONTENT_DOMAIN, FileContentDigest, TimespecV1};
    use std::num::{NonZeroU8, NonZeroU16, NonZeroU32, NonZeroU64};

    const S_IFDIR: u32 = 0o040_000;
    const S_IFREG: u32 = 0o100_000;

    #[derive(Clone, Copy)]
    enum Role {
        Source,
        Destination,
    }

    fn time(seconds: i64) -> TimespecV1 {
        TimespecV1 {
            seconds,
            nanoseconds: 7,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn statx(
        role: Role,
        inode: u64,
        source_mode: u32,
        destination_mode: u32,
        size: u64,
        atime: i64,
        mtime: i64,
        ctime_delta: i64,
    ) -> SourceStatxV1 {
        let (mount, device_major, device_minor, inode, mode, uid, gid, ctime) = match role {
            Role::Source => (1, 2, 0, inode, source_mode, 10, 20, 30),
            Role::Destination => (11, 22, 33, inode + 100, destination_mode, 1_000, 2_000, 300),
        };
        SourceStatxV1::for_test(
            mount,
            device_major,
            device_minor,
            inode,
            mode,
            uid,
            gid,
            1,
            size,
            time(atime),
            time(mtime),
            time(ctime + ctime_delta),
            Some(time(ctime + ctime_delta + 1)),
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn regular_entry(
        role: Role,
        path: &'static [u8],
        inode: u64,
        seed: u8,
        size: u64,
        extent_length: u64,
        source_mode: u32,
        destination_mode: u32,
        ctime_delta: i64,
    ) -> SourceTreeEntryV1 {
        SourceTreeEntryV1::unchecked_for_test(
            path,
            path,
            Some(0),
            statx(
                role,
                inode,
                source_mode,
                destination_mode,
                size,
                inode as i64 + 1,
                inode as i64 + 2,
                ctime_delta,
            ),
            (path == b"a")
                .then(|| CapturedXattrV1::bytes_for_test(b"user.a", b"value"))
                .into_iter()
                .collect(),
            SourcePlanPayloadV1::Regular {
                evidence: SourceRegularEvidenceV1::checked(
                    FileContentDigest::derive(FILE_CONTENT_DOMAIN, &[&[seed]]),
                    (extent_length != 0)
                        .then_some(ExtentV1 {
                            offset: 0,
                            length: extent_length,
                        })
                        .into_iter()
                        .collect(),
                    size,
                )
                .unwrap(),
            },
            None,
        )
    }

    fn fixture_with(
        role: Role,
        digest_seed: u8,
        ctime_delta: i64,
        root_name: &[u8],
        regular_extent_length: u64,
    ) -> SourceTreePlanV1 {
        let root = SourceTreeEntryV1::unchecked_for_test(
            b"",
            b"tree",
            None,
            statx(
                role,
                1,
                S_IFDIR | 0o775,
                S_IFDIR | 0o555,
                if matches!(role, Role::Source) {
                    4_096
                } else {
                    8_192
                },
                1,
                2,
                ctime_delta,
            ),
            Vec::new(),
            SourcePlanPayloadV1::Directory {
                children: vec![1, 2].into_boxed_slice(),
            },
            None,
        );
        let a = || {
            regular_entry(
                role,
                b"a",
                2,
                digest_seed,
                4,
                regular_extent_length,
                S_IFREG | 0o755,
                S_IFREG | 0o555,
                ctime_delta,
            )
        };
        let b = || {
            regular_entry(
                role,
                b"b",
                3,
                9,
                0,
                0,
                S_IFREG | 0o644,
                S_IFREG | 0o444,
                ctime_delta,
            )
        };
        SourceTreePlanV1::unchecked_for_test(root_name, vec![root, a(), b()], Vec::new(), false)
    }

    fn fixture(role: Role, digest_seed: u8, ctime_delta: i64) -> SourceTreePlanV1 {
        fixture_with(role, digest_seed, ctime_delta, b"tree", 4)
    }

    fn source(seed: u8) -> SourceTreePlanV1 {
        fixture(Role::Source, seed, 0)
    }

    fn destination(seed: u8, ctime_delta: i64) -> SourceTreePlanV1 {
        fixture(Role::Destination, seed, ctime_delta)
    }

    fn with_hardlink_group(plan: SourceTreePlanV1) -> SourceTreePlanV1 {
        with_hardlink_group_at(plan, 1, vec![1, 2])
    }

    fn with_hardlink_group_at(
        plan: SourceTreePlanV1,
        inode_entry_index: usize,
        member_indices: Vec<u32>,
    ) -> SourceTreePlanV1 {
        let (root_name, entries, _, has_unsettable_xattrs) = plan.into_parts();
        let inode_key = entries[inode_entry_index].statx().inode_key().clone();
        SourceTreePlanV1::unchecked_for_test(
            &root_name,
            entries.into_vec(),
            vec![SourceHardlinkGroupV1::unchecked_for_test(
                inode_key,
                member_indices,
            )],
            has_unsettable_xattrs,
        )
    }

    fn with_root_statx(plan: SourceTreePlanV1, replacement: SourceStatxV1) -> SourceTreePlanV1 {
        let (root_name, entries, hardlink_groups, has_unsettable_xattrs) = plan.into_parts();
        let mut entries = entries.into_vec();
        let root = entries.remove(0);
        let (relative_path, basename, parent_index, _, xattrs, payload, hardlink_group) =
            root.into_parts();
        entries.insert(
            0,
            SourceTreeEntryV1::unchecked_for_test(
                &relative_path,
                &basename,
                parent_index,
                replacement,
                xattrs.into_vec(),
                payload,
                hardlink_group,
            ),
        );
        SourceTreePlanV1::unchecked_for_test(
            &root_name,
            entries,
            hardlink_groups.into_vec(),
            has_unsettable_xattrs,
        )
    }

    fn witness_resources(transient_heap_bytes: u64) -> SnapshotPipelineResourcesV1 {
        let policy = SnapshotResourcePolicyV1::checked(
            4,
            NonZeroU32::new(16).unwrap(),
            NonZeroU16::new(255).unwrap(),
            4_096,
            4_096,
            16 * 1024 * 1024,
            64 * 1024 * 1024,
            64,
            1_024,
            64,
            1_024,
            255,
            64 * 1024,
            64 * 1024,
            1024 * 1024,
            NonZeroU64::new(1024 * 1024).unwrap(),
            transient_heap_bytes,
            NonZeroU64::new(1_000_000).unwrap(),
            NonZeroU8::new(4).unwrap(),
            NonZeroU8::new(3).unwrap(),
            NonZeroU8::new(4).unwrap(),
        )
        .unwrap();
        SnapshotPipelineResourcesV1::preflight(policy, 0, u64::MAX, u64::MAX).unwrap()
    }

    fn witness_allocator<'resources>(
        resources: &'resources SnapshotPipelineResourcesV1,
    ) -> impl FnOnce(
        usize,
    ) -> Result<
        SnapshotDestinationWitnessBytesV1<'resources>,
        SnapshotPipelineResourceErrorV1,
    > + 'resources {
        move |capacity| mint_destination_witness_bytes_for_test(resources, capacity)
    }

    fn awaiting_d2<'source, 'resources>(
        source_s1: &'source SourceTreePlanV1,
        source_s2: &SourceTreePlanV1,
        destination_d1: &SourceTreePlanV1,
        resources: &'resources SnapshotPipelineResourcesV1,
    ) -> AwaitingDestinationViewD2V1<'source, 'resources> {
        begin_four_view_comparison(source_s1)
            .compare_source_s2(source_s2)
            .unwrap()
            .compare_destination_d1(
                destination_d1,
                DestinationPhysicalIdentityV1::new(1_000, 2_000),
            )
            .unwrap()
            .capture_stability_witness(witness_allocator(resources))
            .unwrap()
    }

    fn error<T>(result: Result<T, SnapshotVerifyErrorV1>) -> SnapshotVerifyErrorV1 {
        match result {
            Ok(_) => panic!("expected comparison failure"),
            Err(error) => error,
        }
    }

    fn assert_mismatch<T>(
        result: Result<T, SnapshotVerifyErrorV1>,
        pair: SnapshotViewPairV1,
        field: SnapshotMismatchFieldV1,
        location: SnapshotVerifyLocationV1,
    ) {
        assert_eq!(
            error(result),
            SnapshotVerifyErrorV1 {
                pair,
                field,
                location,
            }
        );
    }

    #[test]
    fn exact_four_views_complete_all_three_comparisons() {
        let s1 = source(1);
        let s2 = source(1);
        let d1 = destination(1, 0);
        let d2 = destination(1, 0);
        let resources =
            witness_resources(checked_destination_witness_capacity(3, 0).unwrap() as u64);
        let source_root = s1.entries()[0].statx();
        let destination_root = d1.entries()[0].statx();

        // The projection deliberately ignores source-only physical identity,
        // ctime, btime, and directory-size differences at the destination.
        assert_ne!(source_root.inode_key(), destination_root.inode_key());
        assert_ne!(source_root.ctime(), destination_root.ctime());
        assert_ne!(source_root.btime(), destination_root.btime());
        assert_ne!(source_root.size(), destination_root.size());

        awaiting_d2(&s1, &s2, &d1, &resources)
            .compare_destination_d2(&d2)
            .unwrap();
    }

    #[test]
    fn every_required_pair_has_distinct_mismatch_evidence() {
        let s1 = source(1);
        let s2_wrong = source(2);
        let mismatch = error(begin_four_view_comparison(&s1).compare_source_s2(&s2_wrong));
        assert_eq!(mismatch.pair, SnapshotViewPairV1::S1S2);
        assert_eq!(
            mismatch.field,
            SnapshotMismatchFieldV1::RegularContentDigest
        );
        assert_eq!(mismatch.location, SnapshotVerifyLocationV1::Entry(1));

        let s2 = source(1);
        let d1_wrong = destination(2, 0);
        let mismatch = error(
            begin_four_view_comparison(&s1)
                .compare_source_s2(&s2)
                .unwrap()
                .compare_destination_d1(
                    &d1_wrong,
                    DestinationPhysicalIdentityV1::new(1_000, 2_000),
                ),
        );
        assert_eq!(mismatch.pair, SnapshotViewPairV1::S1D1);
        assert_eq!(
            mismatch.field,
            SnapshotMismatchFieldV1::RegularContentDigest
        );
        assert_eq!(mismatch.location, SnapshotVerifyLocationV1::Entry(1));

        let d1 = destination(1, 0);
        let d2_wrong = destination(1, 1);
        let resources =
            witness_resources(checked_destination_witness_capacity(3, 0).unwrap() as u64);
        let mismatch =
            error(awaiting_d2(&s1, &s2, &d1, &resources).compare_destination_d2(&d2_wrong));
        assert_eq!(mismatch.pair, SnapshotViewPairV1::D1D2);
        assert_eq!(mismatch.field, SnapshotMismatchFieldV1::Ctime);
        assert_eq!(mismatch.location, SnapshotVerifyLocationV1::Entry(0));
    }

    #[test]
    fn destination_projection_uses_writer_mode_and_explicit_owner() {
        let s1 = source(1);
        let s2 = source(1);
        let d1 = destination(1, 0);

        let wrong_mode = source(1);
        let mismatch = error(
            begin_four_view_comparison(&s1)
                .compare_source_s2(&s2)
                .unwrap()
                .compare_destination_d1(&wrong_mode, DestinationPhysicalIdentityV1::new(10, 20)),
        );
        assert_eq!(mismatch.pair, SnapshotViewPairV1::S1D1);
        assert_eq!(
            mismatch.field,
            SnapshotMismatchFieldV1::DestinationPhysicalMode
        );
        assert_eq!(mismatch.location, SnapshotVerifyLocationV1::Entry(0));

        let mismatch = error(
            begin_four_view_comparison(&s1)
                .compare_source_s2(&s2)
                .unwrap()
                .compare_destination_d1(&d1, DestinationPhysicalIdentityV1::new(7, 8)),
        );
        assert_eq!(mismatch.pair, SnapshotViewPairV1::S1D1);
        assert_eq!(
            mismatch.field,
            SnapshotMismatchFieldV1::DestinationPhysicalOwner
        );
        assert_eq!(mismatch.location, SnapshotVerifyLocationV1::Entry(0));
    }

    #[test]
    fn mismatch_precedence_is_header_then_entry_then_field() {
        let s1 = source(1);

        let wrong_header = fixture_with(Role::Source, 2, 1, b"wrong", 2);
        assert_mismatch(
            begin_four_view_comparison(&s1).compare_source_s2(&wrong_header),
            SnapshotViewPairV1::S1S2,
            SnapshotMismatchFieldV1::RootName,
            SnapshotVerifyLocationV1::Header,
        );

        // Entry zero's ctime precedes entry one's digest and extent failures.
        let wrong_entries = fixture_with(Role::Source, 2, 1, b"tree", 2);
        assert_mismatch(
            begin_four_view_comparison(&s1).compare_source_s2(&wrong_entries),
            SnapshotViewPairV1::S1S2,
            SnapshotMismatchFieldV1::Ctime,
            SnapshotVerifyLocationV1::Entry(0),
        );

        // Within entry zero, inode identity precedes mode, ownership, size,
        // ctime, and birth-time differences.
        let wrong_fields = destination(2, 1);
        assert_mismatch(
            begin_four_view_comparison(&s1).compare_source_s2(&wrong_fields),
            SnapshotViewPairV1::S1S2,
            SnapshotMismatchFieldV1::InodeIdentity,
            SnapshotVerifyLocationV1::Entry(0),
        );
    }

    #[test]
    fn destination_extent_mismatch_keeps_pair_field_and_location() {
        let s1 = source(1);
        let s2 = source(1);
        let d1 = destination(1, 0);
        let d2_with_different_extents = fixture_with(Role::Destination, 1, 0, b"tree", 2);
        let resources =
            witness_resources(checked_destination_witness_capacity(3, 0).unwrap() as u64);
        assert_mismatch(
            awaiting_d2(&s1, &s2, &d1, &resources)
                .compare_destination_d2(&d2_with_different_extents),
            SnapshotViewPairV1::D1D2,
            SnapshotMismatchFieldV1::RegularExtents,
            SnapshotVerifyLocationV1::Entry(1),
        );
    }

    #[test]
    fn witness_is_exact_raw_d1_layout_without_a_retainable_header_copy() {
        let s1 = with_hardlink_group(source(1));
        let s2 = with_hardlink_group(source(1));
        let d1 = with_hardlink_group(destination(1, 0));
        let d2 = with_hardlink_group(destination(1, 0));
        let capacity = checked_destination_witness_capacity(3, 1).unwrap();
        assert_eq!(capacity, 195);
        let resources = witness_resources(capacity as u64);

        let awaiting_d2 = awaiting_d2(&s1, &s2, &d1, &resources);

        let bytes = awaiting_d2.witness.bytes.as_slice();
        assert_eq!(bytes.len(), capacity);
        assert_eq!(awaiting_d2.witness.entry_count(), 3);
        assert_eq!(awaiting_d2.witness.hardlink_group_count(), 1);
        for (index, entry) in d1.entries().iter().enumerate() {
            let start = index * DESTINATION_WITNESS_ENTRY_BYTES_V1;
            assert_eq!(
                &bytes[start..start + DESTINATION_WITNESS_ENTRY_BYTES_V1],
                &entry.destination_stability_bytes_v1()
            );
        }
        let group_start = 3 * DESTINATION_WITNESS_ENTRY_BYTES_V1;
        assert_eq!(
            &bytes[group_start..group_start + DESTINATION_WITNESS_HARDLINK_BYTES_V1],
            &d1.hardlink_groups()[0].destination_stability_bytes_v1()
        );
        assert_eq!(
            awaiting_d2.exact_physical_identity,
            DestinationPhysicalIdentityV1::new(1_000, 2_000)
        );
        awaiting_d2.compare_destination_d2(&d2).unwrap();
    }

    #[test]
    fn witness_capacity_checks_counts_and_arithmetic() {
        assert_eq!(checked_destination_witness_capacity(3, 1).unwrap(), 195);
        assert_eq!(checked_destination_witness_capacity(0, 0).unwrap(), 0);
        assert_eq!(
            checked_destination_witness_capacity(
                usize::try_from(u64::from(u32::MAX) + 1).unwrap(),
                0,
            ),
            Err(witness_arithmetic_error())
        );
        assert_eq!(
            checked_destination_witness_payload_bytes(
                usize::MAX / DESTINATION_WITNESS_ENTRY_BYTES_V1 + 1,
                0,
            ),
            Err(witness_arithmetic_error())
        );
        assert_eq!(
            checked_destination_witness_payload_bytes(
                0,
                usize::MAX / DESTINATION_WITNESS_HARDLINK_BYTES_V1 + 1,
            ),
            Err(witness_arithmetic_error())
        );
    }

    #[test]
    fn witness_charge_is_released_only_when_owning_state_drops() {
        let capacity = checked_destination_witness_capacity(3, 0).unwrap();
        let resources = witness_resources(capacity as u64);

        let s1_a = source(1);
        let s2_a = source(1);
        let d1_a = destination(1, 0);
        let first = awaiting_d2(&s1_a, &s2_a, &d1_a, &resources);

        let s1_b = source(1);
        let s2_b = source(1);
        let d1_b = destination(1, 0);
        let error = match begin_four_view_comparison(&s1_b)
            .compare_source_s2(&s2_b)
            .unwrap()
            .compare_destination_d1(&d1_b, DestinationPhysicalIdentityV1::new(1_000, 2_000))
            .unwrap()
            .capture_stability_witness(witness_allocator(&resources))
        {
            Ok(_) => panic!("a second concurrent witness must exceed the exact charge"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            SnapshotPipelineResourceErrorV1::TransientHeapCapacityExceeded {
                stage: SnapshotPipelineStageV1::Forward(
                    SnapshotPipelineForwardStageV1::DestinationObservation,
                ),
                live: capacity as u64,
                requested: capacity as u64,
                limit: capacity as u64,
            }
        );

        drop(first);
        let s1_c = source(1);
        let s2_c = source(1);
        let d1_c = destination(1, 0);
        let replacement = awaiting_d2(&s1_c, &s2_c, &d1_c, &resources);
        drop(replacement);
    }

    #[test]
    fn d1_d2_keeps_entry_then_group_and_group_field_precedence() {
        let s1 = with_hardlink_group(source(1));
        let s2 = with_hardlink_group(source(1));
        let d1 = with_hardlink_group(destination(1, 0));
        let d2_wrong_entry = with_hardlink_group(destination(1, 1));
        let capacity = checked_destination_witness_capacity(3, 1).unwrap();
        let resources = witness_resources(capacity as u64);
        assert_mismatch(
            awaiting_d2(&s1, &s2, &d1, &resources).compare_destination_d2(&d2_wrong_entry),
            SnapshotViewPairV1::D1D2,
            SnapshotMismatchFieldV1::Ctime,
            SnapshotVerifyLocationV1::Entry(0),
        );

        let d2_wrong_group = with_hardlink_group_at(destination(1, 0), 0, vec![2]);
        assert_mismatch(
            awaiting_d2(&s1, &s2, &d1, &resources).compare_destination_d2(&d2_wrong_group),
            SnapshotViewPairV1::D1D2,
            SnapshotMismatchFieldV1::HardlinkInodeIdentity,
            SnapshotVerifyLocationV1::HardlinkGroup(0),
        );
    }

    #[test]
    fn d1_d2_reconstructs_each_raw_field_and_same_inode_group_members() {
        let s1 = source(1);
        let s2 = source(1);
        let d1 = destination(1, 0);
        let resources =
            witness_resources(checked_destination_witness_capacity(3, 1).unwrap() as u64);

        let d2_wrong_inode = with_root_statx(
            destination(1, 0),
            statx(
                Role::Destination,
                99,
                S_IFDIR | 0o775,
                S_IFDIR | 0o555,
                8_192,
                1,
                2,
                0,
            ),
        );
        assert_mismatch(
            awaiting_d2(&s1, &s2, &d1, &resources).compare_destination_d2(&d2_wrong_inode),
            SnapshotViewPairV1::D1D2,
            SnapshotMismatchFieldV1::InodeIdentity,
            SnapshotVerifyLocationV1::Entry(0),
        );

        let d2_wrong_directory_size = with_root_statx(
            destination(1, 0),
            statx(
                Role::Destination,
                1,
                S_IFDIR | 0o775,
                S_IFDIR | 0o555,
                9_999,
                1,
                2,
                0,
            ),
        );
        assert_mismatch(
            awaiting_d2(&s1, &s2, &d1, &resources).compare_destination_d2(&d2_wrong_directory_size),
            SnapshotViewPairV1::D1D2,
            SnapshotMismatchFieldV1::Size,
            SnapshotVerifyLocationV1::Entry(0),
        );

        let d2_wrong_btime = with_root_statx(
            destination(1, 0),
            SourceStatxV1::for_test(
                11,
                22,
                33,
                101,
                S_IFDIR | 0o555,
                1_000,
                2_000,
                1,
                8_192,
                time(1),
                time(2),
                time(300),
                Some(time(999)),
            ),
        );
        assert_mismatch(
            awaiting_d2(&s1, &s2, &d1, &resources).compare_destination_d2(&d2_wrong_btime),
            SnapshotViewPairV1::D1D2,
            SnapshotMismatchFieldV1::Btime,
            SnapshotVerifyLocationV1::Entry(0),
        );

        let s1_grouped = with_hardlink_group(source(1));
        let s2_grouped = with_hardlink_group(source(1));
        let d1_grouped = with_hardlink_group(destination(1, 0));
        let d2_wrong_members = with_hardlink_group_at(destination(1, 0), 1, vec![2]);
        assert_mismatch(
            awaiting_d2(&s1_grouped, &s2_grouped, &d1_grouped, &resources)
                .compare_destination_d2(&d2_wrong_members),
            SnapshotViewPairV1::D1D2,
            SnapshotMismatchFieldV1::HardlinkMembers,
            SnapshotVerifyLocationV1::HardlinkGroup(0),
        );
    }

    #[test]
    fn one_byte_short_witness_limit_refuses_before_allocation() {
        let s1 = with_hardlink_group(source(1));
        let s2 = with_hardlink_group(source(1));
        let d1 = with_hardlink_group(destination(1, 0));
        let required = checked_destination_witness_capacity(3, 1).unwrap();
        assert_eq!(required, 195);
        let resources = witness_resources((required - 1) as u64);

        let error = match begin_four_view_comparison(&s1)
            .compare_source_s2(&s2)
            .unwrap()
            .compare_destination_d1(&d1, DestinationPhysicalIdentityV1::new(1_000, 2_000))
            .unwrap()
            .capture_stability_witness(witness_allocator(&resources))
        {
            Ok(_) => panic!("a 194-byte ceiling cannot admit a 195-byte witness"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            SnapshotPipelineResourceErrorV1::TransientHeapCapacityExceeded {
                stage: SnapshotPipelineStageV1::Forward(
                    SnapshotPipelineForwardStageV1::DestinationObservation,
                ),
                live: 0,
                requested: required as u64,
                limit: (required - 1) as u64,
            }
        );
    }

    #[test]
    fn witness_owning_typestates_cannot_gain_clone_or_copy() {
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

        <DestinationViewD1MatchedV1<'static, 'static> as AmbiguousIfClone<_>>::probe();
        <DestinationViewD1MatchedV1<'static, 'static> as AmbiguousIfCopy<_>>::probe();
        <DestinationStabilityWitnessV1<'static> as AmbiguousIfClone<_>>::probe();
        <DestinationStabilityWitnessV1<'static> as AmbiguousIfCopy<_>>::probe();
        <AwaitingDestinationViewD2V1<'static, 'static> as AmbiguousIfClone<_>>::probe();
        <AwaitingDestinationViewD2V1<'static, 'static> as AmbiguousIfCopy<_>>::probe();
        assert!(std::mem::needs_drop::<
            AwaitingDestinationViewD2V1<'static, 'static>,
        >());
    }
}
