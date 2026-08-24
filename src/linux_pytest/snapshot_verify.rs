//! Allocation-free semantic comparison for the four snapshot observations.
//!
//! Connector orchestration must retain at most two policy-bounded plans at
//! once and now drives this typestate in order: S1/S2, S1/D1, then D1/D2. This
//! module only compares already-normalized plans. Successful comparison does
//! not grant manifest or publication authority and is not a substitute for
//! canonical verification.

use super::snapshot_materialize::projected_materialized_permissions;
use super::snapshot_tree::{
    CapturedXattrV1, SourceNodeKindV1, SourcePlanPayloadV1, SourceStatxV1, SourceTreeEntryV1,
    SourceTreePlanV1,
};

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

/// S1/S2 equality is proven; only S1 remains borrowed for materialization
/// projection comparison against D1.
pub(super) struct SourceViewsStableV1<'source> {
    source_s1: &'source SourceTreePlanV1,
}

impl SourceViewsStableV1<'_> {
    /// The returned state no longer borrows S1, allowing its retained-plan
    /// lease to be dropped before D2 is acquired.
    pub(super) fn compare_destination_d1<'destination>(
        self,
        destination_d1: &'destination SourceTreePlanV1,
        physical_identity: DestinationPhysicalIdentityV1,
    ) -> Result<AwaitingDestinationViewD2V1<'destination>, SnapshotVerifyErrorV1> {
        compare_source_destination(self.source_s1, destination_d1, physical_identity)?;
        Ok(AwaitingDestinationViewD2V1 { destination_d1 })
    }
}

/// D1 is retained until an independently produced D2 has compared equal.
pub(super) struct AwaitingDestinationViewD2V1<'destination> {
    destination_d1: &'destination SourceTreePlanV1,
}

impl AwaitingDestinationViewD2V1<'_> {
    /// Success completes comparison only; it grants no publication authority.
    pub(super) fn compare_destination_d2(
        self,
        destination_d2: &SourceTreePlanV1,
    ) -> Result<(), SnapshotVerifyErrorV1> {
        compare_same_plan(
            self.destination_d1,
            destination_d2,
            SnapshotViewPairV1::D1D2,
        )
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
    use crate::linux_pytest::snapshot_tree::{
        CapturedXattrV1, SourceRegularEvidenceV1, SourceStatxV1, SourceTreeEntryV1,
    };
    use crate::linux_pytest::{ExtentV1, FILE_CONTENT_DOMAIN, FileContentDigest, TimespecV1};

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
        let source_root = s1.entries()[0].statx();
        let destination_root = d1.entries()[0].statx();

        // The projection deliberately ignores source-only physical identity,
        // ctime, btime, and directory-size differences at the destination.
        assert_ne!(source_root.inode_key(), destination_root.inode_key());
        assert_ne!(source_root.ctime(), destination_root.ctime());
        assert_ne!(source_root.btime(), destination_root.btime());
        assert_ne!(source_root.size(), destination_root.size());

        begin_four_view_comparison(&s1)
            .compare_source_s2(&s2)
            .unwrap()
            .compare_destination_d1(&d1, DestinationPhysicalIdentityV1::new(1_000, 2_000))
            .unwrap()
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
        let mismatch = error(
            begin_four_view_comparison(&s1)
                .compare_source_s2(&s2)
                .unwrap()
                .compare_destination_d1(&d1, DestinationPhysicalIdentityV1::new(1_000, 2_000))
                .unwrap()
                .compare_destination_d2(&d2_wrong),
        );
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
        assert_mismatch(
            begin_four_view_comparison(&s1)
                .compare_source_s2(&s2)
                .unwrap()
                .compare_destination_d1(&d1, DestinationPhysicalIdentityV1::new(1_000, 2_000))
                .unwrap()
                .compare_destination_d2(&d2_with_different_extents),
            SnapshotViewPairV1::D1D2,
            SnapshotMismatchFieldV1::RegularExtents,
            SnapshotVerifyLocationV1::Entry(1),
        );
    }
}
