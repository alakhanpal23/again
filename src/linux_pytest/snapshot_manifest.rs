//! Pure compilation of paired snapshot tree plans into the frozen manifest
//! representation.
//!
//! This module does not observe the filesystem and does not prove that its two
//! inputs are stable views. The connector must first complete the S1/S2,
//! S1/D1, and D1/D2 contract and pass only the resulting S1 logical view and
//! destination-byte view here. Compilation consumes both plans so their owned
//! paths, logical metadata, xattrs, and destination content evidence cannot be
//! spliced into another result afterward.
//!
//! The returned value is data, not authority. In particular, it owns no file
//! descriptor, does not bind a published directory, is not a full
//! `SnapshotManifestV1`, and cannot grant isolation, execution, or reuse. Its
//! top-level containers use fallible `try_reserve_exact`, but their observed
//! capacities are not connector-ledger charges. Child-name cloning, manifest
//! validation, and the existing canonical node hash helpers also use nested,
//! infallible allocation paths. Production integration must therefore add an
//! exact retained manifest/canonical-byte resource envelope and remove or
//! charge every nested allocation before this compiler is placed on an
//! authority-producing path.

use super::canonical;
use super::snapshot_tree::{
    CapturedXattrValueV1, SourcePlanPayloadV1, SourceTreeEntryV1, SourceTreePlanV1,
};
use super::{
    ChildCommitmentV1, HARDLINK_GROUP_DOMAIN, HardlinkGroupDigest, LinuxPytestContractError,
    ManifestEntryV1, ManifestPayloadV1, MetadataV1, SandboxPath, TreeManifestV1, TreeRoleV1,
    XattrV1,
};

#[derive(Debug, Eq, PartialEq)]
pub(super) enum SnapshotManifestCompileErrorV1 {
    PlanMismatch,
    MalformedPlan,
    VisibleXattrUnrepresentable,
    AllocationFailed,
    Canonical(LinuxPytestContractError),
}

impl From<LinuxPytestContractError> for SnapshotManifestCompileErrorV1 {
    fn from(error: LinuxPytestContractError) -> Self {
        Self::Canonical(error)
    }
}

/// Consume one caller-selected logical-source plan and the paired destination
/// plan whose bytes it projects to, then compile the existing frozen
/// `TreeManifestV1` representation. This function does not prove either plan
/// stable; the connector must enforce that precondition before calling it.
///
/// The destination payload supplies regular-file content digests/extents,
/// symlink targets, and xattrs. Source metadata supplies the logical mode,
/// uid/gid, timestamps, link count, and directory size. A structural equality
/// check is retained here as defense in depth; physical destination mode,
/// owner, and identity remain the verifier's responsibility.
pub(super) fn compile_tree_manifest(
    source: SourceTreePlanV1,
    destination: SourceTreePlanV1,
    mount_path: SandboxPath,
    tree_role: TreeRoleV1,
) -> Result<TreeManifestV1, SnapshotManifestCompileErrorV1> {
    validate_manifest_projection_pair(&source, &destination)?;

    let (_, source_entries, source_groups, _) = source.into_parts();
    let (_, destination_entries, _, _) = destination.into_parts();

    let group_digests = compile_hardlink_group_digests(&source_entries, &source_groups)?;
    let entry_count = source_entries.len();
    let mut entries_reversed = Vec::<ManifestEntryV1>::new();
    entries_reversed
        .try_reserve_exact(entry_count)
        .map_err(|_| SnapshotManifestCompileErrorV1::AllocationFailed)?;

    let entry_pairs = Vec::from(source_entries)
        .into_iter()
        .zip(Vec::from(destination_entries))
        .enumerate();
    for (original_index, (source, destination)) in entry_pairs.rev() {
        // Every directory child must have a greater ascending-plan index, so
        // its completed manifest entry already exists in the reverse output
        // at `entry_count - 1 - child_index`.
        let (relative_path, _, _, statx, _, _, hardlink_group_index) = source.into_parts();
        let (_, _, _, _, destination_xattrs, destination_payload, _) = destination.into_parts();
        let (mode, logical_uid, logical_gid, nlink, size, atime, mtime, ctime, btime) =
            statx.into_manifest_parts();
        let metadata = MetadataV1 {
            mode,
            logical_uid,
            logical_gid,
            size,
            nlink,
            atime,
            mtime,
            ctime,
            btime,
            // Pair validation proves equality with S1; moving D2's bytes
            // preserves destination provenance in the compiled manifest.
            xattrs: compile_xattrs(destination_xattrs)?,
        };
        let hardlink_group = hardlink_group_index
            .map(|index| {
                group_digests
                    .get(index as usize)
                    .copied()
                    .ok_or(SnapshotManifestCompileErrorV1::MalformedPlan)
            })
            .transpose()?;

        let payload = match destination_payload {
            SourcePlanPayloadV1::Directory { children } => {
                let mut commitments = Vec::new();
                commitments
                    .try_reserve_exact(children.len())
                    .map_err(|_| SnapshotManifestCompileErrorV1::AllocationFailed)?;
                for child_index in Vec::from(children) {
                    let child_index = child_index as usize;
                    if child_index <= original_index || child_index >= entry_count {
                        return Err(SnapshotManifestCompileErrorV1::MalformedPlan);
                    }
                    let reverse_index = entry_count
                        .checked_sub(1)
                        .and_then(|last| last.checked_sub(child_index))
                        .ok_or(SnapshotManifestCompileErrorV1::MalformedPlan)?;
                    let child = entries_reversed
                        .get(reverse_index)
                        .ok_or(SnapshotManifestCompileErrorV1::MalformedPlan)?;
                    let name = child
                        .relative_path
                        .rsplit(|byte| *byte == b'/')
                        .next()
                        .filter(|name| !name.is_empty())
                        .ok_or(SnapshotManifestCompileErrorV1::MalformedPlan)?;
                    commitments.push(ChildCommitmentV1 {
                        name: name.to_vec(),
                        kind: child.payload.kind(),
                        node_digest: child.node_digest,
                    });
                }
                ManifestPayloadV1::Directory {
                    children: commitments,
                }
            }
            SourcePlanPayloadV1::Regular { evidence } => {
                let (content_digest, data_extents) = evidence.into_parts();
                ManifestPayloadV1::Regular {
                    content_digest,
                    data_extents,
                }
            }
            SourcePlanPayloadV1::Symlink { target } => ManifestPayloadV1::Symlink { target },
        };
        entries_reversed.push(ManifestEntryV1::with_computed_node_digest(
            Vec::from(relative_path),
            metadata,
            payload,
            hardlink_group,
        )?);
    }
    entries_reversed.reverse();

    let root_digest = entries_reversed
        .first()
        .map(|entry| entry.node_digest)
        .ok_or(SnapshotManifestCompileErrorV1::MalformedPlan)?;
    let manifest = TreeManifestV1 {
        mount_path,
        tree_role,
        entries: entries_reversed,
        root_digest,
    };
    manifest.validate()?;
    Ok(manifest)
}

fn validate_manifest_projection_pair(
    source: &SourceTreePlanV1,
    destination: &SourceTreePlanV1,
) -> Result<(), SnapshotManifestCompileErrorV1> {
    if source.has_unsettable_xattrs() || destination.has_unsettable_xattrs() {
        return Err(SnapshotManifestCompileErrorV1::VisibleXattrUnrepresentable);
    }
    if source.root_name() != destination.root_name()
        || source.entries().is_empty()
        || source.entries().len() != destination.entries().len()
        || source.hardlink_groups().len() != destination.hardlink_groups().len()
    {
        return Err(SnapshotManifestCompileErrorV1::PlanMismatch);
    }
    for (source, destination) in source.entries().iter().zip(destination.entries()) {
        if source.relative_path() != destination.relative_path()
            || source.basename() != destination.basename()
            || source.parent_index() != destination.parent_index()
            || source.payload() != destination.payload()
            || source.xattrs() != destination.xattrs()
            || source.hardlink_group() != destination.hardlink_group()
        {
            return Err(SnapshotManifestCompileErrorV1::PlanMismatch);
        }
    }
    if source
        .hardlink_groups()
        .iter()
        .zip(destination.hardlink_groups())
        .any(|(source, destination)| source.member_indices() != destination.member_indices())
    {
        return Err(SnapshotManifestCompileErrorV1::PlanMismatch);
    }
    Ok(())
}

fn compile_xattrs(
    xattrs: Box<[super::snapshot_tree::CapturedXattrV1]>,
) -> Result<Vec<XattrV1>, SnapshotManifestCompileErrorV1> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(xattrs.len())
        .map_err(|_| SnapshotManifestCompileErrorV1::AllocationFailed)?;
    for xattr in Vec::from(xattrs) {
        let (name, value) = xattr.into_parts();
        let CapturedXattrValueV1::Bytes(value) = value else {
            return Err(SnapshotManifestCompileErrorV1::VisibleXattrUnrepresentable);
        };
        output.push(XattrV1 {
            name: Vec::from(name),
            value: Vec::from(value),
        });
    }
    Ok(output)
}

fn compile_hardlink_group_digests(
    entries: &[SourceTreeEntryV1],
    groups: &[super::snapshot_tree::SourceHardlinkGroupV1],
) -> Result<Vec<HardlinkGroupDigest>, SnapshotManifestCompileErrorV1> {
    let mut output = Vec::new();
    output
        .try_reserve_exact(groups.len())
        .map_err(|_| SnapshotManifestCompileErrorV1::AllocationFailed)?;
    for group in groups {
        let mut paths = Vec::new();
        paths
            .try_reserve_exact(group.member_indices().len())
            .map_err(|_| SnapshotManifestCompileErrorV1::AllocationFailed)?;
        for index in group.member_indices() {
            paths.push(
                entries
                    .get(*index as usize)
                    .ok_or(SnapshotManifestCompileErrorV1::MalformedPlan)?
                    .relative_path(),
            );
        }
        if paths.len() < 2 || paths.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(SnapshotManifestCompileErrorV1::MalformedPlan);
        }
        let encoded = canonical::encode_paths_for_hash(&paths)?;
        output.push(HardlinkGroupDigest::derive(
            HARDLINK_GROUP_DOMAIN,
            &[&encoded],
        ));
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linux_pytest::snapshot_tree::{
        CapturedXattrV1, SourceHardlinkGroupV1, SourceRegularEvidenceV1, SourceStatxV1,
        SourceTreeEntryV1,
    };
    use crate::linux_pytest::{ExtentV1, FILE_CONTENT_DOMAIN, FileContentDigest, TimespecV1};

    const S_IFDIR: u32 = 0o040_000;
    const S_IFREG: u32 = 0o100_000;

    fn time(seconds: i64) -> TimespecV1 {
        TimespecV1 {
            seconds,
            nanoseconds: 17,
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn statx(
        source: bool,
        inode: u64,
        mode: u32,
        nlink: u64,
        size: u64,
        atime: i64,
        mtime: i64,
        ctime: i64,
        btime: Option<i64>,
    ) -> SourceStatxV1 {
        SourceStatxV1::for_test(
            if source { 1 } else { 11 },
            if source { 2 } else { 22 },
            if source { 3 } else { 33 },
            inode,
            mode,
            if source { 10 } else { 1_000 },
            if source { 20 } else { 2_000 },
            nlink,
            size,
            time(atime),
            time(mtime),
            time(ctime),
            btime.map(time),
        )
    }

    fn regular_evidence(seed: u8, size: u64) -> SourceRegularEvidenceV1 {
        SourceRegularEvidenceV1::checked(
            FileContentDigest::derive(FILE_CONTENT_DOMAIN, &[&[seed]]),
            (size != 0)
                .then_some(ExtentV1 {
                    offset: 0,
                    length: size,
                })
                .into_iter()
                .collect(),
            size,
        )
        .unwrap()
    }

    fn fixture(seed: u8, raw_name: &[u8]) -> (SourceTreePlanV1, SourceTreePlanV1) {
        let root = |source| {
            SourceTreeEntryV1::unchecked_for_test(
                b"",
                b"source-root",
                None,
                statx(
                    source,
                    1,
                    S_IFDIR | if source { 0o775 } else { 0o555 },
                    2,
                    if source { 4_096 } else { 8_192 },
                    1,
                    2,
                    if source { 3 } else { 300 },
                    Some(if source { 4 } else { 400 }),
                ),
                Vec::new(),
                SourcePlanPayloadV1::Directory {
                    children: vec![1].into_boxed_slice(),
                },
                None,
            )
        };
        let regular = |source| {
            SourceTreeEntryV1::unchecked_for_test(
                raw_name,
                raw_name,
                Some(0),
                statx(
                    source,
                    2,
                    S_IFREG | if source { 0o640 } else { 0o440 },
                    1,
                    4,
                    5,
                    6,
                    if source { 7 } else { 700 },
                    Some(if source { 8 } else { 800 }),
                ),
                vec![CapturedXattrV1::bytes_for_test(b"user.again", b"value")],
                SourcePlanPayloadV1::Regular {
                    evidence: regular_evidence(seed, 4),
                },
                None,
            )
        };
        (
            SourceTreePlanV1::unchecked_for_test(
                b"source-root",
                vec![root(true), regular(true)],
                Vec::new(),
                false,
            ),
            SourceTreePlanV1::unchecked_for_test(
                b"source-root",
                vec![root(false), regular(false)],
                Vec::new(),
                false,
            ),
        )
    }

    fn workspace_path() -> SandboxPath {
        SandboxPath::new(b"/workspace".to_vec().into_boxed_slice()).unwrap()
    }

    fn directory_entry(
        source: bool,
        path: &[u8],
        basename: &[u8],
        parent: Option<u32>,
        inode: u64,
        children: Vec<u32>,
    ) -> SourceTreeEntryV1 {
        SourceTreeEntryV1::unchecked_for_test(
            path,
            basename,
            parent,
            statx(
                source,
                inode,
                S_IFDIR | if source { 0o755 } else { 0o555 },
                2,
                if source { 4_096 } else { 8_192 },
                1,
                2,
                if source { 3 } else { 300 },
                None,
            ),
            Vec::new(),
            SourcePlanPayloadV1::Directory {
                children: children.into_boxed_slice(),
            },
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn regular_entry(
        source: bool,
        path: &[u8],
        basename: &[u8],
        parent: u32,
        inode: u64,
        nlink: u64,
        seed: u8,
        hardlink_group: Option<u32>,
    ) -> SourceTreeEntryV1 {
        SourceTreeEntryV1::unchecked_for_test(
            path,
            basename,
            Some(parent),
            statx(
                source,
                inode,
                S_IFREG | if source { 0o644 } else { 0o444 },
                nlink,
                4,
                5,
                6,
                if source { 7 } else { 700 },
                None,
            ),
            Vec::new(),
            SourcePlanPayloadV1::Regular {
                evidence: regular_evidence(seed, 4),
            },
            hardlink_group,
        )
    }

    #[test]
    fn compiler_uses_logical_source_metadata_and_destination_content_evidence() {
        let (source, destination) = fixture(0x41, b"file");
        let compiled =
            compile_tree_manifest(source, destination, workspace_path(), TreeRoleV1::Workspace)
                .unwrap();
        compiled.validate().unwrap();

        assert_eq!(compiled.entries[0].metadata.mode, S_IFDIR | 0o775);
        assert_eq!(compiled.entries[0].metadata.logical_uid, 10);
        assert_eq!(compiled.entries[0].metadata.logical_gid, 20);
        assert_eq!(compiled.entries[0].metadata.size, 4_096);
        assert_eq!(compiled.entries[0].metadata.ctime, time(3));
        assert_eq!(compiled.entries[0].metadata.btime, Some(time(4)));
        assert_eq!(compiled.entries[1].metadata.mode, S_IFREG | 0o640);
        let ManifestPayloadV1::Regular {
            content_digest,
            data_extents,
        } = &compiled.entries[1].payload
        else {
            panic!("regular fixture must compile as regular");
        };
        assert_eq!(
            *content_digest,
            FileContentDigest::derive(FILE_CONTENT_DOMAIN, &[&[0x41]])
        );
        assert_eq!(
            data_extents,
            &[ExtentV1 {
                offset: 0,
                length: 4
            }]
        );
    }

    #[test]
    fn raw_non_utf8_paths_are_preserved() {
        let (source, destination) = fixture(0x63, b"\xff");
        let compiled =
            compile_tree_manifest(source, destination, workspace_path(), TreeRoleV1::Workspace)
                .unwrap();
        assert_eq!(compiled.entries[1].relative_path, b"\xff");
        let ManifestPayloadV1::Directory { children } = &compiled.entries[0].payload else {
            panic!("root must be a directory");
        };
        assert_eq!(children[0].name, b"\xff");
    }

    #[test]
    fn nested_directories_are_hashed_bottom_up() {
        let plan = |source| {
            SourceTreePlanV1::unchecked_for_test(
                b"source-root",
                vec![
                    directory_entry(source, b"", b"source-root", None, 1, vec![1]),
                    directory_entry(source, b"dir", b"dir", Some(0), 2, vec![2]),
                    regular_entry(source, b"dir/file", b"file", 1, 3, 1, 0x91, None),
                ],
                Vec::new(),
                false,
            )
        };
        let compiled = compile_tree_manifest(
            plan(true),
            plan(false),
            workspace_path(),
            TreeRoleV1::Workspace,
        )
        .unwrap();
        let entries = &compiled.entries;
        let ManifestPayloadV1::Directory { children: nested } = &entries[1].payload else {
            panic!("nested entry must be a directory");
        };
        assert_eq!(nested[0].node_digest, entries[2].node_digest);
        let ManifestPayloadV1::Directory { children: root } = &entries[0].payload else {
            panic!("root entry must be a directory");
        };
        assert_eq!(root[0].node_digest, entries[1].node_digest);
        assert_eq!(compiled.root_digest, entries[0].node_digest);
    }

    #[test]
    fn hardlink_group_digest_commits_sorted_member_paths() {
        let plan = |source| {
            let first = regular_entry(source, b"a", b"a", 0, 2, 2, 0xa2, Some(0));
            let second = regular_entry(source, b"b", b"b", 0, 2, 2, 0xa2, Some(0));
            let group = SourceHardlinkGroupV1::unchecked_for_test(
                first.statx().inode_key().clone(),
                vec![1, 2],
            );
            SourceTreePlanV1::unchecked_for_test(
                b"source-root",
                vec![
                    directory_entry(source, b"", b"source-root", None, 1, vec![1, 2]),
                    first,
                    second,
                ],
                vec![group],
                false,
            )
        };
        let compiled = compile_tree_manifest(
            plan(true),
            plan(false),
            workspace_path(),
            TreeRoleV1::Workspace,
        )
        .unwrap();
        let paths = [b"a".as_slice(), b"b".as_slice()];
        let encoded = canonical::encode_paths_for_hash(&paths).unwrap();
        let expected = HardlinkGroupDigest::derive(HARDLINK_GROUP_DOMAIN, &[&encoded]);
        assert_eq!(compiled.entries[1].hardlink_group, Some(expected));
        assert_eq!(compiled.entries[2].hardlink_group, Some(expected));
        assert_eq!(
            compiled.entries[1].node_digest,
            compiled.entries[2].node_digest
        );
    }

    #[test]
    fn mismatched_destination_payload_is_rejected_before_compilation() {
        let (source, mut destination) = fixture(0x74, b"file");
        let (_, entries, groups, unsettable) = destination.into_parts();
        let mut entries = Vec::from(entries);
        let old = entries.remove(1);
        let (path, basename, parent, statx, xattrs, _, hardlink) = old.into_parts();
        entries.push(SourceTreeEntryV1::unchecked_for_test(
            &path,
            &basename,
            parent,
            statx,
            Vec::from(xattrs),
            SourcePlanPayloadV1::Regular {
                evidence: regular_evidence(0x75, 4),
            },
            hardlink,
        ));
        destination = SourceTreePlanV1::unchecked_for_test(
            b"source-root",
            entries,
            Vec::from(groups),
            unsettable,
        );
        assert_eq!(
            compile_tree_manifest(source, destination, workspace_path(), TreeRoleV1::Workspace)
                .unwrap_err(),
            SnapshotManifestCompileErrorV1::PlanMismatch
        );
    }

    #[test]
    fn visible_but_unsettable_xattr_is_never_encoded() {
        let root = |source| {
            SourceTreeEntryV1::unchecked_for_test(
                b"",
                b"source-root",
                None,
                statx(source, 1, S_IFDIR | 0o555, 2, 4_096, 1, 2, 3, None),
                vec![CapturedXattrV1::unsettable_for_test(
                    b"security.test",
                    libc::EPERM,
                )],
                SourcePlanPayloadV1::Directory {
                    children: Vec::new().into_boxed_slice(),
                },
                None,
            )
        };
        let source =
            SourceTreePlanV1::unchecked_for_test(b"source-root", vec![root(true)], vec![], true);
        let destination =
            SourceTreePlanV1::unchecked_for_test(b"source-root", vec![root(false)], vec![], true);
        assert_eq!(
            compile_tree_manifest(source, destination, workspace_path(), TreeRoleV1::Workspace)
                .unwrap_err(),
            SnapshotManifestCompileErrorV1::VisibleXattrUnrepresentable
        );
    }

    #[test]
    fn malformed_parent_membership_is_rejected_without_panicking() {
        let (source, destination) = fixture(0x85, b"file");
        let corrupt = |plan: SourceTreePlanV1| {
            let (root_name, entries, groups, unsettable) = plan.into_parts();
            let mut entries = Vec::from(entries);
            let root = entries.remove(0);
            let (path, basename, parent, statx, xattrs, _, hardlink) = root.into_parts();
            entries.insert(
                0,
                SourceTreeEntryV1::unchecked_for_test(
                    &path,
                    &basename,
                    parent,
                    statx,
                    Vec::from(xattrs),
                    SourcePlanPayloadV1::Directory {
                        children: vec![99].into_boxed_slice(),
                    },
                    hardlink,
                ),
            );
            SourceTreePlanV1::unchecked_for_test(&root_name, entries, Vec::from(groups), unsettable)
        };
        assert_eq!(
            compile_tree_manifest(
                corrupt(source),
                corrupt(destination),
                workspace_path(),
                TreeRoleV1::Workspace,
            )
            .unwrap_err(),
            SnapshotManifestCompileErrorV1::MalformedPlan
        );
    }
}
