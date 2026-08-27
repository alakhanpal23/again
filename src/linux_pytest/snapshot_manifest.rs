//! Charged compilation of a verifier-minted stable S1/D2 projection.
//!
//! The production-shaped, non-test compiler consumes the non-forgeable
//! four-view verifier result, moves plan-owned nested buffers under both
//! retained-view leases, charges every new outer container to the
//! persistent-manifest ledger, hashes nodes through allocation-free canonical
//! projections, and retains exact canonical tree bytes plus the 102-byte D2
//! `SourceStatxV1` commitment.
//!
//! The FD-free compiler result is still data, not authority. The integrated
//! connector keeps it live while binding the exact published child, then
//! returns `PublishedCanonicalTreeV1`: paired physical and canonical evidence
//! that still cannot grant isolation, execution, or reuse. The old
//! allocation-heavy owning compiler is retained only under `cfg(test)` as an
//! independent parity oracle.
//! Per-field hard ceilings are refusal bounds, not a promise that every
//! Cartesian-maximum plan fits the persistent envelope; exact precharge may
//! reject such a plan before result construction.

use super::canonical;
use super::execute_only_admission::{
    FIRST_EXECUTE_ONLY_FIXTURE_BYTES_V1, FirstExecuteOnlyLexicalAdmissionV1,
};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use super::snapshot_connector::{
    SnapshotChargedErrorV1, SnapshotConnectorV1, SnapshotPipelineFourViewErrorV1,
};
use super::snapshot_connector::{
    SnapshotManifestCompilationSessionV1, consume_stable_manifest_projection,
};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use super::snapshot_materialize::projected_materialized_permissions;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use super::snapshot_policy::SnapshotPublishedChildBindReservationV1;
use super::snapshot_policy::{
    SnapshotManifestCompilationVecV1, SnapshotPipelineResourceErrorV1, SnapshotRetainedViewLeaseV1,
};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use super::snapshot_publish::{
    BoundPublishedSnapshotChildV1, BoundRegularReadRefusalV1, RuntimeMemoryEscrowV1,
    SnapshotPublishAndBindErrorV1, SnapshotPublishErrorV1, SnapshotPublishedChildBindErrorV1,
    ValidatedBoundRelativePathV1, VerifiedBoundNodeKindV1, VerifiedBoundRegularBytesV1,
    read_bound_regular_bytes_v1, revalidate_bound_published_snapshot_root_v1,
    revalidate_bound_regular_bytes_v1, seal_publish_and_bind_snapshot_child_at,
    validate_snapshot_final_name,
};
#[cfg(all(test, target_os = "linux", target_arch = "x86_64"))]
use super::snapshot_publish::{
    bound_published_snapshot_directory_fd, bound_published_snapshot_root_fd,
};
use super::snapshot_tree::{
    CapturedXattrValueV1, SourcePlanPayloadV1, SourceTreeEntryV1, SourceTreePlanV1,
};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use super::snapshot_tree::{QualifiedNoAtimeSourceViewV1, SourceNodeKindV1};
use super::snapshot_verify::StableManifestProjectionV1;
use super::{
    ChildCommitmentV1, FILE_CONTENT_DOMAIN, FileContentDigest, HardlinkGroupDigest,
    LinuxPytestContractError, ManifestEntryKindV1, NodeDigest, RefusalCode, TimespecV1, TreeRoleV1,
    XattrV1,
};
#[cfg(test)]
use super::{
    HARDLINK_GROUP_DOMAIN, ManifestEntryV1, ManifestPayloadV1, MetadataV1, SandboxPath,
    TreeManifestV1,
};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::ffi::CStr;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::fmt;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use std::os::fd::BorrowedFd;

#[derive(Debug, Eq, PartialEq)]
pub(super) enum SnapshotManifestCompileErrorV1 {
    AuthorityMismatch,
    PlanMismatch,
    MalformedPlan,
    VisibleXattrUnrepresentable,
    #[cfg(test)]
    AllocationFailed,
    Resource(SnapshotPipelineResourceErrorV1),
    Canonical(LinuxPytestContractError),
}

impl From<LinuxPytestContractError> for SnapshotManifestCompileErrorV1 {
    fn from(error: LinuxPytestContractError) -> Self {
        Self::Canonical(error)
    }
}

impl From<SnapshotPipelineResourceErrorV1> for SnapshotManifestCompileErrorV1 {
    fn from(error: SnapshotPipelineResourceErrorV1) -> Self {
        Self::Resource(error)
    }
}

/// Linear handoff from one verified D2 manifest and the exact publication
/// ledger to the descriptor-binding leaf. Private fields make raw commitment
/// bytes and caller-created reservations insufficient to construct it.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[must_use = "a prepared published-child bind must be consumed or its escrow is refunded"]
pub(super) struct SnapshotPreparedPublishedChildBindV1<'resources, 'evidence> {
    reservation: SnapshotPublishedChildBindReservationV1<'resources>,
    root_name: &'evidence CStr,
    manifest: &'evidence ChargedTreeManifestV1<'resources>,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl<'resources, 'evidence> SnapshotPreparedPublishedChildBindV1<'resources, 'evidence> {
    pub(super) fn into_leaf_parts(
        self,
    ) -> (
        &'evidence CStr,
        [u8; 102],
        SnapshotPublishedChildBindReservationV1<'resources>,
    ) {
        (
            self.root_name,
            *self.manifest.destination_root_statx_commitment_v1(),
            self.reservation,
        )
    }
}

/// Physical published-tree descriptors paired with the exact charged
/// canonical manifest that proved their D2 root identity. Physical fields are
/// dropped first. This remains snapshot evidence, not execution/reuse
/// authority; later isolation must address the same-UID mutation boundary.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) struct PublishedCanonicalTreeV1<'resources> {
    physical: BoundPublishedSnapshotChildV1,
    manifest: ChargedTreeManifestV1<'resources>,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl PublishedCanonicalTreeV1<'_> {
    pub(super) const fn manifest(&self) -> &ChargedTreeManifestV1<'_> {
        &self.manifest
    }

    /// Test-only physical inspection. Production intentionally exposes no
    /// clonable descriptor borrow from the canonical composite.
    #[cfg(test)]
    pub(super) fn published_directory(&self) -> BorrowedFd<'_> {
        bound_published_snapshot_directory_fd(&self.physical)
    }

    /// Test-only physical inspection. A future isolation transition must
    /// consume the opaque composite rather than detach this child descriptor.
    #[cfg(test)]
    pub(super) fn root_directory(&self) -> BorrowedFd<'_> {
        bound_published_snapshot_root_fd(&self.physical)
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl fmt::Debug for PublishedCanonicalTreeV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PublishedCanonicalTreeV1")
            .field("physical", &self.physical)
            .field("manifest", &"<charged-canonical-manifest>")
            .finish()
    }
}

/// Linear Gate 3 binding between the exact lexical fixture and one
/// connector-published workspace tree.
///
/// This is only workspace-tree evidence. It deliberately exposes neither the
/// published descriptors nor canonical manifest bytes, and it cannot be
/// converted into a sealed runtime snapshot, execution request, candidate, or
/// reuse authority. Runtime-tree and isolation composition remain separate
/// future gates.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) struct FirstExecuteOnlyWorkspaceTreeBindingV1<'resources> {
    lexical: FirstExecuteOnlyLexicalAdmissionV1,
    workspace: PublishedCanonicalTreeV1<'resources>,
}

const FIRST_EXECUTE_ONLY_EXECUTABLE_V1: &[u8] = b".venv/bin/python";
const FIRST_EXECUTE_ONLY_EXECUTABLE_MAX_BYTES_V1: u32 = 16 * 1024 * 1024;

/// Stable, payload-free failures while consuming workspace evidence into the
/// first executable-byte projection. None is a success-like classification.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1 {
    InvalidFixedExecutable,
    PathComponentLimit,
    SymlinkLimit,
    SymlinkCycle,
    SymlinkTarget,
    MissingNode,
    MountCrossing,
    MagicLink,
    NodeType,
    IdentityDrift,
    SizeMismatch,
    ByteLimit,
    ShortRead,
    Io,
    MemoryBudget,
    ManifestNodeMissing,
    ManifestNodeAmbiguous,
    ManifestKindMismatch,
    ManifestMetadataMismatch,
    ManifestSymlinkMismatch,
    ManifestContentMismatch,
    ManifestDigestMismatch,
    ManifestRootMismatch,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) struct FirstExecuteOnlyRuntimeNodeBindingV1 {
    normalized_path: Box<[u8]>,
    normalized_next_path: Option<Box<[u8]>>,
    kind: VerifiedBoundNodeKindV1,
    statx_commitment: [u8; 102],
    node_digest: NodeDigest,
    logical_mode: u32,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl FirstExecuteOnlyRuntimeNodeBindingV1 {
    pub(super) fn normalized_path(&self) -> &[u8] {
        &self.normalized_path
    }

    pub(super) fn normalized_next_path(&self) -> Option<&[u8]> {
        self.normalized_next_path.as_deref()
    }

    pub(super) const fn kind(&self) -> VerifiedBoundNodeKindV1 {
        self.kind
    }

    pub(super) const fn statx_commitment(&self) -> &[u8; 102] {
        &self.statx_commitment
    }

    pub(super) const fn node_digest(&self) -> NodeDigest {
        self.node_digest
    }

    pub(super) const fn logical_mode(&self) -> u32 {
        self.logical_mode
    }
}

/// Linear operation-specific projection. It retains the exact connector-owned
/// physical and charged canonical tree evidence together with verified bytes;
/// it exposes no descriptor and cannot mint execution authority.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) struct FirstExecuteOnlyWorkspaceRuntimeEvidenceV1<'resources> {
    binding: FirstExecuteOnlyWorkspaceTreeBindingV1<'resources>,
    verified: VerifiedBoundRegularBytesV1,
    nodes: Vec<FirstExecuteOnlyRuntimeNodeBindingV1>,
    terminal_node_digest: NodeDigest,
    terminal_logical_mode: u32,
    runtime_memory: RuntimeMemoryEscrowV1,
}

/// Linear designation of an actually connector-published canonical tree as
/// the runtime-side input to the non-authoritative structural inventory.
/// Construction consumes the publication token; no descriptor-based relabel
/// operation exists.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) struct FirstExecuteOnlyPublishedRuntimeTreeV1<'resources> {
    tree: PublishedCanonicalTreeV1<'resources>,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl FirstExecuteOnlyPublishedRuntimeTreeV1<'_> {
    pub(super) const fn root_digest(&self) -> NodeDigest {
        self.tree.manifest.root_digest()
    }

    pub(super) const fn root_statx_commitment(&self) -> &[u8; 102] {
        self.tree.manifest.destination_root_statx_commitment_v1()
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl fmt::Debug for FirstExecuteOnlyPublishedRuntimeTreeV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("FirstExecuteOnlyPublishedRuntimeTreeV1(<opaque-publication>)")
    }
}

/// Stable, payload-free root-pair revalidation failures. The role remains
/// explicit so a workspace root can never be silently substituted for the
/// independently published runtime root.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum FirstExecuteOnlyPublishedRootPairRefusalV1 {
    WorkspaceIdentityDrift,
    WorkspaceIo,
    RuntimeIdentityDrift,
    RuntimeIo,
}

/// Opaque, linear ownership of the two role-separated publication composites.
/// The physical roots remain reachable only inside this module, so a future
/// sealed attachment leaf can consume this type and perform its syscalls here
/// without adding a raw descriptor/path accessor or arbitrary callback seam.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[must_use = "the two publication-root owners must be consumed or explicitly dropped"]
pub(super) struct FirstExecuteOnlyRetainedPublishedRootPairV1<'resources> {
    workspace: FirstExecuteOnlyWorkspaceRuntimeEvidenceV1<'resources>,
    runtime: FirstExecuteOnlyPublishedRuntimeTreeV1<'resources>,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl fmt::Debug for FirstExecuteOnlyRetainedPublishedRootPairV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FirstExecuteOnlyRetainedPublishedRootPairV1")
            .field("workspace_root", &"<retained-redacted>")
            .field("runtime_root", &"<retained-redacted>")
            .finish()
    }
}

/// Consume and revalidate both typed publication roots into the only
/// operation-specific owner that a future manifest-local attachment leaf may
/// accept. Descriptors, root names, and host paths never escape. This remains
/// a point-in-time same-process proof and does not claim protection against
/// same-UID peers or host root; the attachment leaf must revalidate again at
/// its own irreversible boundary.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) fn consume_first_execute_only_retained_published_root_pair_v1<'resources>(
    workspace: FirstExecuteOnlyWorkspaceRuntimeEvidenceV1<'resources>,
    runtime: FirstExecuteOnlyPublishedRuntimeTreeV1<'resources>,
) -> Result<
    FirstExecuteOnlyRetainedPublishedRootPairV1<'resources>,
    FirstExecuteOnlyPublishedRootPairRefusalV1,
> {
    revalidate_first_execute_only_published_tree_root_v1(&workspace.binding.workspace).map_err(
        |error| map_root_pair_refusal_v1(error, FirstExecuteOnlyInventoryRootV1::Workspace),
    )?;
    revalidate_first_execute_only_published_tree_root_v1(&runtime.tree).map_err(|error| {
        map_root_pair_refusal_v1(error, FirstExecuteOnlyInventoryRootV1::Runtime)
    })?;
    Ok(FirstExecuteOnlyRetainedPublishedRootPairV1 { workspace, runtime })
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn revalidate_first_execute_only_published_tree_root_v1(
    tree: &PublishedCanonicalTreeV1<'_>,
) -> Result<(), BoundRegularReadRefusalV1> {
    const LINUX_NAME_MAX_V1: usize = 255;
    let root_name = tree.manifest.root_name();
    if root_name.is_empty() || root_name.len() > LINUX_NAME_MAX_V1 || root_name.contains(&0) {
        return Err(BoundRegularReadRefusalV1::InvalidPath);
    }
    let mut nul_terminated = [0u8; LINUX_NAME_MAX_V1 + 1];
    nul_terminated[..root_name.len()].copy_from_slice(root_name);
    let root_name = CStr::from_bytes_with_nul(&nul_terminated[..root_name.len() + 1])
        .map_err(|_| BoundRegularReadRefusalV1::InvalidPath)?;
    revalidate_bound_published_snapshot_root_v1(
        &tree.physical,
        root_name,
        *tree.manifest.destination_root_statx_commitment_v1(),
    )
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
const fn map_root_pair_refusal_v1(
    refusal: BoundRegularReadRefusalV1,
    role: FirstExecuteOnlyInventoryRootV1,
) -> FirstExecuteOnlyPublishedRootPairRefusalV1 {
    let identity = !matches!(refusal, BoundRegularReadRefusalV1::Io);
    match (role, identity) {
        (FirstExecuteOnlyInventoryRootV1::Workspace, true) => {
            FirstExecuteOnlyPublishedRootPairRefusalV1::WorkspaceIdentityDrift
        }
        (FirstExecuteOnlyInventoryRootV1::Workspace, false) => {
            FirstExecuteOnlyPublishedRootPairRefusalV1::WorkspaceIo
        }
        (FirstExecuteOnlyInventoryRootV1::Runtime, true) => {
            FirstExecuteOnlyPublishedRootPairRefusalV1::RuntimeIdentityDrift
        }
        (FirstExecuteOnlyInventoryRootV1::Runtime, false) => {
            FirstExecuteOnlyPublishedRootPairRefusalV1::RuntimeIo
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
#[derive(Clone, Copy, Eq, PartialEq)]
enum FirstExecuteOnlyInventoryRootV1 {
    Workspace,
    Runtime,
}

/// One manifest-reconciled object plus every descriptor pin required for a
/// final whole-inventory stability pass. Bytes and descriptors never escape.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) struct FirstExecuteOnlyRuntimeInventoryObjectV1 {
    root: FirstExecuteOnlyInventoryRootV1,
    verified: VerifiedBoundRegularBytesV1,
    manifest_root_digest: NodeDigest,
    manifest_root_statx_commitment: [u8; 102],
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl FirstExecuteOnlyRuntimeInventoryObjectV1 {
    pub(super) fn bytes(&self) -> &[u8] {
        self.verified.bytes()
    }

    pub(super) fn terminal_identity(&self) -> &[u8; 102] {
        self.verified
            .nodes()
            .last()
            .expect("reconciled object has a terminal node")
            .statx_commitment()
    }

    pub(super) fn pinned_fd_count(&self) -> usize {
        self.verified.pinned_fd_count()
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl fmt::Debug for FirstExecuteOnlyRuntimeInventoryObjectV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FirstExecuteOnlyRuntimeInventoryObjectV1")
            .field("bytes", &"<redacted>")
            .field("descriptors", &"<redacted>")
            .field("authority", &false)
            .finish()
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl FirstExecuteOnlyWorkspaceRuntimeEvidenceV1<'_> {
    pub(super) fn executable_bytes(&self) -> &[u8] {
        self.verified.bytes()
    }

    pub(super) fn nodes(&self) -> &[FirstExecuteOnlyRuntimeNodeBindingV1] {
        &self.nodes
    }

    pub(super) const fn workspace_root_digest(&self) -> NodeDigest {
        self.binding.workspace.manifest.root_digest()
    }

    pub(super) const fn workspace_root_statx_commitment(&self) -> &[u8; 102] {
        self.verified.root_statx_commitment()
    }

    pub(super) const fn terminal_node_digest(&self) -> NodeDigest {
        self.terminal_node_digest
    }

    pub(super) const fn terminal_identity_digest(&self) -> super::Blake3Digest {
        self.verified.terminal_identity_digest()
    }

    pub(super) const fn terminal_content_digest(&self) -> FileContentDigest {
        self.verified.content_digest()
    }

    pub(super) const fn terminal_logical_mode(&self) -> u32 {
        self.terminal_logical_mode
    }

    pub(super) const fn runtime_memory(&self) -> &RuntimeMemoryEscrowV1 {
        &self.runtime_memory
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl fmt::Debug for FirstExecuteOnlyWorkspaceRuntimeEvidenceV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FirstExecuteOnlyWorkspaceRuntimeEvidenceV1")
            .field("binding", &"<opaque-connector-evidence>")
            .field("verified_bytes", &"<redacted>")
            .field("node_count", &self.nodes.len())
            .finish()
    }
}

/// Consume the connector-issued workspace binding and resolve only the fixed
/// Gate 3 executable. The physical descriptor never escapes this operation.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) fn consume_first_execute_only_workspace_runtime_evidence_v1<'resources>(
    binding: FirstExecuteOnlyWorkspaceTreeBindingV1<'resources>,
) -> Result<
    FirstExecuteOnlyWorkspaceRuntimeEvidenceV1<'resources>,
    FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1,
> {
    let runtime_memory = RuntimeMemoryEscrowV1::first_checkpoint();
    let path = ValidatedBoundRelativePathV1::parse_with_memory(
        FIRST_EXECUTE_ONLY_EXECUTABLE_V1,
        &runtime_memory,
    )
    .map_err(map_bound_regular_refusal_v1)?;
    let verified = read_bound_regular_bytes_v1(
        &binding.workspace.physical,
        &path,
        FIRST_EXECUTE_ONLY_EXECUTABLE_MAX_BYTES_V1,
        &runtime_memory,
    )
    .map_err(map_bound_regular_refusal_v1)?;
    if verified.root_statx_commitment()
        != binding
            .workspace
            .manifest
            .destination_root_statx_commitment_v1()
    {
        return Err(FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1::ManifestRootMismatch);
    }
    let mut roots = binding
        .workspace
        .manifest
        .entries
        .as_slice()
        .iter()
        .filter(|entry| entry.relative_path.is_empty());
    let root = roots
        .next()
        .ok_or(FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1::ManifestRootMismatch)?;
    if roots.next().is_some()
        || root.node_digest != binding.workspace.manifest.root_digest()
        || !charged_manifest_entry_digest_consistent_v1(root)
    {
        return Err(FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1::ManifestDigestMismatch);
    }
    if !matches!(&root.payload, ChargedManifestPayloadV1::Directory { .. })
        || !live_manifest_metadata_matches_v1(
            root,
            verified.root_live_statx(),
            verified.root_live_statx(),
        )
    {
        return Err(FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1::ManifestMetadataMismatch);
    }

    let mut nodes = runtime_memory
        .try_vec_with_capacity(verified.nodes().len())
        .map_err(map_bound_regular_refusal_v1)?;
    let mut terminal = None;
    for observed in verified.nodes() {
        let mut matches = binding
            .workspace
            .manifest
            .entries
            .as_slice()
            .iter()
            .filter(|entry| entry.relative_path == observed.normalized_path());
        let entry = matches
            .next()
            .ok_or(FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1::ManifestNodeMissing)?;
        if matches.next().is_some() {
            return Err(FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1::ManifestNodeAmbiguous);
        }
        let manifest_kind = match &entry.payload {
            ChargedManifestPayloadV1::Directory { .. } => VerifiedBoundNodeKindV1::Directory,
            ChargedManifestPayloadV1::Regular { .. } => VerifiedBoundNodeKindV1::Regular,
            ChargedManifestPayloadV1::Symlink { .. } => VerifiedBoundNodeKindV1::Symlink,
        };
        if manifest_kind != observed.kind() {
            return Err(FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1::ManifestKindMismatch);
        }
        if !charged_manifest_entry_digest_consistent_v1(entry) {
            return Err(FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1::ManifestDigestMismatch);
        }
        if !live_manifest_metadata_matches_v1(
            entry,
            observed.live_statx(),
            verified.root_live_statx(),
        ) {
            return Err(
                FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1::ManifestMetadataMismatch,
            );
        }
        if let ChargedManifestPayloadV1::Symlink { target } = &entry.payload
            && observed.symlink_target() != Some(target.as_slice())
        {
            return Err(FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1::ManifestSymlinkMismatch);
        }
        if observed.kind() == VerifiedBoundNodeKindV1::Regular {
            let ChargedManifestPayloadV1::Regular { content_digest, .. } = &entry.payload else {
                unreachable!("kind checked above")
            };
            if *content_digest != verified.content_digest()
                || entry.metadata.size
                    != u64::try_from(verified.bytes().len()).expect("bounded bytes fit u64")
            {
                return Err(
                    FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1::ManifestContentMismatch,
                );
            }
            terminal = Some((entry.node_digest, entry.metadata.mode));
        }
        nodes.push(FirstExecuteOnlyRuntimeNodeBindingV1 {
            normalized_path: runtime_memory
                .try_bytes_from_slice(observed.normalized_path())
                .map_err(map_bound_regular_refusal_v1)?
                .into_boxed_slice(),
            normalized_next_path: observed
                .normalized_next_path()
                .map(|path| {
                    runtime_memory
                        .try_bytes_from_slice(path)
                        .map(Vec::into_boxed_slice)
                })
                .transpose()
                .map_err(map_bound_regular_refusal_v1)?,
            kind: observed.kind(),
            statx_commitment: *observed.statx_commitment(),
            node_digest: entry.node_digest,
            logical_mode: entry.metadata.mode,
        });
    }
    let (terminal_node_digest, terminal_logical_mode) =
        terminal.ok_or(FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1::ManifestNodeMissing)?;
    Ok(FirstExecuteOnlyWorkspaceRuntimeEvidenceV1 {
        binding,
        verified,
        nodes,
        terminal_node_digest,
        terminal_logical_mode,
        runtime_memory,
    })
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) fn read_first_execute_only_workspace_inventory_object_v1(
    evidence: &FirstExecuteOnlyWorkspaceRuntimeEvidenceV1<'_>,
    path: &[u8],
    byte_ceiling: u32,
) -> Result<
    FirstExecuteOnlyRuntimeInventoryObjectV1,
    FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1,
> {
    read_first_execute_only_inventory_object_v1(
        &evidence.binding.workspace,
        FirstExecuteOnlyInventoryRootV1::Workspace,
        path,
        byte_ceiling,
        &evidence.runtime_memory,
    )
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) fn read_first_execute_only_runtime_inventory_object_v1(
    runtime: &FirstExecuteOnlyPublishedRuntimeTreeV1<'_>,
    path: &[u8],
    byte_ceiling: u32,
    memory: &RuntimeMemoryEscrowV1,
) -> Result<
    FirstExecuteOnlyRuntimeInventoryObjectV1,
    FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1,
> {
    read_first_execute_only_inventory_object_v1(
        &runtime.tree,
        FirstExecuteOnlyInventoryRootV1::Runtime,
        path,
        byte_ceiling,
        memory,
    )
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn read_first_execute_only_inventory_object_v1(
    tree: &PublishedCanonicalTreeV1<'_>,
    root_tag: FirstExecuteOnlyInventoryRootV1,
    path: &[u8],
    byte_ceiling: u32,
    memory: &RuntimeMemoryEscrowV1,
) -> Result<
    FirstExecuteOnlyRuntimeInventoryObjectV1,
    FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1,
> {
    let path = ValidatedBoundRelativePathV1::parse_with_memory(path, memory)
        .map_err(map_bound_regular_refusal_v1)?;
    let verified = read_bound_regular_bytes_v1(&tree.physical, &path, byte_ceiling, memory)
        .map_err(map_bound_regular_refusal_v1)?;
    let manifest_root_statx_commitment = *tree.manifest.destination_root_statx_commitment_v1();
    if verified.root_statx_commitment() != &manifest_root_statx_commitment {
        return Err(FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1::ManifestRootMismatch);
    }
    let root = unique_charged_manifest_entry_v1(&tree.manifest, b"")?;
    if root.node_digest != tree.manifest.root_digest()
        || !charged_manifest_entry_digest_consistent_v1(root)
    {
        return Err(FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1::ManifestDigestMismatch);
    }
    if !matches!(&root.payload, ChargedManifestPayloadV1::Directory { .. })
        || !live_manifest_metadata_matches_v1(
            root,
            verified.root_live_statx(),
            verified.root_live_statx(),
        )
    {
        return Err(FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1::ManifestMetadataMismatch);
    }

    let mut terminal = None;
    for observed in verified.nodes() {
        // The structural inventory deliberately refuses even authenticated
        // symlinks: every retained object must be pinned through one exact
        // component chain with no alternate spelling.
        if observed.kind() == VerifiedBoundNodeKindV1::Symlink {
            return Err(FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1::SymlinkTarget);
        }
        let entry = unique_charged_manifest_entry_v1(&tree.manifest, observed.normalized_path())?;
        let manifest_kind = match &entry.payload {
            ChargedManifestPayloadV1::Directory { .. } => VerifiedBoundNodeKindV1::Directory,
            ChargedManifestPayloadV1::Regular { .. } => VerifiedBoundNodeKindV1::Regular,
            ChargedManifestPayloadV1::Symlink { .. } => VerifiedBoundNodeKindV1::Symlink,
        };
        if manifest_kind != observed.kind() {
            return Err(FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1::ManifestKindMismatch);
        }
        if !charged_manifest_entry_digest_consistent_v1(entry) {
            return Err(FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1::ManifestDigestMismatch);
        }
        if !live_manifest_metadata_matches_v1(
            entry,
            observed.live_statx(),
            verified.root_live_statx(),
        ) {
            return Err(
                FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1::ManifestMetadataMismatch,
            );
        }
        if observed.kind() == VerifiedBoundNodeKindV1::Regular {
            let ChargedManifestPayloadV1::Regular { content_digest, .. } = &entry.payload else {
                unreachable!("kind checked above")
            };
            if *content_digest != verified.content_digest()
                || entry.metadata.size
                    != u64::try_from(verified.bytes().len()).expect("bounded bytes fit u64")
            {
                return Err(
                    FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1::ManifestContentMismatch,
                );
            }
            if terminal
                .replace((entry.node_digest, entry.metadata.mode))
                .is_some()
            {
                return Err(
                    FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1::ManifestNodeAmbiguous,
                );
            }
        }
    }
    terminal.ok_or(FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1::ManifestNodeMissing)?;
    Ok(FirstExecuteOnlyRuntimeInventoryObjectV1 {
        root: root_tag,
        verified,
        manifest_root_digest: tree.manifest.root_digest(),
        manifest_root_statx_commitment,
    })
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn unique_charged_manifest_entry_v1<'tree, 'resources>(
    manifest: &'tree ChargedTreeManifestV1<'resources>,
    path: &[u8],
) -> Result<
    &'tree ChargedManifestEntryV1<'resources>,
    FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1,
> {
    let mut matches = manifest
        .entries
        .as_slice()
        .iter()
        .filter(|entry| entry.relative_path == path);
    let entry = matches
        .next()
        .ok_or(FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1::ManifestNodeMissing)?;
    if matches.next().is_some() {
        return Err(FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1::ManifestNodeAmbiguous);
    }
    Ok(entry)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn revalidate_first_execute_only_inventory_object_v1(
    tree: &PublishedCanonicalTreeV1<'_>,
    root_tag: FirstExecuteOnlyInventoryRootV1,
    object: &FirstExecuteOnlyRuntimeInventoryObjectV1,
) -> Result<(), FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1> {
    if object.root != root_tag
        || object.manifest_root_digest != tree.manifest.root_digest()
        || object.manifest_root_statx_commitment
            != *tree.manifest.destination_root_statx_commitment_v1()
    {
        return Err(FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1::ManifestRootMismatch);
    }
    revalidate_bound_regular_bytes_v1(&tree.physical, &object.verified)
        .map_err(map_bound_regular_refusal_v1)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) fn revalidate_first_execute_only_workspace_inventory_object_v1(
    evidence: &FirstExecuteOnlyWorkspaceRuntimeEvidenceV1<'_>,
    object: &FirstExecuteOnlyRuntimeInventoryObjectV1,
) -> Result<(), FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1> {
    revalidate_first_execute_only_inventory_object_v1(
        &evidence.binding.workspace,
        FirstExecuteOnlyInventoryRootV1::Workspace,
        object,
    )
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) fn revalidate_first_execute_only_runtime_inventory_object_v1(
    runtime: &FirstExecuteOnlyPublishedRuntimeTreeV1<'_>,
    object: &FirstExecuteOnlyRuntimeInventoryObjectV1,
) -> Result<(), FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1> {
    revalidate_first_execute_only_inventory_object_v1(
        &runtime.tree,
        FirstExecuteOnlyInventoryRootV1::Runtime,
        object,
    )
}

/// Revalidate one already-role-tagged inventory object through the sealed root
/// pair. The object's private role selects the matching publication owner;
/// callers cannot swap roles or obtain either descriptor.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) fn revalidate_first_execute_only_root_pair_inventory_object_v1(
    roots: &FirstExecuteOnlyRetainedPublishedRootPairV1<'_>,
    object: &FirstExecuteOnlyRuntimeInventoryObjectV1,
) -> Result<(), FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1> {
    match object.root {
        FirstExecuteOnlyInventoryRootV1::Workspace => {
            revalidate_first_execute_only_inventory_object_v1(
                &roots.workspace.binding.workspace,
                FirstExecuteOnlyInventoryRootV1::Workspace,
                object,
            )
        }
        FirstExecuteOnlyInventoryRootV1::Runtime => {
            revalidate_first_execute_only_inventory_object_v1(
                &roots.runtime.tree,
                FirstExecuteOnlyInventoryRootV1::Runtime,
                object,
            )
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn live_manifest_metadata_matches_v1(
    entry: &ChargedManifestEntryV1<'_>,
    live: &super::snapshot_tree::SourceStatxV1,
    physical_root: &super::snapshot_tree::SourceStatxV1,
) -> bool {
    let kind = match &entry.payload {
        ChargedManifestPayloadV1::Directory { .. } => SourceNodeKindV1::Directory,
        ChargedManifestPayloadV1::Regular { .. } => SourceNodeKindV1::Regular,
        ChargedManifestPayloadV1::Symlink { .. } => SourceNodeKindV1::Symlink,
    };
    let expected_type = match kind {
        SourceNodeKindV1::Directory => libc::S_IFDIR,
        SourceNodeKindV1::Regular => libc::S_IFREG,
        SourceNodeKindV1::Symlink => libc::S_IFLNK,
    };
    let permission_match = projected_materialized_permissions(entry.metadata.mode, kind)
        .is_none_or(|permissions| live.mode() & 0o7777 == permissions);
    live.mode() & libc::S_IFMT == expected_type
        && permission_match
        && live.uid() == physical_root.uid()
        && live.gid() == physical_root.gid()
        && live.nlink() == entry.metadata.nlink
        && (kind == SourceNodeKindV1::Directory || live.size() == entry.metadata.size)
        && live.atime() == &entry.metadata.atime
        && live.mtime() == &entry.metadata.mtime
}

#[cfg(any(test, all(target_os = "linux", target_arch = "x86_64")))]
fn charged_manifest_entry_digest_consistent_v1(entry: &ChargedManifestEntryV1<'_>) -> bool {
    canonical::derive_manifest_node_digest_projection_streaming_v1(
        entry.metadata.projection(),
        entry.payload.projection(),
        entry.hardlink_group.as_ref(),
    )
    .is_ok_and(|digest| digest == entry.node_digest)
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn map_bound_regular_refusal_v1(
    refusal: BoundRegularReadRefusalV1,
) -> FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1 {
    match refusal {
        BoundRegularReadRefusalV1::InvalidPath
        | BoundRegularReadRefusalV1::InvalidByteCeiling
        | BoundRegularReadRefusalV1::UnsupportedPlatform => {
            FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1::InvalidFixedExecutable
        }
        BoundRegularReadRefusalV1::ComponentLimit => {
            FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1::PathComponentLimit
        }
        BoundRegularReadRefusalV1::SymlinkLimit => {
            FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1::SymlinkLimit
        }
        BoundRegularReadRefusalV1::SymlinkCycle => {
            FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1::SymlinkCycle
        }
        BoundRegularReadRefusalV1::SymlinkTargetInvalid => {
            FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1::SymlinkTarget
        }
        BoundRegularReadRefusalV1::MissingNode => {
            FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1::MissingNode
        }
        BoundRegularReadRefusalV1::MountCrossing => {
            FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1::MountCrossing
        }
        BoundRegularReadRefusalV1::MagicLink => {
            FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1::MagicLink
        }
        BoundRegularReadRefusalV1::NodeType => {
            FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1::NodeType
        }
        BoundRegularReadRefusalV1::IdentityDrift => {
            FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1::IdentityDrift
        }
        BoundRegularReadRefusalV1::SizeMismatch => {
            FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1::SizeMismatch
        }
        BoundRegularReadRefusalV1::ByteLimit => {
            FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1::ByteLimit
        }
        BoundRegularReadRefusalV1::ShortRead => {
            FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1::ShortRead
        }
        BoundRegularReadRefusalV1::Io => FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1::Io,
        BoundRegularReadRefusalV1::MemoryBudget => {
            FirstExecuteOnlyWorkspaceRuntimeEvidenceRefusalV1::MemoryBudget
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl fmt::Debug for FirstExecuteOnlyWorkspaceTreeBindingV1<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FirstExecuteOnlyWorkspaceTreeBindingV1")
            .field("lexical", &"<opaque-fixed-fixture-proof>")
            .field("workspace", &"<opaque-connector-evidence>")
            .finish()
    }
}

fn validate_first_execute_only_workspace_manifest_v1(
    lexical: &FirstExecuteOnlyLexicalAdmissionV1,
    manifest: &ChargedTreeManifestV1<'_>,
) -> Result<(), RefusalCode> {
    let mut matches = manifest
        .entries
        .as_slice()
        .iter()
        .filter(|entry| entry.relative_path == lexical.selector().path());
    let selector = matches.next().ok_or(RefusalCode::SelectorTargetMissing)?;
    if matches.next().is_some() {
        return Err(RefusalCode::SnapshotConstructionFailed);
    }
    let ChargedManifestPayloadV1::Regular {
        content_digest,
        data_extents: _,
    } = &selector.payload
    else {
        return Err(RefusalCode::SelectorTargetType);
    };
    let expected_content =
        FileContentDigest::derive(FILE_CONTENT_DOMAIN, &[FIRST_EXECUTE_ONLY_FIXTURE_BYTES_V1]);
    if selector.metadata.size
        != u64::try_from(FIRST_EXECUTE_ONLY_FIXTURE_BYTES_V1.len())
            .expect("fixed fixture length fits u64")
        || selector.metadata.nlink != 1
        || selector.hardlink_group.is_some()
        || *content_digest != expected_content
    {
        return Err(RefusalCode::SnapshotConstructionFailed);
    }
    Ok(())
}

/// Preserve the ordering boundary between canonical manifest validation and
/// every irreversible publication operation. The manifest is consumed on
/// success and dropped on refusal, releasing its charged containers and both
/// retained-view leases before the caller observes the error.
fn consume_manifest_after_validation_v1<'resources, T, V, C>(
    manifest: ChargedTreeManifestV1<'resources>,
    validate: V,
    consume: C,
) -> Result<T, RefusalCode>
where
    V: FnOnce(&ChargedTreeManifestV1<'_>) -> Result<(), RefusalCode>,
    C: FnOnce(ChargedTreeManifestV1<'resources>) -> T,
{
    validate(&manifest)?;
    Ok(consume(manifest))
}

/// Failures before publication retain their original typed cause. A bind
/// failure is distinct because its final name is already durable and must
/// never be treated as removable or safely retried.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) enum SnapshotPublishedCanonicalTreeErrorV1 {
    RootNameMismatch,
    FirstExecuteOnlyAdmission(RefusalCode),
    FourView(SnapshotPipelineFourViewErrorV1),
    Manifest(SnapshotManifestCompileErrorV1),
    Finalization(SnapshotChargedErrorV1<SnapshotPublishErrorV1>),
    PublishedChildBind(SnapshotPublishedChildBindErrorV1),
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl fmt::Debug for SnapshotPublishedCanonicalTreeErrorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RootNameMismatch => formatter.write_str("RootNameMismatch"),
            Self::FirstExecuteOnlyAdmission(code) => formatter
                .debug_tuple("FirstExecuteOnlyAdmission")
                .field(code)
                .finish(),
            Self::FourView(error) => formatter.debug_tuple("FourView").field(error).finish(),
            Self::Manifest(error) => formatter.debug_tuple("Manifest").field(error).finish(),
            Self::Finalization(error) => {
                formatter.debug_tuple("Finalization").field(error).finish()
            }
            Self::PublishedChildBind(error) => formatter
                .debug_tuple("PublishedChildBind")
                .field(error)
                .finish(),
        }
    }
}

/// One charged, FD-free projection of a stable S1/D2 pair.
///
/// This value is deliberately not a `TreeManifestV1` and grants no snapshot,
/// publication, execution, or reuse authority. Its exact outer container
/// allocations remain charged to the connector's persistent-manifest ledger,
/// while all moved plan-owned buffers remain covered by the two retained-view
/// leases. Field order is part of the safety argument: charged entries and
/// every nested moved buffer are destroyed before either lease is released.
pub(super) struct ChargedTreeManifestV1<'resources> {
    root_name: Box<[u8]>,
    entries: SnapshotManifestCompilationVecV1<'resources, ChargedManifestEntryV1<'resources>>,
    root_digest: NodeDigest,
    destination_root_statx_commitment: [u8; 102],
    canonical_bytes: SnapshotManifestCompilationVecV1<'resources, u8>,
    _source_lease: SnapshotRetainedViewLeaseV1<'resources>,
    _destination_lease: SnapshotRetainedViewLeaseV1<'resources>,
}

impl ChargedTreeManifestV1<'_> {
    fn root_name(&self) -> &[u8] {
        &self.root_name
    }

    #[cfg(test)]
    fn entries(&self) -> &[ChargedManifestEntryV1<'_>] {
        self.entries.as_slice()
    }

    pub(super) const fn root_digest(&self) -> NodeDigest {
        self.root_digest
    }

    const fn destination_root_statx_commitment_v1(&self) -> &[u8; 102] {
        &self.destination_root_statx_commitment
    }

    pub(super) fn canonical_bytes(&self) -> &[u8] {
        self.canonical_bytes.as_slice()
    }
}

struct ChargedManifestEntryV1<'resources> {
    relative_path: Vec<u8>,
    // A non-root basename is moved exactly once into its parent's child
    // commitment. The root's basename is dropped before result construction.
    basename: Option<Vec<u8>>,
    metadata: ChargedManifestMetadataV1<'resources>,
    payload: ChargedManifestPayloadV1<'resources>,
    hardlink_group: Option<HardlinkGroupDigest>,
    node_digest: NodeDigest,
}

impl ChargedManifestEntryV1<'_> {
    #[cfg(test)]
    fn relative_path(&self) -> &[u8] {
        &self.relative_path
    }

    #[cfg(test)]
    const fn metadata(&self) -> &ChargedManifestMetadataV1<'_> {
        &self.metadata
    }

    #[cfg(test)]
    const fn payload(&self) -> &ChargedManifestPayloadV1<'_> {
        &self.payload
    }

    #[cfg(test)]
    const fn hardlink_group(&self) -> Option<HardlinkGroupDigest> {
        self.hardlink_group
    }

    #[cfg(test)]
    const fn node_digest(&self) -> NodeDigest {
        self.node_digest
    }

    const fn kind(&self) -> ManifestEntryKindV1 {
        self.payload.kind()
    }

    fn projection(&self) -> canonical::ManifestEntryProjectionViewV1<'_> {
        canonical::ManifestEntryProjectionViewV1::new(
            &self.relative_path,
            self.metadata.projection(),
            self.payload.projection(),
            self.hardlink_group,
            self.node_digest,
        )
    }
}

struct ChargedManifestMetadataV1<'resources> {
    mode: u32,
    logical_uid: u32,
    logical_gid: u32,
    size: u64,
    nlink: u64,
    atime: TimespecV1,
    mtime: TimespecV1,
    ctime: TimespecV1,
    btime: Option<TimespecV1>,
    xattrs: SnapshotManifestCompilationVecV1<'resources, XattrV1>,
}

impl ChargedManifestMetadataV1<'_> {
    #[cfg(test)]
    fn xattrs(&self) -> &[XattrV1] {
        self.xattrs.as_slice()
    }

    fn projection(&self) -> canonical::ManifestMetadataProjectionV1<'_> {
        canonical::ManifestMetadataProjectionV1::new(
            self.mode,
            self.logical_uid,
            self.logical_gid,
            self.size,
            self.nlink,
            &self.atime,
            &self.mtime,
            &self.ctime,
            self.btime.as_ref(),
            self.xattrs.as_slice(),
        )
    }
}

enum ChargedManifestPayloadV1<'resources> {
    Directory {
        children: SnapshotManifestCompilationVecV1<'resources, ChildCommitmentV1>,
    },
    Regular {
        content_digest: super::FileContentDigest,
        data_extents: Vec<super::ExtentV1>,
    },
    Symlink {
        target: Vec<u8>,
    },
}

impl ChargedManifestPayloadV1<'_> {
    const fn kind(&self) -> ManifestEntryKindV1 {
        match self {
            Self::Directory { .. } => ManifestEntryKindV1::Directory,
            Self::Regular { .. } => ManifestEntryKindV1::Regular,
            Self::Symlink { .. } => ManifestEntryKindV1::Symlink,
        }
    }

    fn projection(&self) -> canonical::ManifestPayloadProjectionV1<'_> {
        match self {
            Self::Directory { children } => canonical::ManifestPayloadProjectionV1::Directory {
                children: children.as_slice(),
            },
            Self::Regular {
                content_digest,
                data_extents,
            } => canonical::ManifestPayloadProjectionV1::Regular {
                content_digest: *content_digest,
                data_extents,
            },
            Self::Symlink { target } => canonical::ManifestPayloadProjectionV1::Symlink { target },
        }
    }
}

impl canonical::ManifestCanonicalByteSinkV1 for SnapshotManifestCompilationVecV1<'_, u8> {
    type Error = SnapshotPipelineResourceErrorV1;

    fn try_extend_canonical(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
        self.try_extend_from_slice(bytes)
    }
}

/// Production compilation of one connector-verified S1/D2 pair without
/// creating an uncharged owning-manifest container.
///
/// The only plan input is the verifier's non-forgeable stable projection. Its
/// connector-owned bridge keeps each plan ahead of its retained-view lease in
/// drop order. The session/lease identity check runs before semantic
/// validation or allocation, preventing proof from one pipeline resource
/// authority from being spliced into another authority's ledger. This remains
/// a data-only projection: the 102-byte D2 `SourceStatxV1` commitment is
/// retained for the integrated publisher binding, but this function alone
/// creates no FD or publication proof.
pub(super) fn compile_tree_manifest_charged<'resources>(
    session: &SnapshotManifestCompilationSessionV1<'resources>,
    stable: StableManifestProjectionV1<'resources, 'resources>,
) -> Result<ChargedTreeManifestV1<'resources>, SnapshotManifestCompileErrorV1> {
    let mut inputs = consume_stable_manifest_projection(stable);
    let (source_lease, destination_lease) = inputs.leases();
    if !session.owns_lease(source_lease) || !session.owns_lease(destination_lease) {
        return Err(SnapshotManifestCompileErrorV1::AuthorityMismatch);
    }

    let (source, destination) = inputs.plans();
    validate_charged_manifest_projection_pair(source, destination)?;
    let destination_root_statx_commitment = destination
        .entries()
        .first()
        .ok_or(SnapshotManifestCompileErrorV1::MalformedPlan)?
        .statx()
        .commitment_bytes_v1();

    let (source, destination) = inputs.take_plans();
    let (source_root_name, source_entries, source_groups, _) = source.into_parts();
    let (destination_root_name, destination_entries, _, _) = destination.into_parts();
    drop(source_root_name);
    let group_digests =
        compile_hardlink_group_digests_charged(session, &source_entries, &source_groups)?;

    let entry_count = source_entries.len();
    let mut entries_reversed =
        session.charged_vec::<ChargedManifestEntryV1<'resources>>(entry_count)?;
    let entry_pairs = source_entries
        .into_vec()
        .into_iter()
        .zip(destination_entries.into_vec());
    for (source, destination) in entry_pairs.rev() {
        let (relative_path, basename, _, source_statx, _, source_payload, hardlink_group_index) =
            source.into_parts();
        let (_, _, _, _, destination_xattrs, destination_payload, _) = destination.into_parts();
        let (mode, logical_uid, logical_gid, nlink, size, atime, mtime, ctime, btime) =
            source_statx.into_manifest_parts();

        let mut xattrs = session.charged_vec::<XattrV1>(destination_xattrs.len())?;
        for xattr in destination_xattrs.into_vec() {
            let (name, value) = xattr.into_parts();
            let CapturedXattrValueV1::Bytes(value) = value else {
                return Err(SnapshotManifestCompileErrorV1::VisibleXattrUnrepresentable);
            };
            xattrs.try_push(XattrV1 {
                name: name.into_vec(),
                value: value.into_vec(),
            })?;
        }
        let metadata = ChargedManifestMetadataV1 {
            mode,
            logical_uid,
            logical_gid,
            size,
            nlink,
            atime,
            mtime,
            ctime,
            btime,
            xattrs,
        };
        let hardlink_group = hardlink_group_index
            .map(|index| {
                group_digests
                    .as_slice()
                    .get(checked_usize_from_u32(index)?)
                    .copied()
                    .ok_or(SnapshotManifestCompileErrorV1::MalformedPlan)
            })
            .transpose()?;

        let payload = match (source_payload, destination_payload) {
            (
                SourcePlanPayloadV1::Directory { children },
                SourcePlanPayloadV1::Directory { .. },
            ) => {
                let mut commitments = session.charged_vec::<ChildCommitmentV1>(children.len())?;
                for child_index in children.into_vec() {
                    let child_index = checked_usize_from_u32(child_index)?;
                    let reverse_index = entry_count
                        .checked_sub(1)
                        .and_then(|last| last.checked_sub(child_index))
                        .ok_or(SnapshotManifestCompileErrorV1::MalformedPlan)?;
                    let child = entries_reversed
                        .as_mut_slice()
                        .get_mut(reverse_index)
                        .ok_or(SnapshotManifestCompileErrorV1::MalformedPlan)?;
                    let name = child
                        .basename
                        .take()
                        .ok_or(SnapshotManifestCompileErrorV1::MalformedPlan)?;
                    commitments.try_push(ChildCommitmentV1 {
                        name,
                        kind: child.kind(),
                        node_digest: child.node_digest,
                    })?;
                }
                ChargedManifestPayloadV1::Directory {
                    children: commitments,
                }
            }
            (SourcePlanPayloadV1::Regular { .. }, SourcePlanPayloadV1::Regular { evidence }) => {
                let (content_digest, data_extents) = evidence.into_parts();
                ChargedManifestPayloadV1::Regular {
                    content_digest,
                    data_extents,
                }
            }
            (SourcePlanPayloadV1::Symlink { .. }, SourcePlanPayloadV1::Symlink { target }) => {
                ChargedManifestPayloadV1::Symlink { target }
            }
            _ => return Err(SnapshotManifestCompileErrorV1::PlanMismatch),
        };
        let node_digest = canonical::derive_manifest_node_digest_projection_streaming_v1(
            metadata.projection(),
            payload.projection(),
            hardlink_group.as_ref(),
        )?;
        entries_reversed.try_push(ChargedManifestEntryV1 {
            relative_path: relative_path.into_vec(),
            basename: Some(basename.into_vec()),
            metadata,
            payload,
            hardlink_group,
            node_digest,
        })?;
    }
    entries_reversed.as_mut_slice().reverse();

    let root_basename = entries_reversed
        .as_mut_slice()
        .first_mut()
        .and_then(|entry| entry.basename.take())
        .ok_or(SnapshotManifestCompileErrorV1::MalformedPlan)?;
    drop(root_basename);
    if entries_reversed
        .as_slice()
        .iter()
        .any(|entry| entry.basename.is_some())
    {
        return Err(SnapshotManifestCompileErrorV1::MalformedPlan);
    }

    let root_digest = entries_reversed
        .as_slice()
        .first()
        .map(|entry| entry.node_digest)
        .ok_or(SnapshotManifestCompileErrorV1::MalformedPlan)?;
    // No digest-index lookup remains after every entry has copied its group
    // digest. Release this temporary charged outer container before the exact
    // canonical byte object is allocated to reduce overlap between phases.
    drop(group_digests);
    // This checked walk exercises the same projection framing used by future
    // persistence without allocating canonical bytes. Semantic admission was
    // completed before any plan-owned buffer was moved.
    let mut entry_views = session.charged_vec::<canonical::ManifestEntryProjectionViewV1<'_>>(
        entries_reversed.as_slice().len(),
    )?;
    for entry in entries_reversed.as_slice() {
        entry_views.try_push(entry.projection())?;
    }
    let canonical_length = canonical::checked_tree_manifest_projection_canonical_length_v1(
        b"/workspace",
        TreeRoleV1::Workspace,
        entry_views.as_slice(),
        root_digest,
    )?;
    let mut canonical_bytes = session.charged_vec::<u8>(canonical_length)?;
    let written = match canonical::write_tree_manifest_projection_canonical_v1(
        b"/workspace",
        TreeRoleV1::Workspace,
        entry_views.as_slice(),
        root_digest,
        &mut canonical_bytes,
    ) {
        Ok(written) => written,
        Err(canonical::ManifestCanonicalWriteErrorV1::Canonical(error)) => {
            return Err(SnapshotManifestCompileErrorV1::Canonical(error));
        }
        Err(canonical::ManifestCanonicalWriteErrorV1::Sink(error)) => {
            return Err(SnapshotManifestCompileErrorV1::Resource(error));
        }
    };
    if written != canonical_length || canonical_bytes.as_slice().len() != canonical_length {
        return Err(SnapshotManifestCompileErrorV1::Canonical(
            LinuxPytestContractError::CanonicalEncoding,
        ));
    }
    drop(entry_views);

    let (source_lease, destination_lease) = inputs.into_leases();

    Ok(ChargedTreeManifestV1 {
        root_name: destination_root_name,
        entries: entries_reversed,
        root_digest,
        destination_root_statx_commitment,
        canonical_bytes,
        _source_lease: source_lease,
        _destination_lease: destination_lease,
    })
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl SnapshotConnectorV1 {
    /// Materializes and verifies four independent views, compiles the exact D2
    /// manifest, escrows post-publication binding before sealing, publishes,
    /// and binds the reopened child without exposing any intermediate token.
    /// Success is still evidence only; it cannot authorize execution or reuse.
    pub(super) fn materialize_workspace_tree_and_publish_at<'resources>(
        &'resources self,
        publication_parent: BorrowedFd<'resources>,
        staging_name: &CStr,
        final_name: &CStr,
        source_s1_view: QualifiedNoAtimeSourceViewV1<'_>,
        source_s2_view: QualifiedNoAtimeSourceViewV1<'_>,
        root_name: &CStr,
    ) -> Result<PublishedCanonicalTreeV1<'resources>, SnapshotPublishedCanonicalTreeErrorV1> {
        self.materialize_workspace_tree_and_publish_with_validation_at(
            publication_parent,
            staging_name,
            final_name,
            source_s1_view,
            source_s2_view,
            root_name,
            |_| Ok(()),
        )
    }

    /// Gate 3 workspace-only composition. The fixed selector bytes are checked
    /// after four-view verification and canonical compilation but before
    /// publication escrow or rename. Success remains non-authoritative and has
    /// no execution consumer.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn materialize_first_execute_only_workspace_tree_and_publish_at<'resources>(
        &'resources self,
        lexical: FirstExecuteOnlyLexicalAdmissionV1,
        publication_parent: BorrowedFd<'resources>,
        staging_name: &CStr,
        final_name: &CStr,
        source_s1_view: QualifiedNoAtimeSourceViewV1<'_>,
        source_s2_view: QualifiedNoAtimeSourceViewV1<'_>,
        root_name: &CStr,
    ) -> Result<
        FirstExecuteOnlyWorkspaceTreeBindingV1<'resources>,
        SnapshotPublishedCanonicalTreeErrorV1,
    > {
        let workspace = self.materialize_workspace_tree_and_publish_with_validation_at(
            publication_parent,
            staging_name,
            final_name,
            source_s1_view,
            source_s2_view,
            root_name,
            |manifest| validate_first_execute_only_workspace_manifest_v1(&lexical, manifest),
        )?;
        Ok(FirstExecuteOnlyWorkspaceTreeBindingV1 { lexical, workspace })
    }

    /// Dedicated linear issuer for the separately published tree used only as
    /// an input to the Gate 3 structural inventory. Unlike a descriptor
    /// relabel, this runs the complete four-view materialize/verify/publish/
    /// bind pipeline and returns no generic publication token to its caller.
    /// It still grants neither loader nor execution authority.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn materialize_first_execute_only_runtime_inventory_tree_and_publish_at<
        'resources,
    >(
        &'resources self,
        publication_parent: BorrowedFd<'resources>,
        staging_name: &CStr,
        final_name: &CStr,
        source_s1_view: QualifiedNoAtimeSourceViewV1<'_>,
        source_s2_view: QualifiedNoAtimeSourceViewV1<'_>,
        root_name: &CStr,
    ) -> Result<
        FirstExecuteOnlyPublishedRuntimeTreeV1<'resources>,
        SnapshotPublishedCanonicalTreeErrorV1,
    > {
        self.materialize_workspace_tree_and_publish_with_validation_at(
            publication_parent,
            staging_name,
            final_name,
            source_s1_view,
            source_s2_view,
            root_name,
            |_| Ok(()),
        )
        .map(|tree| FirstExecuteOnlyPublishedRuntimeTreeV1 { tree })
    }

    #[allow(clippy::too_many_arguments)]
    fn materialize_workspace_tree_and_publish_with_validation_at<'resources, V>(
        &'resources self,
        publication_parent: BorrowedFd<'resources>,
        staging_name: &CStr,
        final_name: &CStr,
        source_s1_view: QualifiedNoAtimeSourceViewV1<'_>,
        source_s2_view: QualifiedNoAtimeSourceViewV1<'_>,
        root_name: &CStr,
        validate_manifest: V,
    ) -> Result<PublishedCanonicalTreeV1<'resources>, SnapshotPublishedCanonicalTreeErrorV1>
    where
        V: FnOnce(&ChargedTreeManifestV1<'_>) -> Result<(), RefusalCode>,
    {
        validate_snapshot_final_name(staging_name, final_name).map_err(|error| {
            SnapshotPublishedCanonicalTreeErrorV1::Finalization(SnapshotChargedErrorV1::Leaf(error))
        })?;

        let (staged, stable) = self
            .materialize_source_tree_four_view_at(
                publication_parent,
                staging_name,
                source_s1_view,
                source_s2_view,
                root_name,
            )
            .map_err(SnapshotPublishedCanonicalTreeErrorV1::FourView)?;
        let compilation = self.manifest_compilation_session();
        let manifest = compile_tree_manifest_charged(&compilation, stable)
            .map_err(SnapshotPublishedCanonicalTreeErrorV1::Manifest)?;
        if manifest.root_name() != root_name.to_bytes() {
            return Err(SnapshotPublishedCanonicalTreeErrorV1::RootNameMismatch);
        }
        consume_manifest_after_validation_v1(manifest, validate_manifest, |manifest| {
            let reservation = staged
                .reserve_published_child_bind_attempts()
                .map_err(|error| {
                    SnapshotPublishedCanonicalTreeErrorV1::Finalization(
                        SnapshotChargedErrorV1::Resource(error),
                    )
                })?;
            let prepared = SnapshotPreparedPublishedChildBindV1 {
                reservation,
                root_name,
                manifest: &manifest,
            };
            let physical = seal_publish_and_bind_snapshot_child_at(staged, final_name, prepared)
                .map_err(|error| match error {
                    SnapshotPublishAndBindErrorV1::Finalization(error) => {
                        SnapshotPublishedCanonicalTreeErrorV1::Finalization(error)
                    }
                    SnapshotPublishAndBindErrorV1::PublishedChildBind(error) => {
                        SnapshotPublishedCanonicalTreeErrorV1::PublishedChildBind(error)
                    }
                })?;

            Ok(PublishedCanonicalTreeV1 { physical, manifest })
        })
        .map_err(SnapshotPublishedCanonicalTreeErrorV1::FirstExecuteOnlyAdmission)?
    }
}

fn compile_hardlink_group_digests_charged<'resources>(
    session: &SnapshotManifestCompilationSessionV1<'resources>,
    source_entries: &[SourceTreeEntryV1],
    source_groups: &[super::snapshot_tree::SourceHardlinkGroupV1],
) -> Result<
    SnapshotManifestCompilationVecV1<'resources, HardlinkGroupDigest>,
    SnapshotManifestCompileErrorV1,
> {
    let mut group_digests = session.charged_vec::<HardlinkGroupDigest>(source_groups.len())?;
    for group in source_groups {
        // Structural admission proves every index valid and member paths
        // strictly ordered. The concrete charged slice ensures validation and
        // hashing observe one immutable sequence.
        let mut paths = session.charged_vec::<&[u8]>(group.member_indices().len())?;
        for index in group.member_indices() {
            paths.try_push(
                source_entries
                    .get(checked_usize_from_u32(*index)?)
                    .ok_or(SnapshotManifestCompileErrorV1::MalformedPlan)?
                    .relative_path(),
            )?;
        }
        let digest = canonical::derive_hardlink_group_digest_streaming_v1(paths.as_slice())?;
        drop(paths);
        group_digests.try_push(digest)?;
    }
    Ok(group_digests)
}

fn checked_usize_from_u32(value: u32) -> Result<usize, SnapshotManifestCompileErrorV1> {
    usize::try_from(value).map_err(|_| SnapshotManifestCompileErrorV1::MalformedPlan)
}

fn checked_u32_from_usize(value: usize) -> Result<u32, SnapshotManifestCompileErrorV1> {
    u32::try_from(value).map_err(|_| SnapshotManifestCompileErrorV1::MalformedPlan)
}

fn checked_u64_from_usize(value: usize) -> Result<u64, SnapshotManifestCompileErrorV1> {
    u64::try_from(value).map_err(|_| SnapshotManifestCompileErrorV1::MalformedPlan)
}

fn validate_charged_manifest_projection_pair(
    source: &SourceTreePlanV1,
    destination: &SourceTreePlanV1,
) -> Result<(), SnapshotManifestCompileErrorV1> {
    validate_manifest_projection_pair(source, destination)?;
    validate_charged_plan_semantics(source)?;
    validate_charged_plan_semantics(destination)
}

fn validate_charged_plan_semantics(
    plan: &SourceTreePlanV1,
) -> Result<(), SnapshotManifestCompileErrorV1> {
    let entries = plan.entries();
    checked_u32_from_usize(entries.len())?;
    checked_u32_from_usize(plan.hardlink_groups().len())?;
    if entries.is_empty()
        || !super::valid_basename(plan.root_name())
        || entries[0].relative_path() != b""
        || entries[0].basename() != plan.root_name()
        || entries[0].parent_index().is_some()
        || !matches!(entries[0].payload(), SourcePlanPayloadV1::Directory { .. })
        || entries
            .windows(2)
            .any(|pair| pair[0].relative_path() >= pair[1].relative_path())
    {
        return Err(SnapshotManifestCompileErrorV1::MalformedPlan);
    }

    let mut child_reference_count = 0usize;
    for (index, entry) in entries.iter().enumerate() {
        let parent_index = checked_u32_from_usize(index)?;
        validate_plan_entry_semantics(index, entry)?;
        match entry.payload() {
            SourcePlanPayloadV1::Directory { children } => {
                let mut previous_name: Option<&[u8]> = None;
                for child_index in children {
                    let child_index = checked_usize_from_u32(*child_index)?;
                    let child = entries
                        .get(child_index)
                        .ok_or(SnapshotManifestCompileErrorV1::MalformedPlan)?;
                    if child_index <= index
                        || child.parent_index() != Some(parent_index)
                        || previous_name.is_some_and(|name| name >= child.basename())
                        || !path_matches_parent(
                            entry.relative_path(),
                            child.basename(),
                            child.relative_path(),
                        )
                    {
                        return Err(SnapshotManifestCompileErrorV1::MalformedPlan);
                    }
                    previous_name = Some(child.basename());
                    child_reference_count = child_reference_count
                        .checked_add(1)
                        .ok_or(SnapshotManifestCompileErrorV1::MalformedPlan)?;
                }
            }
            SourcePlanPayloadV1::Regular { evidence } => {
                validate_charged_extent_sequence(evidence.data_extents(), entry.statx().size())?;
            }
            SourcePlanPayloadV1::Symlink { target } => {
                let target_length = checked_u64_from_usize(target.len())?;
                if target.is_empty() || target.contains(&0) || target_length != entry.statx().size()
                {
                    return Err(SnapshotManifestCompileErrorV1::MalformedPlan);
                }
            }
        }
    }
    if child_reference_count
        != entries
            .len()
            .checked_sub(1)
            .ok_or(SnapshotManifestCompileErrorV1::MalformedPlan)?
    {
        return Err(SnapshotManifestCompileErrorV1::MalformedPlan);
    }
    validate_hardlink_backlinks(plan)?;
    Ok(())
}

fn validate_charged_extent_sequence(
    extents: &[super::ExtentV1],
    logical_size: u64,
) -> Result<(), SnapshotManifestCompileErrorV1> {
    let mut previous_end = None;
    for extent in extents {
        let next = extent
            .offset
            .checked_add(extent.length)
            .ok_or(SnapshotManifestCompileErrorV1::MalformedPlan)?;
        if extent.length == 0
            || previous_end.is_some_and(|end| end >= extent.offset)
            || next > logical_size
        {
            return Err(SnapshotManifestCompileErrorV1::MalformedPlan);
        }
        previous_end = Some(next);
    }
    Ok(())
}

fn validate_plan_entry_semantics(
    index: usize,
    entry: &SourceTreeEntryV1,
) -> Result<(), SnapshotManifestCompileErrorV1> {
    const S_IFMT: u32 = 0o170_000;
    const S_IFDIR: u32 = 0o040_000;
    const S_IFREG: u32 = 0o100_000;
    const S_IFLNK: u32 = 0o120_000;

    if !super::valid_manifest_relative_path(entry.relative_path())
        || (index != 0 && !super::valid_basename(entry.basename()))
        || entry.statx().nlink() == 0
        || [
            Some(entry.statx().atime()),
            Some(entry.statx().mtime()),
            Some(entry.statx().ctime()),
            entry.statx().btime(),
        ]
        .into_iter()
        .flatten()
        .any(|time| time.nanoseconds >= 1_000_000_000)
        || entry
            .xattrs()
            .windows(2)
            .any(|pair| pair[0].name() >= pair[1].name())
        || entry
            .xattrs()
            .iter()
            .any(|xattr| xattr.name().is_empty() || xattr.name().contains(&0))
    {
        return Err(SnapshotManifestCompileErrorV1::MalformedPlan);
    }
    if entry.xattrs().iter().any(|xattr| {
        matches!(
            xattr.value(),
            CapturedXattrValueV1::VisibleButUnsettable { .. }
        )
    }) {
        return Err(SnapshotManifestCompileErrorV1::VisibleXattrUnrepresentable);
    }
    let expected_mode = match entry.payload() {
        SourcePlanPayloadV1::Directory { .. } => S_IFDIR,
        SourcePlanPayloadV1::Regular { .. } => S_IFREG,
        SourcePlanPayloadV1::Symlink { .. } => S_IFLNK,
    };
    if entry.statx().mode() & S_IFMT != expected_mode
        || (matches!(entry.payload(), SourcePlanPayloadV1::Directory { .. })
            && entry.hardlink_group().is_some())
        || (matches!(
            entry.payload(),
            SourcePlanPayloadV1::Regular { .. } | SourcePlanPayloadV1::Symlink { .. }
        ) && ((entry.hardlink_group().is_some() && entry.statx().nlink() < 2)
            || (entry.hardlink_group().is_none() && entry.statx().nlink() != 1)))
    {
        return Err(SnapshotManifestCompileErrorV1::MalformedPlan);
    }
    Ok(())
}

fn validate_hardlink_backlinks(
    source: &SourceTreePlanV1,
) -> Result<(), SnapshotManifestCompileErrorV1> {
    let entries = source.entries();
    let groups = source.hardlink_groups();
    let mut member_count = 0usize;
    for (group_index, group) in groups.iter().enumerate() {
        let group_index = checked_u32_from_usize(group_index)?;
        let members = group.member_indices();
        checked_u32_from_usize(members.len())?;
        if members.len() < 2 || members.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(SnapshotManifestCompileErrorV1::MalformedPlan);
        }
        let expected_nlink = checked_u64_from_usize(members.len())?;
        let first = entries
            .get(checked_usize_from_u32(members[0])?)
            .ok_or(SnapshotManifestCompileErrorV1::MalformedPlan)?;
        for member_index in members {
            let member = entries
                .get(checked_usize_from_u32(*member_index)?)
                .ok_or(SnapshotManifestCompileErrorV1::MalformedPlan)?;
            if group.inode_key() != member.statx().inode_key()
                || member.hardlink_group() != Some(group_index)
                || member.statx().nlink() != expected_nlink
                || member.payload().kind() != first.payload().kind()
                || member.statx().mode() != first.statx().mode()
                || member.statx().uid() != first.statx().uid()
                || member.statx().gid() != first.statx().gid()
                || member.statx().size() != first.statx().size()
                || member.statx().atime() != first.statx().atime()
                || member.statx().mtime() != first.statx().mtime()
                || member.statx().ctime() != first.statx().ctime()
                || member.statx().btime() != first.statx().btime()
                || member.xattrs() != first.xattrs()
                || member.payload() != first.payload()
            {
                return Err(SnapshotManifestCompileErrorV1::MalformedPlan);
            }
            member_count = member_count
                .checked_add(1)
                .ok_or(SnapshotManifestCompileErrorV1::MalformedPlan)?;
        }
    }
    let backlink_count = entries
        .iter()
        .filter(|entry| entry.hardlink_group().is_some())
        .count();
    if member_count != backlink_count {
        return Err(SnapshotManifestCompileErrorV1::MalformedPlan);
    }
    for (index, entry) in entries.iter().enumerate() {
        let Some(group_index) = entry.hardlink_group() else {
            continue;
        };
        let group = groups
            .get(checked_usize_from_u32(group_index)?)
            .ok_or(SnapshotManifestCompileErrorV1::MalformedPlan)?;
        let index = checked_u32_from_usize(index)?;
        if group.member_indices().binary_search(&index).is_err() {
            return Err(SnapshotManifestCompileErrorV1::MalformedPlan);
        }
    }
    Ok(())
}

fn path_matches_parent(parent: &[u8], basename: &[u8], child: &[u8]) -> bool {
    if parent.is_empty() {
        return child == basename;
    }
    let Some(expected_length) = parent
        .len()
        .checked_add(1)
        .and_then(|length| length.checked_add(basename.len()))
    else {
        return false;
    };
    child.len() == expected_length
        && child.starts_with(parent)
        && child.get(parent.len()) == Some(&b'/')
        && child.get(parent.len() + 1..) == Some(basename)
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
#[cfg(test)]
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

#[cfg(test)]
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

#[cfg(test)]
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
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    use crate::linux_pytest::snapshot_connector::connect_snapshot_pipeline;
    use crate::linux_pytest::snapshot_connector::{
        manifest_compilation_session_for_test, mint_destination_witness_bytes_for_test,
        retain_tree_plan_for_test,
    };
    use crate::linux_pytest::snapshot_policy::{
        SnapshotPipelineForwardStageV1, SnapshotPipelineResourcesV1, SnapshotResourcePolicyV1,
    };
    use crate::linux_pytest::snapshot_tree::{
        CapturedXattrV1, SourceHardlinkGroupV1, SourceRegularEvidenceV1, SourceStatxV1,
        SourceTreeEntryV1,
    };
    use crate::linux_pytest::snapshot_verify::{
        DestinationPhysicalIdentityV1, StableManifestProjectionV1, begin_four_view_comparison,
    };
    use crate::linux_pytest::{ExtentV1, TimespecV1};
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    use std::fs::{self, File};
    use std::num::{NonZeroU8, NonZeroU16, NonZeroU32, NonZeroU64};
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    use std::os::fd::AsFd;
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    use std::os::unix::fs::PermissionsExt;

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

    fn replace_root_statx(plan: SourceTreePlanV1, replacement: SourceStatxV1) -> SourceTreePlanV1 {
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

    fn manifest_resources(persistent_manifest_heap_bytes: u64) -> SnapshotPipelineResourcesV1 {
        let policy = SnapshotResourcePolicyV1::checked(
            8,
            NonZeroU32::new(64).unwrap(),
            NonZeroU16::new(255).unwrap(),
            16 * 1024,
            16 * 1024,
            16 * 1024 * 1024,
            64 * 1024 * 1024,
            64,
            4_096,
            64,
            4_096,
            255,
            64 * 1024,
            64 * 1024,
            1024 * 1024,
            NonZeroU64::new(8 * 1024 * 1024).unwrap(),
            persistent_manifest_heap_bytes,
            1024 * 1024,
            NonZeroU64::new(1_000_000).unwrap(),
            NonZeroU8::new(4).unwrap(),
            NonZeroU8::new(3).unwrap(),
            NonZeroU8::new(4).unwrap(),
        )
        .unwrap();
        SnapshotPipelineResourcesV1::preflight(policy, 0, u64::MAX, u64::MAX).unwrap()
    }

    fn stable_projection<'resources>(
        resources: &'resources SnapshotPipelineResourcesV1,
        source_s1: SourceTreePlanV1,
        source_s2: SourceTreePlanV1,
        destination_d1: SourceTreePlanV1,
        destination_d2: SourceTreePlanV1,
    ) -> StableManifestProjectionV1<'resources, 'resources> {
        let source_s1 = retain_tree_plan_for_test(
            resources,
            SnapshotPipelineForwardStageV1::SourceObservation,
            source_s1,
        )
        .unwrap();
        let source_s2 = retain_tree_plan_for_test(
            resources,
            SnapshotPipelineForwardStageV1::SourceObservation,
            source_s2,
        )
        .unwrap();
        let source_stable = begin_four_view_comparison(source_s1)
            .compare_source_s2(&source_s2)
            .unwrap();
        drop(source_s2);
        let destination_d1 = retain_tree_plan_for_test(
            resources,
            SnapshotPipelineForwardStageV1::DestinationObservation,
            destination_d1,
        )
        .unwrap();
        let destination_stable = source_stable
            .compare_destination_d1(
                &destination_d1,
                DestinationPhysicalIdentityV1::new(1_000, 2_000),
            )
            .unwrap();
        let awaiting_d2 = destination_stable
            .capture_stability_witness(|capacity| {
                mint_destination_witness_bytes_for_test(resources, capacity)
            })
            .unwrap();
        drop(destination_d1);
        let destination_d2 = retain_tree_plan_for_test(
            resources,
            SnapshotPipelineForwardStageV1::DestinationObservation,
            destination_d2,
        )
        .unwrap();
        awaiting_d2.compare_destination_d2(destination_d2).unwrap()
    }

    fn compile_charged<'resources>(
        resources: &'resources SnapshotPipelineResourcesV1,
        stable: StableManifestProjectionV1<'resources, 'resources>,
    ) -> Result<ChargedTreeManifestV1<'resources>, SnapshotManifestCompileErrorV1> {
        compile_tree_manifest_charged(&manifest_compilation_session_for_test(resources), stable)
    }

    #[derive(Default)]
    struct TestCanonicalSink(Vec<u8>);

    impl canonical::ManifestCanonicalByteSinkV1 for TestCanonicalSink {
        type Error = ();

        fn try_extend_canonical(&mut self, bytes: &[u8]) -> Result<(), Self::Error> {
            self.0.extend_from_slice(bytes);
            Ok(())
        }
    }

    fn legacy_canonical_bytes(manifest: &TreeManifestV1) -> Vec<u8> {
        let mut sink = TestCanonicalSink::default();
        let written = canonical::write_tree_manifest_canonical_v1(manifest, &mut sink).unwrap();
        assert_eq!(written, sink.0.len());
        sink.0
    }

    fn charged_outer_heap_phases(
        source: &SourceTreePlanV1,
        destination: &SourceTreePlanV1,
        canonical_length: usize,
    ) -> [u64; 3] {
        let entries = u64::try_from(source.entries().len()).unwrap()
            * u64::try_from(std::mem::size_of::<ChargedManifestEntryV1<'static>>()).unwrap();
        let xattrs = u64::try_from(
            destination
                .entries()
                .iter()
                .map(|entry| entry.xattrs().len())
                .sum::<usize>(),
        )
        .unwrap()
            * u64::try_from(std::mem::size_of::<XattrV1>()).unwrap();
        let children = u64::try_from(
            source
                .entries()
                .iter()
                .map(|entry| match entry.payload() {
                    SourcePlanPayloadV1::Directory { children } => children.len(),
                    SourcePlanPayloadV1::Regular { .. } | SourcePlanPayloadV1::Symlink { .. } => 0,
                })
                .sum::<usize>(),
        )
        .unwrap()
            * u64::try_from(std::mem::size_of::<ChildCommitmentV1>()).unwrap();
        let groups = u64::try_from(source.hardlink_groups().len()).unwrap()
            * u64::try_from(std::mem::size_of::<HardlinkGroupDigest>()).unwrap();
        let hardlink_paths = u64::try_from(
            source
                .hardlink_groups()
                .iter()
                .map(|group| group.member_indices().len())
                .max()
                .unwrap_or(0),
        )
        .unwrap()
            * u64::try_from(std::mem::size_of::<&[u8]>()).unwrap();
        let entry_views = u64::try_from(source.entries().len()).unwrap()
            * u64::try_from(std::mem::size_of::<
                canonical::ManifestEntryProjectionViewV1<'static>,
            >())
            .unwrap();
        let retained = entries + xattrs + children;
        // Actual production overlap: group slots + one path-ref group;
        // completed manifest containers + group slots; then completed
        // containers + immutable projection slots + canonical bytes.
        [
            groups + hardlink_paths,
            retained + groups,
            retained + entry_views + u64::try_from(canonical_length).unwrap(),
        ]
    }

    fn assert_full_compiler_exact_boundary(
        fixture: fn(u8) -> (SourceTreePlanV1, SourceTreePlanV1),
        seed: u8,
    ) {
        let (legacy_source, legacy_destination) = fixture(seed);
        let legacy = compile_tree_manifest(
            legacy_source,
            legacy_destination,
            workspace_path(),
            TreeRoleV1::Workspace,
        )
        .unwrap();
        let canonical = legacy_canonical_bytes(&legacy);
        let (source_s1, destination_d1) = fixture(seed);
        let (source_s2, destination_d2) = fixture(seed);
        let phases = charged_outer_heap_phases(&source_s1, &destination_d2, canonical.len());
        let exact = phases.into_iter().max().unwrap();
        assert_eq!(phases[2], exact, "canonical phase must select the peak");
        let resources = manifest_resources(exact);
        let stable = stable_projection(
            &resources,
            source_s1,
            source_s2,
            destination_d1,
            destination_d2,
        );
        let charged = compile_charged(&resources, stable).unwrap();
        assert_eq!(charged.canonical_bytes(), canonical);
        drop(charged);
        assert_eq!(resources.persistent_manifest_heap_live_for_test(), 0);
        assert_eq!(resources.retained_view_heap_live_for_test(), 0);

        let (source_s1, destination_d1) = fixture(seed);
        let (source_s2, destination_d2) = fixture(seed);
        let resources = manifest_resources(exact - 1);
        let stable = stable_projection(
            &resources,
            source_s1,
            source_s2,
            destination_d1,
            destination_d2,
        );
        let error = match compile_charged(&resources, stable) {
            Ok(_) => panic!("one-byte-short manifest budget must refuse"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            SnapshotManifestCompileErrorV1::Resource(
                SnapshotPipelineResourceErrorV1::PersistentManifestHeapCapacityExceeded { .. }
            )
        ));
        assert_eq!(resources.persistent_manifest_heap_live_for_test(), 0);
        assert_eq!(resources.retained_view_heap_live_for_test(), 0);
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

    fn symlink_entry(
        source: bool,
        path: &[u8],
        basename: &[u8],
        parent: u32,
        inode: u64,
        target: &[u8],
    ) -> SourceTreeEntryV1 {
        SourceTreeEntryV1::unchecked_for_test(
            path,
            basename,
            Some(parent),
            statx(
                source,
                inode,
                0o120_000 | if source { 0o777 } else { 0o555 },
                1,
                target.len() as u64,
                5,
                6,
                if source { 7 } else { 700 },
                None,
            ),
            Vec::new(),
            SourcePlanPayloadV1::Symlink {
                target: target.to_vec(),
            },
            None,
        )
    }

    fn rich_fixture(raw_name: &[u8]) -> (SourceTreePlanV1, SourceTreePlanV1) {
        let plan = |source| {
            SourceTreePlanV1::unchecked_for_test(
                b"source-root",
                vec![
                    directory_entry(source, b"", b"source-root", None, 1, vec![1, 2]),
                    regular_entry(source, raw_name, raw_name, 0, 2, 1, 0x51, None),
                    symlink_entry(source, b"link", b"link", 0, 3, b"target"),
                ],
                Vec::new(),
                false,
            )
        };
        (plan(true), plan(false))
    }

    fn hardlink_fixture(seed: u8) -> (SourceTreePlanV1, SourceTreePlanV1) {
        let plan = |source| {
            let first = regular_entry(source, b"a", b"a", 0, 2, 2, seed, Some(0));
            let second = regular_entry(source, b"b", b"b", 0, 2, 2, seed, Some(0));
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
        (plan(true), plan(false))
    }

    fn nested_fixture(seed: u8) -> (SourceTreePlanV1, SourceTreePlanV1) {
        let plan = |source| {
            SourceTreePlanV1::unchecked_for_test(
                b"source-root",
                vec![
                    directory_entry(source, b"", b"source-root", None, 1, vec![1]),
                    directory_entry(source, b"dir", b"dir", Some(0), 2, vec![2]),
                    regular_entry(source, b"dir/file", b"file", 1, 3, 1, seed, None),
                ],
                Vec::new(),
                false,
            )
        };
        (plan(true), plan(false))
    }

    fn first_execute_only_fixture(contents: &[u8]) -> (SourceTreePlanV1, SourceTreePlanV1) {
        let plan = |source| {
            let size = u64::try_from(contents.len()).unwrap();
            let selector = SourceTreeEntryV1::unchecked_for_test(
                b"tests/test_smoke.py",
                b"test_smoke.py",
                Some(1),
                statx(
                    source,
                    3,
                    S_IFREG | if source { 0o644 } else { 0o444 },
                    1,
                    size,
                    5,
                    6,
                    if source { 7 } else { 700 },
                    None,
                ),
                Vec::new(),
                SourcePlanPayloadV1::Regular {
                    evidence: SourceRegularEvidenceV1::checked(
                        FileContentDigest::derive(FILE_CONTENT_DOMAIN, &[contents]),
                        (size != 0)
                            .then_some(ExtentV1 {
                                offset: 0,
                                length: size,
                            })
                            .into_iter()
                            .collect(),
                        size,
                    )
                    .unwrap(),
                },
                None,
            );
            SourceTreePlanV1::unchecked_for_test(
                b"source-root",
                vec![
                    directory_entry(source, b"", b"source-root", None, 1, vec![1]),
                    directory_entry(source, b"tests", b"tests", Some(0), 2, vec![2]),
                    selector,
                ],
                Vec::new(),
                false,
            )
        };
        (plan(true), plan(false))
    }

    fn validate_first_execute_only_fixture(contents: &[u8]) -> Result<(), RefusalCode> {
        let resources = manifest_resources(1024 * 1024);
        let (source_s1, destination_d1) = first_execute_only_fixture(contents);
        let (source_s2, destination_d2) = first_execute_only_fixture(contents);
        let stable = stable_projection(
            &resources,
            source_s1,
            source_s2,
            destination_d1,
            destination_d2,
        );
        let manifest = compile_charged(&resources, stable).unwrap();
        let lexical = first_execute_only_lexical();
        validate_first_execute_only_workspace_manifest_v1(&lexical, &manifest)
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn live_manifest_metadata_requires_projected_permissions_and_stable_fields() {
        let resources = manifest_resources(1024 * 1024);
        let (source_s1, destination_d1) =
            first_execute_only_fixture(FIRST_EXECUTE_ONLY_FIXTURE_BYTES_V1);
        let (source_s2, destination_d2) =
            first_execute_only_fixture(FIRST_EXECUTE_ONLY_FIXTURE_BYTES_V1);
        let stable = stable_projection(
            &resources,
            source_s1,
            source_s2,
            destination_d1,
            destination_d2,
        );
        let manifest = compile_charged(&resources, stable).unwrap();
        let selector = manifest
            .entries()
            .iter()
            .find(|entry| entry.relative_path == b"tests/test_smoke.py")
            .unwrap();
        let physical_root = statx(false, 90, S_IFDIR | 0o555, 2, 8_192, 1, 2, 300, None);
        let matching = statx(
            false,
            91,
            S_IFREG | 0o444,
            1,
            FIRST_EXECUTE_ONLY_FIXTURE_BYTES_V1.len() as u64,
            5,
            6,
            700,
            None,
        );
        assert!(live_manifest_metadata_matches_v1(
            selector,
            &matching,
            &physical_root
        ));

        let chmod_drift = statx(
            false,
            91,
            S_IFREG | 0o400,
            1,
            FIRST_EXECUTE_ONLY_FIXTURE_BYTES_V1.len() as u64,
            5,
            6,
            701,
            None,
        );
        assert!(!live_manifest_metadata_matches_v1(
            selector,
            &chmod_drift,
            &physical_root
        ));
        let timestamp_drift = statx(
            false,
            91,
            S_IFREG | 0o444,
            1,
            FIRST_EXECUTE_ONLY_FIXTURE_BYTES_V1.len() as u64,
            5,
            60,
            702,
            None,
        );
        assert!(!live_manifest_metadata_matches_v1(
            selector,
            &timestamp_drift,
            &physical_root
        ));
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    #[ignore = "requires a provisioned functionally qualified no-atime source view"]
    fn real_elf_materializes_publishes_and_reaches_non_authoritative_runtime_checkpoint() {
        let source = tempfile::tempdir().unwrap();
        let source_root = source.path().join("root");
        fs::create_dir_all(source_root.join(".venv/bin")).unwrap();
        fs::create_dir_all(source_root.join("tests")).unwrap();
        fs::copy("/bin/true", source_root.join(".venv/bin/python")).unwrap();
        fs::set_permissions(
            source_root.join(".venv/bin/python"),
            fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        fs::write(
            source_root.join("tests/test_smoke.py"),
            FIRST_EXECUTE_ONLY_FIXTURE_BYTES_V1,
        )
        .unwrap();
        let source_fd = File::open(source.path()).unwrap();

        let publication = tempfile::tempdir().unwrap();
        let publication_fd = File::open(publication.path()).unwrap();
        let connector = connect_snapshot_pipeline(manifest_resources(8 * 1024 * 1024)).unwrap();
        let lexical = first_execute_only_lexical();
        let source_s1 = unsafe {
            QualifiedNoAtimeSourceViewV1::from_functionally_verified_mount_for_test(
                source_fd.as_fd(),
            )
        };
        let source_s2 = unsafe {
            QualifiedNoAtimeSourceViewV1::from_functionally_verified_mount_for_test(
                source_fd.as_fd(),
            )
        };
        let binding = connector
            .materialize_first_execute_only_workspace_tree_and_publish_at(
                lexical,
                publication_fd.as_fd(),
                c".again-snapshot-stage-11111111111111111111111111111111",
                c"snapshot-final",
                source_s1,
                source_s2,
                c"root",
            )
            .unwrap_or_else(|error| match error {
                SnapshotPublishedCanonicalTreeErrorV1::FourView(
                    SnapshotPipelineFourViewErrorV1::Publication(failure),
                ) => panic!(
                    "publication failure: kind={:?} stage={:?} state={:?} errno={:?}",
                    failure.kind(),
                    failure.stage(),
                    failure.publication_state(),
                    failure.errno()
                ),
                SnapshotPublishedCanonicalTreeErrorV1::FourView(
                    SnapshotPipelineFourViewErrorV1::Materialization(
                        crate::linux_pytest::snapshot_materialize::SnapshotTreeMaterializeErrorV1::Source(
                            failure,
                        ),
                    ),
                ) => panic!(
                    "source failure: code={:?} stage={:?} reason={:?} errno={:?}",
                    failure.code(),
                    failure.stage(),
                    failure.reason(),
                    failure.errno()
                ),
                SnapshotPublishedCanonicalTreeErrorV1::FourView(
                    SnapshotPipelineFourViewErrorV1::Materialization(
                        crate::linux_pytest::snapshot_materialize::SnapshotTreeMaterializeErrorV1::Materializer(
                            failure,
                        ),
                    ),
                ) => panic!(
                    "materializer failure: code={:?} stage={:?} kind={:?} regular_stage={:?} errno={:?}",
                    failure.code(),
                    failure.stage(),
                    failure.kind(),
                    failure.regular_stage(),
                    failure.errno()
                ),
                error => panic!("integrated snapshot failure: {error:?}"),
            });
        let checkpoint =
            crate::linux_pytest::execute_only_runtime::qualify_first_execute_only_runtime_checkpoint_v1(
                binding,
            )
            .unwrap();
        assert!(checkpoint.node_count() >= 3);
        assert_eq!(checkpoint.symlink_hop_count(), 0);
        assert_ne!(checkpoint.chain_digest().as_bytes(), &[0; 32]);
        drop(checkpoint);

        make_tree_owner_writable_for_cleanup(publication.path());
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn make_tree_owner_writable_for_cleanup(path: &std::path::Path) {
        let Ok(metadata) = fs::symlink_metadata(path) else {
            return;
        };
        if !metadata.is_dir() {
            return;
        }
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o700));
        let Ok(entries) = fs::read_dir(path) else {
            return;
        };
        for entry in entries.flatten() {
            make_tree_owner_writable_for_cleanup(&entry.path());
        }
    }

    fn first_execute_only_lexical() -> FirstExecuteOnlyLexicalAdmissionV1 {
        let argv = [
            b".venv/bin/python".as_slice(),
            b"-I",
            b"-m",
            b"pytest",
            b"tests/test_smoke.py::test_smoke",
        ];
        super::super::execute_only_admission::parse_first_execute_only_argv_v1(&argv).unwrap()
    }

    fn nested_xattr_fixture(seed: u8) -> (SourceTreePlanV1, SourceTreePlanV1) {
        let plan = |source| {
            let regular = regular_entry(source, b"dir/file", b"file", 1, 3, 1, seed, None);
            let (path, basename, parent, statx, _, payload, hardlink) = regular.into_parts();
            let regular = SourceTreeEntryV1::unchecked_for_test(
                &path,
                &basename,
                parent,
                statx,
                vec![CapturedXattrV1::bytes_for_test(
                    b"user.again",
                    b"nested-value",
                )],
                payload,
                hardlink,
            );
            SourceTreePlanV1::unchecked_for_test(
                b"source-root",
                vec![
                    directory_entry(source, b"", b"source-root", None, 1, vec![1]),
                    directory_entry(source, b"dir", b"dir", Some(0), 2, vec![2]),
                    regular,
                ],
                Vec::new(),
                false,
            )
        };
        (plan(true), plan(false))
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
    fn first_execute_only_workspace_manifest_binds_exact_fixture_bytes() {
        assert_eq!(FIRST_EXECUTE_ONLY_FIXTURE_BYTES_V1.len(), 96);
        assert_eq!(
            validate_first_execute_only_fixture(FIRST_EXECUTE_ONLY_FIXTURE_BYTES_V1),
            Ok(())
        );
    }

    #[test]
    fn runtime_projection_recomputes_manifest_node_digests() {
        let resources = manifest_resources(1024 * 1024);
        let (source_s1, destination_d1) =
            first_execute_only_fixture(FIRST_EXECUTE_ONLY_FIXTURE_BYTES_V1);
        let (source_s2, destination_d2) =
            first_execute_only_fixture(FIRST_EXECUTE_ONLY_FIXTURE_BYTES_V1);
        let stable = stable_projection(
            &resources,
            source_s1,
            source_s2,
            destination_d1,
            destination_d2,
        );
        let mut manifest = compile_charged(&resources, stable).unwrap();
        assert!(
            manifest
                .entries
                .as_slice()
                .iter()
                .all(charged_manifest_entry_digest_consistent_v1)
        );
        manifest.entries.as_mut_slice()[2].node_digest = NodeDigest::derive(
            "again runtime checkpoint manifest mutation test",
            &[b"mutation"],
        );
        assert!(!charged_manifest_entry_digest_consistent_v1(
            &manifest.entries.as_slice()[2]
        ));
    }

    #[test]
    fn first_execute_only_workspace_manifest_rejects_missing_or_changed_selector() {
        let changed = FIRST_EXECUTE_ONLY_FIXTURE_BYTES_V1
            .iter()
            .copied()
            .enumerate()
            .map(|(index, byte)| if index == 0 { byte ^ 1 } else { byte })
            .collect::<Vec<_>>();
        assert_eq!(changed.len(), FIRST_EXECUTE_ONLY_FIXTURE_BYTES_V1.len());
        assert_eq!(
            validate_first_execute_only_fixture(&changed),
            Err(RefusalCode::SnapshotConstructionFailed)
        );
        assert_eq!(
            validate_first_execute_only_fixture(
                &FIRST_EXECUTE_ONLY_FIXTURE_BYTES_V1
                    [..FIRST_EXECUTE_ONLY_FIXTURE_BYTES_V1.len() - 1]
            ),
            Err(RefusalCode::SnapshotConstructionFailed)
        );

        let resources = manifest_resources(1024 * 1024);
        let (source_s1, destination_d1) = nested_fixture(0x41);
        let (source_s2, destination_d2) = nested_fixture(0x41);
        let stable = stable_projection(
            &resources,
            source_s1,
            source_s2,
            destination_d1,
            destination_d2,
        );
        let manifest = compile_charged(&resources, stable).unwrap();
        let lexical = first_execute_only_lexical();
        assert_eq!(
            validate_first_execute_only_workspace_manifest_v1(&lexical, &manifest),
            Err(RefusalCode::SelectorTargetMissing)
        );
    }

    #[test]
    fn first_execute_only_refusal_drops_manifest_before_publication_continuation() {
        let resources = manifest_resources(1024 * 1024);
        let changed = FIRST_EXECUTE_ONLY_FIXTURE_BYTES_V1
            .iter()
            .copied()
            .enumerate()
            .map(|(index, byte)| if index == 0 { byte ^ 1 } else { byte })
            .collect::<Vec<_>>();
        let (source_s1, destination_d1) = first_execute_only_fixture(&changed);
        let (source_s2, destination_d2) = first_execute_only_fixture(&changed);
        let stable = stable_projection(
            &resources,
            source_s1,
            source_s2,
            destination_d1,
            destination_d2,
        );
        let manifest = compile_charged(&resources, stable).unwrap();
        assert!(resources.persistent_manifest_heap_live_for_test() > 0);
        assert!(resources.retained_view_heap_live_for_test() > 0);

        let lexical = first_execute_only_lexical();
        let publication_entered = std::cell::Cell::new(false);
        let result = consume_manifest_after_validation_v1(
            manifest,
            |manifest| validate_first_execute_only_workspace_manifest_v1(&lexical, manifest),
            |_| publication_entered.set(true),
        );
        assert_eq!(result, Err(RefusalCode::SnapshotConstructionFailed));
        assert!(!publication_entered.get());
        assert_eq!(resources.persistent_manifest_heap_live_for_test(), 0);
        assert_eq!(resources.retained_view_heap_live_for_test(), 0);
    }

    #[test]
    fn first_execute_only_success_consumes_manifest_once_and_releases_on_drop() {
        let resources = manifest_resources(1024 * 1024);
        let (source_s1, destination_d1) =
            first_execute_only_fixture(FIRST_EXECUTE_ONLY_FIXTURE_BYTES_V1);
        let (source_s2, destination_d2) =
            first_execute_only_fixture(FIRST_EXECUTE_ONLY_FIXTURE_BYTES_V1);
        let stable = stable_projection(
            &resources,
            source_s1,
            source_s2,
            destination_d1,
            destination_d2,
        );
        let manifest = compile_charged(&resources, stable).unwrap();
        let expected_root = manifest.root_digest();
        let lexical = first_execute_only_lexical();
        let continuation_calls = std::cell::Cell::new(0u8);
        let result = consume_manifest_after_validation_v1(
            manifest,
            |manifest| validate_first_execute_only_workspace_manifest_v1(&lexical, manifest),
            |manifest| {
                continuation_calls.set(continuation_calls.get() + 1);
                assert!(resources.persistent_manifest_heap_live_for_test() > 0);
                assert!(resources.retained_view_heap_live_for_test() > 0);
                manifest.root_digest()
            },
        );
        assert_eq!(result, Ok(expected_root));
        assert_eq!(continuation_calls.get(), 1);
        assert_eq!(resources.persistent_manifest_heap_live_for_test(), 0);
        assert_eq!(resources.retained_view_heap_live_for_test(), 0);
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

    #[test]
    fn charged_compiler_preserves_owned_buffer_pointers_and_canonical_bytes() {
        let (source_s1, destination_d1) = fixture(0x41, b"file");
        let (source_s2, destination_d2) = fixture(0x41, b"file");
        let source_path_pointer = source_s1.entries()[1].relative_path().as_ptr();
        let source_basename_pointer = source_s1.entries()[1].basename().as_ptr();
        let destination_root_commitment = destination_d2.entries()[0].statx().commitment_bytes_v1();
        let destination_xattr_name_pointer =
            destination_d2.entries()[1].xattrs()[0].name().as_ptr();
        let destination_xattr_value_pointer = match destination_d2.entries()[1].xattrs()[0].value()
        {
            CapturedXattrValueV1::Bytes(value) => value.as_ptr(),
            CapturedXattrValueV1::VisibleButUnsettable { .. } => panic!("fixture must be readable"),
        };
        let destination_extent_pointer = match destination_d2.entries()[1].payload() {
            SourcePlanPayloadV1::Regular { evidence } => evidence.data_extents().as_ptr(),
            _ => panic!("fixture must be regular"),
        };
        let (legacy_source, legacy_destination) = fixture(0x41, b"file");
        let legacy = compile_tree_manifest(
            legacy_source,
            legacy_destination,
            workspace_path(),
            TreeRoleV1::Workspace,
        )
        .unwrap();
        let expected_canonical = legacy_canonical_bytes(&legacy);

        let resources = manifest_resources(4 * 1024 * 1024);
        let stable = stable_projection(
            &resources,
            source_s1,
            source_s2,
            destination_d1,
            destination_d2,
        );
        let charged = compile_charged(&resources, stable).unwrap();

        assert_eq!(charged.root_name(), b"source-root");
        assert_eq!(charged.canonical_bytes(), expected_canonical);
        assert_eq!(
            charged.destination_root_statx_commitment_v1(),
            &destination_root_commitment
        );
        assert_eq!(
            charged.entries()[1].relative_path().as_ptr(),
            source_path_pointer
        );
        assert_eq!(
            charged.entries()[1].metadata().xattrs()[0].name.as_ptr(),
            destination_xattr_name_pointer
        );
        assert_eq!(
            charged.entries()[1].metadata().xattrs()[0].value.as_ptr(),
            destination_xattr_value_pointer
        );
        let ChargedManifestPayloadV1::Directory { children } = charged.entries()[0].payload()
        else {
            panic!("root must be a directory");
        };
        assert_eq!(
            children.as_slice()[0].name.as_ptr(),
            source_basename_pointer
        );
        let ChargedManifestPayloadV1::Regular {
            content_digest,
            data_extents,
        } = charged.entries()[1].payload()
        else {
            panic!("file must be regular");
        };
        let ManifestPayloadV1::Regular {
            content_digest: legacy_content_digest,
            ..
        } = &legacy.entries[1].payload
        else {
            panic!("legacy fixture must be regular");
        };
        assert_eq!(content_digest, legacy_content_digest);
        assert_eq!(data_extents.as_ptr(), destination_extent_pointer);
        assert_eq!(
            charged.entries()[0].node_digest(),
            legacy.entries[0].node_digest
        );
        assert_eq!(charged.root_digest(), legacy.root_digest);
    }

    #[test]
    fn charged_nested_and_hardlink_manifests_match_the_legacy_oracle() {
        type Fixture = fn(u8) -> (SourceTreePlanV1, SourceTreePlanV1);
        for fixture in [nested_fixture as Fixture, hardlink_fixture as Fixture] {
            let (source_s1, destination_d1) = fixture(0xa1);
            let (source_s2, destination_d2) = fixture(0xa1);
            let (legacy_source, legacy_destination) = fixture(0xa1);
            let legacy = compile_tree_manifest(
                legacy_source,
                legacy_destination,
                workspace_path(),
                TreeRoleV1::Workspace,
            )
            .unwrap();
            let expected_canonical = legacy_canonical_bytes(&legacy);
            let resources = manifest_resources(4 * 1024 * 1024);
            let stable = stable_projection(
                &resources,
                source_s1,
                source_s2,
                destination_d1,
                destination_d2,
            );
            let charged = compile_charged(&resources, stable).unwrap();
            assert_eq!(charged.canonical_bytes(), expected_canonical);
            assert_eq!(charged.root_digest(), legacy.root_digest);
            assert_eq!(charged.entries().len(), legacy.entries.len());
            for (charged_entry, legacy_entry) in charged.entries().iter().zip(legacy.entries.iter())
            {
                assert_eq!(charged_entry.relative_path(), legacy_entry.relative_path);
                assert_eq!(charged_entry.node_digest(), legacy_entry.node_digest);
                assert_eq!(charged_entry.hardlink_group(), legacy_entry.hardlink_group);
                assert_eq!(charged_entry.payload().kind(), legacy_entry.payload.kind());
            }
            if legacy.entries.len() == 3 && legacy.entries[1].relative_path == b"dir" {
                let ChargedManifestPayloadV1::Directory { children } =
                    charged.entries()[1].payload()
                else {
                    panic!("nested entry must be a directory");
                };
                assert_eq!(
                    children.as_slice()[0].node_digest,
                    charged.entries()[2].node_digest()
                );
            } else {
                let group = charged.entries()[1]
                    .hardlink_group()
                    .expect("hardlink entry must carry its group digest");
                assert_eq!(charged.entries()[2].hardlink_group(), Some(group));
                assert_eq!(
                    charged.entries()[1].node_digest(),
                    charged.entries()[2].node_digest()
                );
            }
            drop(charged);
            assert_eq!(resources.persistent_manifest_heap_live_for_test(), 0);
            assert_eq!(resources.retained_view_heap_live_for_test(), 0);
        }
    }

    #[test]
    fn symlink_payload_move_and_digest_match_without_verifier_admission() {
        // The current verified profile intentionally refuses symlink
        // materialization before it can mint a stable projection. Exercise
        // the compiler's move-only payload representation directly so future
        // admission cannot regress to cloning this plan-owned buffer.
        let (source, destination) = rich_fixture(b"file");
        let target_pointer = match destination.entries()[2].payload() {
            SourcePlanPayloadV1::Symlink { target } => target.as_ptr(),
            _ => panic!("fixture must be a symlink"),
        };
        let (legacy_source, legacy_destination) = rich_fixture(b"file");
        let legacy = compile_tree_manifest(
            legacy_source,
            legacy_destination,
            workspace_path(),
            TreeRoleV1::Workspace,
        )
        .unwrap();
        let resources = manifest_resources(4 * 1024 * 1024);
        let (_, source_entries, _, _) = source.into_parts();
        let source_entry = source_entries.into_vec().into_iter().nth(2).unwrap();
        let (_, _, _, source_statx, _, source_payload, _) = source_entry.into_parts();
        assert!(matches!(
            source_payload,
            SourcePlanPayloadV1::Symlink { .. }
        ));
        let (_, destination_entries, _, _) = destination.into_parts();
        let destination_entry = destination_entries.into_vec().into_iter().nth(2).unwrap();
        let (_, _, _, _, _, destination_payload, _) = destination_entry.into_parts();
        let SourcePlanPayloadV1::Symlink { target } = destination_payload else {
            panic!("fixture must be a symlink");
        };
        let (mode, logical_uid, logical_gid, nlink, size, atime, mtime, ctime, btime) =
            source_statx.into_manifest_parts();
        let metadata = ChargedManifestMetadataV1 {
            mode,
            logical_uid,
            logical_gid,
            size,
            nlink,
            atime,
            mtime,
            ctime,
            btime,
            xattrs: manifest_compilation_session_for_test(&resources)
                .charged_vec(0)
                .unwrap(),
        };
        let payload = ChargedManifestPayloadV1::Symlink { target };
        let digest = canonical::derive_manifest_node_digest_projection_streaming_v1(
            metadata.projection(),
            payload.projection(),
            None,
        )
        .unwrap();
        let ChargedManifestPayloadV1::Symlink { target } = &payload else {
            panic!("charged payload must be a symlink");
        };
        assert_eq!(target.as_ptr(), target_pointer);
        assert_eq!(digest, legacy.entries[2].node_digest);
        drop(payload);
        drop(metadata);
    }

    #[test]
    fn charged_compiler_preserves_raw_names_end_to_end() {
        let resources = manifest_resources(4 * 1024 * 1024);
        let (source_s1, destination_d1) = fixture(0x63, b"\xff");
        let (source_s2, destination_d2) = fixture(0x63, b"\xff");
        let stable = stable_projection(
            &resources,
            source_s1,
            source_s2,
            destination_d1,
            destination_d2,
        );
        let charged = compile_charged(&resources, stable).unwrap();
        assert_eq!(charged.entries()[1].relative_path(), b"\xff");
        let ChargedManifestPayloadV1::Directory { children } = charged.entries()[0].payload()
        else {
            panic!("root must be a directory");
        };
        assert_eq!(children.as_slice()[0].name, b"\xff");
    }

    #[test]
    fn full_compiler_exact_boundaries_cover_hardlinks_and_nested_xattrs() {
        assert_full_compiler_exact_boundary(hardlink_fixture, 0x52);
        assert_full_compiler_exact_boundary(nested_xattr_fixture, 0x54);
    }

    #[test]
    fn hardlink_path_phase_has_an_exact_and_one_byte_short_boundary() {
        let (source, _) = hardlink_fixture(0x53);
        let group_bytes = u64::try_from(source.hardlink_groups().len()).unwrap()
            * u64::try_from(std::mem::size_of::<HardlinkGroupDigest>()).unwrap();
        let path_bytes = u64::try_from(source.hardlink_groups()[0].member_indices().len()).unwrap()
            * u64::try_from(std::mem::size_of::<&[u8]>()).unwrap();
        let exact = group_bytes + path_bytes;
        let resources = manifest_resources(exact);
        let digests = compile_hardlink_group_digests_charged(
            &manifest_compilation_session_for_test(&resources),
            source.entries(),
            source.hardlink_groups(),
        )
        .unwrap();
        assert_eq!(digests.as_slice().len(), 1);
        assert_eq!(
            resources.persistent_manifest_heap_live_for_test(),
            group_bytes
        );
        drop(digests);
        assert_eq!(resources.persistent_manifest_heap_live_for_test(), 0);

        let resources = manifest_resources(exact - 1);
        let error = match compile_hardlink_group_digests_charged(
            &manifest_compilation_session_for_test(&resources),
            source.entries(),
            source.hardlink_groups(),
        ) {
            Ok(_) => panic!("one-byte-short hardlink path budget must refuse"),
            Err(error) => error,
        };
        assert!(matches!(
            error,
            SnapshotManifestCompileErrorV1::Resource(
                SnapshotPipelineResourceErrorV1::PersistentManifestHeapCapacityExceeded { .. }
            )
        ));
        assert_eq!(resources.persistent_manifest_heap_live_for_test(), 0);
    }

    #[test]
    fn foreign_session_cannot_consume_a_stable_projection() {
        let owner = manifest_resources(4 * 1024 * 1024);
        let foreign = manifest_resources(4 * 1024 * 1024);
        let (source_s1, destination_d1) = fixture(0x61, b"file");
        let (source_s2, destination_d2) = fixture(0x61, b"file");
        let stable =
            stable_projection(&owner, source_s1, source_s2, destination_d1, destination_d2);
        let error = match compile_tree_manifest_charged(
            &manifest_compilation_session_for_test(&foreign),
            stable,
        ) {
            Ok(_) => panic!("foreign session must refuse stable proof"),
            Err(error) => error,
        };
        assert_eq!(error, SnapshotManifestCompileErrorV1::AuthorityMismatch);
        assert_eq!(owner.retained_view_heap_live_for_test(), 0);
        assert_eq!(foreign.persistent_manifest_heap_live_for_test(), 0);
    }

    #[test]
    fn semantic_walk_rejects_hidden_unsettable_xattr_before_allocation() {
        let root = |source| {
            SourceTreeEntryV1::unchecked_for_test(
                b"",
                b"source-root",
                None,
                statx(source, 1, S_IFDIR | 0o555, 2, 4_096, 1, 2, 3, None),
                vec![CapturedXattrV1::unsettable_for_test(
                    b"security.again",
                    libc::EPERM,
                )],
                SourcePlanPayloadV1::Directory {
                    children: Vec::new().into_boxed_slice(),
                },
                None,
            )
        };
        // Deliberately lie in the plan-level summary flag; the entry walk must
        // still inspect the typed value rather than trusting the summary.
        let source = SourceTreePlanV1::unchecked_for_test(
            b"source-root",
            vec![root(true)],
            Vec::new(),
            false,
        );
        let destination = SourceTreePlanV1::unchecked_for_test(
            b"source-root",
            vec![root(false)],
            Vec::new(),
            false,
        );
        assert_eq!(
            validate_charged_manifest_projection_pair(&source, &destination).unwrap_err(),
            SnapshotManifestCompileErrorV1::VisibleXattrUnrepresentable
        );
    }

    #[test]
    fn malformed_backlink_root_name_extent_and_hardlink_identity_are_rejected() {
        assert_eq!(
            validate_charged_extent_sequence(
                &[
                    ExtentV1 {
                        offset: 0,
                        length: 2,
                    },
                    ExtentV1 {
                        offset: 2,
                        length: 2,
                    },
                ],
                4,
            )
            .unwrap_err(),
            SnapshotManifestCompileErrorV1::MalformedPlan
        );

        let bad_root = |source| {
            SourceTreePlanV1::unchecked_for_test(
                b".",
                vec![directory_entry(source, b"", b".", None, 1, Vec::new())],
                Vec::new(),
                false,
            )
        };
        assert_eq!(
            validate_charged_manifest_projection_pair(&bad_root(true), &bad_root(false))
                .unwrap_err(),
            SnapshotManifestCompileErrorV1::MalformedPlan
        );

        let bad_parent = |source| {
            SourceTreePlanV1::unchecked_for_test(
                b"source-root",
                vec![
                    directory_entry(source, b"", b"source-root", None, 1, vec![1]),
                    SourceTreeEntryV1::unchecked_for_test(
                        b"file",
                        b"file",
                        Some(9),
                        statx(source, 2, S_IFREG | 0o444, 1, 4, 5, 6, 7, None),
                        Vec::new(),
                        SourcePlanPayloadV1::Regular {
                            evidence: regular_evidence(0x71, 4),
                        },
                        None,
                    ),
                ],
                Vec::new(),
                false,
            )
        };
        assert_eq!(
            validate_charged_manifest_projection_pair(&bad_parent(true), &bad_parent(false))
                .unwrap_err(),
            SnapshotManifestCompileErrorV1::MalformedPlan
        );

        let wrong_inode_group = |source| {
            let root = directory_entry(source, b"", b"source-root", None, 1, vec![1, 2]);
            let first = regular_entry(source, b"a", b"a", 0, 2, 2, 0x81, Some(0));
            let second = regular_entry(source, b"b", b"b", 0, 2, 2, 0x81, Some(0));
            let group = SourceHardlinkGroupV1::unchecked_for_test(
                root.statx().inode_key().clone(),
                vec![1, 2],
            );
            SourceTreePlanV1::unchecked_for_test(
                b"source-root",
                vec![root, first, second],
                vec![group],
                false,
            )
        };
        assert_eq!(
            validate_charged_manifest_projection_pair(
                &wrong_inode_group(true),
                &wrong_inode_group(false),
            )
            .unwrap_err(),
            SnapshotManifestCompileErrorV1::MalformedPlan
        );
    }

    #[test]
    fn malformed_verified_projection_releases_both_ledgers_on_refusal() {
        let malformed = |source| {
            let child = regular_entry(source, b"file", b"file", 0, 2, 1, 0xb1, None);
            let (path, basename, _, statx, xattrs, payload, hardlink) = child.into_parts();
            let child = SourceTreeEntryV1::unchecked_for_test(
                &path,
                &basename,
                Some(9),
                statx,
                xattrs.into_vec(),
                payload,
                hardlink,
            );
            SourceTreePlanV1::unchecked_for_test(
                b"source-root",
                vec![
                    directory_entry(source, b"", b"source-root", None, 1, vec![1]),
                    child,
                ],
                Vec::new(),
                false,
            )
        };
        let resources = manifest_resources(4 * 1024 * 1024);
        let stable = stable_projection(
            &resources,
            malformed(true),
            malformed(true),
            malformed(false),
            malformed(false),
        );
        let error = match compile_charged(&resources, stable) {
            Ok(_) => panic!("malformed parent backlink must refuse"),
            Err(error) => error,
        };
        assert_eq!(error, SnapshotManifestCompileErrorV1::MalformedPlan);
        assert_eq!(resources.persistent_manifest_heap_live_for_test(), 0);
        assert_eq!(resources.retained_view_heap_live_for_test(), 0);
    }

    #[test]
    fn malformed_destination_semantics_refuse_before_allocation() {
        let malformed_destination = || {
            let (_, destination) = fixture(0xb2, b"file");
            replace_root_statx(
                destination,
                SourceStatxV1::for_test(
                    11,
                    22,
                    33,
                    1,
                    S_IFDIR | 0o555,
                    1_000,
                    2_000,
                    2,
                    8_192,
                    time(1),
                    time(2),
                    TimespecV1 {
                        seconds: 300,
                        nanoseconds: 1_000_000_000,
                    },
                    Some(time(400)),
                ),
            )
        };
        let (source_s1, _) = fixture(0xb2, b"file");
        let (source_s2, _) = fixture(0xb2, b"file");
        // A zero-byte persistent envelope proves semantic refusal precedes
        // every charged allocation, rather than merely releasing one later.
        let resources = manifest_resources(0);
        let stable = stable_projection(
            &resources,
            source_s1,
            source_s2,
            malformed_destination(),
            malformed_destination(),
        );
        let error = match compile_charged(&resources, stable) {
            Ok(_) => panic!("malformed D2 semantics must refuse"),
            Err(error) => error,
        };
        assert_eq!(error, SnapshotManifestCompileErrorV1::MalformedPlan);
        assert_eq!(resources.persistent_manifest_heap_live_for_test(), 0);
        assert_eq!(resources.retained_view_heap_live_for_test(), 0);
    }

    #[test]
    fn charged_result_is_linear_and_drop_releases_both_ledgers() {
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

        <ChargedTreeManifestV1<'static> as AmbiguousIfClone<_>>::probe();
        <ChargedTreeManifestV1<'static> as AmbiguousIfCopy<_>>::probe();
        assert!(std::mem::needs_drop::<ChargedTreeManifestV1<'static>>());
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            <SnapshotPreparedPublishedChildBindV1<'static, 'static> as AmbiguousIfClone<_>>::probe(
            );
            <SnapshotPreparedPublishedChildBindV1<'static, 'static> as AmbiguousIfCopy<_>>::probe();
            <PublishedCanonicalTreeV1<'static> as AmbiguousIfClone<_>>::probe();
            <PublishedCanonicalTreeV1<'static> as AmbiguousIfCopy<_>>::probe();
            <FirstExecuteOnlyWorkspaceTreeBindingV1<'static> as AmbiguousIfClone<_>>::probe();
            <FirstExecuteOnlyWorkspaceTreeBindingV1<'static> as AmbiguousIfCopy<_>>::probe();
            assert!(std::mem::needs_drop::<
                SnapshotPreparedPublishedChildBindV1<'static, 'static>,
            >());
            assert!(std::mem::needs_drop::<PublishedCanonicalTreeV1<'static>>());
            assert!(std::mem::needs_drop::<
                FirstExecuteOnlyWorkspaceTreeBindingV1<'static>,
            >());
        }

        let resources = manifest_resources(4 * 1024 * 1024);
        let (source_s1, destination_d1) = fixture(0x91, b"file");
        let (source_s2, destination_d2) = fixture(0x91, b"file");
        let stable = stable_projection(
            &resources,
            source_s1,
            source_s2,
            destination_d1,
            destination_d2,
        );
        let charged = compile_charged(&resources, stable).unwrap();
        assert!(resources.persistent_manifest_heap_live_for_test() > 0);
        assert_eq!(
            resources.retained_view_heap_live_for_test(),
            2 * resources.policy().max_retained_view_bytes().get()
        );
        drop(charged);
        assert_eq!(resources.persistent_manifest_heap_live_for_test(), 0);
        assert_eq!(resources.retained_view_heap_live_for_test(), 0);
    }
}
