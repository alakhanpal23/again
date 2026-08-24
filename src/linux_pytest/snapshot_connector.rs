//! Shared resource connector for the snapshot pipeline.
//!
//! Static projection is allocation-free and derives every leaf input from one
//! preflighted policy. Optional zero-valued classes and aggregate budgets that
//! current nonzero leaf shapes cannot enforce exactly are refused rather than
//! widened. The connector then owns the mutable resource ledger and keeps leaf
//! policies private. Only staged-directory creation and its RAII cleanup are
//! wired so far; the charged guard cannot enter the still-unmetered ready or
//! publish transitions. Every wired phase charges the same ledger before each
//! budgeted attempt and allocator-observed capacity increase.

use std::ffi::CStr;
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
use std::os::fd::BorrowedFd;

use super::snapshot_materialize::SnapshotMaterializePolicyV1;
use super::snapshot_policy::{
    SnapshotChargedBytesV1, SnapshotPipelineForwardStageV1, SnapshotPipelineResourceErrorV1,
    SnapshotPipelineResourcesV1, SnapshotResourcePolicyFieldV1, SnapshotResourcePolicyV1,
};
use super::snapshot_publish::{
    ChargedStagedSnapshotDirectoryV1, SnapshotPublishErrorV1, SnapshotPublishPolicyV1,
};
use super::snapshot_regular::RegularCopyPolicyV1;
use super::snapshot_tree::{
    SourceEnumerationPolicyV1, SourceTraversalLimitsV1, SourceXattrLimitsV1,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SnapshotProjectedLeafV1 {
    SourceTraversal,
    SourceXattrs,
    SourceEnumeration,
    Materialization,
    Publication,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SnapshotDerivedResourceV1 {
    SourceDepth,
    SourceEntries,
    SourceNameBytes,
    SourceTotalXattrs,
    SourceTotalXattrBytes,
    MaterializerDepth,
    MaterializerEntries,
    MaterializerNameBytes,
    CleanupDepth,
    TreeFileDescriptors,
    MaterializerFileDescriptors,
    RegularCopyFileDescriptors,
    StagedPublisherFileDescriptors,
    PublisherCleanupFileDescriptors,
    PublicationFileDescriptors,
    SnapshotFileDescriptors,
    FourViewHeapBytes,
    SourcePlanBytes,
    MaterializerPlanBytes,
    MaterializerTotalXattrs,
    MaterializerTotalXattrBytes,
    PublisherCleanupEntries,
    PublisherCleanupNameBytes,
    PublisherRetainedNameBytes,
    PublisherCleanupGetdentsAttempts,
    SourceOpenat2Attempts,
    SourceSyscallAttempts,
    SourceXattrStabilityRounds,
    MaterializerOpenat2Attempts,
    MaterializerSyscallAttempts,
    PublicationOpenat2Attempts,
    PublicationSyscallAttempts,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum SnapshotPolicyProjectionErrorV1 {
    /// The shared policy intentionally disabled a class that a current leaf
    /// cannot represent without silently substituting a positive limit.
    ZeroCannotBeRepresented(SnapshotResourcePolicyFieldV1),
    /// A leaf exposes only `entries * per-entry`, so a smaller shared
    /// aggregate ceiling would be lost at that boundary.
    AggregateCannotBeEnforcedExactly {
        field: SnapshotResourcePolicyFieldV1,
        committed: u64,
        leaf_implied: u64,
    },
    ArithmeticOverflow(SnapshotResourcePolicyFieldV1),
    DerivedResourceOverflow(SnapshotDerivedResourceV1),
    LeafRejected(SnapshotProjectedLeafV1),
    LeafCapacityInsufficient {
        leaf: SnapshotProjectedLeafV1,
        field: SnapshotResourcePolicyFieldV1,
    },
    CleanupOperationReserveMismatch {
        committed: u64,
        projected: u64,
    },
    DerivedResourceMismatch {
        resource: SnapshotDerivedResourceV1,
        committed: u64,
        projected: u64,
    },
}

#[derive(Eq, PartialEq)]
pub(super) enum SnapshotChargedErrorV1<E> {
    PublicationAlreadyStarted,
    Resource(SnapshotPipelineResourceErrorV1),
    Leaf(E),
}

impl<E> std::fmt::Debug for SnapshotChargedErrorV1<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PublicationAlreadyStarted => formatter.write_str("PublicationAlreadyStarted"),
            Self::Resource(error) => formatter.debug_tuple("Resource").field(error).finish(),
            Self::Leaf(_) => formatter.write_str("Leaf(<redacted>)"),
        }
    }
}

impl<E> From<SnapshotPipelineResourceErrorV1> for SnapshotChargedErrorV1<E> {
    fn from(error: SnapshotPipelineResourceErrorV1) -> Self {
        Self::Resource(error)
    }
}

/// One matched publication session. It never exposes independently spliceable
/// forward and cleanup authority.
#[derive(Debug)]
pub(super) struct SnapshotPublicationSessionV1<'resources> {
    resources: &'resources SnapshotPipelineResourcesV1,
    policy: &'resources SnapshotPublishPolicyV1,
}

impl<'resources> SnapshotPublicationSessionV1<'resources> {
    pub(super) const fn policy(&self) -> &'resources SnapshotPublishPolicyV1 {
        self.policy
    }

    pub(super) fn run_forward_attempt<T>(
        &self,
        attempt: impl FnOnce() -> T,
    ) -> Result<T, SnapshotPipelineResourceErrorV1> {
        self.resources
            .run_forward_attempt(SnapshotPipelineForwardStageV1::Publication, attempt)
    }

    pub(super) fn run_cleanup_attempt<T>(
        &self,
        attempt: impl FnOnce() -> T,
    ) -> Result<T, SnapshotPipelineResourceErrorV1> {
        self.resources.run_cleanup_attempt(attempt)
    }

    pub(super) fn charged_forward_bytes(
        &self,
        max_capacity: usize,
    ) -> Result<SnapshotChargedBytesV1<'resources>, SnapshotPipelineResourceErrorV1> {
        self.resources
            .charged_forward_bytes(SnapshotPipelineForwardStageV1::Publication, max_capacity)
    }

    pub(super) fn charged_cleanup_bytes(
        &self,
        max_capacity: usize,
    ) -> Result<SnapshotChargedBytesV1<'resources>, SnapshotPipelineResourceErrorV1> {
        self.resources.charged_cleanup_bytes(max_capacity)
    }

    #[cfg(test)]
    pub(super) fn forward_attempts_remaining(&self) -> u64 {
        self.resources.forward_attempts_remaining_for_test()
    }

    #[cfg(test)]
    pub(super) fn cleanup_attempts_remaining(&self) -> u64 {
        self.resources.cleanup_attempts_remaining_for_test()
    }
}

/// Owns the sole mutable resource ledger and its exact leaf projections.
///
/// The lack of `Clone`/`Copy` prevents detaching the ledger from these
/// policies. Resource-budget authority is exposed only by connector-owned
/// phase methods that mint non-`Clone`, non-`Copy` shared-budget sessions.
#[derive(Debug)]
pub(super) struct SnapshotConnectorV1 {
    resources: SnapshotPipelineResourcesV1,
    source: SourceEnumerationPolicyV1,
    materialization: SnapshotMaterializePolicyV1,
    publication: SnapshotPublishPolicyV1,
    publication_started: std::cell::Cell<bool>,
}

impl SnapshotConnectorV1 {
    fn begin_publication(&self) -> Option<SnapshotPublicationSessionV1<'_>> {
        if self.publication_started.replace(true) {
            return None;
        }
        Some(SnapshotPublicationSessionV1 {
            resources: &self.resources,
            policy: &self.publication,
        })
    }

    /// Consumes the sole publication attempt, even when staging refuses or
    /// fails. A returned guard can expose its pinned directory and clean it up,
    /// but cannot enter the still-unmetered ready or publish transitions.
    pub(super) fn create_staged_snapshot_directory_at<'scope>(
        &'scope self,
        parent: BorrowedFd<'scope>,
        staging_name: &CStr,
    ) -> Result<
        ChargedStagedSnapshotDirectoryV1<'scope>,
        SnapshotChargedErrorV1<SnapshotPublishErrorV1>,
    > {
        let session = self
            .begin_publication()
            .ok_or(SnapshotChargedErrorV1::PublicationAlreadyStarted)?;
        super::snapshot_publish::create_charged_staged_snapshot_directory_at(
            parent,
            staging_name,
            session,
        )
    }
}

/// Consumes the already-preflighted resource authority and projects its policy
/// before any allocation or filesystem work.
pub(super) fn connect_snapshot_pipeline(
    resources: SnapshotPipelineResourcesV1,
) -> Result<SnapshotConnectorV1, SnapshotPolicyProjectionErrorV1> {
    use SnapshotProjectedLeafV1 as Leaf;
    use SnapshotResourcePolicyFieldV1 as Field;

    let policy = resources.policy();

    // Check total file bytes before per-file bytes to freeze typed error
    // precedence for the valid all-zero file class.
    let max_total_file_bytes = nonzero_u64(policy.max_total_file_bytes(), Field::TotalFileBytes)?;
    let max_file_bytes = nonzero_u64(policy.max_file_bytes(), Field::FileBytes)?;
    let max_relative_path_bytes =
        nonzero_u32(policy.max_relative_path_bytes(), Field::RelativePathBytes)?;
    let max_symlink_target_bytes =
        nonzero_u32(policy.max_symlink_target_bytes(), Field::SymlinkTargetBytes)?;
    let max_data_extents = nonzero_u32(
        policy.max_data_extents_per_file(),
        Field::DataExtentsPerFile,
    )?;
    let max_xattrs_per_entry = nonzero_u16(policy.max_xattrs_per_entry(), Field::XattrsPerEntry)?;
    let max_xattr_name_bytes = nonzero_u16(policy.max_xattr_name_bytes(), Field::XattrNameBytes)?;
    let max_xattr_value_bytes =
        nonzero_u32(policy.max_xattr_value_bytes(), Field::XattrValueBytes)?;
    let max_xattr_list_bytes = nonzero_u32(policy.max_xattr_list_bytes(), Field::XattrListBytes)?;
    let max_total_xattr_bytes = nonzero_u64(
        policy.max_total_xattr_payload_bytes(),
        Field::TotalXattrPayloadBytes,
    )?;
    let cleanup_retained_name_bytes =
        nonzero_u64(policy.max_transient_heap_bytes(), Field::TransientHeapBytes)?;

    let implied_extents = u64::from(policy.max_entries().get())
        .checked_mul(u64::from(max_data_extents.get()))
        .ok_or(SnapshotPolicyProjectionErrorV1::ArithmeticOverflow(
            Field::TotalDataExtents,
        ))?;
    if policy.max_total_data_extents() != implied_extents {
        return Err(
            SnapshotPolicyProjectionErrorV1::AggregateCannotBeEnforcedExactly {
                field: Field::TotalDataExtents,
                committed: policy.max_total_data_extents(),
                leaf_implied: implied_extents,
            },
        );
    }

    let implied_xattrs = u64::from(policy.max_entries().get())
        .checked_mul(u64::from(max_xattrs_per_entry.get()))
        .ok_or(SnapshotPolicyProjectionErrorV1::ArithmeticOverflow(
            Field::TotalXattrs,
        ))?;
    if policy.max_total_xattrs() != implied_xattrs {
        return Err(
            SnapshotPolicyProjectionErrorV1::AggregateCannotBeEnforcedExactly {
                field: Field::TotalXattrs,
                committed: policy.max_total_xattrs(),
                leaf_implied: implied_xattrs,
            },
        );
    }

    let traversal = SourceTraversalLimitsV1::checked(
        policy.max_depth(),
        policy.max_name_bytes(),
        max_relative_path_bytes,
        policy.max_entries(),
        max_symlink_target_bytes,
        max_file_bytes,
        max_total_file_bytes,
    )
    .ok_or(SnapshotPolicyProjectionErrorV1::LeafRejected(
        Leaf::SourceTraversal,
    ))?;
    let xattrs = SourceXattrLimitsV1::checked(
        max_xattrs_per_entry,
        max_xattr_name_bytes,
        max_xattr_value_bytes,
        max_xattr_list_bytes,
        max_total_xattr_bytes,
    )
    .ok_or(SnapshotPolicyProjectionErrorV1::LeafRejected(
        Leaf::SourceXattrs,
    ))?;
    let source = SourceEnumerationPolicyV1::checked(
        traversal,
        xattrs,
        policy.max_retained_view_bytes(),
        max_data_extents,
        policy.openat2_attempts(),
        policy.syscall_attempts(),
        policy.xattr_stability_rounds(),
    )
    .ok_or(SnapshotPolicyProjectionErrorV1::LeafCapacityInsufficient {
        leaf: Leaf::SourceEnumeration,
        field: Field::RetainedViewBytes,
    })?;

    let materialization = SnapshotMaterializePolicyV1::from_source_policy(source).ok_or(
        SnapshotPolicyProjectionErrorV1::LeafRejected(Leaf::Materialization),
    )?;

    let publication = SnapshotPublishPolicyV1::checked(
        policy.openat2_attempts(),
        policy.syscall_attempts(),
        policy.max_depth(),
        policy.max_entries(),
        policy.max_name_bytes(),
        cleanup_retained_name_bytes,
    )
    .ok_or(SnapshotPolicyProjectionErrorV1::LeafCapacityInsufficient {
        leaf: Leaf::Publication,
        field: Field::TransientHeapBytes,
    })?;

    validate_derived_resources(policy, source, materialization, publication)?;

    let projected_cleanup_attempts = publication.cleanup_operation_attempt_bound().ok_or(
        SnapshotPolicyProjectionErrorV1::ArithmeticOverflow(Field::OperationAttempts),
    )?;
    if projected_cleanup_attempts != policy.cleanup_operation_reserve() {
        return Err(
            SnapshotPolicyProjectionErrorV1::CleanupOperationReserveMismatch {
                committed: policy.cleanup_operation_reserve(),
                projected: projected_cleanup_attempts,
            },
        );
    }

    Ok(SnapshotConnectorV1 {
        resources,
        source,
        materialization,
        publication,
        publication_started: std::cell::Cell::new(false),
    })
}

fn validate_derived_resources(
    policy: SnapshotResourcePolicyV1,
    source: SourceEnumerationPolicyV1,
    materialization: SnapshotMaterializePolicyV1,
    publication: SnapshotPublishPolicyV1,
) -> Result<(), SnapshotPolicyProjectionErrorV1> {
    use SnapshotDerivedResourceV1 as Resource;

    let build_fds = u64::from(source.max_live_source_fds())
        .checked_add(u64::from(materialization.max_live_destination_fds()))
        .and_then(|value| {
            value.checked_add(u64::from(RegularCopyPolicyV1::max_live_transient_fds()))
        })
        .and_then(|value| value.checked_add(u64::from(publication.max_live_staged_fds())))
        .ok_or(SnapshotPolicyProjectionErrorV1::DerivedResourceOverflow(
            Resource::SnapshotFileDescriptors,
        ))?;
    let projected_snapshot_fds = build_fds
        .max(u64::from(source.max_live_source_fds()))
        .max(u64::from(publication.max_live_cleanup_fds()))
        .max(u64::from(publication.max_live_publication_fds()));

    let projected_getdents_attempts = u64::from(policy.max_entries().get())
        .checked_mul(5)
        .and_then(|value| value.checked_add(3))
        .and_then(|value| value.checked_mul(u64::from(policy.syscall_attempts().get())))
        .ok_or(SnapshotPolicyProjectionErrorV1::DerivedResourceOverflow(
            Resource::PublisherCleanupGetdentsAttempts,
        ))?;

    let projected_four_view_heap = source
        .max_plan_bytes()
        .checked_add(materialization.max_plan_bytes())
        .and_then(|value| value.checked_add(publication.max_cleanup_retained_name_bytes()))
        .ok_or(SnapshotPolicyProjectionErrorV1::DerivedResourceOverflow(
            Resource::FourViewHeapBytes,
        ))?;
    let exact = [
        (
            Resource::SourceDepth,
            u64::from(policy.max_depth()),
            u64::from(source.max_depth()),
        ),
        (
            Resource::SourceEntries,
            u64::from(policy.max_entries().get()),
            u64::from(source.max_entries()),
        ),
        (
            Resource::SourceNameBytes,
            u64::from(policy.max_name_bytes().get()),
            u64::from(source.max_basename_bytes()),
        ),
        (
            Resource::SourceTotalXattrs,
            policy.max_total_xattrs(),
            source.max_total_xattrs(),
        ),
        (
            Resource::SourceTotalXattrBytes,
            policy.max_total_xattr_payload_bytes(),
            source.max_total_xattr_bytes(),
        ),
        (
            Resource::MaterializerDepth,
            u64::from(policy.max_depth()),
            u64::from(materialization.max_depth()),
        ),
        (
            Resource::MaterializerEntries,
            u64::from(policy.max_entries().get()),
            u64::from(materialization.max_entries()),
        ),
        (
            Resource::MaterializerNameBytes,
            u64::from(policy.max_name_bytes().get()),
            u64::from(materialization.max_basename_bytes()),
        ),
        (
            Resource::CleanupDepth,
            u64::from(policy.max_cleanup_depth()),
            u64::from(publication.max_cleanup_depth()),
        ),
        (
            Resource::TreeFileDescriptors,
            u64::from(policy.max_live_tree_fds()),
            u64::from(source.max_live_source_fds()),
        ),
        (
            Resource::MaterializerFileDescriptors,
            u64::from(policy.max_live_materializer_fds()),
            u64::from(materialization.max_live_destination_fds()),
        ),
        (
            Resource::RegularCopyFileDescriptors,
            u64::from(policy.max_live_regular_copy_fds()),
            u64::from(RegularCopyPolicyV1::max_live_transient_fds()),
        ),
        (
            Resource::StagedPublisherFileDescriptors,
            u64::from(policy.max_live_staged_publisher_fds()),
            u64::from(publication.max_live_staged_fds()),
        ),
        (
            Resource::PublisherCleanupFileDescriptors,
            u64::from(policy.max_live_publisher_cleanup_fds()),
            u64::from(publication.max_live_cleanup_fds()),
        ),
        (
            Resource::PublicationFileDescriptors,
            u64::from(policy.max_live_publication_fds()),
            u64::from(publication.max_live_publication_fds()),
        ),
        (
            Resource::SnapshotFileDescriptors,
            u64::from(policy.max_live_snapshot_fds()),
            projected_snapshot_fds,
        ),
        (
            Resource::FourViewHeapBytes,
            policy.max_four_view_heap_bytes(),
            projected_four_view_heap,
        ),
        (
            Resource::SourcePlanBytes,
            policy.max_retained_view_bytes().get(),
            source.max_plan_bytes(),
        ),
        (
            Resource::MaterializerPlanBytes,
            policy.max_retained_view_bytes().get(),
            materialization.max_plan_bytes(),
        ),
        (
            Resource::MaterializerTotalXattrs,
            policy.max_total_xattrs(),
            materialization.max_total_xattrs(),
        ),
        (
            Resource::MaterializerTotalXattrBytes,
            policy.max_total_xattr_payload_bytes(),
            materialization.max_total_xattr_bytes(),
        ),
        (
            Resource::PublisherCleanupEntries,
            u64::from(policy.max_entries().get()),
            u64::from(publication.max_cleanup_entries()),
        ),
        (
            Resource::PublisherCleanupNameBytes,
            u64::from(policy.max_name_bytes().get()),
            u64::from(publication.max_cleanup_name_bytes()),
        ),
        (
            Resource::PublisherRetainedNameBytes,
            policy.max_transient_heap_bytes(),
            publication.max_cleanup_retained_name_bytes(),
        ),
        (
            Resource::PublisherCleanupGetdentsAttempts,
            projected_getdents_attempts,
            publication.max_cleanup_getdents_attempts(),
        ),
        (
            Resource::SourceOpenat2Attempts,
            u64::from(policy.openat2_attempts().get()),
            u64::from(source.openat2_attempts()),
        ),
        (
            Resource::SourceSyscallAttempts,
            u64::from(policy.syscall_attempts().get()),
            u64::from(source.syscall_attempts()),
        ),
        (
            Resource::SourceXattrStabilityRounds,
            u64::from(policy.xattr_stability_rounds().get()),
            u64::from(source.xattr_stability_attempts()),
        ),
        (
            Resource::MaterializerOpenat2Attempts,
            u64::from(policy.openat2_attempts().get()),
            u64::from(materialization.openat2_attempts()),
        ),
        (
            Resource::MaterializerSyscallAttempts,
            u64::from(policy.syscall_attempts().get()),
            u64::from(materialization.syscall_attempts()),
        ),
        (
            Resource::PublicationOpenat2Attempts,
            u64::from(policy.openat2_attempts().get()),
            u64::from(publication.openat2_attempts()),
        ),
        (
            Resource::PublicationSyscallAttempts,
            u64::from(policy.syscall_attempts().get()),
            u64::from(publication.syscall_attempts()),
        ),
    ];
    for (resource, committed, projected) in exact {
        exact_resource(resource, committed, projected)?;
    }
    Ok(())
}

fn exact_resource(
    resource: SnapshotDerivedResourceV1,
    committed: u64,
    projected: u64,
) -> Result<(), SnapshotPolicyProjectionErrorV1> {
    if committed == projected {
        Ok(())
    } else {
        Err(SnapshotPolicyProjectionErrorV1::DerivedResourceMismatch {
            resource,
            committed,
            projected,
        })
    }
}

fn nonzero_u16(
    value: u16,
    field: SnapshotResourcePolicyFieldV1,
) -> Result<NonZeroU16, SnapshotPolicyProjectionErrorV1> {
    NonZeroU16::new(value).ok_or(SnapshotPolicyProjectionErrorV1::ZeroCannotBeRepresented(
        field,
    ))
}

fn nonzero_u32(
    value: u32,
    field: SnapshotResourcePolicyFieldV1,
) -> Result<NonZeroU32, SnapshotPolicyProjectionErrorV1> {
    NonZeroU32::new(value).ok_or(SnapshotPolicyProjectionErrorV1::ZeroCannotBeRepresented(
        field,
    ))
}

fn nonzero_u64(
    value: u64,
    field: SnapshotResourcePolicyFieldV1,
) -> Result<NonZeroU64, SnapshotPolicyProjectionErrorV1> {
    NonZeroU64::new(value).ok_or(SnapshotPolicyProjectionErrorV1::ZeroCannotBeRepresented(
        field,
    ))
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::num::{NonZeroU8, NonZeroU16, NonZeroU32, NonZeroU64};

    use super::*;

    #[derive(Clone, Copy)]
    struct Inputs {
        depth: u16,
        entries: u32,
        name_bytes: u16,
        relative_path_bytes: u32,
        symlink_target_bytes: u32,
        file_bytes: u64,
        total_file_bytes: u64,
        data_extents_per_file: u32,
        total_data_extents: u64,
        xattrs_per_entry: u16,
        total_xattrs: u64,
        xattr_name_bytes: u16,
        xattr_value_bytes: u32,
        xattr_list_bytes: u32,
        total_xattr_payload_bytes: u64,
        retained_view_bytes: u64,
        transient_heap_bytes: u64,
        operation_attempts: u64,
        openat2_attempts: u8,
        syscall_attempts: u8,
        xattr_stability_rounds: u8,
    }

    impl Inputs {
        const fn exact() -> Self {
            Self {
                depth: 2,
                entries: 4,
                name_bytes: 64,
                relative_path_bytes: 1024,
                symlink_target_bytes: 1024,
                file_bytes: 1024 * 1024,
                total_file_bytes: 4 * 1024 * 1024,
                data_extents_per_file: 8,
                total_data_extents: 32,
                xattrs_per_entry: 4,
                total_xattrs: 16,
                xattr_name_bytes: 64,
                xattr_value_bytes: 1024,
                xattr_list_bytes: 4096,
                total_xattr_payload_bytes: 64 * 1024,
                retained_view_bytes: 8 * 1024 * 1024,
                transient_heap_bytes: 1024 * 1024,
                operation_attempts: 1_000_000,
                openat2_attempts: 4,
                syscall_attempts: 3,
                xattr_stability_rounds: 2,
            }
        }
    }

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

    fn resources(inputs: Inputs) -> SnapshotPipelineResourcesV1 {
        let policy = SnapshotResourcePolicyV1::checked(
            inputs.depth,
            nz32(inputs.entries),
            nz16(inputs.name_bytes),
            inputs.relative_path_bytes,
            inputs.symlink_target_bytes,
            inputs.file_bytes,
            inputs.total_file_bytes,
            inputs.data_extents_per_file,
            inputs.total_data_extents,
            inputs.xattrs_per_entry,
            inputs.total_xattrs,
            inputs.xattr_name_bytes,
            inputs.xattr_value_bytes,
            inputs.xattr_list_bytes,
            inputs.total_xattr_payload_bytes,
            nz64(inputs.retained_view_bytes),
            inputs.transient_heap_bytes,
            nz64(inputs.operation_attempts),
            nz8(inputs.openat2_attempts),
            nz8(inputs.syscall_attempts),
            nz8(inputs.xattr_stability_rounds),
        )
        .unwrap();
        SnapshotPipelineResourcesV1::preflight(policy, 0, u64::MAX, u64::MAX).unwrap()
    }

    fn projection_error(inputs: Inputs) -> SnapshotPolicyProjectionErrorV1 {
        let resources = resources(inputs);
        connect_snapshot_pipeline(resources).unwrap_err()
    }

    #[test]
    fn exact_projection_preserves_every_leaf_input() {
        let inputs = Inputs::exact();
        let resources = resources(inputs);
        let projected = connect_snapshot_pipeline(resources).unwrap();
        let traversal = SourceTraversalLimitsV1::checked(
            inputs.depth,
            nz16(inputs.name_bytes),
            nz32(inputs.relative_path_bytes),
            nz32(inputs.entries),
            nz32(inputs.symlink_target_bytes),
            nz64(inputs.file_bytes),
            nz64(inputs.total_file_bytes),
        )
        .unwrap();
        let xattrs = SourceXattrLimitsV1::checked(
            nz16(inputs.xattrs_per_entry),
            nz16(inputs.xattr_name_bytes),
            nz32(inputs.xattr_value_bytes),
            nz32(inputs.xattr_list_bytes),
            nz64(inputs.total_xattr_payload_bytes),
        )
        .unwrap();
        let source = SourceEnumerationPolicyV1::checked(
            traversal,
            xattrs,
            nz64(inputs.retained_view_bytes),
            nz32(inputs.data_extents_per_file),
            nz8(inputs.openat2_attempts),
            nz8(inputs.syscall_attempts),
            nz8(inputs.xattr_stability_rounds),
        )
        .unwrap();
        let materialization = SnapshotMaterializePolicyV1::from_source_policy(source).unwrap();
        let publication = SnapshotPublishPolicyV1::checked(
            nz8(inputs.openat2_attempts),
            nz8(inputs.syscall_attempts),
            inputs.depth,
            nz32(inputs.entries),
            nz16(inputs.name_bytes),
            nz64(inputs.transient_heap_bytes),
        )
        .unwrap();

        assert_eq!(projected.source, source);
        assert_eq!(projected.materialization, materialization);
        assert_eq!(projected.publication, publication);
        let projected_four_view_heap = projected
            .source
            .max_plan_bytes()
            .checked_add(projected.materialization.max_plan_bytes())
            .and_then(|value| {
                value.checked_add(projected.publication.max_cleanup_retained_name_bytes())
            })
            .unwrap();
        assert_eq!(projected_four_view_heap, 17 * 1024 * 1024);
        assert_eq!(
            projected_four_view_heap,
            projected.resources.policy().max_four_view_heap_bytes()
        );
        assert_eq!(
            projected.publication.cleanup_operation_attempt_bound(),
            Some(projected.resources.policy().cleanup_operation_reserve())
        );
        assert_eq!(projected.resources.policy().max_live_snapshot_fds(), 16);
    }

    #[test]
    fn every_valid_but_unrepresentable_zero_fails_on_its_field() {
        use SnapshotResourcePolicyFieldV1 as Field;

        let mut relative_path = Inputs::exact();
        relative_path.entries = 1;
        relative_path.relative_path_bytes = 0;
        relative_path.total_data_extents = relative_path.data_extents_per_file as u64;
        relative_path.total_xattrs = relative_path.xattrs_per_entry as u64;

        let mut symlink = Inputs::exact();
        symlink.symlink_target_bytes = 0;

        let mut total_file = Inputs::exact();
        total_file.file_bytes = 0;
        total_file.total_file_bytes = 0;
        total_file.data_extents_per_file = 0;
        total_file.total_data_extents = 0;

        let mut file = Inputs::exact();
        file.file_bytes = 0;
        file.data_extents_per_file = 0;
        file.total_data_extents = 0;

        let mut extents = Inputs::exact();
        extents.data_extents_per_file = 0;
        extents.total_data_extents = 0;

        let mut xattrs = Inputs::exact();
        xattrs.xattrs_per_entry = 0;
        xattrs.total_xattrs = 0;
        xattrs.xattr_name_bytes = 0;
        xattrs.xattr_value_bytes = 0;
        xattrs.xattr_list_bytes = 0;
        xattrs.total_xattr_payload_bytes = 0;

        let mut xattr_value = Inputs::exact();
        xattr_value.xattr_value_bytes = 0;

        let mut transient = Inputs::exact();
        transient.transient_heap_bytes = 0;

        for (inputs, field) in [
            (relative_path, Field::RelativePathBytes),
            (symlink, Field::SymlinkTargetBytes),
            (total_file, Field::TotalFileBytes),
            (file, Field::FileBytes),
            (extents, Field::DataExtentsPerFile),
            (xattrs, Field::XattrsPerEntry),
            (xattr_value, Field::XattrValueBytes),
            (transient, Field::TransientHeapBytes),
        ] {
            assert_eq!(
                projection_error(inputs),
                SnapshotPolicyProjectionErrorV1::ZeroCannotBeRepresented(field)
            );
        }
    }

    #[test]
    fn smaller_aggregate_extent_and_xattr_budgets_fail_closed() {
        use SnapshotResourcePolicyFieldV1 as Field;

        let mut extents = Inputs::exact();
        extents.total_data_extents -= 1;
        assert_eq!(
            projection_error(extents),
            SnapshotPolicyProjectionErrorV1::AggregateCannotBeEnforcedExactly {
                field: Field::TotalDataExtents,
                committed: 31,
                leaf_implied: 32,
            }
        );

        let mut xattrs = Inputs::exact();
        xattrs.total_xattrs -= 1;
        assert_eq!(
            projection_error(xattrs),
            SnapshotPolicyProjectionErrorV1::AggregateCannotBeEnforcedExactly {
                field: Field::TotalXattrs,
                committed: 15,
                leaf_implied: 16,
            }
        );
    }

    #[test]
    fn open_syscall_and_xattr_retry_fields_never_collapse() {
        let mut inputs = Inputs::exact();
        inputs.openat2_attempts = 7;
        inputs.syscall_attempts = 5;
        inputs.xattr_stability_rounds = 3;
        let resources = resources(inputs);
        let projected = connect_snapshot_pipeline(resources).unwrap();

        assert_eq!(projected.source.openat2_attempts(), 7);
        assert_eq!(projected.source.syscall_attempts(), 5);
        assert_eq!(projected.source.xattr_stability_attempts(), 3);
        assert_eq!(projected.materialization.openat2_attempts(), 7);
        assert_eq!(projected.materialization.syscall_attempts(), 5);
        assert_eq!(projected.publication.openat2_attempts(), 7);
        assert_eq!(projected.publication.syscall_attempts(), 5);
    }

    #[test]
    fn connector_and_publication_session_cannot_clone_and_zero_forward_stays_inert() {
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

        <SnapshotConnectorV1 as AmbiguousIfClone<_>>::probe();
        <SnapshotConnectorV1 as AmbiguousIfCopy<_>>::probe();
        <SnapshotPublicationSessionV1<'static> as AmbiguousIfClone<_>>::probe();
        <SnapshotPublicationSessionV1<'static> as AmbiguousIfCopy<_>>::probe();

        let mut inputs = Inputs::exact();
        // `(5E + 3) * open + (12E + 12) * syscall` for E=4.
        inputs.operation_attempts = 272;
        let resources = resources(inputs);
        assert_eq!(resources.policy().max_forward_operation_attempts(), 0);
        let projected = connect_snapshot_pipeline(resources).unwrap();
        assert_eq!(
            projected
                .resources
                .policy()
                .max_forward_operation_attempts(),
            0
        );
        let session = projected.begin_publication().unwrap();
        assert!(std::ptr::eq(session.policy(), &projected.publication));
        assert_eq!(session.forward_attempts_remaining(), 0);
        let invoked = Cell::new(false);
        assert_eq!(
            session
                .run_forward_attempt(|| invoked.set(true))
                .unwrap_err(),
            SnapshotPipelineResourceErrorV1::OperationBudgetExhausted {
                stage: super::super::snapshot_policy::SnapshotPipelineStageV1::Forward(
                    SnapshotPipelineForwardStageV1::Publication,
                ),
                bucket: super::super::snapshot_policy::SnapshotPipelineAttemptBucketV1::Forward,
            }
        );
        assert!(!invoked.get());
        let cleanup_before = session.cleanup_attempts_remaining();
        session.run_cleanup_attempt(|| invoked.set(true)).unwrap();
        assert!(invoked.get());
        assert_eq!(session.cleanup_attempts_remaining(), cleanup_before - 1);
    }

    #[test]
    fn connector_issues_at_most_one_publication_session() {
        let connector = connect_snapshot_pipeline(resources(Inputs::exact())).unwrap();
        let _first = connector.begin_publication().unwrap();
        assert!(connector.begin_publication().is_none());
    }

    #[test]
    fn charged_error_debug_redacts_leaf_payloads() {
        let rendered = format!(
            "{:?}",
            SnapshotChargedErrorV1::<&str>::Leaf("secret-leaf-sentinel")
        );
        assert_eq!(rendered, "Leaf(<redacted>)");
    }

    #[test]
    fn insufficient_retained_view_has_typed_pre_filesystem_refusal() {
        let mut inputs = Inputs::exact();
        inputs.retained_view_bytes = 1;
        assert_eq!(
            projection_error(inputs),
            SnapshotPolicyProjectionErrorV1::LeafCapacityInsufficient {
                leaf: SnapshotProjectedLeafV1::SourceEnumeration,
                field: SnapshotResourcePolicyFieldV1::RetainedViewBytes,
            }
        );
    }

    #[test]
    fn centrally_valid_policy_beyond_materializer_capacity_fails_closed() {
        let mut inputs = Inputs::exact();
        inputs.entries = 129;
        inputs.data_extents_per_file = 1;
        inputs.total_data_extents = 129;
        inputs.xattrs_per_entry = 32_768;
        inputs.total_xattrs = 129 * 32_768;
        inputs.xattr_name_bytes = 1;
        inputs.xattr_value_bytes = 1;
        inputs.xattr_list_bytes = 64 * 1024;
        inputs.total_xattr_payload_bytes = inputs.total_xattrs * 2;
        inputs.retained_view_bytes = 512 * 1024 * 1024;

        assert_eq!(
            projection_error(inputs),
            SnapshotPolicyProjectionErrorV1::LeafRejected(SnapshotProjectedLeafV1::Materialization,)
        );
    }

    #[test]
    fn insufficient_publisher_cleanup_memory_has_typed_refusal() {
        use SnapshotResourcePolicyFieldV1 as Field;

        let mut insufficient = Inputs::exact();
        insufficient.transient_heap_bytes = 1;
        assert_eq!(
            projection_error(insufficient),
            SnapshotPolicyProjectionErrorV1::LeafCapacityInsufficient {
                leaf: SnapshotProjectedLeafV1::Publication,
                field: Field::TransientHeapBytes,
            }
        );
    }
}
