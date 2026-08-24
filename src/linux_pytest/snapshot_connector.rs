//! Shared resource connector for the snapshot pipeline.
//!
//! Static projection is allocation-free and derives every leaf input from one
//! preflighted policy. Optional zero-valued classes and aggregate budgets that
//! current nonzero leaf shapes cannot enforce exactly are refused rather than
//! widened. The connector then owns the mutable resource ledger and keeps leaf
//! policies private. On Linux x86_64, connector-owned source observation,
//! charged source-to-stage materialization, independent destination
//! observation, and the ordered S1/S2, S1/D1, D1/D2 comparisons are wired.
//! Success still returns only the unready RAII cleanup guard and cannot enter
//! ready or publish transitions. Every wired kernel attempt charges the same
//! ledger.
//! Source-observation logical counts and payloads are bounded by leaf policy.
//! Source plans and materializer workspace use conservative full-ceiling
//! leases; allocator-observed capacity inside them is not yet reconciled to
//! those structural reservations.

use std::ffi::CStr;
use std::num::{NonZeroU16, NonZeroU32, NonZeroU64};
#[cfg(any(test, all(target_os = "linux", target_arch = "x86_64")))]
use std::os::fd::BorrowedFd;

use super::snapshot_materialize::SnapshotMaterializePolicyV1;
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use super::snapshot_materialize::{
    SnapshotTreeMaterializeErrorV1, materialize_source_tree_charged_at,
};
use super::snapshot_policy::{
    SnapshotChargedBytesV1, SnapshotPipelineForwardStageV1, SnapshotPipelineResourceErrorV1,
    SnapshotPipelineResourcesV1, SnapshotResourcePolicyFieldV1, SnapshotResourcePolicyV1,
    SnapshotRetainedViewLeaseV1,
};
use super::snapshot_publish::SnapshotPublishPolicyV1;
#[cfg(any(test, all(target_os = "linux", target_arch = "x86_64")))]
use super::snapshot_publish::{ChargedStagedSnapshotDirectoryV1, SnapshotPublishErrorV1};
use super::snapshot_regular::{RegularCopyPolicyV1, SnapshotRegularFailureV1};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use super::snapshot_tree::enumerate_destination_tree_view_charged_at;
use super::snapshot_tree::{
    QualifiedNoAtimeSourceViewV1, SourceEnumerationPolicyV1, SourceObservationTreeVisitorV1,
    SourceObservedRegularVisitV1, SourceRegularEvidenceV1, SourceTraversalLimitsV1,
    SourceTreeAcquireFailureV1, SourceTreeFailureV1, SourceTreePlanV1, SourceXattrLimitsV1,
    admit_observed_regular_evidence, enumerate_source_tree_view_charged_at,
};
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
use super::snapshot_verify::{
    DestinationPhysicalIdentityV1, SnapshotVerifyErrorV1, begin_four_view_comparison,
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
    RegularCopyCleanupAttempts,
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
    PublisherCleanupAttempts,
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

/// Flat connector-owned failure for materialization plus all three semantic
/// comparisons. Resource exhaustion remains top-level regardless of the leaf
/// that encountered it; potentially path-bearing leaf payloads stay redacted.
/// The type carries no staged directory or transition authority.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) enum SnapshotPipelineFourViewErrorV1 {
    PublicationAlreadyStarted,
    Resource(SnapshotPipelineResourceErrorV1),
    Publication(SnapshotPublishErrorV1),
    Materialization(SnapshotTreeMaterializeErrorV1),
    SourceObservation(SnapshotSourceObservationFailureV1),
    DestinationObservation(SnapshotDestinationObservationFailureV1),
    Comparison(SnapshotVerifyErrorV1),
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl std::fmt::Debug for SnapshotPipelineFourViewErrorV1 {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PublicationAlreadyStarted => formatter.write_str("PublicationAlreadyStarted"),
            Self::Resource(error) => formatter.debug_tuple("Resource").field(error).finish(),
            Self::Publication(_) => formatter.write_str("Publication(<redacted>)"),
            Self::Materialization(error) => formatter
                .debug_tuple("Materialization")
                .field(error)
                .finish(),
            Self::SourceObservation(_) => formatter.write_str("SourceObservation(<redacted>)"),
            Self::DestinationObservation(_) => {
                formatter.write_str("DestinationObservation(<redacted>)")
            }
            Self::Comparison(error) => formatter.debug_tuple("Comparison").field(error).finish(),
        }
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn flatten_four_view_observation_error(
    error: SnapshotSourceObservationErrorV1<SnapshotSourceObservationFailureV1>,
    map_leaf: fn(SnapshotSourceObservationFailureV1) -> SnapshotPipelineFourViewErrorV1,
) -> SnapshotPipelineFourViewErrorV1 {
    match error {
        SnapshotSourceObservationErrorV1::Resource(error) => {
            SnapshotPipelineFourViewErrorV1::Resource(error)
        }
        SnapshotSourceObservationErrorV1::Leaf(error) => map_leaf(error),
    }
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

/// A charged source-observation failure.
///
/// Publication state is deliberately absent: source observation has no
/// publication transition, so that impossible state must not be representable
/// on this path. Leaf debug payloads remain redacted because they may originate
/// at a raw-path traversal boundary.
#[derive(Eq, PartialEq)]
pub(super) enum SnapshotSourceObservationErrorV1<E> {
    Resource(SnapshotPipelineResourceErrorV1),
    Leaf(E),
}

/// Destination observation has the same fail-closed resource/leaf envelope as
/// source observation. The connector-minted session below selects the distinct
/// charged stage; an alias avoids a second identical error representation.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) type SnapshotDestinationObservationErrorV1<E> = SnapshotSourceObservationErrorV1<E>;

impl<E> SnapshotSourceObservationErrorV1<E> {
    pub(super) fn map_leaf<F>(
        self,
        map: impl FnOnce(E) -> F,
    ) -> SnapshotSourceObservationErrorV1<F> {
        match self {
            Self::Resource(error) => SnapshotSourceObservationErrorV1::Resource(error),
            Self::Leaf(error) => SnapshotSourceObservationErrorV1::Leaf(map(error)),
        }
    }
}

impl<E> std::fmt::Debug for SnapshotSourceObservationErrorV1<E> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Resource(error) => formatter.debug_tuple("Resource").field(error).finish(),
            Self::Leaf(_) => formatter.write_str("Leaf(<redacted>)"),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum SnapshotSourceObservationFailureV1 {
    Tree(SourceTreeFailureV1),
    Regular(SnapshotRegularFailureV1),
    InvalidRegularEvidence,
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) type SnapshotDestinationObservationFailureV1 = SnapshotSourceObservationFailureV1;

/// One matched publication session. It never exposes independently spliceable
/// forward and cleanup authority.
#[derive(Debug)]
pub(super) struct SnapshotPublicationSessionV1<'resources> {
    resources: &'resources SnapshotPipelineResourcesV1,
    policy: &'resources SnapshotPublishPolicyV1,
}

/// One connector-minted source-observation authority.
///
/// Its private fields bind the exact derived source policy to the connector's
/// sole mutable resource ledger. The stage is structural rather than stored,
/// so a caller cannot splice another phase into this authority.
pub(super) struct SnapshotSourceObservationSessionV1<'resources> {
    resources: &'resources SnapshotPipelineResourcesV1,
    policy: &'resources SourceEnumerationPolicyV1,
}

/// Connector-minted authority for observing the owner-private staged tree.
/// It shares the connector's immutable enumeration policy but charges every
/// raw attempt to the distinct destination-observation stage.
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub(super) struct SnapshotDestinationObservationSessionV1<'resources> {
    resources: &'resources SnapshotPipelineResourcesV1,
    policy: &'resources SourceEnumerationPolicyV1,
}

/// Connector-minted authority for materializer-local and regular-copy attempts
/// in one sequential, connector-owned traversal.
///
/// The exact source-enumeration, destination-materialization, and regular-copy
/// policies plus both non-fungible attempt buckets come from the same
/// preflighted pipeline ledger. No caller can substitute retry limits or spend
/// publisher cleanup authority on leaf-local failure cleanup. The traversal
/// must abort on its first fatal leaf, which keeps at most one failed local
/// destination active against the fixed reserve.
pub(super) struct SnapshotMaterializationSessionV1<'resources> {
    resources: &'resources SnapshotPipelineResourcesV1,
    source_policy: &'resources SourceEnumerationPolicyV1,
    materialization_policy: &'resources SnapshotMaterializePolicyV1,
}

/// One FD-free tree view paired with the connector's linear retained-heap
/// lease. Qualified-source observation, the materializer's copy-time source
/// pass, and private-destination observation all mint this wrapper through
/// their distinct connector-owned sessions. Field order is intentional: the
/// owned plan is destroyed before its budget lease is released.
pub(super) struct SnapshotRetainedTreeViewV1<'resources> {
    plan: SourceTreePlanV1,
    _lease: SnapshotRetainedViewLeaseV1<'resources>,
}

impl<'resources> SnapshotSourceObservationSessionV1<'resources> {
    pub(super) const fn source_policy(&self) -> &'resources SourceEnumerationPolicyV1 {
        self.policy
    }

    pub(super) const fn regular_copy_policy(&self) -> RegularCopyPolicyV1 {
        self.policy.regular_copy_policy()
    }

    pub(super) fn run_attempt<T>(
        &self,
        attempt: impl FnOnce() -> T,
    ) -> Result<T, SnapshotPipelineResourceErrorV1> {
        self.resources
            .run_forward_attempt(SnapshotPipelineForwardStageV1::SourceObservation, attempt)
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
impl<'resources> SnapshotDestinationObservationSessionV1<'resources> {
    pub(super) const fn enumeration_policy(&self) -> &'resources SourceEnumerationPolicyV1 {
        self.policy
    }

    pub(super) const fn regular_copy_policy(&self) -> RegularCopyPolicyV1 {
        self.policy.regular_copy_policy()
    }

    pub(super) fn run_attempt<T>(
        &self,
        attempt: impl FnOnce() -> T,
    ) -> Result<T, SnapshotPipelineResourceErrorV1> {
        self.resources.run_forward_attempt(
            SnapshotPipelineForwardStageV1::DestinationObservation,
            attempt,
        )
    }
}

impl SnapshotMaterializationSessionV1<'_> {
    pub(super) const fn source_policy(&self) -> &SourceEnumerationPolicyV1 {
        self.source_policy
    }

    pub(super) const fn materialization_policy(&self) -> &SnapshotMaterializePolicyV1 {
        self.materialization_policy
    }

    pub(super) const fn regular_copy_policy(&self) -> RegularCopyPolicyV1 {
        self.source_policy.regular_copy_policy()
    }

    pub(super) fn run_materialization_attempt<T>(
        &self,
        attempt: impl FnOnce() -> T,
    ) -> Result<T, SnapshotPipelineResourceErrorV1> {
        self.resources
            .run_forward_attempt(SnapshotPipelineForwardStageV1::Materialization, attempt)
    }

    pub(super) fn run_regular_copy_attempt<T>(
        &self,
        attempt: impl FnOnce() -> T,
    ) -> Result<T, SnapshotPipelineResourceErrorV1> {
        self.resources
            .run_forward_attempt(SnapshotPipelineForwardStageV1::RegularCopy, attempt)
    }

    pub(super) fn run_local_cleanup_attempt<T>(
        &self,
        attempt: impl FnOnce() -> T,
    ) -> Result<T, SnapshotPipelineResourceErrorV1> {
        self.resources.run_local_cleanup_attempt(attempt)
    }

    #[cfg(test)]
    pub(super) fn forward_attempts_remaining(&self) -> u64 {
        self.resources.forward_attempts_remaining_for_test()
    }

    #[cfg(test)]
    pub(super) fn local_cleanup_attempts_remaining(&self) -> u64 {
        self.resources.local_cleanup_attempts_remaining_for_test()
    }
}

/// Connector-owned visitor for one charged source observation. The charged
/// walker supplies a regular-file capability that can only observe through
/// the exact embedded session; no unmetered copy operation is available here.
struct SnapshotSourceObservationVisitorV1;

impl SourceObservationTreeVisitorV1 for SnapshotSourceObservationVisitorV1 {
    type Error = SnapshotSourceObservationErrorV1<SnapshotSourceObservationFailureV1>;

    fn regular(
        &mut self,
        visit: SourceObservedRegularVisitV1<'_, '_>,
    ) -> Result<SourceRegularEvidenceV1, Self::Error> {
        let logical_size = visit.logical_size();
        let evidence = visit
            .observe()
            .map_err(|error| error.map_leaf(SnapshotSourceObservationFailureV1::Regular))?;
        admit_observed_regular_evidence(logical_size, evidence).ok_or(
            SnapshotSourceObservationErrorV1::Leaf(
                SnapshotSourceObservationFailureV1::InvalidRegularEvidence,
            ),
        )
    }
}

fn flatten_tree_observation_error(
    error: SnapshotSourceObservationErrorV1<
        SourceTreeAcquireFailureV1<
            SnapshotSourceObservationErrorV1<SnapshotSourceObservationFailureV1>,
        >,
    >,
) -> SnapshotSourceObservationErrorV1<SnapshotSourceObservationFailureV1> {
    match error {
        SnapshotSourceObservationErrorV1::Resource(error) => {
            SnapshotSourceObservationErrorV1::Resource(error)
        }
        SnapshotSourceObservationErrorV1::Leaf(SourceTreeAcquireFailureV1::Source(error)) => {
            SnapshotSourceObservationErrorV1::Leaf(SnapshotSourceObservationFailureV1::Tree(error))
        }
        SnapshotSourceObservationErrorV1::Leaf(SourceTreeAcquireFailureV1::Visitor {
            source: SnapshotSourceObservationErrorV1::Resource(error),
            ..
        }) => SnapshotSourceObservationErrorV1::Resource(error),
        SnapshotSourceObservationErrorV1::Leaf(SourceTreeAcquireFailureV1::Visitor {
            source: SnapshotSourceObservationErrorV1::Leaf(error),
            ..
        }) => SnapshotSourceObservationErrorV1::Leaf(error),
    }
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

    pub(super) fn run_publisher_cleanup_attempt<T>(
        &self,
        attempt: impl FnOnce() -> T,
    ) -> Result<T, SnapshotPipelineResourceErrorV1> {
        self.resources.run_publisher_cleanup_attempt(attempt)
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
    pub(super) fn publisher_cleanup_attempts_remaining(&self) -> u64 {
        self.resources
            .publisher_cleanup_attempts_remaining_for_test()
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
    fn source_observation_session(&self) -> SnapshotSourceObservationSessionV1<'_> {
        SnapshotSourceObservationSessionV1 {
            resources: &self.resources,
            policy: &self.source,
        }
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn destination_observation_session(&self) -> SnapshotDestinationObservationSessionV1<'_> {
        SnapshotDestinationObservationSessionV1 {
            resources: &self.resources,
            policy: &self.source,
        }
    }

    fn materialization_session(&self) -> SnapshotMaterializationSessionV1<'_> {
        SnapshotMaterializationSessionV1 {
            resources: &self.resources,
            source_policy: &self.source,
            materialization_policy: &self.materialization,
        }
    }

    fn begin_publication(&self) -> Option<SnapshotPublicationSessionV1<'_>> {
        if self.publication_started.replace(true) {
            return None;
        }
        Some(SnapshotPublicationSessionV1 {
            resources: &self.resources,
            policy: &self.publication,
        })
    }

    /// Observe one exact, qualified source view under the connector's derived
    /// source policy and sole resource ledger. The session and visitor never
    /// escape, and callback paths are discarded while errors are flattened.
    pub(super) fn observe_source_tree_view_at(
        &self,
        source_view: QualifiedNoAtimeSourceViewV1<'_>,
        root_name: &CStr,
    ) -> Result<
        SnapshotRetainedTreeViewV1<'_>,
        SnapshotSourceObservationErrorV1<SnapshotSourceObservationFailureV1>,
    > {
        let lease = self
            .resources
            .reserve_retained_view(SnapshotPipelineForwardStageV1::SourceObservation)
            .map_err(SnapshotSourceObservationErrorV1::Resource)?;
        let session = self.source_observation_session();
        let mut visitor = SnapshotSourceObservationVisitorV1;
        let plan =
            enumerate_source_tree_view_charged_at(source_view, root_name, &session, &mut visitor)
                .map_err(flatten_tree_observation_error)?;
        Ok(SnapshotRetainedTreeViewV1 {
            plan,
            _lease: lease,
        })
    }

    /// Observe one exact view of the connector-created private destination.
    /// The returned plan is FD-free and retains exactly one full-plan lease;
    /// it grants no cleanup, readiness, publication, or execution authority.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn observe_destination_tree_view_at<'scope>(
        &'scope self,
        staging: &ChargedStagedSnapshotDirectoryV1<'_>,
        root_name: &CStr,
    ) -> Result<
        SnapshotRetainedTreeViewV1<'scope>,
        SnapshotDestinationObservationErrorV1<SnapshotDestinationObservationFailureV1>,
    > {
        let lease = self
            .resources
            .reserve_retained_view(SnapshotPipelineForwardStageV1::DestinationObservation)
            .map_err(SnapshotDestinationObservationErrorV1::Resource)?;
        let session = self.destination_observation_session();
        let plan =
            enumerate_destination_tree_view_charged_at(staging.directory(), root_name, &session)
                .map_err(flatten_tree_observation_error)?;
        Ok(SnapshotRetainedTreeViewV1 {
            plan,
            _lease: lease,
        })
    }

    /// Materialize a private stage and complete the mandatory comparison
    /// sequence S1/S2, S1/D1, and D1/D2 while never retaining more than two
    /// bounded plans. Success returns only the still-unready cleanup guard;
    /// comparison success is deliberately not represented as authority.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    pub(super) fn materialize_source_tree_four_view_at<'scope>(
        &'scope self,
        publication_parent: BorrowedFd<'scope>,
        staging_name: &CStr,
        source_s1_view: QualifiedNoAtimeSourceViewV1<'_>,
        source_s2_view: QualifiedNoAtimeSourceViewV1<'_>,
        root_name: &CStr,
    ) -> Result<ChargedStagedSnapshotDirectoryV1<'scope>, SnapshotPipelineFourViewErrorV1> {
        let (staging, source_s1) = self.materialize_source_tree_at(
            publication_parent,
            staging_name,
            source_s1_view,
            root_name,
        )?;

        let source_s2 = self
            .observe_source_tree_view_at(source_s2_view, root_name)
            .map_err(|error| {
                flatten_four_view_observation_error(
                    error,
                    SnapshotPipelineFourViewErrorV1::SourceObservation,
                )
            })?;
        let source_stable = begin_four_view_comparison(&source_s1.plan)
            .compare_source_s2(&source_s2.plan)
            .map_err(SnapshotPipelineFourViewErrorV1::Comparison)?;
        drop(source_s2);

        let destination_d1 = self
            .observe_destination_tree_view_at(&staging, root_name)
            .map_err(|error| {
                flatten_four_view_observation_error(
                    error,
                    SnapshotPipelineFourViewErrorV1::DestinationObservation,
                )
            })?;
        let (uid, gid) = staging.expected_owner();
        let destination_stable = source_stable
            .compare_destination_d1(
                &destination_d1.plan,
                DestinationPhysicalIdentityV1::new(uid, gid),
            )
            .map_err(SnapshotPipelineFourViewErrorV1::Comparison)?;
        drop(source_s1);

        let destination_d2 = self
            .observe_destination_tree_view_at(&staging, root_name)
            .map_err(|error| {
                flatten_four_view_observation_error(
                    error,
                    SnapshotPipelineFourViewErrorV1::DestinationObservation,
                )
            })?;
        destination_stable
            .compare_destination_d2(&destination_d2.plan)
            .map_err(SnapshotPipelineFourViewErrorV1::Comparison)?;
        drop(destination_d2);
        drop(destination_d1);

        Ok(staging)
    }

    /// In one connector-owned operation, selects this connector's policies and
    /// resource ledger, creates its sole private stage, and populates that
    /// stage through one charged source traversal. No independently spliceable
    /// session or policy escapes. Success returns the populated guard beside
    /// the exact copy-time source plan under its retained-view lease; the
    /// materializer-workspace lease has already been released. The guard can
    /// expose its pinned directory and clean it up, but cannot enter readiness
    /// or publication transitions. Capacity refusal before publication leaves
    /// the one-shot unused; any failure after publication begins consumes it.
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn materialize_source_tree_at<'scope>(
        &'scope self,
        publication_parent: BorrowedFd<'scope>,
        staging_name: &CStr,
        source_view: QualifiedNoAtimeSourceViewV1<'_>,
        root_name: &CStr,
    ) -> Result<
        (
            ChargedStagedSnapshotDirectoryV1<'scope>,
            SnapshotRetainedTreeViewV1<'scope>,
        ),
        SnapshotPipelineFourViewErrorV1,
    > {
        // The traversal's source plan and the materializer's event workspace
        // can each reach one full-plan ceiling. Reserve both before publication
        // or filesystem work. If the second reservation fails, ordinary drop
        // rollback releases the first before this method returns.
        let source_plan_lease = self
            .resources
            .reserve_retained_view(SnapshotPipelineForwardStageV1::Materialization)
            .map_err(SnapshotPipelineFourViewErrorV1::Resource)?;
        let materializer_plan_lease = self
            .resources
            .reserve_retained_view(SnapshotPipelineForwardStageV1::Materialization)
            .map_err(SnapshotPipelineFourViewErrorV1::Resource)?;
        let publication = self
            .begin_publication()
            .ok_or(SnapshotPipelineFourViewErrorV1::PublicationAlreadyStarted)?;
        let staging = super::snapshot_publish::create_charged_staged_snapshot_directory_at(
            publication_parent,
            staging_name,
            publication,
        )
        .map_err(|error| match error {
            SnapshotChargedErrorV1::PublicationAlreadyStarted => {
                SnapshotPipelineFourViewErrorV1::PublicationAlreadyStarted
            }
            SnapshotChargedErrorV1::Resource(error) => {
                SnapshotPipelineFourViewErrorV1::Resource(error)
            }
            SnapshotChargedErrorV1::Leaf(error) => {
                SnapshotPipelineFourViewErrorV1::Publication(error)
            }
        })?;
        let materialization = self.materialization_session();
        let (staging, plan) =
            materialize_source_tree_charged_at(staging, source_view, root_name, &materialization)
                .map_err(|error| match error {
                SnapshotTreeMaterializeErrorV1::Resource(error) => {
                    SnapshotPipelineFourViewErrorV1::Resource(error)
                }
                error @ (SnapshotTreeMaterializeErrorV1::Source(_)
                | SnapshotTreeMaterializeErrorV1::Materializer(_)) => {
                    SnapshotPipelineFourViewErrorV1::Materialization(error)
                }
            })?;
        drop(materializer_plan_lease);
        Ok((
            staging,
            SnapshotRetainedTreeViewV1 {
                plan,
                _lease: source_plan_lease,
            },
        ))
    }

    /// Test-only access to the charged staging checkpoint. Production code
    /// must use `materialize_source_tree_four_view_at` so a stage cannot escape
    /// before population and all mandatory comparisons complete.
    #[cfg(test)]
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
    if projected_cleanup_attempts != policy.publisher_cleanup_operation_reserve() {
        return Err(SnapshotPolicyProjectionErrorV1::DerivedResourceMismatch {
            resource: SnapshotDerivedResourceV1::PublisherCleanupAttempts,
            committed: policy.publisher_cleanup_operation_reserve(),
            projected: projected_cleanup_attempts,
        });
    }
    let projected_local_cleanup_attempts =
        source.regular_copy_policy().local_cleanup_attempt_bound();
    if projected_local_cleanup_attempts != policy.local_cleanup_operation_reserve() {
        return Err(SnapshotPolicyProjectionErrorV1::DerivedResourceMismatch {
            resource: SnapshotDerivedResourceV1::RegularCopyCleanupAttempts,
            committed: policy.local_cleanup_operation_reserve(),
            projected: projected_local_cleanup_attempts,
        });
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
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    use std::fs;
    use std::fs::File;
    use std::num::{NonZeroU8, NonZeroU16, NonZeroU32, NonZeroU64};
    use std::os::fd::AsFd;
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    use std::os::unix::ffi::OsStrExt;
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    use std::os::unix::fs::MetadataExt;

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

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    fn source_atime(path: &std::path::Path) -> (i64, i64) {
        let metadata = fs::symlink_metadata(path).unwrap();
        (metadata.atime(), metadata.atime_nsec())
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
            Some(
                projected
                    .resources
                    .policy()
                    .publisher_cleanup_operation_reserve()
            )
        );
        assert_eq!(
            projected
                .source
                .regular_copy_policy()
                .local_cleanup_attempt_bound(),
            projected
                .resources
                .policy()
                .local_cleanup_operation_reserve()
        );
        assert_eq!(projected.resources.policy().max_live_snapshot_fds(), 17);
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
        assert_eq!(
            resources(file).policy().local_cleanup_operation_reserve(),
            0
        );

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
    fn connector_and_sessions_cannot_clone_and_zero_forward_stays_inert() {
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
        <SnapshotSourceObservationSessionV1<'static> as AmbiguousIfClone<_>>::probe();
        <SnapshotSourceObservationSessionV1<'static> as AmbiguousIfCopy<_>>::probe();
        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            <SnapshotDestinationObservationSessionV1<'static> as AmbiguousIfClone<_>>::probe();
            <SnapshotDestinationObservationSessionV1<'static> as AmbiguousIfCopy<_>>::probe();
        }
        <SnapshotMaterializationSessionV1<'static> as AmbiguousIfClone<_>>::probe();
        <SnapshotMaterializationSessionV1<'static> as AmbiguousIfCopy<_>>::probe();
        <SnapshotRetainedTreeViewV1<'static> as AmbiguousIfClone<_>>::probe();
        <SnapshotRetainedTreeViewV1<'static> as AmbiguousIfCopy<_>>::probe();

        let mut inputs = Inputs::exact();
        // Publisher cleanup plus one active regular-copy cleanup reserve.
        inputs.operation_attempts = 272 + 4 + 2 * 3;
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
        let cleanup_before = session.publisher_cleanup_attempts_remaining();
        session
            .run_publisher_cleanup_attempt(|| invoked.set(true))
            .unwrap();
        assert!(invoked.get());
        assert_eq!(
            session.publisher_cleanup_attempts_remaining(),
            cleanup_before - 1
        );
    }

    #[test]
    fn source_observation_sessions_share_exact_policy_and_forward_ledger() {
        let connector = connect_snapshot_pipeline(resources(Inputs::exact())).unwrap();
        let first = connector.source_observation_session();
        let second = connector.source_observation_session();

        assert!(std::ptr::eq(first.source_policy(), &connector.source));
        assert!(std::ptr::eq(first.source_policy(), second.source_policy()));
        assert_eq!(first.regular_copy_policy(), second.regular_copy_policy());
        assert!(std::ptr::eq(first.resources, second.resources));

        let before = connector.resources.forward_attempts_remaining_for_test();
        first.run_attempt(|| ()).unwrap();
        assert_eq!(
            second.resources.forward_attempts_remaining_for_test(),
            before - 1
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn destination_observation_sessions_share_exact_policy_and_forward_ledger() {
        let connector = connect_snapshot_pipeline(resources(Inputs::exact())).unwrap();
        let first = connector.destination_observation_session();
        let second = connector.destination_observation_session();

        assert!(std::ptr::eq(first.enumeration_policy(), &connector.source));
        assert!(std::ptr::eq(
            first.enumeration_policy(),
            second.enumeration_policy()
        ));
        assert_eq!(first.regular_copy_policy(), second.regular_copy_policy());
        assert!(std::ptr::eq(first.resources, second.resources));

        let before = connector.resources.forward_attempts_remaining_for_test();
        first.run_attempt(|| ()).unwrap();
        assert_eq!(
            second.resources.forward_attempts_remaining_for_test(),
            before - 1
        );
    }

    #[test]
    fn materialization_sessions_bind_policy_and_disjoint_attempt_buckets() {
        let connector = connect_snapshot_pipeline(resources(Inputs::exact())).unwrap();
        let first = connector.materialization_session();
        let second = connector.materialization_session();

        assert_eq!(
            first.regular_copy_policy(),
            connector.source.regular_copy_policy()
        );
        assert!(std::ptr::eq(first.source_policy(), &connector.source));
        assert!(std::ptr::eq(first.source_policy(), second.source_policy()));
        assert!(std::ptr::eq(
            first.materialization_policy(),
            &connector.materialization
        ));
        assert!(std::ptr::eq(
            first.materialization_policy(),
            second.materialization_policy()
        ));
        assert_eq!(first.regular_copy_policy(), second.regular_copy_policy());
        let forward_before = first.forward_attempts_remaining();
        let local_before = first.local_cleanup_attempts_remaining();

        first.run_materialization_attempt(|| ()).unwrap();
        second.run_regular_copy_attempt(|| ()).unwrap();
        assert_eq!(second.forward_attempts_remaining(), forward_before - 2);
        assert_eq!(second.local_cleanup_attempts_remaining(), local_before);

        second.run_local_cleanup_attempt(|| ()).unwrap();
        assert_eq!(first.forward_attempts_remaining(), forward_before - 2);
        assert_eq!(first.local_cleanup_attempts_remaining(), local_before - 1);
    }

    #[test]
    fn materialization_exhaustion_is_typed_and_precedes_attempt() {
        let mut inputs = Inputs::exact();
        // Publisher cleanup plus one active regular-copy cleanup reserve leave
        // no forward attempts.
        inputs.operation_attempts = 272 + 4 + 2 * 3;
        let connector = connect_snapshot_pipeline(resources(inputs)).unwrap();
        let session = connector.materialization_session();
        let local_cleanup_before = session.local_cleanup_attempts_remaining();
        let publisher_cleanup_before = connector
            .resources
            .publisher_cleanup_attempts_remaining_for_test();
        let invoked = Cell::new(false);

        assert_eq!(
            session
                .run_materialization_attempt(|| invoked.set(true))
                .unwrap_err(),
            SnapshotPipelineResourceErrorV1::OperationBudgetExhausted {
                stage: super::super::snapshot_policy::SnapshotPipelineStageV1::Forward(
                    SnapshotPipelineForwardStageV1::Materialization,
                ),
                bucket: super::super::snapshot_policy::SnapshotPipelineAttemptBucketV1::Forward,
            }
        );
        assert!(!invoked.get());
        assert_eq!(session.forward_attempts_remaining(), 0);
        assert_eq!(
            session.local_cleanup_attempts_remaining(),
            local_cleanup_before
        );
        assert_eq!(
            connector
                .resources
                .publisher_cleanup_attempts_remaining_for_test(),
            publisher_cleanup_before
        );
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn publication_failure_is_flat_redacted_cleans_leases_and_consumes_one_shot() {
        let publication_parent = tempfile::tempdir().unwrap();
        let publication_parent_fd = File::open(publication_parent.path()).unwrap();
        let invalid_source = File::open("/dev/null").unwrap();
        let invalid_staging_name = c"secret-invalid-staging-sentinel";
        let invalid_staging_path = publication_parent
            .path()
            .join(std::ffi::OsStr::from_bytes(invalid_staging_name.to_bytes()));
        let connector = connect_snapshot_pipeline(resources(Inputs::exact())).unwrap();
        let forward_before = connector.resources.forward_attempts_remaining_for_test();
        // SAFETY: the invalid staging basename refuses before either source
        // view can be traversed.
        let source_s1_view = unsafe {
            QualifiedNoAtimeSourceViewV1::from_functionally_verified_mount_for_test(
                invalid_source.as_fd(),
            )
        };
        // SAFETY: the same pre-filesystem refusal keeps this independent view
        // unused as well.
        let source_s2_view = unsafe {
            QualifiedNoAtimeSourceViewV1::from_functionally_verified_mount_for_test(
                invalid_source.as_fd(),
            )
        };

        let error = match connector.materialize_source_tree_four_view_at(
            publication_parent_fd.as_fd(),
            invalid_staging_name,
            source_s1_view,
            source_s2_view,
            c"root",
        ) {
            Err(error) => error,
            Ok(staging) => {
                drop(staging);
                panic!("an invalid staging basename must fail closed");
            }
        };

        assert!(matches!(
            &error,
            SnapshotPipelineFourViewErrorV1::Publication(_)
        ));
        assert_eq!(format!("{error:?}"), "Publication(<redacted>)");
        assert_eq!(
            connector.resources.forward_attempts_remaining_for_test(),
            forward_before
        );
        assert_eq!(connector.resources.retained_view_heap_live_for_test(), 0);
        assert!(!invalid_staging_path.exists());
        assert!(connector.publication_started.get());
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn destination_observation_leaf_failure_rolls_back_its_lease() {
        let publication_parent = tempfile::tempdir().unwrap();
        let publication_parent_fd = File::open(publication_parent.path()).unwrap();
        let staging_name = c".again-snapshot-stage-55555555555555555555555555555555";
        let staging_path = publication_parent
            .path()
            .join(std::ffi::OsStr::from_bytes(staging_name.to_bytes()));
        let connector = connect_snapshot_pipeline(resources(Inputs::exact())).unwrap();
        let staging = connector
            .create_staged_snapshot_directory_at(publication_parent_fd.as_fd(), staging_name)
            .unwrap();
        // Keep this hosted lane independent of destination-filesystem
        // qualification. Successful D1/D2 observation remains covered by the
        // provisioned full-path test; a missing root deterministically proves
        // that a post-reservation leaf refusal releases its lease.
        let forward_before = connector.resources.forward_attempts_remaining_for_test();
        let missing_error = match connector
            .observe_destination_tree_view_at(&staging, c"secret-missing-root-sentinel")
        {
            Err(error) => error,
            Ok(view) => {
                drop(view);
                panic!("a missing destination root must fail closed");
            }
        };
        assert!(matches!(
            &missing_error,
            SnapshotDestinationObservationErrorV1::Leaf(
                SnapshotDestinationObservationFailureV1::Tree(_)
            )
        ));
        let rendered = format!("{missing_error:?}");
        assert_eq!(rendered, "Leaf(<redacted>)");
        assert!(!rendered.contains("secret-missing-root-sentinel"));
        assert!(connector.resources.forward_attempts_remaining_for_test() < forward_before);
        assert_eq!(connector.resources.retained_view_heap_live_for_test(), 0);

        drop(staging);
        assert!(!staging_path.exists());
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn materialization_plan_reservations_roll_back_before_staging() {
        let connector = connect_snapshot_pipeline(resources(Inputs::exact())).unwrap();
        let per_view = connector.resources.policy().max_retained_view_bytes().get();
        let retained = connector
            .resources
            .reserve_retained_view(SnapshotPipelineForwardStageV1::SourceObservation)
            .unwrap();
        let publication_parent = tempfile::tempdir().unwrap();
        let publication_parent_fd = File::open(publication_parent.path()).unwrap();
        let invalid_source = File::open("/dev/null").unwrap();
        // SAFETY: the capacity refusal below precedes all source filesystem
        // access. The deliberately invalid descriptor makes accidental access
        // fail rather than touching an unqualified source tree.
        let source_view = unsafe {
            QualifiedNoAtimeSourceViewV1::from_functionally_verified_mount_for_test(
                invalid_source.as_fd(),
            )
        };
        let staging_name = c".again-snapshot-stage-0123456789abcdef0123456789abcdef";
        let staging_path = publication_parent
            .path()
            .join(std::ffi::OsStr::from_bytes(staging_name.to_bytes()));
        let forward_before = connector.resources.forward_attempts_remaining_for_test();

        assert!(matches!(
            connector.materialize_source_tree_at(
                publication_parent_fd.as_fd(),
                staging_name,
                source_view,
                c"root",
            ),
            Err(SnapshotPipelineFourViewErrorV1::Resource(
                SnapshotPipelineResourceErrorV1::RetainedViewHeapCapacityExceeded {
                    stage: SnapshotPipelineForwardStageV1::Materialization,
                    live,
                    requested,
                    limit,
                }
            )) if live == per_view * 2 && requested == per_view && limit == per_view * 2
        ));
        assert_eq!(
            connector.resources.forward_attempts_remaining_for_test(),
            forward_before
        );
        assert!(!connector.publication_started.get());
        assert!(!staging_path.exists());
        assert_eq!(
            connector.resources.retained_view_heap_live_for_test(),
            per_view
        );

        drop(retained);
        assert_eq!(connector.resources.retained_view_heap_live_for_test(), 0);
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    #[ignore = "requires qualified no-atime source and destination staging filesystems"]
    fn four_view_materialization_copies_exact_bytes_preserves_atime_and_cleans_on_drop() {
        let source_parent = tempfile::tempdir().unwrap();
        let source_tree = source_parent.path().join("tree");
        let source_file = source_tree.join("file");
        let expected = b"again charged materialization mechanics\n";
        fs::create_dir(&source_tree).unwrap();
        fs::write(&source_file, expected).unwrap();

        let primed_names = fs::read_dir(&source_tree)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(primed_names, vec![std::ffi::OsString::from("file")]);
        assert_eq!(fs::read(&source_file).unwrap(), expected);
        let tree_atime = source_atime(&source_tree);
        let file_atime = source_atime(&source_file);
        assert_eq!(fs::read_dir(&source_tree).unwrap().count(), 1);
        assert_eq!(fs::read(&source_file).unwrap(), expected);
        assert_eq!(source_atime(&source_tree), tree_atime);
        assert_eq!(source_atime(&source_file), file_atime);

        let publication_parent = tempfile::tempdir().unwrap();
        let publication_parent_fd = File::open(publication_parent.path()).unwrap();
        let source_parent_fd = File::open(source_parent.path()).unwrap();
        let staging_name = c".again-snapshot-stage-44444444444444444444444444444444";
        let staging_path = publication_parent
            .path()
            .join(std::ffi::OsStr::from_bytes(staging_name.to_bytes()));
        let connector = connect_snapshot_pipeline(resources(Inputs::exact())).unwrap();
        // SAFETY: this mechanics-only fixture is owned by the test, has no
        // concurrent writer, and the repeated probes above proved that the
        // exact objects retain atime. This does not claim that the host passed
        // production functional qualification.
        let source_s1_view = unsafe {
            QualifiedNoAtimeSourceViewV1::from_functionally_verified_mount_for_test(
                source_parent_fd.as_fd(),
            )
        };
        // SAFETY: this is a separately constructed view for the independent
        // S2 traversal over that still-live provisioned source mount.
        let source_s2_view = unsafe {
            QualifiedNoAtimeSourceViewV1::from_functionally_verified_mount_for_test(
                source_parent_fd.as_fd(),
            )
        };
        let staged = connector
            .materialize_source_tree_four_view_at(
                publication_parent_fd.as_fd(),
                staging_name,
                source_s1_view,
                source_s2_view,
                c"tree",
            )
            .unwrap();

        assert_eq!(fs::read(staging_path.join("tree/file")).unwrap(), expected);
        assert_eq!(source_atime(&source_tree), tree_atime);
        assert_eq!(source_atime(&source_file), file_atime);
        assert_eq!(connector.resources.retained_view_heap_live_for_test(), 0);
        drop(staged);
        assert!(!staging_path.exists());
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    #[ignore = "requires a provisioned ST_NOATIME source view that passes functional qualification"]
    fn source_s1_s2_mismatch_cleans_stage_leases_and_consumes_one_shot() {
        use super::super::snapshot_verify::{SnapshotMismatchFieldV1, SnapshotViewPairV1};

        let source_a = tempfile::tempdir().unwrap();
        let source_b = tempfile::tempdir().unwrap();
        let tree_a = source_a.path().join("tree");
        let tree_b = source_b.path().join("tree");
        fs::create_dir(&tree_a).unwrap();
        fs::create_dir(&tree_b).unwrap();

        assert_eq!(fs::read_dir(&tree_a).unwrap().count(), 0);
        assert_eq!(fs::read_dir(&tree_b).unwrap().count(), 0);
        let tree_a_atime = source_atime(&tree_a);
        let tree_b_atime = source_atime(&tree_b);
        assert_eq!(fs::read_dir(&tree_a).unwrap().count(), 0);
        assert_eq!(fs::read_dir(&tree_b).unwrap().count(), 0);
        assert_eq!(source_atime(&tree_a), tree_a_atime);
        assert_eq!(source_atime(&tree_b), tree_b_atime);

        let source_a_fd = File::open(source_a.path()).unwrap();
        let source_b_fd = File::open(source_b.path()).unwrap();
        let publication_parent = tempfile::tempdir().unwrap();
        let publication_parent_fd = File::open(publication_parent.path()).unwrap();
        let staging_name = c".again-snapshot-stage-66666666666666666666666666666666";
        let staging_path = publication_parent
            .path()
            .join(std::ffi::OsStr::from_bytes(staging_name.to_bytes()));
        let connector = connect_snapshot_pipeline(resources(Inputs::exact())).unwrap();
        // SAFETY: the repeated probes above establish the mechanics-only
        // no-atime precondition for the exact source-A objects in this ignored
        // provisioned-runner test.
        let source_s1_view = unsafe {
            QualifiedNoAtimeSourceViewV1::from_functionally_verified_mount_for_test(
                source_a_fd.as_fd(),
            )
        };
        // SAFETY: the repeated probes above independently establish the same
        // precondition for the exact source-B objects.
        let source_s2_view = unsafe {
            QualifiedNoAtimeSourceViewV1::from_functionally_verified_mount_for_test(
                source_b_fd.as_fd(),
            )
        };

        let error = match connector.materialize_source_tree_four_view_at(
            publication_parent_fd.as_fd(),
            staging_name,
            source_s1_view,
            source_s2_view,
            c"tree",
        ) {
            Err(error) => error,
            Ok(staging) => {
                drop(staging);
                panic!("distinct source views must fail S1/S2 comparison");
            }
        };

        let SnapshotPipelineFourViewErrorV1::Comparison(mismatch) = &error else {
            panic!("expected a comparison failure: {error:?}")
        };
        assert_eq!(mismatch.pair, SnapshotViewPairV1::S1S2);
        assert_eq!(mismatch.field, SnapshotMismatchFieldV1::InodeIdentity);
        assert!(!staging_path.exists());
        assert_eq!(connector.resources.retained_view_heap_live_for_test(), 0);
        assert!(connector.publication_started.get());
        assert_eq!(source_atime(&tree_a), tree_a_atime);
        assert_eq!(source_atime(&tree_b), tree_b_atime);
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    #[ignore = "requires a provisioned ST_NOATIME source view that passes functional qualification"]
    fn post_staging_symlink_refusal_cleans_stage_leases_and_keeps_publication_consumed() {
        let source_parent = tempfile::tempdir().unwrap();
        let source_tree = source_parent.path().join("tree");
        let source_link = source_tree.join("secret-symlink-path-sentinel");
        fs::create_dir(&source_tree).unwrap();
        std::os::unix::fs::symlink("missing-target", &source_link).unwrap();

        let primed_names = fs::read_dir(&source_tree)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>();
        assert_eq!(
            primed_names,
            vec![std::ffi::OsString::from("secret-symlink-path-sentinel")]
        );
        assert_eq!(
            fs::read_link(&source_link).unwrap(),
            std::path::PathBuf::from("missing-target")
        );
        let tree_atime = source_atime(&source_tree);
        let link_atime = source_atime(&source_link);
        assert_eq!(fs::read_dir(&source_tree).unwrap().count(), 1);
        assert_eq!(
            fs::read_link(&source_link).unwrap(),
            std::path::PathBuf::from("missing-target")
        );
        assert_eq!(source_atime(&source_tree), tree_atime);
        assert_eq!(source_atime(&source_link), link_atime);

        let publication_parent = tempfile::tempdir().unwrap();
        let publication_parent_fd = File::open(publication_parent.path()).unwrap();
        let source_parent_fd = File::open(source_parent.path()).unwrap();
        let staging_name = c".again-snapshot-stage-22222222222222222222222222222222";
        let staging_path = publication_parent
            .path()
            .join(std::ffi::OsStr::from_bytes(staging_name.to_bytes()));
        let connector = connect_snapshot_pipeline(resources(Inputs::exact())).unwrap();
        // SAFETY: this mechanics-only fixture is owned by the test, has no
        // concurrent writer, and an immediate second directory/symlink probe
        // above proved that the exact objects used here retain atime. The
        // assertions below recheck that condition; this does not claim
        // production functional qualification.
        let source_view = unsafe {
            QualifiedNoAtimeSourceViewV1::from_functionally_verified_mount_for_test(
                source_parent_fd.as_fd(),
            )
        };

        let error = match connector.materialize_source_tree_at(
            publication_parent_fd.as_fd(),
            staging_name,
            source_view,
            c"tree",
        ) {
            Err(error) => error,
            Ok((staged, source_s1)) => {
                drop(source_s1);
                drop(staged);
                panic!("an unqualified symlink must fail closed");
            }
        };

        assert!(matches!(
            &error,
            SnapshotPipelineFourViewErrorV1::Materialization(
                SnapshotTreeMaterializeErrorV1::Materializer(_)
            )
        ));
        let rendered = format!("{error:?}");
        assert_eq!(rendered, "Materialization(Materializer(<redacted>))");
        assert!(!rendered.contains("secret-symlink-path-sentinel"));
        assert_eq!(source_atime(&source_tree), tree_atime);
        assert_eq!(source_atime(&source_link), link_atime);
        assert!(!staging_path.exists());
        assert_eq!(connector.resources.retained_view_heap_live_for_test(), 0);
        assert!(connector.publication_started.get());
        assert!(connector.begin_publication().is_none());
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn post_staging_source_refusal_cleans_stage_leases_and_keeps_publication_consumed() {
        let publication_parent = tempfile::tempdir().unwrap();
        let publication_parent_fd = File::open(publication_parent.path()).unwrap();
        let invalid_source = File::open("/dev/null").unwrap();
        let staging_name = c".again-snapshot-stage-33333333333333333333333333333333";
        let staging_path = publication_parent
            .path()
            .join(std::ffi::OsStr::from_bytes(staging_name.to_bytes()));
        let connector = connect_snapshot_pipeline(resources(Inputs::exact())).unwrap();
        // SAFETY: the non-directory descriptor makes traversal refuse at its
        // first path-resolution operation. No source data, directory stream,
        // regular bytes, symlink target, or xattrs can be read through it.
        let source_s1_view = unsafe {
            QualifiedNoAtimeSourceViewV1::from_functionally_verified_mount_for_test(
                invalid_source.as_fd(),
            )
        };
        // SAFETY: materialization refuses before this independently supplied
        // second view can be observed.
        let source_s2_view = unsafe {
            QualifiedNoAtimeSourceViewV1::from_functionally_verified_mount_for_test(
                invalid_source.as_fd(),
            )
        };

        let error = match connector.materialize_source_tree_four_view_at(
            publication_parent_fd.as_fd(),
            staging_name,
            source_s1_view,
            source_s2_view,
            c"root",
        ) {
            Err(error) => error,
            Ok(staged) => {
                drop(staged);
                panic!("a non-directory source parent must fail closed");
            }
        };

        assert!(matches!(
            &error,
            SnapshotPipelineFourViewErrorV1::Materialization(
                SnapshotTreeMaterializeErrorV1::Source(_)
            )
        ));
        assert_eq!(format!("{error:?}"), "Materialization(Source(<redacted>))");
        assert!(!staging_path.exists());
        assert_eq!(connector.resources.retained_view_heap_live_for_test(), 0);

        let forward_before = connector.resources.forward_attempts_remaining_for_test();
        // SAFETY: publication refusal occurs after structural lease
        // reservation but before traversal, so this descriptor is not read.
        let second_source_s1_view = unsafe {
            QualifiedNoAtimeSourceViewV1::from_functionally_verified_mount_for_test(
                invalid_source.as_fd(),
            )
        };
        // SAFETY: publication refusal occurs before this second view is read.
        let second_source_s2_view = unsafe {
            QualifiedNoAtimeSourceViewV1::from_functionally_verified_mount_for_test(
                invalid_source.as_fd(),
            )
        };
        assert!(matches!(
            connector.materialize_source_tree_four_view_at(
                publication_parent_fd.as_fd(),
                staging_name,
                second_source_s1_view,
                second_source_s2_view,
                c"root",
            ),
            Err(SnapshotPipelineFourViewErrorV1::PublicationAlreadyStarted)
        ));
        assert_eq!(
            connector.resources.forward_attempts_remaining_for_test(),
            forward_before
        );
        assert_eq!(connector.resources.retained_view_heap_live_for_test(), 0);
        assert!(!staging_path.exists());
    }

    #[test]
    fn source_observation_exhaustion_is_typed_and_precedes_attempt() {
        let mut inputs = Inputs::exact();
        // Publisher cleanup plus one active regular-copy cleanup reserve leave
        // no forward attempts.
        inputs.operation_attempts = 272 + 4 + 2 * 3;
        let connector = connect_snapshot_pipeline(resources(inputs)).unwrap();
        let cleanup_before = connector
            .resources
            .publisher_cleanup_attempts_remaining_for_test();
        let session = connector.source_observation_session();

        let invoked = Cell::new(false);
        assert_eq!(
            session.run_attempt(|| invoked.set(true)).unwrap_err(),
            SnapshotPipelineResourceErrorV1::OperationBudgetExhausted {
                stage: super::super::snapshot_policy::SnapshotPipelineStageV1::Forward(
                    SnapshotPipelineForwardStageV1::SourceObservation,
                ),
                bucket: super::super::snapshot_policy::SnapshotPipelineAttemptBucketV1::Forward,
            }
        );
        assert!(!invoked.get());
        assert_eq!(
            connector
                .resources
                .publisher_cleanup_attempts_remaining_for_test(),
            cleanup_before
        );

        #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
        {
            let destination_session = connector.destination_observation_session();
            assert_eq!(
                destination_session
                    .run_attempt(|| invoked.set(true))
                    .unwrap_err(),
                SnapshotPipelineResourceErrorV1::OperationBudgetExhausted {
                    stage: super::super::snapshot_policy::SnapshotPipelineStageV1::Forward(
                        SnapshotPipelineForwardStageV1::DestinationObservation,
                    ),
                    bucket: super::super::snapshot_policy::SnapshotPipelineAttemptBucketV1::Forward,
                }
            );
            assert!(!invoked.get());
        }
    }

    #[test]
    fn connector_issues_at_most_one_publication_session() {
        let connector = connect_snapshot_pipeline(resources(Inputs::exact())).unwrap();
        let _first = connector.begin_publication().unwrap();
        assert!(connector.begin_publication().is_none());
    }

    #[test]
    fn publication_session_does_not_block_source_observation() {
        let connector = connect_snapshot_pipeline(resources(Inputs::exact())).unwrap();
        let staging = connector.begin_publication().unwrap();
        let forward_before = staging.forward_attempts_remaining();
        let cleanup_before = staging.publisher_cleanup_attempts_remaining();

        connector
            .source_observation_session()
            .run_attempt(|| ())
            .unwrap();

        assert_eq!(staging.forward_attempts_remaining(), forward_before - 1);
        assert_eq!(
            staging.publisher_cleanup_attempts_remaining(),
            cleanup_before
        );
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
    fn source_observation_error_debug_redacts_leaf_payloads() {
        let rendered = format!(
            "{:?}",
            SnapshotSourceObservationErrorV1::<&str>::Leaf("secret-leaf-sentinel")
        );
        assert_eq!(rendered, "Leaf(<redacted>)");
    }

    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    #[test]
    fn four_view_error_flattening_routes_resources_and_roles_exactly() {
        let resource = SnapshotPipelineResourceErrorV1::OperationBudgetExhausted {
            stage: super::super::snapshot_policy::SnapshotPipelineStageV1::Forward(
                SnapshotPipelineForwardStageV1::DestinationObservation,
            ),
            bucket: super::super::snapshot_policy::SnapshotPipelineAttemptBucketV1::Forward,
        };
        let mapped_resource = flatten_four_view_observation_error(
            SnapshotSourceObservationErrorV1::Resource(resource),
            SnapshotPipelineFourViewErrorV1::SourceObservation,
        );
        assert!(matches!(
            mapped_resource,
            SnapshotPipelineFourViewErrorV1::Resource(actual) if actual == resource
        ));

        let source = flatten_four_view_observation_error(
            SnapshotSourceObservationErrorV1::Leaf(
                SnapshotSourceObservationFailureV1::InvalidRegularEvidence,
            ),
            SnapshotPipelineFourViewErrorV1::SourceObservation,
        );
        assert!(matches!(
            &source,
            SnapshotPipelineFourViewErrorV1::SourceObservation(
                SnapshotSourceObservationFailureV1::InvalidRegularEvidence
            )
        ));
        assert_eq!(format!("{source:?}"), "SourceObservation(<redacted>)");

        let destination = flatten_four_view_observation_error(
            SnapshotDestinationObservationErrorV1::Leaf(
                SnapshotDestinationObservationFailureV1::InvalidRegularEvidence,
            ),
            SnapshotPipelineFourViewErrorV1::DestinationObservation,
        );
        assert!(matches!(
            &destination,
            SnapshotPipelineFourViewErrorV1::DestinationObservation(
                SnapshotDestinationObservationFailureV1::InvalidRegularEvidence
            )
        ));
        assert_eq!(
            format!("{destination:?}"),
            "DestinationObservation(<redacted>)"
        );
    }

    #[test]
    fn source_visitor_resource_exhaustion_flattens_to_top_level_resource() {
        let resource = SnapshotPipelineResourceErrorV1::OperationBudgetExhausted {
            stage: super::super::snapshot_policy::SnapshotPipelineStageV1::Forward(
                SnapshotPipelineForwardStageV1::SourceObservation,
            ),
            bucket: super::super::snapshot_policy::SnapshotPipelineAttemptBucketV1::Forward,
        };
        let nested = SnapshotSourceObservationErrorV1::Leaf(SourceTreeAcquireFailureV1::Visitor {
            stage: super::super::snapshot_tree::SourceTreeStageV1::VisitRegular,
            relative_path: b"secret-path-sentinel".as_slice().into(),
            source: SnapshotSourceObservationErrorV1::Resource(resource),
        });

        assert_eq!(
            flatten_tree_observation_error(nested),
            SnapshotSourceObservationErrorV1::Resource(resource)
        );
    }

    #[test]
    fn source_visitor_leaf_flattening_discards_callback_path() {
        let nested = SnapshotSourceObservationErrorV1::Leaf(SourceTreeAcquireFailureV1::Visitor {
            stage: super::super::snapshot_tree::SourceTreeStageV1::VisitRegular,
            relative_path: b"secret-path-sentinel".as_slice().into(),
            source: SnapshotSourceObservationErrorV1::Leaf(
                SnapshotSourceObservationFailureV1::InvalidRegularEvidence,
            ),
        });

        let flattened = flatten_tree_observation_error(nested);
        assert_eq!(
            flattened,
            SnapshotSourceObservationErrorV1::Leaf(
                SnapshotSourceObservationFailureV1::InvalidRegularEvidence,
            )
        );
        let rendered = format!("{flattened:?}");
        assert_eq!(rendered, "Leaf(<redacted>)");
        assert!(!rendered.contains("secret-path-sentinel"));
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
    fn failed_source_observation_releases_its_retained_view_lease() {
        let connector = connect_snapshot_pipeline(resources(Inputs::exact())).unwrap();
        let non_directory = File::open("/dev/null").unwrap();
        // SAFETY: the invalid parent is intentional: no source read can occur,
        // and the test exercises only the failure-path lease lifetime.
        let source_view = unsafe {
            QualifiedNoAtimeSourceViewV1::from_functionally_verified_mount_for_test(
                non_directory.as_fd(),
            )
        };

        assert!(
            connector
                .observe_source_tree_view_at(source_view, c"root")
                .is_err()
        );
        assert_eq!(connector.resources.retained_view_heap_live_for_test(), 0);
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
