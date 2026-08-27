//! Gate 3 namespace and blocked pre-exec handoff boundary.
//!
//! The current milestone reuses the diagnostic's production clone/map/pin
//! bootstrap, retains the child behind an authenticated release, and offers
//! one consuming continuation to a non-authoritative isolation checkpoint.
//! That continuation fixes the UTS identity, enters the bounded private mount
//! topology, normalizes credentials, clears capabilities, sets and verifies
//! `no_new_privs`, and invokes a pre-clone, child-branded one-shot seam through
//! which the sibling stdio owner can place descriptors 0/1/2. The isolation
//! leaf then scrubs all non-stdio descriptors except fixed authenticated
//! control/report channels and blocks again while the opaque permit owns
//! bounded kill-and-reap cleanup.
//! The extracted value also retains the diagnostic's dedicated-single-task
//! precondition and fixed protocol/cleanup deadlines; it is a short-lived
//! handoff, not a general process-hosting API.
//!
//! Consequently these values are namespace-bootstrap evidence only. They
//! accept no command, path, environment, or parent-side descriptor callback
//! and grant no isolation-session, profile, execution, candidate, replay, hit,
//! or reuse authority.

#![allow(
    dead_code,
    reason = "the crate-private ready-child handoff remains dormant until filesystem attachment and command release composition"
)]

use std::fmt;

use super::RefusalCode;
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64"
))]
use super::execute_only_stdio::ProfileStdioIsolationChildV1;
use super::isolation_qualification::{
    self, BlockedRootlessNamespaceBootstrapV1, IsolationCancellationCodeV1,
    IsolationCancellationFailureV1, IsolationCancellationOperationV1,
    IsolationQualificationFailureV1, IsolationReadyRootlessNamespaceV1,
};
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64"
))]
use super::snapshot_manifest::FirstExecuteOnlyForkChildRootPairV1;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BlockedIsolationPhaseV1 {
    New,
    NamespaceBootstrap,
    NamespaceBlocked,
    ContinuationIssued,
    IsolationConfiguring,
    IsolationReady,
    Poisoned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct BlockedIsolationStateErrorV1 {
    phase: BlockedIsolationPhaseV1,
    errno: Option<i32>,
}

#[derive(Debug, Eq, PartialEq)]
struct BlockedIsolationStateV1 {
    phase: BlockedIsolationPhaseV1,
    first_failure: Option<BlockedIsolationStateErrorV1>,
    cleanup_errno: Option<i32>,
}

impl BlockedIsolationStateV1 {
    const fn new() -> Self {
        Self {
            phase: BlockedIsolationPhaseV1::New,
            first_failure: None,
            cleanup_errno: None,
        }
    }

    fn advance(
        &mut self,
        expected: BlockedIsolationPhaseV1,
        next: BlockedIsolationPhaseV1,
    ) -> Result<(), BlockedIsolationStateErrorV1> {
        if let Some(first) = self.first_failure {
            return Err(first);
        }
        if self.phase != expected || matches!(next, BlockedIsolationPhaseV1::Poisoned) {
            return Err(self.poison(None));
        }
        self.phase = next;
        Ok(())
    }

    fn poison(&mut self, errno: Option<i32>) -> BlockedIsolationStateErrorV1 {
        let first = *self
            .first_failure
            .get_or_insert(BlockedIsolationStateErrorV1 {
                phase: self.phase,
                errno,
            });
        self.phase = BlockedIsolationPhaseV1::Poisoned;
        first
    }

    fn record_cleanup_failure(&mut self, errno: Option<i32>) {
        if self.cleanup_errno.is_none() {
            self.cleanup_errno = errno.or(Some(libc::EIO));
        }
    }
}

/// Typed refusal from construction of the blocked namespace handoff.
///
/// This preserves the diagnostic's existing refusal contract while projecting
/// the first operational failure independently from cleanup completeness and
/// cleanup errno.
pub(super) struct BlockedExecuteOnlyIsolationFailureV1 {
    code: RefusalCode,
    stage: &'static str,
    reason: &'static str,
    primary_errno: Option<i32>,
    cleanup_complete: bool,
    cleanup_errno: Option<i32>,
    expected_unavailable: bool,
}

impl BlockedExecuteOnlyIsolationFailureV1 {
    fn from_qualification(failure: IsolationQualificationFailureV1) -> Self {
        let cleanup_complete = failure.cleanup_complete();
        let expected_unavailable = failure.is_expected_unavailable();
        Self {
            code: failure.code(),
            stage: failure.stage(),
            reason: failure.reason(),
            primary_errno: failure.errno(),
            cleanup_complete,
            cleanup_errno: failure.cleanup_errno(),
            expected_unavailable,
        }
    }

    pub(super) const fn code(&self) -> RefusalCode {
        self.code
    }

    pub(super) const fn stage(&self) -> &'static str {
        self.stage
    }

    pub(super) const fn reason(&self) -> &'static str {
        self.reason
    }

    pub(super) const fn primary_errno(&self) -> Option<i32> {
        self.primary_errno
    }

    pub(super) const fn cleanup_complete(&self) -> bool {
        self.cleanup_complete
    }

    pub(super) const fn cleanup_errno(&self) -> Option<i32> {
        self.cleanup_errno
    }

    pub(super) const fn is_expected_unavailable(&self) -> bool {
        self.expected_unavailable
    }
}

impl fmt::Debug for BlockedExecuteOnlyIsolationFailureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BlockedExecuteOnlyIsolationFailureV1")
            .field("code", &self.code)
            .field("stage", &self.stage)
            .field("reason", &self.reason)
            .field("primary_errno", &self.primary_errno)
            .field("cleanup_complete", &self.cleanup_complete)
            .field("cleanup_errno", &self.cleanup_errno)
            .finish()
    }
}

/// Opaque linear live bootstrap blocked before the diagnostic release frame.
pub(super) struct BlockedExecuteOnlyIsolationV1 {
    live: BlockedRootlessNamespaceBootstrapV1,
    state: BlockedIsolationStateV1,
}

impl fmt::Debug for BlockedExecuteOnlyIsolationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BlockedExecuteOnlyIsolationV1")
            .field("state", &"namespace-bootstrap-blocked")
            .field("live", &"<opaque-cleanup-owned>")
            .finish()
    }
}

/// One consuming permit reserved for the main Gate 3 composition module.
///
/// It deliberately has no operation or raw-resource accessor in this
/// checkpoint. Dropping it closes control/report/namespace descriptors and
/// performs the existing bounded kill-and-reap cleanup.
pub(super) struct BlockedExecuteOnlyIsolationContinuationPermitV1 {
    live: BlockedRootlessNamespaceBootstrapV1,
    state: BlockedIsolationStateV1,
}

impl fmt::Debug for BlockedExecuteOnlyIsolationContinuationPermitV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BlockedExecuteOnlyIsolationContinuationPermitV1")
            .field("state", &"continuation-issued")
            .field("live", &"<opaque-cleanup-owned>")
            .finish()
    }
}

/// Opaque, linear, cleanup-owning isolation checkpoint.
///
/// It carries no command, PID, descriptor, or execution accessor and is not a
/// profile, candidate, replay, hit, or reuse authority.
pub(super) struct FirstExecuteOnlyIsolationReadyPermitV1 {
    _live: IsolationReadyRootlessNamespaceV1,
    state: BlockedIsolationStateV1,
}

/// Typed uncertainty from explicit cancellation of an isolation-ready child.
/// The live guard has been consumed and still performs its bounded Drop
/// fallback, but that retry is not observable and cannot prove cleanup.
pub(super) struct ExecuteOnlyIsolationCancellationFailureV1 {
    operation: IsolationCancellationOperationV1,
    code: IsolationCancellationCodeV1,
    errno: Option<i32>,
    terminal_reap_complete: bool,
    cleanup_complete: bool,
}

impl ExecuteOnlyIsolationCancellationFailureV1 {
    pub(super) const fn operation(&self) -> IsolationCancellationOperationV1 {
        self.operation
    }

    pub(super) const fn code(&self) -> IsolationCancellationCodeV1 {
        self.code
    }

    pub(super) const fn errno(&self) -> Option<i32> {
        self.errno
    }

    pub(super) const fn terminal_reap_complete(&self) -> bool {
        self.terminal_reap_complete
    }

    pub(super) const fn cleanup_complete(&self) -> bool {
        self.cleanup_complete
    }
}

impl fmt::Debug for ExecuteOnlyIsolationCancellationFailureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ExecuteOnlyIsolationCancellationFailureV1")
            .field("operation", &self.operation)
            .field("code", &self.code)
            .field("errno", &self.errno)
            .field("terminal_reap_complete", &self.terminal_reap_complete)
            .field("cleanup_complete", &self.cleanup_complete)
            .finish()
    }
}

impl fmt::Debug for FirstExecuteOnlyIsolationReadyPermitV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FirstExecuteOnlyIsolationReadyPermitV1")
            .field("state", &"isolation-ready-non-authoritative")
            .field("live", &"<opaque-cleanup-owned>")
            .finish()
    }
}

impl FirstExecuteOnlyIsolationReadyPermitV1 {
    pub(super) fn cancel_and_reap_v1(
        self,
    ) -> Result<(), ExecuteOnlyIsolationCancellationFailureV1> {
        self._live
            .cancel_and_reap_v1()
            .map_err(|failure: IsolationCancellationFailureV1| {
                ExecuteOnlyIsolationCancellationFailureV1 {
                    operation: failure.operation(),
                    code: failure.code(),
                    errno: failure.errno(),
                    terminal_reap_complete: failure.terminal_reap_complete(),
                    cleanup_complete: failure.cleanup_complete(),
                }
            })
    }
}

pub(super) fn begin_blocked_execute_only_isolation_v1()
-> Result<BlockedExecuteOnlyIsolationV1, BlockedExecuteOnlyIsolationFailureV1> {
    finish_blocked_execute_only_isolation_v1(
        isolation_qualification::begin_blocked_rootless_namespace_bootstrap_v1(),
    )
}

/// Compose one sibling-owned continuation into namespace PID 1 before clone.
/// The parent drops its fork-local copy immediately and retains only cleanup
/// ownership.
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64"
))]
pub(super) fn begin_blocked_execute_only_isolation_with_profile_stdio_v1(
    continuation: ProfileStdioIsolationChildV1,
) -> Result<BlockedExecuteOnlyIsolationV1, BlockedExecuteOnlyIsolationFailureV1> {
    finish_blocked_execute_only_isolation_v1(
        isolation_qualification::begin_blocked_rootless_namespace_bootstrap_with_profile_stdio_v1(
            continuation,
        ),
    )
}

/// Compose the exact child-only workspace/runtime roots and profile stdio into
/// the one authenticated namespace child. The root pair is consumed before
/// capability elimination; stdio is placed afterward.
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64"
))]
pub(super) fn begin_blocked_execute_only_isolation_with_filesystem_stdio_v1(
    roots: FirstExecuteOnlyForkChildRootPairV1,
    stdio: ProfileStdioIsolationChildV1,
) -> Result<BlockedExecuteOnlyIsolationV1, BlockedExecuteOnlyIsolationFailureV1> {
    let continuation =
        isolation_qualification::compose_filesystem_profile_isolation_child_v1(roots, stdio);
    finish_blocked_execute_only_isolation_v1(
        isolation_qualification::begin_blocked_rootless_namespace_bootstrap_with_filesystem_stdio_v1(
            continuation,
        ),
    )
}

/// Begin the same live child with the one fixed runtime-open refusal used by
/// the provisioned command-free cleanup diagnostic.
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64"
))]
pub(super) fn begin_blocked_execute_only_isolation_with_filesystem_stdio_fixed_runtime_refusal_v1(
    roots: FirstExecuteOnlyForkChildRootPairV1,
    stdio: ProfileStdioIsolationChildV1,
) -> Result<BlockedExecuteOnlyIsolationV1, BlockedExecuteOnlyIsolationFailureV1> {
    let continuation = isolation_qualification::compose_filesystem_profile_isolation_child_with_fixed_runtime_refusal_v1(
        roots, stdio,
    );
    finish_blocked_execute_only_isolation_v1(
        isolation_qualification::begin_blocked_rootless_namespace_bootstrap_with_filesystem_stdio_v1(
            continuation,
        ),
    )
}

#[cfg(all(
    test,
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64"
))]
pub(super) fn begin_blocked_execute_only_isolation_with_filesystem_stdio_test_fault_v1(
    roots: FirstExecuteOnlyForkChildRootPairV1,
    stdio: ProfileStdioIsolationChildV1,
    role: super::snapshot_publish::SnapshotChildRootRoleV1,
    operation: super::snapshot_publish::SnapshotChildAttachOperationV1,
) -> Result<BlockedExecuteOnlyIsolationV1, BlockedExecuteOnlyIsolationFailureV1> {
    let continuation =
        isolation_qualification::compose_filesystem_profile_isolation_child_with_test_fault_v1(
            roots, stdio, role, operation,
        );
    finish_blocked_execute_only_isolation_v1(
        isolation_qualification::begin_blocked_rootless_namespace_bootstrap_with_filesystem_stdio_v1(
            continuation,
        ),
    )
}

fn finish_blocked_execute_only_isolation_v1(
    live: Result<BlockedRootlessNamespaceBootstrapV1, IsolationQualificationFailureV1>,
) -> Result<BlockedExecuteOnlyIsolationV1, BlockedExecuteOnlyIsolationFailureV1> {
    let mut state = BlockedIsolationStateV1::new();
    state
        .advance(
            BlockedIsolationPhaseV1::New,
            BlockedIsolationPhaseV1::NamespaceBootstrap,
        )
        .expect("fixed initial transition is valid");
    let live = live.map_err(BlockedExecuteOnlyIsolationFailureV1::from_qualification)?;
    state
        .advance(
            BlockedIsolationPhaseV1::NamespaceBootstrap,
            BlockedIsolationPhaseV1::NamespaceBlocked,
        )
        .expect("successful production bootstrap has not poisoned its wrapper");
    Ok(BlockedExecuteOnlyIsolationV1 { live, state })
}

impl BlockedExecuteOnlyIsolationV1 {
    pub(super) fn into_continuation_permit(
        mut self,
    ) -> BlockedExecuteOnlyIsolationContinuationPermitV1 {
        self.state
            .advance(
                BlockedIsolationPhaseV1::NamespaceBlocked,
                BlockedIsolationPhaseV1::ContinuationIssued,
            )
            .expect("only a successfully blocked value can issue the permit");
        BlockedExecuteOnlyIsolationContinuationPermitV1 {
            live: self.live,
            state: self.state,
        }
    }
}

impl BlockedExecuteOnlyIsolationContinuationPermitV1 {
    pub(super) fn continue_to_isolation_ready_v1(
        mut self,
    ) -> Result<FirstExecuteOnlyIsolationReadyPermitV1, BlockedExecuteOnlyIsolationFailureV1> {
        self.state
            .advance(
                BlockedIsolationPhaseV1::ContinuationIssued,
                BlockedIsolationPhaseV1::IsolationConfiguring,
            )
            .expect("only the linear continuation can cross the release boundary");
        let live = self
            .live
            .continue_to_isolation_ready_v1()
            .map_err(BlockedExecuteOnlyIsolationFailureV1::from_qualification)?;
        self.state
            .advance(
                BlockedIsolationPhaseV1::IsolationConfiguring,
                BlockedIsolationPhaseV1::IsolationReady,
            )
            .expect("a verified child checkpoint has not poisoned its wrapper");
        Ok(FirstExecuteOnlyIsolationReadyPermitV1 {
            _live: live,
            state: self.state,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn state_machine_is_monotonic_and_poison_preserves_first_failure() {
        let mut state = BlockedIsolationStateV1::new();
        state
            .advance(
                BlockedIsolationPhaseV1::New,
                BlockedIsolationPhaseV1::NamespaceBootstrap,
            )
            .unwrap();
        let first = state.poison(Some(libc::EPERM));
        assert_eq!(first.phase, BlockedIsolationPhaseV1::NamespaceBootstrap);
        assert_eq!(first.errno, Some(libc::EPERM));
        assert_eq!(state.poison(Some(libc::EIO)), first);
        assert_eq!(
            state.advance(
                BlockedIsolationPhaseV1::NamespaceBootstrap,
                BlockedIsolationPhaseV1::NamespaceBlocked,
            ),
            Err(first)
        );
        assert_eq!(state.phase, BlockedIsolationPhaseV1::Poisoned);
    }

    #[test]
    fn cleanup_failure_is_separate_and_first_cleanup_errno_wins() {
        let mut state = BlockedIsolationStateV1::new();
        let first = state.poison(Some(libc::EPERM));
        state.record_cleanup_failure(Some(libc::ETIMEDOUT));
        state.record_cleanup_failure(Some(libc::EBADF));
        assert_eq!(state.first_failure, Some(first));
        assert_eq!(state.cleanup_errno, Some(libc::ETIMEDOUT));
    }

    #[test]
    fn invalid_transition_poison_is_stable() {
        let mut state = BlockedIsolationStateV1::new();
        let first = state
            .advance(
                BlockedIsolationPhaseV1::NamespaceBlocked,
                BlockedIsolationPhaseV1::ContinuationIssued,
            )
            .unwrap_err();
        assert_eq!(first.phase, BlockedIsolationPhaseV1::New);
        assert_eq!(state.phase, BlockedIsolationPhaseV1::Poisoned);
        assert_eq!(state.poison(Some(libc::EINVAL)), first);
    }

    #[test]
    fn live_types_are_linear_and_debug_is_redacted_by_construction() {
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

        <BlockedExecuteOnlyIsolationV1 as AmbiguousIfClone<_>>::probe();
        <BlockedExecuteOnlyIsolationV1 as AmbiguousIfCopy<_>>::probe();
        <BlockedExecuteOnlyIsolationContinuationPermitV1 as AmbiguousIfClone<_>>::probe();
        <BlockedExecuteOnlyIsolationContinuationPermitV1 as AmbiguousIfCopy<_>>::probe();
        <FirstExecuteOnlyIsolationReadyPermitV1 as AmbiguousIfClone<_>>::probe();
        <FirstExecuteOnlyIsolationReadyPermitV1 as AmbiguousIfCopy<_>>::probe();
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu",
        target_pointer_width = "64"
    ))]
    #[test]
    fn stdio_composition_surface_accepts_only_the_concrete_profile_child() {
        let _concrete: fn(
            ProfileStdioIsolationChildV1,
        ) -> Result<
            BlockedExecuteOnlyIsolationV1,
            BlockedExecuteOnlyIsolationFailureV1,
        > = begin_blocked_execute_only_isolation_with_profile_stdio_v1;
    }

    #[cfg(not(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu",
        target_pointer_width = "64"
    )))]
    #[test]
    fn unsupported_platform_refusal_is_stable() {
        let error = begin_blocked_execute_only_isolation_v1().unwrap_err();
        #[cfg(not(target_os = "linux"))]
        assert_eq!(error.code(), RefusalCode::UnsupportedOs);
        #[cfg(all(target_os = "linux", not(target_arch = "x86_64")))]
        assert_eq!(error.code(), RefusalCode::UnsupportedArchitecture);
        #[cfg(all(
            target_os = "linux",
            target_arch = "x86_64",
            not(all(target_env = "gnu", target_pointer_width = "64"))
        ))]
        assert_eq!(error.code(), RefusalCode::RequiredKernelCapabilityMissing);
        assert_eq!(error.stage(), "platform");
        #[cfg(not(target_os = "linux"))]
        assert_eq!(error.reason(), "unsupported_platform");
        #[cfg(all(target_os = "linux", not(target_arch = "x86_64")))]
        assert_eq!(error.reason(), "unsupported_architecture");
        #[cfg(all(
            target_os = "linux",
            target_arch = "x86_64",
            not(all(target_env = "gnu", target_pointer_width = "64"))
        ))]
        assert_eq!(error.reason(), "unsupported_environment");
        assert_eq!(error.primary_errno(), None);
        assert!(error.cleanup_complete());
        assert_eq!(error.cleanup_errno(), None);
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu",
        target_pointer_width = "64"
    ))]
    #[test]
    #[ignore = "requires the provisioned rootless namespace tuple and a single-threaded test process"]
    fn provisioned_live_bootstrap_reaches_isolation_ready_and_drop_cleans() {
        let blocked = begin_blocked_execute_only_isolation_v1()
            .expect("provisioned tuple must produce a live blocked bootstrap");
        let debug = format!("{blocked:?}");
        assert_eq!(
            debug,
            "BlockedExecuteOnlyIsolationV1 { state: \"namespace-bootstrap-blocked\", live: \"<opaque-cleanup-owned>\" }"
        );
        let ready = blocked
            .into_continuation_permit()
            .continue_to_isolation_ready_v1()
            .expect("provisioned tuple must reach the fixed isolation checkpoint");
        assert_eq!(
            format!("{ready:?}"),
            "FirstExecuteOnlyIsolationReadyPermitV1 { state: \"isolation-ready-non-authoritative\", live: \"<opaque-cleanup-owned>\" }"
        );
        ready
            .cancel_and_reap_v1()
            .expect("explicit cancellation must terminally reap the child");
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu",
        target_pointer_width = "64"
    ))]
    #[test]
    #[ignore = "requires the provisioned rootless namespace tuple and a single-threaded test process"]
    fn provisioned_live_stdio_child_half_composes_through_isolation_pid_one() {
        let session = super::super::execute_only_stdio::open_profile_owned_stdio_v1()
            .expect("profile stdio pipes");
        let (parent_capture, child_stdio) = session
            .split_for_isolation_v1()
            .expect("pre-clone linear split");
        let blocked = begin_blocked_execute_only_isolation_with_profile_stdio_v1(child_stdio)
            .expect("authenticated child consumes only the stdio child half");
        let ready = blocked
            .into_continuation_permit()
            .continue_to_isolation_ready_v1()
            .expect("stdio placement preserves protocol descriptors 3 and 4");
        ready
            .cancel_and_reap_v1()
            .expect("explicit cancellation must terminally reap the child");
        let capture = parent_capture
            .drain_capture_v1()
            .expect("isolation cleanup closes child writers and exposes exact EOF");
        assert!(capture.capture_complete());
        assert_eq!(capture.stdout().drained_bytes(), 0);
        assert_eq!(capture.stderr().drained_bytes(), 0);
    }
}
