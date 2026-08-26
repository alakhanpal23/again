//! Gate 3 namespace and blocked pre-exec handoff boundary.
//!
//! The current milestone is intentionally smaller than the final isolation
//! session. It reuses the diagnostic's production clone/map/pin bootstrap and
//! returns while the child is blocked on its authenticated release frame. The
//! child has fresh user, mount, PID, network, UTS, and IPC namespaces, but has
//! not crossed the release boundary that configures UTS, mounts the private
//! root/scratch/procfs topology, scrubs descriptors, or eliminates
//! capabilities. Extracting that post-release protocol without duplicating the
//! diagnostic's raw syscall implementation requires a later descriptor/control
//! refactor with per-leaf injected failures.
//! The extracted value also retains the diagnostic's dedicated-single-task
//! precondition and fixed protocol/cleanup deadlines; it is a short-lived
//! handoff, not a general process-hosting API.
//!
//! Consequently these values are namespace-bootstrap evidence only. They
//! accept no command, path, environment, descriptor, or callback and grant no
//! isolation-session, profile, execution, candidate, replay, hit, or reuse
//! authority.

#![allow(
    dead_code,
    reason = "crate-private Gate 3 handoff is held until runtime and stdio composition"
)]

use std::fmt;

use super::RefusalCode;
use super::isolation_qualification::{
    self, BlockedRootlessNamespaceBootstrapV1, IsolationQualificationFailureV1,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BlockedIsolationPhaseV1 {
    New,
    NamespaceBootstrap,
    NamespaceBlocked,
    ContinuationIssued,
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
/// cleanup completeness and cleanup errno into separate fields. If the old
/// diagnostic reports cleanup uncertainty, it has already replaced the first
/// operational failure with its cleanup failure; recovering both errors
/// requires the later per-leaf cleanup refactor documented above.
pub(super) struct BlockedExecuteOnlyIsolationFailureV1 {
    code: RefusalCode,
    stage: &'static str,
    reason: &'static str,
    primary_errno: Option<i32>,
    cleanup_complete: bool,
    cleanup_errno: Option<i32>,
}

impl BlockedExecuteOnlyIsolationFailureV1 {
    fn from_qualification(failure: IsolationQualificationFailureV1) -> Self {
        let cleanup_complete = failure.cleanup_complete();
        let observed_errno = failure.errno();
        Self {
            code: failure.code(),
            stage: failure.stage(),
            reason: failure.reason(),
            primary_errno: cleanup_complete.then_some(observed_errno).flatten(),
            cleanup_complete,
            cleanup_errno: (!cleanup_complete).then_some(observed_errno).flatten(),
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
    _live: BlockedRootlessNamespaceBootstrapV1,
    state: BlockedIsolationStateV1,
}

impl fmt::Debug for BlockedExecuteOnlyIsolationContinuationPermitV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BlockedExecuteOnlyIsolationContinuationPermitV1")
            .field("state", &"continuation-issued-no-operation")
            .field("live", &"<opaque-cleanup-owned>")
            .finish()
    }
}

pub(super) fn begin_blocked_execute_only_isolation_v1()
-> Result<BlockedExecuteOnlyIsolationV1, BlockedExecuteOnlyIsolationFailureV1> {
    let mut state = BlockedIsolationStateV1::new();
    state
        .advance(
            BlockedIsolationPhaseV1::New,
            BlockedIsolationPhaseV1::NamespaceBootstrap,
        )
        .expect("fixed initial transition is valid");
    let live = isolation_qualification::begin_blocked_rootless_namespace_bootstrap_v1()
        .map_err(BlockedExecuteOnlyIsolationFailureV1::from_qualification)?;
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
            _live: self.live,
            state: self.state,
        }
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
    fn provisioned_live_bootstrap_reaches_blocked_handoff_and_drop_cleans() {
        let blocked = begin_blocked_execute_only_isolation_v1()
            .expect("provisioned tuple must produce a live blocked bootstrap");
        let debug = format!("{blocked:?}");
        assert_eq!(
            debug,
            "BlockedExecuteOnlyIsolationV1 { state: \"namespace-bootstrap-blocked\", live: \"<opaque-cleanup-owned>\" }"
        );
        drop(blocked.into_continuation_permit());
    }
}
