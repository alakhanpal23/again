//! Command-free composition of existing Gate 3 checkpoints.
//!
//! This owner requires and retains the bounded structural inventory from both
//! connector publications before it can prepare an isolation-ready child with
//! authenticated profile stdio. It can cancel that child again. It has no
//! command, environment, release, task, descriptor, execution-result,
//! candidate, replay, or reuse surface. In particular, reaching this
//! checkpoint cannot execute a workload.

#![allow(
    dead_code,
    reason = "the command-free checkpoint is private until a later execute-only orchestrator exists"
)]
#![allow(
    private_bounds,
    private_interfaces,
    reason = "the concrete stdio syscall owner remains private behind this crate-private checkpoint"
)]

struct IsolationCancellationStepFailureV1<P> {
    primary: P,
    terminal_reap_complete: bool,
    cleanup_complete: bool,
}

struct StdioCancellationStepFailureV1<P> {
    primary: P,
    cleanup_complete: bool,
}

#[derive(Debug, Eq, PartialEq)]
enum CommandFreeCancellationFlowFailureV1<I, S> {
    Isolation {
        primary: I,
        terminal_reap_complete: bool,
        isolation_cleanup_complete: bool,
        stdio_cleanup_complete: bool,
    },
    Stdio {
        primary: S,
        isolation_cleanup_complete: bool,
        stdio_cleanup_complete: bool,
    },
}

trait CommandFreeCancellationDriverV1 {
    type IsolationFailure;
    type StdioFailure;
    type Report;

    fn terminate_and_reap_v1(
        &mut self,
    ) -> Result<(), IsolationCancellationStepFailureV1<Self::IsolationFailure>>;
    fn drain_stdio_v1(
        &mut self,
    ) -> Result<Self::Report, StdioCancellationStepFailureV1<Self::StdioFailure>>;
    fn close_stdio_without_capture_v1(&mut self) -> bool;
}

fn explicit_cancellation_flow_v1<D: CommandFreeCancellationDriverV1>(
    driver: &mut D,
) -> Result<D::Report, CommandFreeCancellationFlowFailureV1<D::IsolationFailure, D::StdioFailure>> {
    if let Err(failure) = driver.terminate_and_reap_v1() {
        let stdio_cleanup_complete = driver.close_stdio_without_capture_v1();
        return Err(CommandFreeCancellationFlowFailureV1::Isolation {
            primary: failure.primary,
            terminal_reap_complete: failure.terminal_reap_complete,
            isolation_cleanup_complete: failure.cleanup_complete,
            stdio_cleanup_complete,
        });
    }
    driver
        .drain_stdio_v1()
        .map_err(|failure| CommandFreeCancellationFlowFailureV1::Stdio {
            primary: failure.primary,
            isolation_cleanup_complete: true,
            stdio_cleanup_complete: failure.cleanup_complete,
        })
}

fn drop_cleanup_flow_v1<D: CommandFreeCancellationDriverV1>(driver: &mut D) {
    let _ = driver.terminate_and_reap_v1();
    let _ = driver.close_stdio_without_capture_v1();
}

fn setup_failure_cleanup_v1<P>(
    primary: P,
    isolation_cleanup_complete: Option<bool>,
    close_stdio: impl FnOnce() -> bool,
) -> (P, Option<bool>, bool) {
    let stdio_cleanup_complete = close_stdio();
    (primary, isolation_cleanup_complete, stdio_cleanup_complete)
}
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64"
))]
mod supported {
    use std::fmt;

    use super::super::execute_only_isolation::{
        BlockedExecuteOnlyIsolationFailureV1, ExecuteOnlyIsolationCancellationFailureV1,
    };
    use super::super::execute_only_runtime::{
        FirstExecuteOnlyRuntimeFilesystemReadyChildV1,
        FirstExecuteOnlyRuntimeFilesystemSplitRefusalV1, FirstExecuteOnlyRuntimeRetainedRootPairV1,
        split_first_execute_only_runtime_filesystem_roots_v1,
    };
    use super::super::execute_only_stdio::{
        LinuxProfileStdioSyscallsV1, ParentStdioDrainV1, ProfileStdioDrainReportV1,
        ProfileStdioFailureV1, open_profile_owned_stdio_v1,
    };
    use super::super::isolation_qualification::{
        IsolationCancellationCodeV1, IsolationCancellationOperationV1,
    };
    use super::{
        CommandFreeCancellationDriverV1, CommandFreeCancellationFlowFailureV1,
        IsolationCancellationStepFailureV1, StdioCancellationStepFailureV1, drop_cleanup_flow_v1,
        explicit_cancellation_flow_v1, setup_failure_cleanup_v1,
    };

    /// The first failure that prevented construction of the command-free
    /// checkpoint. Cleanup state is recorded separately on the wrapper.
    pub(in crate::linux_pytest) enum CommandFreeSetupPrimaryV1 {
        Stdio(ProfileStdioFailureV1),
        Runtime(FirstExecuteOnlyRuntimeFilesystemSplitRefusalV1),
        Isolation(BlockedExecuteOnlyIsolationFailureV1),
    }

    impl CommandFreeSetupPrimaryV1 {
        pub(in crate::linux_pytest) const fn subsystem(&self) -> &'static str {
            match self {
                Self::Stdio(_) => "stdio",
                Self::Runtime(_) => "runtime",
                Self::Isolation(_) => "isolation",
            }
        }
    }

    impl fmt::Debug for CommandFreeSetupPrimaryV1 {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Stdio(failure) => formatter.debug_tuple("Stdio").field(failure).finish(),
                Self::Runtime(failure) => formatter.debug_tuple("Runtime").field(failure).finish(),
                Self::Isolation(failure) => {
                    formatter.debug_tuple("Isolation").field(failure).finish()
                }
            }
        }
    }

    /// Construction refusal with the original error and independent cleanup
    /// facts. An absent isolation fact means no child was created.
    pub(in crate::linux_pytest) struct CommandFreeSetupFailureV1 {
        primary: CommandFreeSetupPrimaryV1,
        isolation_cleanup_complete: Option<bool>,
        stdio_cleanup_complete: bool,
    }

    impl CommandFreeSetupFailureV1 {
        pub(in crate::linux_pytest) const fn primary(&self) -> &CommandFreeSetupPrimaryV1 {
            &self.primary
        }

        pub(in crate::linux_pytest) const fn isolation_cleanup_complete(&self) -> Option<bool> {
            self.isolation_cleanup_complete
        }

        pub(in crate::linux_pytest) const fn stdio_cleanup_complete(&self) -> bool {
            self.stdio_cleanup_complete
        }

        pub(in crate::linux_pytest) const fn cleanup_complete(&self) -> bool {
            match self.isolation_cleanup_complete {
                Some(isolation) => isolation && self.stdio_cleanup_complete,
                None => self.stdio_cleanup_complete,
            }
        }

        fn from_stdio(primary: ProfileStdioFailureV1) -> Self {
            let stdio_cleanup_complete = primary.cleanup_complete();
            Self {
                primary: CommandFreeSetupPrimaryV1::Stdio(primary),
                isolation_cleanup_complete: None,
                stdio_cleanup_complete,
            }
        }

        fn from_isolation(
            primary: BlockedExecuteOnlyIsolationFailureV1,
            stdio_cleanup_complete: bool,
        ) -> Self {
            let isolation_cleanup_complete = Some(primary.cleanup_complete());
            Self {
                primary: CommandFreeSetupPrimaryV1::Isolation(primary),
                isolation_cleanup_complete,
                stdio_cleanup_complete,
            }
        }

        fn from_runtime(
            primary: FirstExecuteOnlyRuntimeFilesystemSplitRefusalV1,
            stdio_cleanup_complete: bool,
        ) -> Self {
            Self {
                primary: CommandFreeSetupPrimaryV1::Runtime(primary),
                isolation_cleanup_complete: None,
                stdio_cleanup_complete,
            }
        }
    }

    impl fmt::Debug for CommandFreeSetupFailureV1 {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("CommandFreeSetupFailureV1")
                .field("primary", &self.primary)
                .field(
                    "isolation_cleanup_complete",
                    &self.isolation_cleanup_complete,
                )
                .field("stdio_cleanup_complete", &self.stdio_cleanup_complete)
                .finish()
        }
    }

    /// Opaque, linear command-free owner. The two-publication structural
    /// inventory is retained solely to preserve the complete runtime admission
    /// chain while the child remains live.
    pub(in crate::linux_pytest) struct FirstExecuteOnlyFilesystemReadyCheckpointV1<'resources> {
        runtime_child: Option<FirstExecuteOnlyRuntimeFilesystemReadyChildV1<'resources>>,
        stdio: Option<ParentStdioDrainV1<LinuxProfileStdioSyscallsV1>>,
    }

    impl fmt::Debug for FirstExecuteOnlyFilesystemReadyCheckpointV1<'_> {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("FirstExecuteOnlyFilesystemReadyCheckpointV1")
                .field("runtime_anchor", &"<full-inventory-publications-retained>")
                .field("child", &"<filesystem-ready-cleanup-owned>")
                .field("stdio", &"<profile-owned-redacted>")
                .field("command", &"<none>")
                .field("authority", &"<none>")
                .finish()
        }
    }

    impl Drop for FirstExecuteOnlyFilesystemReadyCheckpointV1<'_> {
        fn drop(&mut self) {
            drop_cleanup_flow_v1(self);
        }
    }

    impl CommandFreeCancellationDriverV1 for FirstExecuteOnlyFilesystemReadyCheckpointV1<'_> {
        type IsolationFailure = ExecuteOnlyIsolationCancellationFailureV1;
        type StdioFailure = ProfileStdioFailureV1;
        type Report = ProfileStdioDrainReportV1;

        fn terminate_and_reap_v1(
            &mut self,
        ) -> Result<(), IsolationCancellationStepFailureV1<Self::IsolationFailure>> {
            let Some(runtime_child) = self.runtime_child.take() else {
                return Ok(());
            };
            runtime_child.cancel_and_reap_v1().map_err(|primary| {
                IsolationCancellationStepFailureV1 {
                    terminal_reap_complete: primary.terminal_reap_complete(),
                    cleanup_complete: primary.cleanup_complete(),
                    primary,
                }
            })
        }

        fn drain_stdio_v1(
            &mut self,
        ) -> Result<Self::Report, StdioCancellationStepFailureV1<Self::StdioFailure>> {
            self.stdio
                .take()
                .expect("command-free owner retains one stdio drain")
                .drain_capture_v1()
                .map_err(|primary| StdioCancellationStepFailureV1 {
                    cleanup_complete: primary.cleanup_complete(),
                    primary,
                })
        }

        fn close_stdio_without_capture_v1(&mut self) -> bool {
            self.stdio
                .take()
                .is_none_or(ParentStdioDrainV1::close_without_capture_v1)
        }
    }

    /// Prepare the command-free child. No release or command is accepted and
    /// the returned child remains at the isolation protocol's ready barrier.
    pub(in crate::linux_pytest) fn prepare_first_execute_only_filesystem_ready_checkpoint_v1<
        'resources,
    >(
        roots: FirstExecuteOnlyRuntimeRetainedRootPairV1<'resources>,
    ) -> Result<FirstExecuteOnlyFilesystemReadyCheckpointV1<'resources>, CommandFreeSetupFailureV1>
    {
        let session =
            open_profile_owned_stdio_v1().map_err(CommandFreeSetupFailureV1::from_stdio)?;
        let (parent, child) = session
            .split_for_isolation_v1()
            .map_err(CommandFreeSetupFailureV1::from_stdio)?;
        let split = match split_first_execute_only_runtime_filesystem_roots_v1(roots) {
            Ok(split) => split,
            Err(primary) => {
                let _parent_stdio_cleanup_complete = parent.close_without_capture_v1();
                // The child half is raw-close Drop-cleaned, but those close
                // results are unobservable. Do not claim complete stdio
                // cleanup on this pre-clone refusal.
                return Err(CommandFreeSetupFailureV1::from_runtime(primary, false));
            }
        };
        let blocked = match split.begin_with_profile_stdio_v1(child) {
            Ok(blocked) => blocked,
            Err(primary) => {
                let isolation_cleanup_complete = primary.cleanup_complete();
                let (primary, _, stdio_cleanup_complete) =
                    setup_failure_cleanup_v1(primary, Some(isolation_cleanup_complete), || {
                        parent.close_without_capture_v1()
                    });
                let _parent_stdio_cleanup_complete = stdio_cleanup_complete;
                return Err(CommandFreeSetupFailureV1::from_isolation(primary, false));
            }
        };
        let runtime_child = match blocked.continue_to_filesystem_ready_v1() {
            Ok(runtime_child) => runtime_child,
            Err(primary) => {
                let isolation_cleanup_complete = primary.cleanup_complete();
                let (primary, _, stdio_cleanup_complete) =
                    setup_failure_cleanup_v1(primary, Some(isolation_cleanup_complete), || {
                        parent.close_without_capture_v1()
                    });
                let _parent_stdio_cleanup_complete = stdio_cleanup_complete;
                return Err(CommandFreeSetupFailureV1::from_isolation(primary, false));
            }
        };
        Ok(FirstExecuteOnlyFilesystemReadyCheckpointV1 {
            runtime_child: Some(runtime_child),
            stdio: Some(parent),
        })
    }

    pub(in crate::linux_pytest) enum CommandFreeCancellationPrimaryV1 {
        Isolation(ExecuteOnlyIsolationCancellationFailureV1),
        Stdio(ProfileStdioFailureV1),
    }

    impl CommandFreeCancellationPrimaryV1 {
        pub(in crate::linux_pytest) const fn subsystem(&self) -> &'static str {
            match self {
                Self::Isolation(_) => "isolation",
                Self::Stdio(_) => "stdio",
            }
        }
    }

    impl fmt::Debug for CommandFreeCancellationPrimaryV1 {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Isolation(failure) => {
                    formatter.debug_tuple("Isolation").field(failure).finish()
                }
                Self::Stdio(failure) => formatter.debug_tuple("Stdio").field(failure).finish(),
            }
        }
    }

    /// Explicit cancellation refusal. Stream EOF is attempted only after
    /// terminal child cleanup succeeds; otherwise stdio is closed directly.
    pub(in crate::linux_pytest) struct CommandFreeCancellationFailureV1 {
        primary: CommandFreeCancellationPrimaryV1,
        terminal_reap_complete: bool,
        isolation_cleanup_complete: bool,
        stdio_cleanup_complete: bool,
    }

    impl CommandFreeCancellationFailureV1 {
        pub(in crate::linux_pytest) const fn primary(&self) -> &CommandFreeCancellationPrimaryV1 {
            &self.primary
        }

        pub(in crate::linux_pytest) const fn isolation_cleanup_complete(&self) -> bool {
            self.isolation_cleanup_complete
        }

        pub(in crate::linux_pytest) const fn terminal_reap_complete(&self) -> bool {
            self.terminal_reap_complete
        }

        pub(in crate::linux_pytest) const fn isolation_operation(
            &self,
        ) -> Option<IsolationCancellationOperationV1> {
            match &self.primary {
                CommandFreeCancellationPrimaryV1::Isolation(failure) => Some(failure.operation()),
                CommandFreeCancellationPrimaryV1::Stdio(_) => None,
            }
        }

        pub(in crate::linux_pytest) const fn isolation_code(
            &self,
        ) -> Option<IsolationCancellationCodeV1> {
            match &self.primary {
                CommandFreeCancellationPrimaryV1::Isolation(failure) => Some(failure.code()),
                CommandFreeCancellationPrimaryV1::Stdio(_) => None,
            }
        }

        pub(in crate::linux_pytest) const fn stdio_cleanup_complete(&self) -> bool {
            self.stdio_cleanup_complete
        }

        pub(in crate::linux_pytest) const fn cleanup_complete(&self) -> bool {
            self.isolation_cleanup_complete && self.stdio_cleanup_complete
        }
    }

    impl fmt::Debug for CommandFreeCancellationFailureV1 {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("CommandFreeCancellationFailureV1")
                .field("primary", &self.primary)
                .field("terminal_reap_complete", &self.terminal_reap_complete)
                .field(
                    "isolation_cleanup_complete",
                    &self.isolation_cleanup_complete,
                )
                .field("stdio_cleanup_complete", &self.stdio_cleanup_complete)
                .finish()
        }
    }

    /// Non-authoritative evidence that cancellation completed and both streams
    /// reached exact EOF after the child was terminally reaped.
    pub(in crate::linux_pytest) struct CommandFreeCancellationReportV1 {
        stdio: ProfileStdioDrainReportV1,
    }

    impl CommandFreeCancellationReportV1 {
        pub(in crate::linux_pytest) const fn capture_complete(&self) -> bool {
            self.stdio.capture_complete()
        }

        pub(in crate::linux_pytest) const fn requires_execute_only_classification(&self) -> bool {
            self.stdio.requires_execute_only_classification()
        }
    }

    impl fmt::Debug for CommandFreeCancellationReportV1 {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("CommandFreeCancellationReportV1")
                .field("stdio", &self.stdio)
                .field("execution_result", &"<not-issued>")
                .field("authority", &"<none>")
                .finish()
        }
    }

    impl FirstExecuteOnlyFilesystemReadyCheckpointV1<'_> {
        /// Cancel and reap the child first, then require exact stdout/stderr
        /// EOF. If terminal cleanup is uncertain, close the streams immediately
        /// rather than waiting on a potentially live writer.
        pub(in crate::linux_pytest) fn cancel_and_finish_v1(
            mut self,
        ) -> Result<CommandFreeCancellationReportV1, CommandFreeCancellationFailureV1> {
            match explicit_cancellation_flow_v1(&mut self) {
                Ok(stdio) => Ok(CommandFreeCancellationReportV1 { stdio }),
                Err(CommandFreeCancellationFlowFailureV1::Isolation {
                    primary,
                    terminal_reap_complete,
                    isolation_cleanup_complete,
                    stdio_cleanup_complete,
                }) => Err(CommandFreeCancellationFailureV1 {
                    primary: CommandFreeCancellationPrimaryV1::Isolation(primary),
                    terminal_reap_complete,
                    isolation_cleanup_complete,
                    stdio_cleanup_complete,
                }),
                Err(CommandFreeCancellationFlowFailureV1::Stdio {
                    primary,
                    isolation_cleanup_complete,
                    stdio_cleanup_complete,
                }) => Err(CommandFreeCancellationFailureV1 {
                    primary: CommandFreeCancellationPrimaryV1::Stdio(primary),
                    terminal_reap_complete: true,
                    isolation_cleanup_complete,
                    stdio_cleanup_complete,
                }),
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

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

        #[test]
        fn command_free_owner_is_linear_and_constructor_requires_structural_inventory() {
            <FirstExecuteOnlyFilesystemReadyCheckpointV1<'static> as AmbiguousIfClone<_>>::probe();
            <FirstExecuteOnlyFilesystemReadyCheckpointV1<'static> as AmbiguousIfCopy<_>>::probe();
            <FirstExecuteOnlyRuntimeRetainedRootPairV1<'static> as AmbiguousIfClone<_>>::probe();
            <FirstExecuteOnlyRuntimeRetainedRootPairV1<'static> as AmbiguousIfCopy<_>>::probe();
            let _constructor: fn(
                FirstExecuteOnlyRuntimeRetainedRootPairV1<'static>,
            ) -> Result<
                FirstExecuteOnlyFilesystemReadyCheckpointV1<'static>,
                CommandFreeSetupFailureV1,
            > = prepare_first_execute_only_filesystem_ready_checkpoint_v1;
        }
    }
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64"
))]
#[allow(
    unused_imports,
    reason = "the private re-export is the intentionally dormant later-orchestrator surface"
)]
pub(super) use supported::*;

#[cfg(test)]
mod portable_state_machine_tests {
    use super::*;

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ActionV1 {
        TerminateAndReap,
        Drain,
        CloseWithoutCapture,
    }

    struct FakeDriverV1 {
        actions: Vec<ActionV1>,
        isolation_failure: Option<(bool, bool)>,
        stdio_failure: Option<bool>,
        evidence_issued: bool,
    }

    impl FakeDriverV1 {
        fn successful() -> Self {
            Self {
                actions: Vec::new(),
                isolation_failure: None,
                stdio_failure: None,
                evidence_issued: false,
            }
        }
    }

    impl CommandFreeCancellationDriverV1 for FakeDriverV1 {
        type IsolationFailure = &'static str;
        type StdioFailure = &'static str;
        type Report = &'static str;

        fn terminate_and_reap_v1(
            &mut self,
        ) -> Result<(), IsolationCancellationStepFailureV1<Self::IsolationFailure>> {
            self.actions.push(ActionV1::TerminateAndReap);
            match self.isolation_failure {
                Some((terminal_reap_complete, cleanup_complete)) => {
                    Err(IsolationCancellationStepFailureV1 {
                        primary: "isolation",
                        terminal_reap_complete,
                        cleanup_complete,
                    })
                }
                None => Ok(()),
            }
        }

        fn drain_stdio_v1(
            &mut self,
        ) -> Result<Self::Report, StdioCancellationStepFailureV1<Self::StdioFailure>> {
            self.actions.push(ActionV1::Drain);
            match self.stdio_failure {
                Some(cleanup_complete) => Err(StdioCancellationStepFailureV1 {
                    primary: "stdio",
                    cleanup_complete,
                }),
                None => {
                    self.evidence_issued = true;
                    Ok("non-authoritative-evidence")
                }
            }
        }

        fn close_stdio_without_capture_v1(&mut self) -> bool {
            self.actions.push(ActionV1::CloseWithoutCapture);
            true
        }
    }

    #[test]
    fn setup_failure_cleanup_is_explicit_and_preserves_primary() {
        let mut calls = Vec::new();
        let (primary, isolation, stdio) =
            setup_failure_cleanup_v1("setup-first", Some(false), || {
                calls.push(ActionV1::CloseWithoutCapture);
                false
            });
        assert_eq!(primary, "setup-first");
        assert_eq!(isolation, Some(false));
        assert!(!stdio);
        assert_eq!(calls, [ActionV1::CloseWithoutCapture]);
    }

    #[test]
    fn cancellation_terminates_before_drain_and_only_success_issues_evidence() {
        let mut driver = FakeDriverV1::successful();
        assert_eq!(
            explicit_cancellation_flow_v1(&mut driver),
            Ok("non-authoritative-evidence")
        );
        assert_eq!(
            driver.actions,
            [ActionV1::TerminateAndReap, ActionV1::Drain]
        );
        assert!(driver.evidence_issued);
    }

    #[test]
    fn uncertain_reap_closes_without_capture_and_issues_no_evidence() {
        let mut driver = FakeDriverV1::successful();
        driver.isolation_failure = Some((false, false));
        let failure = explicit_cancellation_flow_v1(&mut driver)
            .expect_err("uncertain terminal reap refuses capture");
        assert!(matches!(
            failure,
            CommandFreeCancellationFlowFailureV1::Isolation {
                primary: "isolation",
                terminal_reap_complete: false,
                isolation_cleanup_complete: false,
                stdio_cleanup_complete: true,
            }
        ));
        assert_eq!(
            driver.actions,
            [ActionV1::TerminateAndReap, ActionV1::CloseWithoutCapture]
        );
        assert!(!driver.evidence_issued);
    }

    #[test]
    fn stdio_failure_after_successful_reap_keeps_order_and_cleanup_facts() {
        let mut driver = FakeDriverV1::successful();
        driver.stdio_failure = Some(false);
        let failure = explicit_cancellation_flow_v1(&mut driver)
            .expect_err("stdio drain failure remains typed");
        assert!(matches!(
            failure,
            CommandFreeCancellationFlowFailureV1::Stdio {
                primary: "stdio",
                isolation_cleanup_complete: true,
                stdio_cleanup_complete: false,
            }
        ));
        assert_eq!(
            driver.actions,
            [ActionV1::TerminateAndReap, ActionV1::Drain]
        );
        assert!(!driver.evidence_issued);
    }

    #[test]
    fn drop_flow_terminates_then_closes_and_never_drains_or_issues_evidence() {
        let mut driver = FakeDriverV1::successful();
        drop_cleanup_flow_v1(&mut driver);
        assert_eq!(
            driver.actions,
            [ActionV1::TerminateAndReap, ActionV1::CloseWithoutCapture]
        );
        assert!(!driver.evidence_issued);
    }
}
