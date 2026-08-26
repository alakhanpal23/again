//! Command-free composition of existing Gate 3 checkpoints.
//!
//! This owner can prepare an isolation-ready child with authenticated profile
//! stdio and can cancel that child again. It has no command, environment,
//! release, task, descriptor, execution-result, candidate, replay, or reuse
//! surface. In particular, reaching this checkpoint cannot execute a workload.

#![allow(
    dead_code,
    reason = "the command-free checkpoint is private until a later execute-only orchestrator exists"
)]
#![allow(
    private_bounds,
    private_interfaces,
    reason = "the concrete stdio syscall owner remains private behind this crate-private checkpoint"
)]

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
        FirstExecuteOnlyIsolationReadyPermitV1,
        begin_blocked_execute_only_isolation_with_profile_stdio_v1,
    };
    use super::super::execute_only_runtime::FirstExecuteOnlyRuntimeCheckpointV1;
    use super::super::execute_only_stdio::{
        LinuxProfileStdioSyscallsV1, ParentStdioDrainV1, ProfileStdioDrainReportV1,
        ProfileStdioFailureV1, open_profile_owned_stdio_v1,
    };

    /// The first failure that prevented construction of the command-free
    /// checkpoint. Cleanup state is recorded separately on the wrapper.
    pub(in crate::linux_pytest) enum CommandFreeSetupPrimaryV1 {
        Stdio(ProfileStdioFailureV1),
        Isolation(BlockedExecuteOnlyIsolationFailureV1),
    }

    impl CommandFreeSetupPrimaryV1 {
        pub(in crate::linux_pytest) const fn subsystem(&self) -> &'static str {
            match self {
                Self::Stdio(_) => "stdio",
                Self::Isolation(_) => "isolation",
            }
        }
    }

    impl fmt::Debug for CommandFreeSetupPrimaryV1 {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            match self {
                Self::Stdio(failure) => formatter.debug_tuple("Stdio").field(failure).finish(),
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

    /// Opaque, linear command-free owner. The runtime checkpoint is retained
    /// solely to preserve the admission chain while the child remains live.
    pub(in crate::linux_pytest) struct FirstExecuteOnlyCommandFreeCheckpointV1<'resources> {
        _runtime: FirstExecuteOnlyRuntimeCheckpointV1<'resources>,
        isolation: Option<FirstExecuteOnlyIsolationReadyPermitV1>,
        stdio: Option<ParentStdioDrainV1<LinuxProfileStdioSyscallsV1>>,
    }

    impl fmt::Debug for FirstExecuteOnlyCommandFreeCheckpointV1<'_> {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter
                .debug_struct("FirstExecuteOnlyCommandFreeCheckpointV1")
                .field("runtime", &"<retained-redacted>")
                .field("child", &"<isolation-ready-cleanup-owned>")
                .field("stdio", &"<profile-owned-redacted>")
                .field("command", &"<none>")
                .field("authority", &"<none>")
                .finish()
        }
    }

    impl Drop for FirstExecuteOnlyCommandFreeCheckpointV1<'_> {
        fn drop(&mut self) {
            if let Some(isolation) = self.isolation.take() {
                let _ = isolation.cancel_and_reap_v1();
            }
            if let Some(stdio) = self.stdio.take() {
                let _ = stdio.close_without_capture_v1();
            }
        }
    }

    /// Prepare the command-free child. No release or command is accepted and
    /// the returned child remains at the isolation protocol's ready barrier.
    pub(in crate::linux_pytest) fn prepare_first_execute_only_command_free_checkpoint_v1<
        'resources,
    >(
        runtime: FirstExecuteOnlyRuntimeCheckpointV1<'resources>,
    ) -> Result<FirstExecuteOnlyCommandFreeCheckpointV1<'resources>, CommandFreeSetupFailureV1>
    {
        let session =
            open_profile_owned_stdio_v1().map_err(CommandFreeSetupFailureV1::from_stdio)?;
        let (parent, child) = session
            .split_for_isolation_v1()
            .map_err(CommandFreeSetupFailureV1::from_stdio)?;
        let blocked = match begin_blocked_execute_only_isolation_with_profile_stdio_v1(child) {
            Ok(blocked) => blocked,
            Err(primary) => {
                let stdio_cleanup_complete = parent.close_without_capture_v1();
                return Err(CommandFreeSetupFailureV1::from_isolation(
                    primary,
                    stdio_cleanup_complete,
                ));
            }
        };
        let isolation = match blocked
            .into_continuation_permit()
            .continue_to_isolation_ready_v1()
        {
            Ok(isolation) => isolation,
            Err(primary) => {
                let stdio_cleanup_complete = parent.close_without_capture_v1();
                return Err(CommandFreeSetupFailureV1::from_isolation(
                    primary,
                    stdio_cleanup_complete,
                ));
            }
        };
        Ok(FirstExecuteOnlyCommandFreeCheckpointV1 {
            _runtime: runtime,
            isolation: Some(isolation),
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

    impl FirstExecuteOnlyCommandFreeCheckpointV1<'_> {
        /// Cancel and reap the child first, then require exact stdout/stderr
        /// EOF. If terminal cleanup is uncertain, close the streams immediately
        /// rather than waiting on a potentially live writer.
        pub(in crate::linux_pytest) fn cancel_and_finish_v1(
            mut self,
        ) -> Result<CommandFreeCancellationReportV1, CommandFreeCancellationFailureV1> {
            let isolation = self
                .isolation
                .take()
                .expect("command-free owner retains one isolation permit");
            if let Err(primary) = isolation.cancel_and_reap_v1() {
                let stdio_cleanup_complete = self
                    .stdio
                    .take()
                    .expect("command-free owner retains one stdio drain")
                    .close_without_capture_v1();
                return Err(CommandFreeCancellationFailureV1 {
                    primary: CommandFreeCancellationPrimaryV1::Isolation(primary),
                    isolation_cleanup_complete: false,
                    stdio_cleanup_complete,
                });
            }

            let stdio = self
                .stdio
                .take()
                .expect("command-free owner retains one stdio drain");
            match stdio.drain_capture_v1() {
                Ok(stdio) => Ok(CommandFreeCancellationReportV1 { stdio }),
                Err(primary) => {
                    let stdio_cleanup_complete = primary.cleanup_complete();
                    Err(CommandFreeCancellationFailureV1 {
                        primary: CommandFreeCancellationPrimaryV1::Stdio(primary),
                        isolation_cleanup_complete: true,
                        stdio_cleanup_complete,
                    })
                }
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
        fn command_free_owner_is_linear_and_constructor_requires_runtime_checkpoint() {
            <FirstExecuteOnlyCommandFreeCheckpointV1<'static> as AmbiguousIfClone<_>>::probe();
            <FirstExecuteOnlyCommandFreeCheckpointV1<'static> as AmbiguousIfCopy<_>>::probe();
            let _constructor: fn(
                FirstExecuteOnlyRuntimeCheckpointV1<'static>,
            ) -> Result<
                FirstExecuteOnlyCommandFreeCheckpointV1<'static>,
                CommandFreeSetupFailureV1,
            > = prepare_first_execute_only_command_free_checkpoint_v1;
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
