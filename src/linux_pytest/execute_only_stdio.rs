//! Gate 3 profile-owned stdio and exact foreground capture boundary.
//!
//! This module owns only live descriptors and bounded stream capture. Its
//! values cannot grant execution, candidate, or reuse authority, and no code
//! here executes a workload.
//!
//! Capture is a fixed nonblocking parent operation with no caller callback;
//! captured bytes become inspectable only after both read ends reached EOF and
//! were closed. Child descriptor placement is a linear continuation consumed
//! only by the authenticated namespace child. It owns no parent endpoint and
//! deliberately preserves isolation's protocol descriptors 3 and 4.

#![allow(
    dead_code,
    reason = "the Gate 3 stdio connector is crate-private until the execute-only orchestrator exists"
)]
#![allow(
    private_bounds,
    private_interfaces,
    reason = "the syscall seam and its vocabulary intentionally remain private behind crate-private RAII handles"
)]

use std::fmt;
use std::os::fd::RawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64"
))]
use super::isolation_qualification::IsolationChildOnlyBrandV1;

const STREAM_CAPTURE_LIMIT_V1: usize = super::LINUX_PYTEST_V1_MAX_STREAM_BYTES as usize;
const DRAIN_BUFFER_BYTES_V1: usize = 64 * 1024;
const MAX_READS_PER_STREAM_TURN_V1: usize = 16;
const DRAIN_POLL_SLICE_V1: Duration = Duration::from_millis(25);
const DRAIN_DEADLINE_V1: Duration = Duration::from_secs(15 * 60);
const STREAM_HASH_DOMAIN_V1: &str = "again linux pytest foreground stream v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ProfileStreamV1 {
    Stdout,
    Stderr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FdRoleV1 {
    ChildStdin,
    StdinEofWriter,
    ParentStdout,
    ChildStdout,
    ParentStderr,
    ChildStderr,
    PlacedStdin,
    PlacedStdout,
    PlacedStderr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PipeRoleV1 {
    Stdin,
    Stdout,
    Stderr,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StdioOperationV1 {
    Unsupported,
    Pipe(PipeRoleV1),
    Fstat(FdRoleV1),
    FcntlGetFd(FdRoleV1),
    FcntlGetFl(FdRoleV1),
    FcntlSetFl(FdRoleV1),
    FcntlDupMin(FdRoleV1),
    Authenticate(FdRoleV1),
    Close(FdRoleV1),
    Dup3(FdRoleV1),
    CloseRange,
    Poll,
    Read(ProfileStreamV1),
    Control,
    Protocol,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StdioFailureReasonV1 {
    Unsupported,
    Syscall,
    DescriptorContract,
    DrainProtocol,
    DrainCancelled,
    DrainDeadline,
}

#[derive(Eq, PartialEq)]
pub(super) struct ProfileStdioFailureV1 {
    reason: StdioFailureReasonV1,
    first_operation: StdioOperationV1,
    errno: Option<i32>,
    cleanup_complete: bool,
}

impl ProfileStdioFailureV1 {
    const fn unsupported() -> Self {
        Self {
            reason: StdioFailureReasonV1::Unsupported,
            first_operation: StdioOperationV1::Unsupported,
            errno: None,
            cleanup_complete: true,
        }
    }

    const fn syscall(operation: StdioOperationV1, errno: i32) -> Self {
        Self {
            reason: StdioFailureReasonV1::Syscall,
            first_operation: operation,
            errno: Some(errno),
            cleanup_complete: true,
        }
    }

    const fn contract(operation: StdioOperationV1) -> Self {
        Self {
            reason: StdioFailureReasonV1::DescriptorContract,
            first_operation: operation,
            errno: None,
            cleanup_complete: true,
        }
    }

    const fn protocol() -> Self {
        Self {
            reason: StdioFailureReasonV1::DrainProtocol,
            first_operation: StdioOperationV1::Protocol,
            errno: None,
            cleanup_complete: true,
        }
    }

    const fn cancelled() -> Self {
        Self {
            reason: StdioFailureReasonV1::DrainCancelled,
            first_operation: StdioOperationV1::Control,
            errno: None,
            cleanup_complete: true,
        }
    }

    const fn deadline() -> Self {
        Self {
            reason: StdioFailureReasonV1::DrainDeadline,
            first_operation: StdioOperationV1::Control,
            errno: Some(libc::ETIMEDOUT),
            cleanup_complete: true,
        }
    }

    pub(super) const fn reason(&self) -> &'static str {
        match self.reason {
            StdioFailureReasonV1::Unsupported => "unsupported_platform",
            StdioFailureReasonV1::Syscall => "stdio_syscall_failed",
            StdioFailureReasonV1::DescriptorContract => "descriptor_contract_mismatch",
            StdioFailureReasonV1::DrainProtocol => "drain_protocol_mismatch",
            StdioFailureReasonV1::DrainCancelled => "stdio_drain_cancelled",
            StdioFailureReasonV1::DrainDeadline => "stdio_drain_deadline_exceeded",
        }
    }

    pub(super) const fn cleanup_complete(&self) -> bool {
        self.cleanup_complete
    }

    fn with_cleanup(mut self, cleanup_complete: bool) -> Self {
        self.cleanup_complete &= cleanup_complete;
        self
    }
}

impl fmt::Debug for ProfileStdioFailureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProfileStdioFailureV1")
            .field("reason", &self.reason())
            .field("operation", &self.first_operation)
            .field("errno", &self.errno)
            .field("cleanup_complete", &self.cleanup_complete)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CallErrorV1 {
    Interrupted,
    TimedOut,
    WouldBlock,
    Errno(i32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct DescriptorFactsV1 {
    device: u64,
    inode: u64,
    mode: libc::mode_t,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct PollInterestResultV1 {
    stdout: PollStreamResultV1,
    stderr: PollStreamResultV1,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct PollStreamResultV1 {
    readable: bool,
    hangup: bool,
    invalid: bool,
}

impl PollStreamResultV1 {
    const fn actionable(self) -> bool {
        self.readable || self.hangup
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReadResultV1 {
    Bytes(usize),
    Eof,
    WouldBlock,
}

trait ProfileStdioSyscallsV1 {
    fn pipe2(&mut self, role: PipeRoleV1, flags: i32) -> Result<(RawFd, RawFd), i32>;
    fn fstat(&mut self, fd: RawFd, role: FdRoleV1) -> Result<DescriptorFactsV1, i32>;
    fn fcntl_getfd(&mut self, fd: RawFd, role: FdRoleV1) -> Result<i32, i32>;
    fn fcntl_getfl(&mut self, fd: RawFd, role: FdRoleV1) -> Result<i32, i32>;
    fn fcntl_setfl(&mut self, fd: RawFd, role: FdRoleV1, flags: i32) -> Result<(), i32>;
    fn fcntl_dupfd_cloexec(
        &mut self,
        fd: RawFd,
        role: FdRoleV1,
        minimum: RawFd,
    ) -> Result<RawFd, i32>;
    fn close(&mut self, fd: RawFd, role: FdRoleV1) -> Result<(), i32>;
    fn dup3(&mut self, old: RawFd, new: RawFd, role: FdRoleV1) -> Result<(), i32>;
    fn close_range_unshare(&mut self, first: u32, last: u32) -> Result<(), i32>;
    fn poll(
        &mut self,
        stdout: Option<RawFd>,
        stderr: Option<RawFd>,
        timeout_millis: i32,
    ) -> Result<PollInterestResultV1, CallErrorV1>;
    fn read(
        &mut self,
        fd: RawFd,
        stream: ProfileStreamV1,
        buffer: &mut [u8],
    ) -> Result<ReadResultV1, CallErrorV1>;
}

struct TrackedFdV1 {
    raw: RawFd,
    role: FdRoleV1,
}

impl fmt::Debug for TrackedFdV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TrackedFdV1")
            .field("role", &self.role)
            .field("descriptor", &"<owned-fd>")
            .finish()
    }
}

pub(super) struct ProfileOwnedStdioSessionV1<S: ProfileStdioSyscallsV1> {
    syscalls: Option<S>,
    descriptors: [Option<TrackedFdV1>; 6],
}

impl<S: ProfileStdioSyscallsV1> fmt::Debug for ProfileOwnedStdioSessionV1<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProfileOwnedStdioSessionV1")
            .field("descriptors", &"<profile-owned-fds>")
            .finish()
    }
}

impl<S: ProfileStdioSyscallsV1> Drop for ProfileOwnedStdioSessionV1<S> {
    fn drop(&mut self) {
        self.drop_all();
    }
}

impl<S: ProfileStdioSyscallsV1> ProfileOwnedStdioSessionV1<S> {
    fn construct(syscalls: S) -> Result<Self, ProfileStdioFailureV1> {
        let mut session = Self {
            syscalls: Some(syscalls),
            descriptors: [None, None, None, None, None, None],
        };
        if let Err(first) = session.construct_inner() {
            let cleanup = session.cleanup_all();
            return Err(first.with_cleanup(cleanup));
        }
        Ok(session)
    }

    fn construct_inner(&mut self) -> Result<(), ProfileStdioFailureV1> {
        self.add_pipe(
            PipeRoleV1::Stdin,
            FdRoleV1::ChildStdin,
            FdRoleV1::StdinEofWriter,
        )?;
        self.add_pipe(
            PipeRoleV1::Stdout,
            FdRoleV1::ParentStdout,
            FdRoleV1::ChildStdout,
        )?;
        self.add_pipe(
            PipeRoleV1::Stderr,
            FdRoleV1::ParentStderr,
            FdRoleV1::ChildStderr,
        )?;
        self.relocate_isolation_protocol_collisions()?;
        if self
            .descriptors
            .iter()
            .flatten()
            .any(|descriptor| descriptor.raw <= libc::STDERR_FILENO)
        {
            return Err(ProfileStdioFailureV1::contract(
                StdioOperationV1::Authenticate(FdRoleV1::ChildStdin),
            ));
        }
        for index in 0..self.descriptors.len() {
            if let Some(descriptor) = self.descriptors[index].as_ref() {
                if self.descriptors[index + 1..]
                    .iter()
                    .flatten()
                    .any(|other| other.raw == descriptor.raw)
                {
                    return Err(ProfileStdioFailureV1::contract(
                        StdioOperationV1::Authenticate(descriptor.role),
                    ));
                }
            }
        }
        self.set_parent_nonblocking(FdRoleV1::ParentStdout)?;
        self.set_parent_nonblocking(FdRoleV1::ParentStderr)?;
        for role in [
            FdRoleV1::ChildStdin,
            FdRoleV1::StdinEofWriter,
            FdRoleV1::ParentStdout,
            FdRoleV1::ChildStdout,
            FdRoleV1::ParentStderr,
            FdRoleV1::ChildStderr,
        ] {
            self.authenticate(role)?;
        }
        self.authenticate_independent_pipes()
    }

    fn relocate_isolation_protocol_collisions(&mut self) -> Result<(), ProfileStdioFailureV1> {
        for index in 0..self.descriptors.len() {
            let Some((raw, role)) = self.descriptors[index]
                .as_ref()
                .map(|descriptor| (descriptor.raw, descriptor.role))
            else {
                continue;
            };
            if raw > 4 {
                continue;
            }
            let replacement = self
                .syscalls_mut()
                .fcntl_dupfd_cloexec(raw, role, 5)
                .map_err(|errno| {
                    ProfileStdioFailureV1::syscall(StdioOperationV1::FcntlDupMin(role), errno)
                })?;
            if replacement < 5
                || self
                    .descriptors
                    .iter()
                    .flatten()
                    .any(|descriptor| descriptor.raw == replacement)
            {
                let _ = self.syscalls_mut().close(replacement, role);
                return Err(ProfileStdioFailureV1::contract(
                    StdioOperationV1::FcntlDupMin(role),
                ));
            }
            self.descriptors[index] = Some(TrackedFdV1 {
                raw: replacement,
                role,
            });
            self.syscalls_mut().close(raw, role).map_err(|errno| {
                ProfileStdioFailureV1::syscall(StdioOperationV1::Close(role), errno)
                    .with_cleanup(false)
            })?;
        }
        Ok(())
    }

    fn add_pipe(
        &mut self,
        pipe: PipeRoleV1,
        read_role: FdRoleV1,
        write_role: FdRoleV1,
    ) -> Result<(), ProfileStdioFailureV1> {
        let (read, write) = self
            .syscalls_mut()
            .pipe2(pipe, libc::O_CLOEXEC)
            .map_err(|errno| ProfileStdioFailureV1::syscall(StdioOperationV1::Pipe(pipe), errno))?;
        self.push_descriptor(TrackedFdV1 {
            raw: read,
            role: read_role,
        });
        self.push_descriptor(TrackedFdV1 {
            raw: write,
            role: write_role,
        });
        Ok(())
    }

    fn push_descriptor(&mut self, descriptor: TrackedFdV1) {
        let slot = self
            .descriptors
            .iter_mut()
            .find(|slot| slot.is_none())
            .expect("the fixed profile owns exactly six initial endpoints");
        *slot = Some(descriptor);
    }

    fn set_parent_nonblocking(&mut self, role: FdRoleV1) -> Result<(), ProfileStdioFailureV1> {
        let raw = self.raw(role)?;
        let flags = self
            .syscalls_mut()
            .fcntl_getfl(raw, role)
            .map_err(|errno| {
                ProfileStdioFailureV1::syscall(StdioOperationV1::FcntlGetFl(role), errno)
            })?;
        self.syscalls_mut()
            .fcntl_setfl(raw, role, flags | libc::O_NONBLOCK)
            .map_err(|errno| {
                ProfileStdioFailureV1::syscall(StdioOperationV1::FcntlSetFl(role), errno)
            })
    }

    fn authenticate(&mut self, role: FdRoleV1) -> Result<(), ProfileStdioFailureV1> {
        let raw = self.raw(role)?;
        let facts = self.syscalls_mut().fstat(raw, role).map_err(|errno| {
            ProfileStdioFailureV1::syscall(StdioOperationV1::Fstat(role), errno)
        })?;
        let fd_flags = self
            .syscalls_mut()
            .fcntl_getfd(raw, role)
            .map_err(|errno| {
                ProfileStdioFailureV1::syscall(StdioOperationV1::FcntlGetFd(role), errno)
            })?;
        let status = self
            .syscalls_mut()
            .fcntl_getfl(raw, role)
            .map_err(|errno| {
                ProfileStdioFailureV1::syscall(StdioOperationV1::FcntlGetFl(role), errno)
            })?;
        let expected_access = match role {
            FdRoleV1::ChildStdin | FdRoleV1::ParentStdout | FdRoleV1::ParentStderr => {
                libc::O_RDONLY
            }
            FdRoleV1::StdinEofWriter | FdRoleV1::ChildStdout | FdRoleV1::ChildStderr => {
                libc::O_WRONLY
            }
            FdRoleV1::PlacedStdin | FdRoleV1::PlacedStdout | FdRoleV1::PlacedStderr => {
                return Err(ProfileStdioFailureV1::contract(
                    StdioOperationV1::Authenticate(role),
                ));
            }
        };
        let expected_nonblocking = matches!(role, FdRoleV1::ParentStdout | FdRoleV1::ParentStderr);
        if facts.mode & libc::S_IFMT != libc::S_IFIFO
            || fd_flags & libc::FD_CLOEXEC == 0
            || status & libc::O_ACCMODE != expected_access
            || (status & libc::O_NONBLOCK != 0) != expected_nonblocking
        {
            return Err(ProfileStdioFailureV1::contract(
                StdioOperationV1::Authenticate(role),
            ));
        }
        Ok(())
    }

    fn authenticate_independent_pipes(&mut self) -> Result<(), ProfileStdioFailureV1> {
        let stdin = self.facts(FdRoleV1::ChildStdin)?;
        let stdin_writer = self.facts(FdRoleV1::StdinEofWriter)?;
        let stdout = self.facts(FdRoleV1::ParentStdout)?;
        let stdout_writer = self.facts(FdRoleV1::ChildStdout)?;
        let stderr = self.facts(FdRoleV1::ParentStderr)?;
        let stderr_writer = self.facts(FdRoleV1::ChildStderr)?;
        if stdin != stdin_writer
            || stdout != stdout_writer
            || stderr != stderr_writer
            || (stdin.device, stdin.inode) == (stdout.device, stdout.inode)
            || (stdin.device, stdin.inode) == (stderr.device, stderr.inode)
            || (stdout.device, stdout.inode) == (stderr.device, stderr.inode)
        {
            return Err(ProfileStdioFailureV1::contract(
                StdioOperationV1::Authenticate(FdRoleV1::ParentStderr),
            ));
        }
        Ok(())
    }

    fn facts(&mut self, role: FdRoleV1) -> Result<DescriptorFactsV1, ProfileStdioFailureV1> {
        let raw = self.raw(role)?;
        self.syscalls_mut()
            .fstat(raw, role)
            .map_err(|errno| ProfileStdioFailureV1::syscall(StdioOperationV1::Fstat(role), errno))
    }

    fn raw(&self, role: FdRoleV1) -> Result<RawFd, ProfileStdioFailureV1> {
        self.descriptors
            .iter()
            .flatten()
            .find(|descriptor| descriptor.role == role)
            .map(|descriptor| descriptor.raw)
            .ok_or_else(|| ProfileStdioFailureV1::contract(StdioOperationV1::Authenticate(role)))
    }

    fn syscalls_mut(&mut self) -> &mut S {
        self.syscalls
            .as_mut()
            .expect("stdio syscall owner remains live until handoff")
    }

    fn close_required(&mut self, role: FdRoleV1) -> Result<(), ProfileStdioFailureV1> {
        let descriptor = self.take(role)?;
        self.syscalls_mut()
            .close(descriptor.raw, role)
            .map_err(|errno| {
                ProfileStdioFailureV1::syscall(StdioOperationV1::Close(role), errno)
                    .with_cleanup(false)
            })
    }

    fn take(&mut self, role: FdRoleV1) -> Result<TrackedFdV1, ProfileStdioFailureV1> {
        let index = self
            .descriptors
            .iter()
            .position(|descriptor| descriptor.as_ref().is_some_and(|value| value.role == role))
            .ok_or_else(|| ProfileStdioFailureV1::contract(StdioOperationV1::Authenticate(role)))?;
        self.descriptors[index]
            .take()
            .ok_or_else(|| ProfileStdioFailureV1::contract(StdioOperationV1::Authenticate(role)))
    }

    fn cleanup_all(&mut self) -> bool {
        let mut complete = true;
        if let Some(syscalls) = self.syscalls.as_mut() {
            for descriptor in &mut self.descriptors {
                if let Some(descriptor) = descriptor.take() {
                    complete &= syscalls.close(descriptor.raw, descriptor.role).is_ok();
                }
            }
        } else {
            complete = false;
        }
        complete
    }

    fn drop_all(&mut self) {
        let _ = self.cleanup_all();
    }

    pub(super) fn into_parent_drain(
        mut self,
    ) -> Result<ParentStdioDrainV1<S>, ProfileStdioFailureV1> {
        for role in [
            FdRoleV1::ChildStdin,
            FdRoleV1::ChildStdout,
            FdRoleV1::ChildStderr,
            FdRoleV1::StdinEofWriter,
        ] {
            if let Err(first) = self.close_required(role) {
                let cleanup = self.cleanup_all();
                return Err(first.with_cleanup(cleanup));
            }
        }
        let stdout = self.take(FdRoleV1::ParentStdout)?;
        let stderr = self.take(FdRoleV1::ParentStderr)?;
        let syscalls = self
            .syscalls
            .take()
            .expect("parent drain consumes the syscall owner exactly once");
        Ok(ParentStdioDrainV1 {
            syscalls: Some(syscalls),
            descriptors: [None, Some(stdout), Some(stderr)],
            control: Arc::new(ProfileStdioDrainControlStateV1 {
                cancelled: AtomicBool::new(false),
            }),
            cancellation_issued: false,
        })
    }

    #[cfg(test)]
    fn prepare_blocked_child_for_test(
        mut self,
    ) -> Result<BlockedChildStdioHandoffV1<S>, ProfileStdioFailureV1> {
        let placements = [
            (
                FdRoleV1::ChildStdin,
                libc::STDIN_FILENO,
                FdRoleV1::PlacedStdin,
            ),
            (
                FdRoleV1::ChildStdout,
                libc::STDOUT_FILENO,
                FdRoleV1::PlacedStdout,
            ),
            (
                FdRoleV1::ChildStderr,
                libc::STDERR_FILENO,
                FdRoleV1::PlacedStderr,
            ),
        ];
        // This path is intended for a stopped post-fork child. Its bookkeeping
        // stays on the stack; only injected kernel operations run before the
        // opaque pre-exec handoff is returned.
        let mut placed = [None, None, None];
        for (index, (source_role, target, placed_role)) in placements.into_iter().enumerate() {
            let source = self.raw(source_role)?;
            if let Err(errno) = self.syscalls_mut().dup3(source, target, placed_role) {
                let first =
                    ProfileStdioFailureV1::syscall(StdioOperationV1::Dup3(placed_role), errno);
                let cleanup = self.cleanup_placed_and_owned(&placed);
                return Err(first.with_cleanup(cleanup));
            }
            placed[index] = Some(TrackedFdV1 {
                raw: target,
                role: placed_role,
            });
            if let Err(first) = self.authenticate_placed(source_role, target, placed_role) {
                let cleanup = self.cleanup_placed_and_owned(&placed);
                return Err(first.with_cleanup(cleanup));
            }
        }
        if let Err(errno) = self.syscalls_mut().close_range_unshare(5, u32::MAX) {
            let first = ProfileStdioFailureV1::syscall(StdioOperationV1::CloseRange, errno);
            let cleanup = self.cleanup_placed_and_owned(&placed);
            return Err(first.with_cleanup(cleanup));
        }
        for descriptor in &mut self.descriptors {
            *descriptor = None;
        }
        let syscalls = self
            .syscalls
            .take()
            .expect("blocked-child handoff consumes the syscall owner exactly once");
        Ok(BlockedChildStdioHandoffV1 {
            syscalls: Some(syscalls),
            descriptors: placed,
        })
    }

    fn authenticate_placed(
        &mut self,
        source_role: FdRoleV1,
        target: RawFd,
        placed_role: FdRoleV1,
    ) -> Result<(), ProfileStdioFailureV1> {
        let source = self.facts(source_role)?;
        let placed = self
            .syscalls_mut()
            .fstat(target, placed_role)
            .map_err(|errno| {
                ProfileStdioFailureV1::syscall(StdioOperationV1::Fstat(placed_role), errno)
            })?;
        let fd_flags = self
            .syscalls_mut()
            .fcntl_getfd(target, placed_role)
            .map_err(|errno| {
                ProfileStdioFailureV1::syscall(StdioOperationV1::FcntlGetFd(placed_role), errno)
            })?;
        let status = self
            .syscalls_mut()
            .fcntl_getfl(target, placed_role)
            .map_err(|errno| {
                ProfileStdioFailureV1::syscall(StdioOperationV1::FcntlGetFl(placed_role), errno)
            })?;
        let expected_access = if placed_role == FdRoleV1::PlacedStdin {
            libc::O_RDONLY
        } else {
            libc::O_WRONLY
        };
        if source != placed
            || fd_flags & libc::FD_CLOEXEC != 0
            || status & libc::O_ACCMODE != expected_access
            || status & libc::O_NONBLOCK != 0
        {
            return Err(ProfileStdioFailureV1::contract(
                StdioOperationV1::Authenticate(placed_role),
            ));
        }
        Ok(())
    }

    fn cleanup_placed_and_owned(&mut self, placed: &[Option<TrackedFdV1>; 3]) -> bool {
        let mut complete = true;
        if let Some(syscalls) = self.syscalls.as_mut() {
            for descriptor in placed.iter().flatten() {
                complete &= syscalls.close(descriptor.raw, descriptor.role).is_ok();
            }
        } else {
            complete = false;
        }
        complete & self.cleanup_all()
    }
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64"
))]
impl<S: ProfileStdioSyscallsV1> ProfileOwnedStdioSessionV1<S> {
    fn split_for_isolation_inner_v1(
        mut self,
    ) -> Result<(ParentStdioDrainV1<S>, ProfileStdioIsolationChildV1), ProfileStdioFailureV1> {
        let authentication = (|| {
            for role in [
                FdRoleV1::ChildStdin,
                FdRoleV1::ChildStdout,
                FdRoleV1::ChildStderr,
            ] {
                if self.raw(role)? <= 4 {
                    return Err(ProfileStdioFailureV1::contract(
                        StdioOperationV1::Authenticate(role),
                    ));
                }
            }
            Ok([
                self.facts(FdRoleV1::ChildStdin)?,
                self.facts(FdRoleV1::ChildStdout)?,
                self.facts(FdRoleV1::ChildStderr)?,
            ])
        })();
        let child_facts = match authentication {
            Ok(facts) => facts,
            Err(first) => {
                let cleanup_complete = self.cleanup_all();
                return Err(first.with_cleanup(cleanup_complete));
            }
        };

        // Authentication above proves all six slots remain present. From this
        // point onward ownership transfer is infallible; no error path may
        // delegate observable cleanup to Drop.
        let child = [
            self.take(FdRoleV1::ChildStdin)
                .expect("authenticated child stdin remains owned"),
            self.take(FdRoleV1::ChildStdout)
                .expect("authenticated child stdout remains owned"),
            self.take(FdRoleV1::ChildStderr)
                .expect("authenticated child stderr remains owned"),
        ];
        let eof_writer = self
            .take(FdRoleV1::StdinEofWriter)
            .expect("constructed stdin EOF writer remains owned");
        let stdout = self
            .take(FdRoleV1::ParentStdout)
            .expect("constructed parent stdout remains owned");
        let stderr = self
            .take(FdRoleV1::ParentStderr)
            .expect("constructed parent stderr remains owned");
        let syscalls = self
            .syscalls
            .take()
            .expect("pre-clone split consumes the syscall owner exactly once");
        let parent = ParentStdioDrainV1 {
            syscalls: Some(syscalls),
            descriptors: [Some(eof_writer), Some(stdout), Some(stderr)],
            control: Arc::new(ProfileStdioDrainControlStateV1 {
                cancelled: AtomicBool::new(false),
            }),
            cancellation_issued: false,
        };
        let child = ProfileStdioIsolationChildV1 {
            descriptors: [
                ForkSafeChildFdV1::new(child[0].raw),
                ForkSafeChildFdV1::new(child[1].raw),
                ForkSafeChildFdV1::new(child[2].raw),
            ],
            expected: child_facts,
            fault: ChildStdioFaultPlanV1::none(),
        };
        Ok((parent, child))
    }
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64"
))]
impl ProfileOwnedStdioSessionV1<LinuxProfileStdioSyscallsV1> {
    /// Split ownership before `clone3`: the parent receives only its EOF and
    /// capture endpoints, while the child continuation receives only the three
    /// pipe endpoints that must become descriptors 0, 1, and 2.
    pub(super) fn split_for_isolation_v1(
        self,
    ) -> Result<
        (
            ParentStdioDrainV1<LinuxProfileStdioSyscallsV1>,
            ProfileStdioIsolationChildV1,
        ),
        ProfileStdioFailureV1,
    > {
        self.split_for_isolation_inner_v1()
    }
}

#[cfg(all(
    test,
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64"
))]
impl ParentStdioDrainV1<LinuxProfileStdioSyscallsV1> {
    /// Discard the fork-local copies of the parent-only endpoints before the
    /// child continues. `fork` duplicates descriptors even though the Rust
    /// values were split linearly before it, so leaving these copies open can
    /// suppress stdin EOF and stdout/stderr EOF in the real parent.
    fn discard_fork_copy_in_child_v1(mut self) -> Result<(), i32> {
        let mut first_errno = None;
        for descriptor in &mut self.descriptors {
            if let Some(descriptor) = descriptor.take()
                // SAFETY: close is an async-signal/fork-safe syscall and this
                // branch owns only its fork-local descriptor-table copies.
                && unsafe { libc::syscall(libc::SYS_close, descriptor.raw) } != 0
            {
                first_errno.get_or_insert_with(child_errno_v1);
            }
        }
        // The child exits without unwinding. Avoid dropping the syscall owner
        // and Arc after fork; their memory is reclaimed by `_exit`.
        std::mem::forget(self);
        first_errno.map_or(Ok(()), Err)
    }
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64"
))]
struct ForkSafeChildFdV1 {
    raw: RawFd,
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64"
))]
impl ForkSafeChildFdV1 {
    const fn new(raw: RawFd) -> Self {
        Self { raw }
    }

    fn take(&mut self) -> RawFd {
        std::mem::replace(&mut self.raw, -1)
    }
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64"
))]
impl Drop for ForkSafeChildFdV1 {
    fn drop(&mut self) {
        if self.raw > 4 {
            // SAFETY: a direct close syscall is async-signal/fork-safe and this
            // value owns only its child-half endpoint.
            unsafe {
                libc::syscall(libc::SYS_close, self.raw);
            }
            self.raw = -1;
        }
    }
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64"
))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChildStdioRawOperationV1 {
    SourceFstat(FdRoleV1),
    SourceGetFd(FdRoleV1),
    SourceGetFl(FdRoleV1),
    Dup3(FdRoleV1),
    PlacedFstat(FdRoleV1),
    PlacedGetFd(FdRoleV1),
    PlacedGetFl(FdRoleV1),
    CloseSource(FdRoleV1),
    ClosePlaced(FdRoleV1),
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64"
))]
#[derive(Clone, Copy)]
struct ChildStdioFaultPlanV1 {
    primary: Option<ChildStdioRawOperationV1>,
    cleanup: Option<ChildStdioRawOperationV1>,
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64"
))]
impl ChildStdioFaultPlanV1 {
    const fn none() -> Self {
        Self {
            primary: None,
            cleanup: None,
        }
    }

    fn check(&mut self, operation: ChildStdioRawOperationV1) -> Result<(), i32> {
        if self.primary == Some(operation) {
            self.primary = None;
            return Err(libc::EIO);
        }
        if self.cleanup == Some(operation) {
            self.cleanup = None;
            return Err(libc::EBUSY);
        }
        Ok(())
    }
}

/// Linear child-half stdio continuation. It has no raw descriptor accessor and
/// owns no parent cleanup endpoint or isolation protocol endpoint.
#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64"
))]
pub(super) struct ProfileStdioIsolationChildV1 {
    descriptors: [ForkSafeChildFdV1; 3],
    expected: [DescriptorFactsV1; 3],
    fault: ChildStdioFaultPlanV1,
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64"
))]
impl fmt::Debug for ProfileStdioIsolationChildV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProfileStdioIsolationChildV1")
            .field("descriptors", &"<child-half-fds>")
            .field("authority", &"<none>")
            .finish()
    }
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64"
))]
impl ProfileStdioIsolationChildV1 {
    pub(super) fn continue_in_authenticated_child_v1(
        self,
        _brand: IsolationChildOnlyBrandV1,
    ) -> Result<(), i32> {
        self.continue_raw_v1()
    }

    fn continue_raw_v1(mut self) -> Result<(), i32> {
        let roles = [
            (
                FdRoleV1::ChildStdin,
                FdRoleV1::PlacedStdin,
                libc::STDIN_FILENO,
            ),
            (
                FdRoleV1::ChildStdout,
                FdRoleV1::PlacedStdout,
                libc::STDOUT_FILENO,
            ),
            (
                FdRoleV1::ChildStderr,
                FdRoleV1::PlacedStderr,
                libc::STDERR_FILENO,
            ),
        ];
        let mut placed = [false; 3];
        let result = (|| {
            for (index, (source_role, placed_role, target)) in roles.into_iter().enumerate() {
                let source = self.descriptors[index].raw;
                if source <= 4 {
                    return Err(libc::EINVAL);
                }
                let source_facts = child_fstat_v1(
                    &mut self.fault,
                    ChildStdioRawOperationV1::SourceFstat(source_role),
                    source,
                )?;
                let source_fd_flags = child_fcntl_v1(
                    &mut self.fault,
                    ChildStdioRawOperationV1::SourceGetFd(source_role),
                    source,
                    libc::F_GETFD,
                )?;
                let source_status = child_fcntl_v1(
                    &mut self.fault,
                    ChildStdioRawOperationV1::SourceGetFl(source_role),
                    source,
                    libc::F_GETFL,
                )?;
                let expected_access = if index == 0 {
                    libc::O_RDONLY
                } else {
                    libc::O_WRONLY
                };
                if source_facts != self.expected[index]
                    || source_facts.mode & libc::S_IFMT != libc::S_IFIFO
                    || source_fd_flags & libc::FD_CLOEXEC == 0
                    || source_status & libc::O_ACCMODE != expected_access
                    || source_status & libc::O_NONBLOCK != 0
                {
                    return Err(libc::EIO);
                }
                self.fault
                    .check(ChildStdioRawOperationV1::Dup3(placed_role))?;
                // SAFETY: direct dup3 is async-signal/fork-safe. Sources are
                // authenticated child-half fds >4 and targets are exactly 0/1/2.
                if unsafe { libc::syscall(libc::SYS_dup3, source, target, 0) }
                    != libc::c_long::from(target)
                {
                    return Err(child_errno_v1());
                }
                placed[index] = true;
                let placed_facts = child_fstat_v1(
                    &mut self.fault,
                    ChildStdioRawOperationV1::PlacedFstat(placed_role),
                    target,
                )?;
                let placed_fd_flags = child_fcntl_v1(
                    &mut self.fault,
                    ChildStdioRawOperationV1::PlacedGetFd(placed_role),
                    target,
                    libc::F_GETFD,
                )?;
                let placed_status = child_fcntl_v1(
                    &mut self.fault,
                    ChildStdioRawOperationV1::PlacedGetFl(placed_role),
                    target,
                    libc::F_GETFL,
                )?;
                if placed_facts != self.expected[index]
                    || placed_fd_flags != 0
                    || placed_status & libc::O_ACCMODE != expected_access
                    || placed_status & libc::O_NONBLOCK != 0
                {
                    return Err(libc::EIO);
                }
                self.fault
                    .check(ChildStdioRawOperationV1::CloseSource(source_role))?;
                if unsafe { libc::syscall(libc::SYS_close, source) } != 0 {
                    return Err(child_errno_v1());
                }
                self.descriptors[index].take();
            }
            Ok(())
        })();

        if let Err(primary) = result {
            for (index, (_, placed_role, target)) in roles.into_iter().enumerate() {
                if placed[index]
                    && self
                        .fault
                        .check(ChildStdioRawOperationV1::ClosePlaced(placed_role))
                        .is_ok()
                {
                    unsafe {
                        libc::syscall(libc::SYS_close, target);
                    }
                }
            }
            return Err(primary);
        }
        Ok(())
    }
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64"
))]
fn child_fstat_v1(
    fault: &mut ChildStdioFaultPlanV1,
    operation: ChildStdioRawOperationV1,
    descriptor: RawFd,
) -> Result<DescriptorFactsV1, i32> {
    fault.check(operation)?;
    let mut value = std::mem::MaybeUninit::<libc::stat>::zeroed();
    if unsafe { libc::syscall(libc::SYS_fstat, descriptor, value.as_mut_ptr()) } != 0 {
        return Err(child_errno_v1());
    }
    let value = unsafe { value.assume_init() };
    Ok(DescriptorFactsV1 {
        device: value.st_dev,
        inode: value.st_ino,
        mode: value.st_mode,
    })
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64"
))]
fn child_fcntl_v1(
    fault: &mut ChildStdioFaultPlanV1,
    operation: ChildStdioRawOperationV1,
    descriptor: RawFd,
    command: i32,
) -> Result<i32, i32> {
    fault.check(operation)?;
    let result = unsafe { libc::syscall(libc::SYS_fcntl, descriptor, command, 0) };
    if result < 0 {
        Err(child_errno_v1())
    } else {
        Ok(result as i32)
    }
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64"
))]
fn child_errno_v1() -> i32 {
    unsafe { *libc::__errno_location() }
}

pub(super) struct BlockedChildStdioHandoffV1<S: ProfileStdioSyscallsV1> {
    syscalls: Option<S>,
    descriptors: [Option<TrackedFdV1>; 3],
}

impl<S: ProfileStdioSyscallsV1> fmt::Debug for BlockedChildStdioHandoffV1<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BlockedChildStdioHandoffV1")
            .field("stdio", &"<placed-fds-0-1-2>")
            .finish()
    }
}

impl<S: ProfileStdioSyscallsV1> Drop for BlockedChildStdioHandoffV1<S> {
    fn drop(&mut self) {
        if let Some(syscalls) = self.syscalls.as_mut() {
            for descriptor in &mut self.descriptors {
                if let Some(descriptor) = descriptor.take() {
                    let _ = syscalls.close(descriptor.raw, descriptor.role);
                }
            }
        }
    }
}

#[cfg(test)]
trait ProfileStreamSinkV1 {
    /// Returns the exact prefix length delivered by this call. An error means
    /// no bytes from that individual call were delivered.
    fn write_stream(&mut self, stream: ProfileStreamV1, bytes: &[u8]) -> Result<usize, ()>;
}

enum DrainPresentationV1<'a> {
    CaptureOnly(std::marker::PhantomData<&'a ()>),
    #[cfg(test)]
    TestSink(&'a mut dyn ProfileStreamSinkV1),
}

impl DrainPresentationV1<'_> {
    fn write_stream(&mut self, _stream: ProfileStreamV1, bytes: &[u8]) -> Result<usize, ()> {
        match self {
            Self::CaptureOnly(_) => Ok(bytes.len()),
            #[cfg(test)]
            Self::TestSink(sink) => sink.write_stream(_stream, bytes),
        }
    }

    const fn records_delivery(&self) -> bool {
        match self {
            Self::CaptureOnly(_) => false,
            #[cfg(test)]
            Self::TestSink(_) => true,
        }
    }
}

struct StreamAccumulatorV1 {
    stream: ProfileStreamV1,
    captured: Vec<u8>,
    drained_bytes: u64,
    delivered_bytes: u64,
    capture_complete: bool,
    hasher: blake3::Hasher,
    eof: bool,
}

impl StreamAccumulatorV1 {
    fn new(stream: ProfileStreamV1) -> Self {
        let mut hasher = blake3::Hasher::new_derive_key(STREAM_HASH_DOMAIN_V1);
        hasher.update(match stream {
            ProfileStreamV1::Stdout => b"stdout",
            ProfileStreamV1::Stderr => b"stderr",
        });
        Self {
            stream,
            captured: Vec::new(),
            drained_bytes: 0,
            delivered_bytes: 0,
            capture_complete: true,
            hasher,
            eof: false,
        }
    }

    fn observe(&mut self, bytes: &[u8]) -> Result<(), ProfileStdioFailureV1> {
        if bytes.is_empty() {
            return Err(ProfileStdioFailureV1::protocol());
        }
        self.drained_bytes = self
            .drained_bytes
            .checked_add(bytes.len() as u64)
            .ok_or_else(ProfileStdioFailureV1::protocol)?;
        self.hasher.update(bytes);
        let remaining = STREAM_CAPTURE_LIMIT_V1.saturating_sub(self.captured.len());
        let retained = remaining.min(bytes.len());
        self.captured.extend_from_slice(&bytes[..retained]);
        if retained != bytes.len() {
            self.capture_complete = false;
        }
        Ok(())
    }

    fn delivered(&mut self, bytes: usize) -> Result<(), ProfileStdioFailureV1> {
        self.delivered_bytes = self
            .delivered_bytes
            .checked_add(bytes as u64)
            .ok_or_else(ProfileStdioFailureV1::protocol)?;
        Ok(())
    }

    fn finish(self) -> ProfileStreamCaptureV1 {
        ProfileStreamCaptureV1 {
            stream: self.stream,
            captured: self.captured,
            drained_bytes: self.drained_bytes,
            delivered_bytes: self.delivered_bytes,
            streaming_hash: *self.hasher.finalize().as_bytes(),
            capture_complete: self.capture_complete && self.eof,
            eof_observed: self.eof,
        }
    }
}

pub(super) struct ProfileStreamCaptureV1 {
    stream: ProfileStreamV1,
    captured: Vec<u8>,
    drained_bytes: u64,
    delivered_bytes: u64,
    streaming_hash: [u8; 32],
    capture_complete: bool,
    eof_observed: bool,
}

impl ProfileStreamCaptureV1 {
    pub(super) const fn stream(&self) -> ProfileStreamV1 {
        self.stream
    }

    pub(super) fn captured(&self) -> &[u8] {
        &self.captured
    }

    pub(super) const fn drained_bytes(&self) -> u64 {
        self.drained_bytes
    }

    pub(super) const fn delivered_bytes(&self) -> u64 {
        self.delivered_bytes
    }

    pub(super) const fn streaming_hash(&self) -> &[u8; 32] {
        &self.streaming_hash
    }

    pub(super) const fn capture_complete(&self) -> bool {
        self.capture_complete
    }

    pub(super) const fn eof_observed(&self) -> bool {
        self.eof_observed
    }
}

impl fmt::Debug for ProfileStreamCaptureV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProfileStreamCaptureV1")
            .field("stream", &self.stream)
            .field("captured", &"<redacted-bytes>")
            .field("drained_bytes", &self.drained_bytes)
            .field("delivered_bytes", &self.delivered_bytes)
            .field("streaming_hash", &"<redacted-digest>")
            .field("capture_complete", &self.capture_complete)
            .field("eof_observed", &self.eof_observed)
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum PresentationFailureV1 {
    Stdout,
    Stderr,
}

pub(super) struct ProfileStdioDrainReportV1 {
    stdout: ProfileStreamCaptureV1,
    stderr: ProfileStreamCaptureV1,
    presentation_failure: Option<PresentationFailureV1>,
}

impl ProfileStdioDrainReportV1 {
    pub(super) const fn stdout(&self) -> &ProfileStreamCaptureV1 {
        &self.stdout
    }

    pub(super) const fn stderr(&self) -> &ProfileStreamCaptureV1 {
        &self.stderr
    }

    pub(super) const fn presentation_failure(&self) -> Option<PresentationFailureV1> {
        self.presentation_failure
    }

    pub(super) const fn capture_complete(&self) -> bool {
        self.stdout.capture_complete && self.stderr.capture_complete
    }

    pub(super) const fn requires_execute_only_classification(&self) -> bool {
        !self.capture_complete() || self.presentation_failure.is_some()
    }
}

impl fmt::Debug for ProfileStdioDrainReportV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProfileStdioDrainReportV1")
            .field("stdout", &self.stdout)
            .field("stderr", &self.stderr)
            .field("presentation_failure", &self.presentation_failure)
            .field("authority", &"<none>")
            .finish()
    }
}

struct ProfileStdioDrainControlStateV1 {
    cancelled: AtomicBool,
}

/// One opaque cancellation signal for the foreground drain.
///
/// Cancellation only asks the drain owner to close its two read endpoints and
/// return a typed failure. It exposes no descriptor, signal, process, command,
/// execution, candidate, or reuse authority.
pub(super) struct ProfileStdioDrainCancellationV1 {
    state: Arc<ProfileStdioDrainControlStateV1>,
}

impl fmt::Debug for ProfileStdioDrainCancellationV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProfileStdioDrainCancellationV1")
            .field("control", &"<opaque-cancel-only>")
            .field("authority", &"<none>")
            .finish()
    }
}

impl ProfileStdioDrainCancellationV1 {
    pub(super) fn cancel(self) {
        self.state.cancelled.store(true, Ordering::Release);
    }
}

pub(super) struct ParentStdioDrainV1<S: ProfileStdioSyscallsV1> {
    syscalls: Option<S>,
    descriptors: [Option<TrackedFdV1>; 3],
    control: Arc<ProfileStdioDrainControlStateV1>,
    cancellation_issued: bool,
}

impl<S: ProfileStdioSyscallsV1> fmt::Debug for ParentStdioDrainV1<S> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ParentStdioDrainV1")
            .field("descriptors", &"<parent-read-fds>")
            .field("control", &"<opaque-bounded-control>")
            .finish()
    }
}

impl<S: ProfileStdioSyscallsV1> Drop for ParentStdioDrainV1<S> {
    fn drop(&mut self) {
        let _ = self.cleanup_all();
    }
}

impl<S: ProfileStdioSyscallsV1> ParentStdioDrainV1<S> {
    /// Close every parent endpoint without waiting for EOF.
    ///
    /// This is reserved for setup refusal or for cancellation paths where the
    /// child could not be proved terminally reaped. It is deliberately
    /// consuming and reports only cleanup completeness.
    pub(super) fn close_without_capture_v1(mut self) -> bool {
        self.cleanup_all()
    }

    /// Issue the drain's only cancellation signal before moving the drain to
    /// its foreground owner.
    pub(super) fn take_cancellation(&mut self) -> Option<ProfileStdioDrainCancellationV1> {
        if self.cancellation_issued {
            return None;
        }
        self.cancellation_issued = true;
        Some(ProfileStdioDrainCancellationV1 {
            state: Arc::clone(&self.control),
        })
    }

    /// Drain both nonblocking capture pipes to exact EOF. No caller code runs
    /// while this value owns cleanup; the returned bytes may be presented only
    /// after this method has closed all parent stdio descriptors.
    pub(super) fn drain_capture_v1(
        mut self,
    ) -> Result<ProfileStdioDrainReportV1, ProfileStdioFailureV1> {
        let deadline = Instant::now()
            .checked_add(DRAIN_DEADLINE_V1)
            .ok_or_else(ProfileStdioFailureV1::deadline)?;
        self.drain_until(
            &mut DrainPresentationV1::CaptureOnly(std::marker::PhantomData),
            deadline,
        )
    }

    #[cfg(test)]
    fn drain<Sink: ProfileStreamSinkV1>(
        mut self,
        sink: &mut Sink,
    ) -> Result<ProfileStdioDrainReportV1, ProfileStdioFailureV1> {
        let deadline = Instant::now()
            .checked_add(DRAIN_DEADLINE_V1)
            .ok_or_else(ProfileStdioFailureV1::deadline)?;
        self.drain_until(&mut DrainPresentationV1::TestSink(sink), deadline)
    }

    fn drain_until(
        &mut self,
        presentation: &mut DrainPresentationV1<'_>,
        deadline: Instant,
    ) -> Result<ProfileStdioDrainReportV1, ProfileStdioFailureV1> {
        if self.raw_optional(FdRoleV1::StdinEofWriter).is_some() {
            let descriptor = self.take(FdRoleV1::StdinEofWriter)?;
            if let Err(errno) = self
                .syscalls_mut()
                .close(descriptor.raw, FdRoleV1::StdinEofWriter)
            {
                let _cleanup = self.cleanup_all();
                return Err(ProfileStdioFailureV1::syscall(
                    StdioOperationV1::Close(FdRoleV1::StdinEofWriter),
                    errno,
                )
                .with_cleanup(false));
            }
        }
        let mut stdout = StreamAccumulatorV1::new(ProfileStreamV1::Stdout);
        let mut stderr = StreamAccumulatorV1::new(ProfileStreamV1::Stderr);
        let mut presentation_failure = None;
        let mut first_close_failure = None;
        let mut cleanup_complete = true;
        let mut buffer = [0u8; DRAIN_BUFFER_BYTES_V1];
        while !stdout.eof || !stderr.eof {
            if let Some(new) = self.control_failure(deadline) {
                let failure =
                    self.finalize_failure(new, &mut first_close_failure, cleanup_complete);
                return Err(failure);
            }
            let stdout_fd = self.raw_optional(FdRoleV1::ParentStdout);
            let stderr_fd = self.raw_optional(FdRoleV1::ParentStderr);
            let timeout_millis = poll_timeout_millis_v1(deadline);
            let readiness = match self
                .syscalls_mut()
                .poll(stdout_fd, stderr_fd, timeout_millis)
            {
                Ok(readiness) => readiness,
                Err(CallErrorV1::Interrupted) => continue,
                Err(CallErrorV1::TimedOut) => continue,
                Err(CallErrorV1::Errno(errno)) => {
                    let failure = self.finalize_failure(
                        ProfileStdioFailureV1::syscall(StdioOperationV1::Poll, errno),
                        &mut first_close_failure,
                        cleanup_complete,
                    );
                    return Err(failure);
                }
                Err(CallErrorV1::WouldBlock) => {
                    let failure = self.finalize_failure(
                        ProfileStdioFailureV1::protocol(),
                        &mut first_close_failure,
                        cleanup_complete,
                    );
                    return Err(failure);
                }
            };
            if readiness.stdout.invalid || readiness.stderr.invalid {
                let failure = self.finalize_failure(
                    ProfileStdioFailureV1::protocol(),
                    &mut first_close_failure,
                    cleanup_complete,
                );
                return Err(failure);
            }
            let mut acted = false;
            if !stdout.eof && readiness.stdout.actionable() {
                acted = true;
                self.drain_ready_stream(
                    &mut stdout,
                    presentation,
                    &mut presentation_failure,
                    &mut first_close_failure,
                    &mut cleanup_complete,
                    &mut buffer,
                    deadline,
                )?;
            }
            if !stderr.eof && readiness.stderr.actionable() {
                acted = true;
                self.drain_ready_stream(
                    &mut stderr,
                    presentation,
                    &mut presentation_failure,
                    &mut first_close_failure,
                    &mut cleanup_complete,
                    &mut buffer,
                    deadline,
                )?;
            }
            if !acted {
                let failure = self.finalize_failure(
                    ProfileStdioFailureV1::protocol(),
                    &mut first_close_failure,
                    cleanup_complete,
                );
                return Err(failure);
            }
        }
        if let Some(first) = first_close_failure {
            return Err(first.with_cleanup(cleanup_complete));
        }
        Ok(ProfileStdioDrainReportV1 {
            stdout: stdout.finish(),
            stderr: stderr.finish(),
            presentation_failure,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn drain_ready_stream(
        &mut self,
        accumulator: &mut StreamAccumulatorV1,
        presentation: &mut DrainPresentationV1<'_>,
        presentation_failure: &mut Option<PresentationFailureV1>,
        first_close_failure: &mut Option<ProfileStdioFailureV1>,
        cleanup_complete: &mut bool,
        buffer: &mut [u8],
        deadline: Instant,
    ) -> Result<(), ProfileStdioFailureV1> {
        let role = match accumulator.stream {
            ProfileStreamV1::Stdout => FdRoleV1::ParentStdout,
            ProfileStreamV1::Stderr => FdRoleV1::ParentStderr,
        };
        let Some(raw) = self.raw_optional(role) else {
            let failure = self.finalize_failure(
                ProfileStdioFailureV1::protocol(),
                first_close_failure,
                *cleanup_complete,
            );
            return Err(failure);
        };
        let mut successful_reads = 0usize;
        loop {
            if let Some(new) = self.control_failure(deadline) {
                let failure = self.finalize_failure(new, first_close_failure, *cleanup_complete);
                return Err(failure);
            }
            match self.syscalls_mut().read(raw, accumulator.stream, buffer) {
                Ok(ReadResultV1::Bytes(length)) if length > 0 && length <= buffer.len() => {
                    let bytes = &buffer[..length];
                    if let Err(new) = accumulator.observe(bytes) {
                        let failure =
                            self.finalize_failure(new, first_close_failure, *cleanup_complete);
                        return Err(failure);
                    }
                    if presentation_failure.is_none() {
                        let mut remaining = bytes;
                        while !remaining.is_empty() {
                            if let Some(new) = self.control_failure(deadline) {
                                let failure = self.finalize_failure(
                                    new,
                                    first_close_failure,
                                    *cleanup_complete,
                                );
                                return Err(failure);
                            }
                            match presentation.write_stream(accumulator.stream, remaining) {
                                Ok(delivered) if delivered > 0 && delivered <= remaining.len() => {
                                    if presentation.records_delivery()
                                        && let Err(new) = accumulator.delivered(delivered)
                                    {
                                        let failure = self.finalize_failure(
                                            new,
                                            first_close_failure,
                                            *cleanup_complete,
                                        );
                                        return Err(failure);
                                    }
                                    remaining = &remaining[delivered..];
                                }
                                Ok(_) | Err(()) => {
                                    *presentation_failure = Some(match accumulator.stream {
                                        ProfileStreamV1::Stdout => PresentationFailureV1::Stdout,
                                        ProfileStreamV1::Stderr => PresentationFailureV1::Stderr,
                                    });
                                    break;
                                }
                            }
                        }
                    }
                    successful_reads += 1;
                    if successful_reads == MAX_READS_PER_STREAM_TURN_V1 {
                        return Ok(());
                    }
                }
                Ok(ReadResultV1::Bytes(_)) => {
                    let failure = self.finalize_failure(
                        ProfileStdioFailureV1::protocol(),
                        first_close_failure,
                        *cleanup_complete,
                    );
                    return Err(failure);
                }
                Ok(ReadResultV1::WouldBlock) | Err(CallErrorV1::WouldBlock) => return Ok(()),
                Err(CallErrorV1::Interrupted) => continue,
                Err(CallErrorV1::TimedOut) => {
                    let failure = self.finalize_failure(
                        ProfileStdioFailureV1::protocol(),
                        first_close_failure,
                        *cleanup_complete,
                    );
                    return Err(failure);
                }
                Ok(ReadResultV1::Eof) => {
                    accumulator.eof = true;
                    let descriptor = match self.take(role) {
                        Ok(descriptor) => descriptor,
                        Err(new) => {
                            let failure =
                                self.finalize_failure(new, first_close_failure, *cleanup_complete);
                            return Err(failure);
                        }
                    };
                    if let Err(errno) = self.syscalls_mut().close(descriptor.raw, role) {
                        *cleanup_complete = false;
                        first_close_failure.get_or_insert_with(|| {
                            ProfileStdioFailureV1::syscall(StdioOperationV1::Close(role), errno)
                        });
                    }
                    return Ok(());
                }
                Err(CallErrorV1::Errno(errno)) => {
                    let failure = self.finalize_failure(
                        ProfileStdioFailureV1::syscall(
                            StdioOperationV1::Read(accumulator.stream),
                            errno,
                        ),
                        first_close_failure,
                        *cleanup_complete,
                    );
                    return Err(failure);
                }
            }
        }
    }

    fn finalize_failure(
        &mut self,
        new: ProfileStdioFailureV1,
        earlier: &mut Option<ProfileStdioFailureV1>,
        cleanup_complete: bool,
    ) -> ProfileStdioFailureV1 {
        let cleanup = self.cleanup_all();
        earlier
            .take()
            .unwrap_or(new)
            .with_cleanup(cleanup_complete & cleanup)
    }

    fn control_failure(&self, deadline: Instant) -> Option<ProfileStdioFailureV1> {
        if self.control.cancelled.load(Ordering::Acquire) {
            Some(ProfileStdioFailureV1::cancelled())
        } else if Instant::now() >= deadline {
            Some(ProfileStdioFailureV1::deadline())
        } else {
            None
        }
    }

    fn syscalls_mut(&mut self) -> &mut S {
        self.syscalls
            .as_mut()
            .expect("parent drain retains its syscall owner")
    }
    fn raw_optional(&self, role: FdRoleV1) -> Option<RawFd> {
        self.descriptors
            .iter()
            .flatten()
            .find(|descriptor| descriptor.role == role)
            .map(|descriptor| descriptor.raw)
    }
    fn take(&mut self, role: FdRoleV1) -> Result<TrackedFdV1, ProfileStdioFailureV1> {
        let index = self
            .descriptors
            .iter()
            .position(|descriptor| descriptor.as_ref().is_some_and(|value| value.role == role))
            .ok_or_else(ProfileStdioFailureV1::protocol)?;
        self.descriptors[index]
            .take()
            .ok_or_else(ProfileStdioFailureV1::protocol)
    }
    fn cleanup_all(&mut self) -> bool {
        let mut complete = true;
        if let Some(syscalls) = self.syscalls.as_mut() {
            for descriptor in &mut self.descriptors {
                if let Some(descriptor) = descriptor.take() {
                    complete &= syscalls.close(descriptor.raw, descriptor.role).is_ok();
                }
            }
        } else {
            complete = false;
        }
        complete
    }
}

fn poll_timeout_millis_v1(deadline: Instant) -> i32 {
    let remaining = deadline.saturating_duration_since(Instant::now());
    let bounded = remaining.min(DRAIN_POLL_SLICE_V1);
    i32::try_from(bounded.as_millis().max(1)).unwrap_or(1)
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64"
))]
pub(super) struct LinuxProfileStdioSyscallsV1;

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64"
))]
impl ProfileStdioSyscallsV1 for LinuxProfileStdioSyscallsV1 {
    fn pipe2(&mut self, _role: PipeRoleV1, flags: i32) -> Result<(RawFd, RawFd), i32> {
        let mut descriptors = [-1; 2];
        if unsafe { libc::pipe2(descriptors.as_mut_ptr(), flags) } == 0 {
            Ok((descriptors[0], descriptors[1]))
        } else {
            Err(last_errno())
        }
    }
    fn fstat(&mut self, fd: RawFd, _role: FdRoleV1) -> Result<DescriptorFactsV1, i32> {
        let mut value = std::mem::MaybeUninit::<libc::stat>::zeroed();
        if unsafe { libc::fstat(fd, value.as_mut_ptr()) } != 0 {
            return Err(last_errno());
        }
        let value = unsafe { value.assume_init() };
        Ok(DescriptorFactsV1 {
            device: value.st_dev,
            inode: value.st_ino,
            mode: value.st_mode,
        })
    }
    fn fcntl_getfd(&mut self, fd: RawFd, _role: FdRoleV1) -> Result<i32, i32> {
        let result = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        (result >= 0).then_some(result).ok_or_else(last_errno)
    }
    fn fcntl_getfl(&mut self, fd: RawFd, _role: FdRoleV1) -> Result<i32, i32> {
        let result = unsafe { libc::fcntl(fd, libc::F_GETFL) };
        (result >= 0).then_some(result).ok_or_else(last_errno)
    }
    fn fcntl_setfl(&mut self, fd: RawFd, _role: FdRoleV1, flags: i32) -> Result<(), i32> {
        let result = unsafe { libc::fcntl(fd, libc::F_SETFL, flags) };
        (result == 0).then_some(()).ok_or_else(last_errno)
    }
    fn fcntl_dupfd_cloexec(
        &mut self,
        fd: RawFd,
        _role: FdRoleV1,
        minimum: RawFd,
    ) -> Result<RawFd, i32> {
        let result = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, minimum) };
        (result >= minimum).then_some(result).ok_or_else(last_errno)
    }
    fn close(&mut self, fd: RawFd, _role: FdRoleV1) -> Result<(), i32> {
        let result = unsafe { libc::close(fd) };
        (result == 0).then_some(()).ok_or_else(last_errno)
    }
    fn dup3(&mut self, old: RawFd, new: RawFd, _role: FdRoleV1) -> Result<(), i32> {
        let result = unsafe { libc::dup3(old, new, 0) };
        (result == new).then_some(()).ok_or_else(last_errno)
    }
    fn close_range_unshare(&mut self, first: u32, last: u32) -> Result<(), i32> {
        let result = unsafe {
            libc::syscall(
                libc::SYS_close_range,
                first,
                last,
                libc::CLOSE_RANGE_UNSHARE,
            )
        };
        (result == 0).then_some(()).ok_or_else(last_errno)
    }
    fn poll(
        &mut self,
        stdout: Option<RawFd>,
        stderr: Option<RawFd>,
        timeout_millis: i32,
    ) -> Result<PollInterestResultV1, CallErrorV1> {
        let mut descriptors = Vec::with_capacity(2);
        let mut streams = Vec::with_capacity(2);
        for (fd, stream) in [
            (stdout, ProfileStreamV1::Stdout),
            (stderr, ProfileStreamV1::Stderr),
        ] {
            if let Some(fd) = fd {
                descriptors.push(libc::pollfd {
                    fd,
                    events: libc::POLLIN | libc::POLLHUP | libc::POLLERR,
                    revents: 0,
                });
                streams.push(stream);
            }
        }
        let result = unsafe {
            libc::poll(
                descriptors.as_mut_ptr(),
                descriptors.len() as _,
                timeout_millis,
            )
        };
        if result < 0 {
            let errno = last_errno();
            return Err(if errno == libc::EINTR {
                CallErrorV1::Interrupted
            } else {
                CallErrorV1::Errno(errno)
            });
        }
        if result == 0 {
            return Err(CallErrorV1::TimedOut);
        }
        let mut readiness = PollInterestResultV1::default();
        for (descriptor, stream) in descriptors.into_iter().zip(streams) {
            let observed = PollStreamResultV1 {
                readable: descriptor.revents & (libc::POLLIN | libc::POLLERR) != 0,
                hangup: descriptor.revents & libc::POLLHUP != 0,
                invalid: descriptor.revents & libc::POLLNVAL != 0,
            };
            match stream {
                ProfileStreamV1::Stdout => readiness.stdout = observed,
                ProfileStreamV1::Stderr => readiness.stderr = observed,
            }
        }
        Ok(readiness)
    }
    fn read(
        &mut self,
        fd: RawFd,
        _stream: ProfileStreamV1,
        buffer: &mut [u8],
    ) -> Result<ReadResultV1, CallErrorV1> {
        let result = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
        if result > 0 {
            return Ok(ReadResultV1::Bytes(result as usize));
        }
        if result == 0 {
            return Ok(ReadResultV1::Eof);
        }
        let errno = last_errno();
        match errno {
            libc::EINTR => Err(CallErrorV1::Interrupted),
            libc::EAGAIN => Ok(ReadResultV1::WouldBlock),
            _ => Err(CallErrorV1::Errno(errno)),
        }
    }
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64"
))]
fn last_errno() -> i32 {
    std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EIO)
}

#[cfg(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64"
))]
pub(super) fn open_profile_owned_stdio_v1()
-> Result<ProfileOwnedStdioSessionV1<LinuxProfileStdioSyscallsV1>, ProfileStdioFailureV1> {
    ProfileOwnedStdioSessionV1::construct(LinuxProfileStdioSyscallsV1)
}

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64"
)))]
#[derive(Debug)]
pub(super) struct UnsupportedProfileStdioSessionV1;

#[cfg(not(all(
    target_os = "linux",
    target_arch = "x86_64",
    target_env = "gnu",
    target_pointer_width = "64"
)))]
pub(super) fn open_profile_owned_stdio_v1()
-> Result<UnsupportedProfileStdioSessionV1, ProfileStdioFailureV1> {
    Err(ProfileStdioFailureV1::unsupported())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::{BTreeMap, VecDeque};
    use std::rc::Rc;
    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu",
        target_pointer_width = "64"
    ))]
    use std::{
        fs::File,
        os::fd::{AsRawFd, FromRawFd, OwnedFd},
    };

    #[derive(Clone, Debug)]
    struct FakeDescriptorV1 {
        facts: DescriptorFactsV1,
        fd_flags: i32,
        status_flags: i32,
    }

    #[derive(Clone, Debug)]
    enum FakeReadV1 {
        Data(Vec<u8>),
        Eof,
        Interrupted,
        WouldBlock,
        Errno(i32),
    }

    #[derive(Default)]
    struct FakeStateV1 {
        calls: Vec<StdioOperationV1>,
        fail_at: Option<usize>,
        additional_failures: Vec<usize>,
        mismatched_fstat_role: Option<FdRoleV1>,
        next_fd: RawFd,
        next_inode: u64,
        open: BTreeMap<RawFd, FakeDescriptorV1>,
        polls: VecDeque<Result<PollInterestResultV1, CallErrorV1>>,
        cancel_on_poll: Option<Arc<ProfileStdioDrainControlStateV1>>,
        stdout_reads: VecDeque<FakeReadV1>,
        stderr_reads: VecDeque<FakeReadV1>,
    }

    impl FakeStateV1 {
        fn record(&mut self, operation: StdioOperationV1) -> Result<(), i32> {
            self.calls.push(operation);
            if self.fail_at == Some(self.calls.len())
                || self.additional_failures.contains(&self.calls.len())
            {
                Err(libc::EIO)
            } else {
                Ok(())
            }
        }

        fn install_parent_reader(&mut self, fd: RawFd) {
            self.open.insert(
                fd,
                FakeDescriptorV1 {
                    facts: DescriptorFactsV1 {
                        device: 7,
                        inode: fd as u64,
                        mode: libc::S_IFIFO,
                    },
                    fd_flags: libc::FD_CLOEXEC,
                    status_flags: libc::O_RDONLY | libc::O_NONBLOCK,
                },
            );
        }
    }

    #[derive(Clone)]
    struct FakeSyscallsV1(Rc<RefCell<FakeStateV1>>);

    impl FakeSyscallsV1 {
        fn new() -> (Self, Rc<RefCell<FakeStateV1>>) {
            let state = Rc::new(RefCell::new(FakeStateV1 {
                next_fd: 10,
                next_inode: 100,
                ..FakeStateV1::default()
            }));
            (Self(Rc::clone(&state)), state)
        }
    }

    impl ProfileStdioSyscallsV1 for FakeSyscallsV1 {
        fn pipe2(&mut self, role: PipeRoleV1, flags: i32) -> Result<(RawFd, RawFd), i32> {
            let mut state = self.0.borrow_mut();
            state.record(StdioOperationV1::Pipe(role))?;
            assert_eq!(flags, libc::O_CLOEXEC);
            let read = state.next_fd;
            let write = read + 1;
            state.next_fd += 2;
            let facts = DescriptorFactsV1 {
                device: 7,
                inode: state.next_inode,
                mode: libc::S_IFIFO,
            };
            state.next_inode += 1;
            state.open.insert(
                read,
                FakeDescriptorV1 {
                    facts,
                    fd_flags: libc::FD_CLOEXEC,
                    status_flags: libc::O_RDONLY,
                },
            );
            state.open.insert(
                write,
                FakeDescriptorV1 {
                    facts,
                    fd_flags: libc::FD_CLOEXEC,
                    status_flags: libc::O_WRONLY,
                },
            );
            Ok((read, write))
        }

        fn fstat(&mut self, fd: RawFd, role: FdRoleV1) -> Result<DescriptorFactsV1, i32> {
            let mut state = self.0.borrow_mut();
            state.record(StdioOperationV1::Fstat(role))?;
            let mut facts = state
                .open
                .get(&fd)
                .map(|value| value.facts)
                .ok_or(libc::EBADF)?;
            if state.mismatched_fstat_role == Some(role) {
                facts.inode += 10_000;
            }
            Ok(facts)
        }

        fn fcntl_getfd(&mut self, fd: RawFd, role: FdRoleV1) -> Result<i32, i32> {
            let mut state = self.0.borrow_mut();
            state.record(StdioOperationV1::FcntlGetFd(role))?;
            state
                .open
                .get(&fd)
                .map(|value| value.fd_flags)
                .ok_or(libc::EBADF)
        }

        fn fcntl_getfl(&mut self, fd: RawFd, role: FdRoleV1) -> Result<i32, i32> {
            let mut state = self.0.borrow_mut();
            state.record(StdioOperationV1::FcntlGetFl(role))?;
            state
                .open
                .get(&fd)
                .map(|value| value.status_flags)
                .ok_or(libc::EBADF)
        }

        fn fcntl_setfl(&mut self, fd: RawFd, role: FdRoleV1, flags: i32) -> Result<(), i32> {
            let mut state = self.0.borrow_mut();
            state.record(StdioOperationV1::FcntlSetFl(role))?;
            state.open.get_mut(&fd).ok_or(libc::EBADF)?.status_flags = flags;
            Ok(())
        }

        fn fcntl_dupfd_cloexec(
            &mut self,
            fd: RawFd,
            role: FdRoleV1,
            minimum: RawFd,
        ) -> Result<RawFd, i32> {
            let mut state = self.0.borrow_mut();
            state.record(StdioOperationV1::FcntlDupMin(role))?;
            let descriptor = state.open.get(&fd).cloned().ok_or(libc::EBADF)?;
            let replacement = state.next_fd.max(minimum);
            state.next_fd = replacement + 1;
            state.open.insert(replacement, descriptor);
            Ok(replacement)
        }

        fn close(&mut self, fd: RawFd, role: FdRoleV1) -> Result<(), i32> {
            let mut state = self.0.borrow_mut();
            let result = state.record(StdioOperationV1::Close(role));
            let existed = state.open.remove(&fd).is_some();
            result?;
            if existed { Ok(()) } else { Err(libc::EBADF) }
        }

        fn dup3(&mut self, old: RawFd, new: RawFd, role: FdRoleV1) -> Result<(), i32> {
            let mut state = self.0.borrow_mut();
            state.record(StdioOperationV1::Dup3(role))?;
            let mut descriptor = state.open.get(&old).cloned().ok_or(libc::EBADF)?;
            descriptor.fd_flags &= !libc::FD_CLOEXEC;
            state.open.insert(new, descriptor);
            Ok(())
        }

        fn close_range_unshare(&mut self, first: u32, last: u32) -> Result<(), i32> {
            let mut state = self.0.borrow_mut();
            state.record(StdioOperationV1::CloseRange)?;
            assert_eq!((first, last), (5, u32::MAX));
            state.open.retain(|fd, _| (*fd as u32) < first);
            Ok(())
        }

        fn poll(
            &mut self,
            _stdout: Option<RawFd>,
            _stderr: Option<RawFd>,
            timeout_millis: i32,
        ) -> Result<PollInterestResultV1, CallErrorV1> {
            let mut state = self.0.borrow_mut();
            assert!((1..=DRAIN_POLL_SLICE_V1.as_millis() as i32).contains(&timeout_millis));
            state
                .record(StdioOperationV1::Poll)
                .map_err(CallErrorV1::Errno)?;
            if let Some(control) = state.cancel_on_poll.take() {
                control.cancelled.store(true, Ordering::Release);
            }
            state
                .polls
                .pop_front()
                .unwrap_or(Err(CallErrorV1::Errno(libc::ENODATA)))
        }

        fn read(
            &mut self,
            _fd: RawFd,
            stream: ProfileStreamV1,
            buffer: &mut [u8],
        ) -> Result<ReadResultV1, CallErrorV1> {
            let mut state = self.0.borrow_mut();
            state
                .record(StdioOperationV1::Read(stream))
                .map_err(CallErrorV1::Errno)?;
            let queue = match stream {
                ProfileStreamV1::Stdout => &mut state.stdout_reads,
                ProfileStreamV1::Stderr => &mut state.stderr_reads,
            };
            match queue.pop_front().unwrap_or(FakeReadV1::WouldBlock) {
                FakeReadV1::Data(bytes) => {
                    let length = bytes.len().min(buffer.len());
                    buffer[..length].copy_from_slice(&bytes[..length]);
                    if length != bytes.len() {
                        queue.push_front(FakeReadV1::Data(bytes[length..].to_vec()));
                    }
                    Ok(ReadResultV1::Bytes(length))
                }
                FakeReadV1::Eof => Ok(ReadResultV1::Eof),
                FakeReadV1::Interrupted => Err(CallErrorV1::Interrupted),
                FakeReadV1::WouldBlock => Ok(ReadResultV1::WouldBlock),
                FakeReadV1::Errno(errno) => Err(CallErrorV1::Errno(errno)),
            }
        }
    }

    #[derive(Default)]
    struct CollectSinkV1 {
        stdout: Vec<u8>,
        stderr: Vec<u8>,
        call_order: Vec<ProfileStreamV1>,
        fail_on: Option<ProfileStreamV1>,
    }

    impl ProfileStreamSinkV1 for CollectSinkV1 {
        fn write_stream(&mut self, stream: ProfileStreamV1, bytes: &[u8]) -> Result<usize, ()> {
            self.call_order.push(stream);
            if self.fail_on == Some(stream) {
                return Err(());
            }
            match stream {
                ProfileStreamV1::Stdout => self.stdout.extend_from_slice(bytes),
                ProfileStreamV1::Stderr => self.stderr.extend_from_slice(bytes),
            }
            Ok(bytes.len())
        }
    }

    struct PartialThenFailSinkV1 {
        delivered: Vec<u8>,
        first_call: bool,
    }

    impl ProfileStreamSinkV1 for PartialThenFailSinkV1 {
        fn write_stream(&mut self, _stream: ProfileStreamV1, bytes: &[u8]) -> Result<usize, ()> {
            if self.first_call {
                self.first_call = false;
                let delivered = bytes.len().min(2);
                self.delivered.extend_from_slice(&bytes[..delivered]);
                Ok(delivered)
            } else {
                Err(())
            }
        }
    }

    fn ready(stdout: PollStreamResultV1, stderr: PollStreamResultV1) -> PollInterestResultV1 {
        PollInterestResultV1 { stdout, stderr }
    }

    fn readable() -> PollStreamResultV1 {
        PollStreamResultV1 {
            readable: true,
            ..PollStreamResultV1::default()
        }
    }

    fn hung_up() -> PollStreamResultV1 {
        PollStreamResultV1 {
            hangup: true,
            ..PollStreamResultV1::default()
        }
    }

    fn fake_parent() -> (ParentStdioDrainV1<FakeSyscallsV1>, Rc<RefCell<FakeStateV1>>) {
        let (syscalls, state) = FakeSyscallsV1::new();
        state.borrow_mut().install_parent_reader(20);
        state.borrow_mut().install_parent_reader(21);
        (
            ParentStdioDrainV1 {
                syscalls: Some(syscalls),
                descriptors: [
                    None,
                    Some(TrackedFdV1 {
                        raw: 20,
                        role: FdRoleV1::ParentStdout,
                    }),
                    Some(TrackedFdV1 {
                        raw: 21,
                        role: FdRoleV1::ParentStderr,
                    }),
                ],
                control: Arc::new(ProfileStdioDrainControlStateV1 {
                    cancelled: AtomicBool::new(false),
                }),
                cancellation_issued: false,
            },
            state,
        )
    }

    #[test]
    fn close_without_capture_is_consuming_and_reports_every_close_failure() {
        let (parent, state) = fake_parent();
        assert!(parent.close_without_capture_v1());
        assert!(state.borrow().open.is_empty());

        let (parent, state) = fake_parent();
        state.borrow_mut().fail_at = Some(1);
        assert!(!parent.close_without_capture_v1());
        assert!(state.borrow().open.is_empty());
        assert_eq!(
            state
                .borrow()
                .calls
                .iter()
                .filter(|operation| matches!(operation, StdioOperationV1::Close(_)))
                .count(),
            2
        );
    }

    fn eof_schedule(state: &Rc<RefCell<FakeStateV1>>) {
        let mut state = state.borrow_mut();
        state.polls.push_back(Ok(ready(hung_up(), hung_up())));
        state.stdout_reads.push_back(FakeReadV1::Eof);
        state.stderr_reads.push_back(FakeReadV1::Eof);
    }

    #[test]
    fn portable_drain_preserves_split_interleaved_streams_and_hup_final_read() {
        let (parent, state) = fake_parent();
        {
            let mut state = state.borrow_mut();
            state.polls.push_back(Err(CallErrorV1::Interrupted));
            state.polls.push_back(Ok(ready(readable(), readable())));
            state.polls.push_back(Ok(ready(hung_up(), hung_up())));
            state.stdout_reads.extend([
                FakeReadV1::Interrupted,
                FakeReadV1::Data(b"ab".to_vec()),
                FakeReadV1::WouldBlock,
                FakeReadV1::Data(b"c".to_vec()),
                FakeReadV1::Eof,
            ]);
            state.stderr_reads.extend([
                FakeReadV1::Data(b"x".to_vec()),
                FakeReadV1::WouldBlock,
                FakeReadV1::Data(b"yz".to_vec()),
                FakeReadV1::Eof,
            ]);
        }
        let mut sink = CollectSinkV1::default();
        let report = parent.drain(&mut sink).expect("bounded drain");
        assert_eq!(sink.stdout, b"abc");
        assert_eq!(sink.stderr, b"xyz");
        assert_eq!(
            sink.call_order,
            [
                ProfileStreamV1::Stdout,
                ProfileStreamV1::Stderr,
                ProfileStreamV1::Stdout,
                ProfileStreamV1::Stderr,
            ]
        );
        assert_eq!(report.stdout.captured, b"abc");
        assert_eq!(report.stderr.captured, b"xyz");
        assert_eq!(report.stdout.drained_bytes, 3);
        assert_eq!(report.stderr.drained_bytes, 3);
        assert_eq!(report.stdout.delivered_bytes, 3);
        assert_eq!(report.stderr.delivered_bytes, 3);
        assert!(report.capture_complete());
        assert!(!report.requires_execute_only_classification());
        assert!(state.borrow().open.is_empty());
    }

    #[test]
    fn portable_drain_accepts_exact_empty_early_close() {
        let (parent, state) = fake_parent();
        eof_schedule(&state);
        let report = parent
            .drain(&mut CollectSinkV1::default())
            .expect("empty drain");
        assert!(report.stdout.captured.is_empty());
        assert!(report.stderr.captured.is_empty());
        assert!(report.capture_complete());
        assert!(state.borrow().open.is_empty());
    }

    #[test]
    fn bounded_poll_slice_observes_supervisor_cancellation_and_cleans() {
        let (mut parent, state) = fake_parent();
        let cancellation = parent
            .take_cancellation()
            .expect("one opaque cancellation signal");
        assert!(parent.take_cancellation().is_none());
        state.borrow_mut().cancel_on_poll = Some(Arc::clone(&cancellation.state));
        state
            .borrow_mut()
            .polls
            .push_back(Err(CallErrorV1::TimedOut));
        let error = parent
            .drain(&mut CollectSinkV1::default())
            .expect_err("cancellation after a bounded poll slice");
        assert_eq!(error.reason(), "stdio_drain_cancelled");
        assert_eq!(error.first_operation, StdioOperationV1::Control);
        assert_eq!(error.errno, None);
        assert!(error.cleanup_complete());
        assert!(state.borrow().open.is_empty());
    }

    #[test]
    fn fixed_deadline_failure_is_typed_and_cleans_without_polling() {
        let (mut parent, state) = fake_parent();
        let mut sink = CollectSinkV1::default();
        let error = parent
            .drain_until(
                &mut DrainPresentationV1::TestSink(&mut sink),
                Instant::now(),
            )
            .expect_err("expired deadline");
        assert_eq!(error.reason(), "stdio_drain_deadline_exceeded");
        assert_eq!(error.first_operation, StdioOperationV1::Control);
        assert_eq!(error.errno, Some(libc::ETIMEDOUT));
        assert!(error.cleanup_complete());
        assert!(!state.borrow().calls.contains(&StdioOperationV1::Poll));
        assert!(state.borrow().open.is_empty());
    }

    #[test]
    fn cancellation_handle_can_cancel_before_the_first_poll() {
        let (mut parent, state) = fake_parent();
        parent
            .take_cancellation()
            .expect("one opaque cancellation signal")
            .cancel();
        let error = parent
            .drain(&mut CollectSinkV1::default())
            .expect_err("pre-poll cancellation");
        assert_eq!(error.reason(), "stdio_drain_cancelled");
        assert!(error.cleanup_complete());
        assert!(!state.borrow().calls.contains(&StdioOperationV1::Poll));
        assert!(state.borrow().open.is_empty());
    }

    #[test]
    fn bounded_read_turn_prevents_one_hot_stream_from_starving_the_other() {
        let (parent, state) = fake_parent();
        {
            let mut state = state.borrow_mut();
            state.polls.push_back(Ok(ready(readable(), readable())));
            state.polls.push_back(Ok(ready(hung_up(), hung_up())));
            for _ in 0..=MAX_READS_PER_STREAM_TURN_V1 {
                state.stdout_reads.push_back(FakeReadV1::Data(vec![b'o']));
            }
            state.stdout_reads.push_back(FakeReadV1::Eof);
            state.stderr_reads.extend([
                FakeReadV1::Data(vec![b'e']),
                FakeReadV1::WouldBlock,
                FakeReadV1::Eof,
            ]);
        }
        let mut sink = CollectSinkV1::default();
        let report = parent.drain(&mut sink).expect("fair bounded drain");
        assert_eq!(sink.stdout, vec![b'o'; MAX_READS_PER_STREAM_TURN_V1 + 1]);
        assert_eq!(sink.stderr, b"e");
        assert_eq!(
            sink.call_order[MAX_READS_PER_STREAM_TURN_V1],
            ProfileStreamV1::Stderr
        );
        assert!(report.capture_complete());
        assert!(state.borrow().open.is_empty());
    }

    #[test]
    fn capture_limit_boundary_is_exact_and_plus_one_is_execute_only() {
        let exact = vec![b'a'; STREAM_CAPTURE_LIMIT_V1];
        let mut at_limit = StreamAccumulatorV1::new(ProfileStreamV1::Stdout);
        at_limit.observe(&exact).expect("at limit");
        at_limit.eof = true;
        let at_limit = at_limit.finish();
        assert_eq!(at_limit.captured.len(), STREAM_CAPTURE_LIMIT_V1);
        assert_eq!(at_limit.drained_bytes, STREAM_CAPTURE_LIMIT_V1 as u64);
        assert!(at_limit.capture_complete);

        let mut overflow = StreamAccumulatorV1::new(ProfileStreamV1::Stdout);
        overflow.observe(&exact).expect("at limit");
        overflow.observe(b"!").expect("continue hashing past limit");
        overflow.eof = true;
        let overflow = overflow.finish();
        assert_eq!(overflow.captured.len(), STREAM_CAPTURE_LIMIT_V1);
        assert_eq!(overflow.drained_bytes, STREAM_CAPTURE_LIMIT_V1 as u64 + 1);
        assert!(!overflow.capture_complete);
        assert_ne!(overflow.streaming_hash, at_limit.streaming_hash);

        let mut empty = StreamAccumulatorV1::new(ProfileStreamV1::Stderr);
        empty.eof = true;
        let report = ProfileStdioDrainReportV1 {
            stdout: overflow,
            stderr: empty.finish(),
            presentation_failure: None,
        };
        assert!(!report.capture_complete());
        assert!(report.requires_execute_only_classification());
    }

    #[test]
    fn drain_streams_and_hashes_every_byte_after_capture_limit() {
        let (parent, state) = fake_parent();
        {
            let mut state = state.borrow_mut();
            for _ in 0..17 {
                state.polls.push_back(Ok(ready(hung_up(), hung_up())));
            }
            for _ in 0..(STREAM_CAPTURE_LIMIT_V1 / DRAIN_BUFFER_BYTES_V1) {
                state
                    .stdout_reads
                    .push_back(FakeReadV1::Data(vec![b'a'; DRAIN_BUFFER_BYTES_V1]));
            }
            state
                .stdout_reads
                .extend([FakeReadV1::Data(vec![b'!']), FakeReadV1::Eof]);
            state.stderr_reads.push_back(FakeReadV1::Eof);
        }
        let mut sink = CollectSinkV1::default();
        let report = parent.drain(&mut sink).expect("overflow drain reaches EOF");
        assert_eq!(sink.stdout.len(), STREAM_CAPTURE_LIMIT_V1 + 1);
        assert_eq!(sink.stdout[STREAM_CAPTURE_LIMIT_V1], b'!');
        assert_eq!(report.stdout.captured.len(), STREAM_CAPTURE_LIMIT_V1);
        assert_eq!(
            report.stdout.drained_bytes,
            STREAM_CAPTURE_LIMIT_V1 as u64 + 1
        );
        assert_eq!(report.stdout.delivered_bytes, report.stdout.drained_bytes);
        let mut expected = blake3::Hasher::new_derive_key(STREAM_HASH_DOMAIN_V1);
        expected.update(b"stdout");
        for _ in 0..(STREAM_CAPTURE_LIMIT_V1 / DRAIN_BUFFER_BYTES_V1) {
            expected.update(&[b'a'; DRAIN_BUFFER_BYTES_V1]);
        }
        expected.update(b"!");
        assert_eq!(
            report.stdout.streaming_hash,
            *expected.finalize().as_bytes()
        );
        assert!(!report.capture_complete());
        assert!(report.requires_execute_only_classification());
        assert!(state.borrow().open.is_empty());
    }

    #[test]
    fn sink_failure_stops_delivery_but_continues_draining_both_streams() {
        let (parent, state) = fake_parent();
        {
            let mut state = state.borrow_mut();
            state.polls.push_back(Ok(ready(hung_up(), hung_up())));
            state
                .stdout_reads
                .extend([FakeReadV1::Data(b"stdout".to_vec()), FakeReadV1::Eof]);
            state
                .stderr_reads
                .extend([FakeReadV1::Data(b"stderr".to_vec()), FakeReadV1::Eof]);
        }
        let mut sink = CollectSinkV1 {
            fail_on: Some(ProfileStreamV1::Stdout),
            ..CollectSinkV1::default()
        };
        let report = parent
            .drain(&mut sink)
            .expect("presentation failure must not stop pipe draining");
        assert_eq!(sink.call_order, [ProfileStreamV1::Stdout]);
        assert!(sink.stdout.is_empty());
        assert!(sink.stderr.is_empty());
        assert_eq!(report.stdout.captured, b"stdout");
        assert_eq!(report.stderr.captured, b"stderr");
        assert_eq!(report.stdout.drained_bytes, 6);
        assert_eq!(report.stderr.drained_bytes, 6);
        assert_eq!(report.stdout.delivered_bytes, 0);
        assert_eq!(report.stderr.delivered_bytes, 0);
        assert!(report.capture_complete());
        assert_eq!(
            report.presentation_failure,
            Some(PresentationFailureV1::Stdout)
        );
        assert!(report.requires_execute_only_classification());
        assert!(state.borrow().open.is_empty());
    }

    #[test]
    fn sink_failure_is_typed_without_forging_delivery_counts() {
        let (parent, state) = fake_parent();
        {
            let mut state = state.borrow_mut();
            state.polls.push_back(Ok(ready(hung_up(), hung_up())));
            state
                .stdout_reads
                .extend([FakeReadV1::Data(b"hello".to_vec()), FakeReadV1::Eof]);
            state.stderr_reads.push_back(FakeReadV1::Eof);
        }
        let mut sink = CollectSinkV1 {
            fail_on: Some(ProfileStreamV1::Stdout),
            ..CollectSinkV1::default()
        };
        let report = parent
            .drain(&mut sink)
            .expect("sink failure is report data");
        assert_eq!(
            report.presentation_failure,
            Some(PresentationFailureV1::Stdout)
        );
        assert_eq!(report.stdout.drained_bytes, 5);
        assert_eq!(report.stdout.delivered_bytes, 0);
        assert_eq!(report.stdout.captured, b"hello");
        assert!(report.capture_complete());
        assert!(report.requires_execute_only_classification());
        assert!(state.borrow().open.is_empty());
    }

    #[test]
    fn partial_sink_delivery_is_counted_before_typed_failure() {
        let (parent, state) = fake_parent();
        {
            let mut state = state.borrow_mut();
            state.polls.push_back(Ok(ready(hung_up(), hung_up())));
            state
                .stdout_reads
                .extend([FakeReadV1::Data(b"hello".to_vec()), FakeReadV1::Eof]);
            state.stderr_reads.push_back(FakeReadV1::Eof);
        }
        let mut sink = PartialThenFailSinkV1 {
            delivered: Vec::new(),
            first_call: true,
        };
        let report = parent
            .drain(&mut sink)
            .expect("partial sink failure is report data");
        assert_eq!(sink.delivered, b"he");
        assert_eq!(report.stdout.delivered_bytes, 2);
        assert_eq!(report.stdout.drained_bytes, 5);
        assert_eq!(
            report.presentation_failure,
            Some(PresentationFailureV1::Stdout)
        );
        assert!(report.requires_execute_only_classification());
        assert!(state.borrow().open.is_empty());
    }

    #[test]
    fn construction_injection_covers_every_normal_pipe_fcntl_fstat_and_close_call() {
        let (syscalls, state) = FakeSyscallsV1::new();
        let session = ProfileOwnedStdioSessionV1::construct(syscalls).expect("baseline construct");
        let baseline = state.borrow().calls.clone();
        drop(session);
        assert!(
            baseline
                .iter()
                .any(|op| matches!(op, StdioOperationV1::Pipe(_)))
        );
        assert!(
            baseline
                .iter()
                .any(|op| matches!(op, StdioOperationV1::Fstat(_)))
        );
        assert!(
            baseline
                .iter()
                .any(|op| matches!(op, StdioOperationV1::FcntlGetFd(_)))
        );
        assert!(
            baseline
                .iter()
                .any(|op| matches!(op, StdioOperationV1::FcntlGetFl(_)))
        );
        assert!(
            baseline
                .iter()
                .any(|op| matches!(op, StdioOperationV1::FcntlSetFl(_)))
        );
        for (offset, expected) in baseline.iter().copied().enumerate() {
            let (syscalls, state) = FakeSyscallsV1::new();
            state.borrow_mut().fail_at = Some(offset + 1);
            let error = ProfileOwnedStdioSessionV1::construct(syscalls)
                .expect_err("each injected construction call must fail closed");
            assert_eq!(error.first_operation, expected, "call {}", offset + 1);
            assert!(
                state.borrow().open.is_empty(),
                "leaked at call {}",
                offset + 1
            );
        }
    }

    #[test]
    fn construction_relocates_every_protocol_descriptor_above_four() {
        let (syscalls, state) = FakeSyscallsV1::new();
        state.borrow_mut().next_fd = 3;
        let session = ProfileOwnedStdioSessionV1::construct(syscalls).expect("relocated construct");
        assert!(state.borrow().open.keys().all(|descriptor| *descriptor > 4));
        assert!(
            state
                .borrow()
                .calls
                .iter()
                .any(|operation| matches!(operation, StdioOperationV1::FcntlDupMin(_)))
        );
        drop(session);
        assert!(state.borrow().open.is_empty());
    }

    #[test]
    fn relocation_injection_preserves_first_error_and_closes_every_tracked_copy() {
        let (syscalls, state) = FakeSyscallsV1::new();
        state.borrow_mut().next_fd = 3;
        let session = ProfileOwnedStdioSessionV1::construct(syscalls).expect("baseline relocation");
        let baseline = state.borrow().calls.clone();
        drop(session);
        for (offset, expected) in baseline.iter().copied().enumerate() {
            let (syscalls, state) = FakeSyscallsV1::new();
            state.borrow_mut().next_fd = 3;
            state.borrow_mut().fail_at = Some(offset + 1);
            let failure = ProfileOwnedStdioSessionV1::construct(syscalls)
                .expect_err("injected relocation/construction call");
            assert_eq!(failure.first_operation, expected, "call {}", offset + 1);
            assert!(state.borrow().open.is_empty(), "call {} leaked", offset + 1);
        }
    }

    #[test]
    fn construction_rejects_cross_pipe_endpoint_identity_mismatch() {
        let (syscalls, state) = FakeSyscallsV1::new();
        state.borrow_mut().mismatched_fstat_role = Some(FdRoleV1::ChildStdout);
        let error = ProfileOwnedStdioSessionV1::construct(syscalls)
            .expect_err("a writer from another pipe must not authenticate");
        assert_eq!(error.reason, StdioFailureReasonV1::DescriptorContract);
        assert!(error.cleanup_complete());
        assert!(state.borrow().open.is_empty());
    }

    #[test]
    fn construction_preserves_pipe_failure_when_explicit_cleanup_also_fails() {
        let (baseline_syscalls, baseline_state) = FakeSyscallsV1::new();
        let baseline_session =
            ProfileOwnedStdioSessionV1::construct(baseline_syscalls).expect("baseline construct");
        let stdout_pipe_call = baseline_state
            .borrow()
            .calls
            .iter()
            .position(|operation| *operation == StdioOperationV1::Pipe(PipeRoleV1::Stdout))
            .expect("stdout pipe call")
            + 1;
        drop(baseline_session);

        let (syscalls, state) = FakeSyscallsV1::new();
        state.borrow_mut().fail_at = Some(stdout_pipe_call);
        state
            .borrow_mut()
            .additional_failures
            .push(stdout_pipe_call + 1);
        let error =
            ProfileOwnedStdioSessionV1::construct(syscalls).expect_err("pipe and cleanup failure");
        assert_eq!(
            error.first_operation,
            StdioOperationV1::Pipe(PipeRoleV1::Stdout)
        );
        assert!(!error.cleanup_complete());
        assert!(state.borrow().open.is_empty());
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu",
        target_pointer_width = "64"
    ))]
    #[test]
    fn split_authentication_failure_explicitly_closes_every_endpoint_and_preserves_first_error() {
        for cleanup_failures in [vec![2_usize], vec![2_usize, 4_usize]] {
            let (syscalls, state) = FakeSyscallsV1::new();
            let session = ProfileOwnedStdioSessionV1::construct(syscalls).expect("construct");
            let start = state.borrow().calls.len();
            {
                let mut state = state.borrow_mut();
                state.fail_at = Some(start + 1);
                state.additional_failures = cleanup_failures
                    .iter()
                    .map(|offset| start + offset)
                    .collect();
            }
            let error = session
                .split_for_isolation_inner_v1()
                .expect_err("split authentication is injected to fail");
            assert_eq!(
                error.first_operation,
                StdioOperationV1::Fstat(FdRoleV1::ChildStdin)
            );
            assert_eq!(error.errno, Some(libc::EIO));
            assert!(!error.cleanup_complete());
            let state = state.borrow();
            assert!(state.open.is_empty());
            assert_eq!(
                state.calls[start..]
                    .iter()
                    .filter(|operation| matches!(operation, StdioOperationV1::Close(_)))
                    .count(),
                6
            );
        }
    }

    #[test]
    fn parent_transition_injection_closes_every_known_descriptor() {
        for transition_call in 1..=4 {
            let (syscalls, state) = FakeSyscallsV1::new();
            let session = ProfileOwnedStdioSessionV1::construct(syscalls).expect("construct");
            let start = state.borrow().calls.len();
            state.borrow_mut().fail_at = Some(start + transition_call);
            let error = session.into_parent_drain().expect_err("injected close");
            assert!(matches!(error.first_operation, StdioOperationV1::Close(_)));
            assert!(!error.cleanup_complete());
            assert!(state.borrow().open.is_empty());
        }
    }

    fn child_preparation_baseline() -> Vec<StdioOperationV1> {
        let (syscalls, state) = FakeSyscallsV1::new();
        let session = ProfileOwnedStdioSessionV1::construct(syscalls).expect("construct");
        let start = state.borrow().calls.len();
        let handoff = session.prepare_blocked_child_for_test().expect("prepare");
        let baseline = state.borrow().calls[start..].to_vec();
        assert_eq!(
            state.borrow().open.keys().copied().collect::<Vec<_>>(),
            [0, 1, 2]
        );
        drop(handoff);
        assert!(state.borrow().open.is_empty());
        baseline
    }

    #[test]
    fn child_preparation_injection_covers_dup_authentication_close_range_and_cleanup() {
        let baseline = child_preparation_baseline();
        assert!(
            baseline
                .iter()
                .any(|op| matches!(op, StdioOperationV1::Dup3(_)))
        );
        assert!(baseline.contains(&StdioOperationV1::CloseRange));
        assert!(baseline.iter().any(|op| matches!(
            op,
            StdioOperationV1::Fstat(
                FdRoleV1::PlacedStdin | FdRoleV1::PlacedStdout | FdRoleV1::PlacedStderr
            )
        )));

        for (offset, expected) in baseline.iter().copied().enumerate() {
            let (syscalls, state) = FakeSyscallsV1::new();
            let session = ProfileOwnedStdioSessionV1::construct(syscalls).expect("construct");
            let start = state.borrow().calls.len();
            state.borrow_mut().fail_at = Some(start + offset + 1);
            let error = session
                .prepare_blocked_child_for_test()
                .expect_err("injected child preparation call");
            assert_eq!(error.first_operation, expected, "call {}", offset + 1);
            assert!(
                state.borrow().open.is_empty(),
                "leaked at call {}",
                offset + 1
            );
        }
    }

    #[test]
    fn child_preparation_preserves_dup_failure_when_placed_cleanup_also_fails() {
        let baseline = child_preparation_baseline();
        let second_dup_offset = baseline
            .iter()
            .enumerate()
            .filter(|(_, operation)| matches!(operation, StdioOperationV1::Dup3(_)))
            .nth(1)
            .map(|(offset, _)| offset)
            .expect("second dup3");
        let (syscalls, state) = FakeSyscallsV1::new();
        let session = ProfileOwnedStdioSessionV1::construct(syscalls).expect("construct");
        let start = state.borrow().calls.len();
        state.borrow_mut().fail_at = Some(start + second_dup_offset + 1);
        state
            .borrow_mut()
            .additional_failures
            .push(start + second_dup_offset + 2);
        let error = session
            .prepare_blocked_child_for_test()
            .expect_err("dup3 and cleanup failure");
        assert_eq!(
            error.first_operation,
            StdioOperationV1::Dup3(FdRoleV1::PlacedStdout)
        );
        assert!(!error.cleanup_complete());
        assert!(state.borrow().open.is_empty());
    }

    #[test]
    fn close_range_unavailable_is_typed_and_cleans_every_known_descriptor() {
        let baseline = child_preparation_baseline();
        let close_range_offset = baseline
            .iter()
            .position(|operation| *operation == StdioOperationV1::CloseRange)
            .expect("close_range call");
        let (syscalls, state) = FakeSyscallsV1::new();
        let session = ProfileOwnedStdioSessionV1::construct(syscalls).expect("construct");
        let start = state.borrow().calls.len();
        state.borrow_mut().fail_at = Some(start + close_range_offset + 1);
        let error = session
            .prepare_blocked_child_for_test()
            .expect_err("close_range unavailable");
        assert_eq!(error.first_operation, StdioOperationV1::CloseRange);
        assert_eq!(error.errno, Some(libc::EIO));
        assert!(error.cleanup_complete());
        assert!(state.borrow().open.is_empty());
    }

    fn drain_baseline() -> Vec<StdioOperationV1> {
        let (parent, state) = fake_parent();
        eof_schedule(&state);
        let start = state.borrow().calls.len();
        parent
            .drain(&mut CollectSinkV1::default())
            .expect("baseline drain");
        let calls = state.borrow().calls[start..].to_vec();
        assert!(state.borrow().open.is_empty());
        calls
    }

    #[test]
    fn production_capture_api_returns_exact_eof_evidence_without_a_callback() {
        let (parent, state) = fake_parent();
        {
            let mut state = state.borrow_mut();
            state.polls.push_back(Ok(ready(readable(), readable())));
            state
                .stdout_reads
                .push_back(FakeReadV1::Data(b"out".to_vec()));
            state.stdout_reads.push_back(FakeReadV1::Eof);
            state
                .stderr_reads
                .push_back(FakeReadV1::Data(b"err".to_vec()));
            state.stderr_reads.push_back(FakeReadV1::Eof);
        }
        let report = parent.drain_capture_v1().expect("exact capture");
        assert_eq!(report.stdout().captured(), b"out");
        assert_eq!(report.stderr().captured(), b"err");
        assert_eq!(report.stdout().drained_bytes(), 3);
        assert_eq!(report.stderr().drained_bytes(), 3);
        assert_eq!(report.stdout().delivered_bytes(), 0);
        assert_eq!(report.stderr().delivered_bytes(), 0);
        assert!(report.stdout().eof_observed());
        assert!(report.stderr().eof_observed());
        assert!(report.capture_complete());
        assert!(state.borrow().open.is_empty());
    }

    #[test]
    fn drain_injection_covers_poll_read_and_close_boundaries_without_leaks() {
        let baseline = drain_baseline();
        assert!(baseline.contains(&StdioOperationV1::Poll));
        assert!(
            baseline
                .iter()
                .any(|op| matches!(op, StdioOperationV1::Read(_)))
        );
        assert!(
            baseline
                .iter()
                .any(|op| matches!(op, StdioOperationV1::Close(_)))
        );
        for (offset, expected) in baseline.iter().copied().enumerate() {
            let (parent, state) = fake_parent();
            eof_schedule(&state);
            let start = state.borrow().calls.len();
            state.borrow_mut().fail_at = Some(start + offset + 1);
            let error = parent
                .drain(&mut CollectSinkV1::default())
                .expect_err("injected drain call");
            assert_eq!(error.first_operation, expected, "call {}", offset + 1);
            assert!(
                state.borrow().open.is_empty(),
                "leaked at call {}",
                offset + 1
            );
        }
    }

    #[test]
    fn explicit_read_errno_preserves_first_error_and_cleans_both_streams() {
        let (parent, state) = fake_parent();
        {
            let mut state = state.borrow_mut();
            state
                .polls
                .push_back(Ok(ready(readable(), PollStreamResultV1::default())));
            state.stdout_reads.push_back(FakeReadV1::Errno(libc::EPIPE));
        }
        let error = parent
            .drain(&mut CollectSinkV1::default())
            .expect_err("read errno");
        assert_eq!(
            error.first_operation,
            StdioOperationV1::Read(ProfileStreamV1::Stdout)
        );
        assert_eq!(error.errno, Some(libc::EPIPE));
        assert!(error.cleanup_complete());
        assert!(state.borrow().open.is_empty());
    }

    #[test]
    fn first_read_error_survives_cleanup_failure_and_uncertainty_is_retained() {
        let (parent, state) = fake_parent();
        {
            let mut state = state.borrow_mut();
            state
                .polls
                .push_back(Ok(ready(readable(), PollStreamResultV1::default())));
            state.stdout_reads.push_back(FakeReadV1::Errno(libc::EPIPE));
            let start = state.calls.len();
            state.fail_at = Some(start + 3);
        }
        let error = parent
            .drain(&mut CollectSinkV1::default())
            .expect_err("read and cleanup failure");
        assert_eq!(
            error.first_operation,
            StdioOperationV1::Read(ProfileStreamV1::Stdout)
        );
        assert_eq!(error.errno, Some(libc::EPIPE));
        assert!(!error.cleanup_complete());
        assert!(state.borrow().open.is_empty());
    }

    #[test]
    fn earlier_close_failure_is_not_replaced_by_a_later_read_failure() {
        let (parent, state) = fake_parent();
        {
            let mut state = state.borrow_mut();
            state.polls.push_back(Ok(ready(hung_up(), readable())));
            state.stdout_reads.push_back(FakeReadV1::Eof);
            state.stderr_reads.push_back(FakeReadV1::Errno(libc::EPIPE));
            let start = state.calls.len();
            state.fail_at = Some(start + 3);
        }
        let error = parent
            .drain(&mut CollectSinkV1::default())
            .expect_err("close precedes read failure");
        assert_eq!(
            error.first_operation,
            StdioOperationV1::Close(FdRoleV1::ParentStdout)
        );
        assert_eq!(error.errno, Some(libc::EIO));
        assert!(!error.cleanup_complete());
        assert!(state.borrow().open.is_empty());
    }

    #[test]
    fn drop_is_leak_free_and_debug_redacts_descriptors_bytes_and_hashes() {
        let (syscalls, state) = FakeSyscallsV1::new();
        let session = ProfileOwnedStdioSessionV1::construct(syscalls).expect("construct");
        let debug = format!("{session:?}");
        assert!(debug.contains("profile-owned-fds"));
        assert!(!debug.contains("10"));
        drop(session);
        assert!(state.borrow().open.is_empty());

        let mut stream = StreamAccumulatorV1::new(ProfileStreamV1::Stdout);
        stream.observe(b"do-not-print-this").expect("observe");
        stream.eof = true;
        let debug = format!("{:?}", stream.finish());
        assert!(debug.contains("redacted-bytes"));
        assert!(debug.contains("redacted-digest"));
        assert!(!debug.contains("do-not-print-this"));

        let (syscalls, state) = FakeSyscallsV1::new();
        let session = ProfileOwnedStdioSessionV1::construct(syscalls).expect("construct");
        let next_call = state.borrow().calls.len() + 1;
        state.borrow_mut().fail_at = Some(next_call);
        drop(session);
        assert!(state.borrow().open.is_empty());
    }

    trait AmbiguousIfCloneV1<Marker> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfCloneV1<()> for T {}
    impl<T: Clone> AmbiguousIfCloneV1<u8> for T {}
    fn assert_not_clone<T: ?Sized>() {
        let _ = <T as AmbiguousIfCloneV1<_>>::check;
    }

    trait AmbiguousIfCopyV1<Marker> {
        fn check() {}
    }
    impl<T: ?Sized> AmbiguousIfCopyV1<()> for T {}
    impl<T: Copy> AmbiguousIfCopyV1<u8> for T {}
    fn assert_not_copy<T: ?Sized>() {
        let _ = <T as AmbiguousIfCopyV1<_>>::check;
    }

    #[test]
    fn linear_raii_handles_are_compile_time_non_clone_non_copy() {
        assert_not_clone::<TrackedFdV1>();
        assert_not_copy::<TrackedFdV1>();
        assert_not_clone::<ProfileOwnedStdioSessionV1<FakeSyscallsV1>>();
        assert_not_copy::<ProfileOwnedStdioSessionV1<FakeSyscallsV1>>();
        assert_not_clone::<BlockedChildStdioHandoffV1<FakeSyscallsV1>>();
        assert_not_copy::<BlockedChildStdioHandoffV1<FakeSyscallsV1>>();
        assert_not_clone::<ParentStdioDrainV1<FakeSyscallsV1>>();
        assert_not_copy::<ParentStdioDrainV1<FakeSyscallsV1>>();
        assert_not_clone::<ProfileStdioDrainCancellationV1>();
        assert_not_copy::<ProfileStdioDrainCancellationV1>();
        #[cfg(all(
            target_os = "linux",
            target_arch = "x86_64",
            target_env = "gnu",
            target_pointer_width = "64"
        ))]
        {
            assert_not_clone::<ProfileStdioIsolationChildV1>();
            assert_not_copy::<ProfileStdioIsolationChildV1>();
            assert_not_clone::<ForkSafeChildFdV1>();
            assert_not_copy::<ForkSafeChildFdV1>();
        }
    }

    #[cfg(not(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu",
        target_pointer_width = "64"
    )))]
    #[test]
    fn unsupported_target_refusal_is_stable_and_cleanup_certain() {
        let error = open_profile_owned_stdio_v1().expect_err("non-Linux target is refused");
        assert_eq!(error.reason(), "unsupported_platform");
        assert!(error.cleanup_complete());
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu",
        target_pointer_width = "64"
    ))]
    fn live_child_descriptor_contract(high_descriptor: RawFd) -> bool {
        let mut facts = [DescriptorFactsV1 {
            device: 0,
            inode: 0,
            mode: 0,
        }; 3];
        for (index, fd) in [0, 1, 2].into_iter().enumerate() {
            let mut value = std::mem::MaybeUninit::<libc::stat>::zeroed();
            if unsafe { libc::fstat(fd, value.as_mut_ptr()) } != 0 {
                return false;
            }
            let value = unsafe { value.assume_init() };
            facts[index] = DescriptorFactsV1 {
                device: value.st_dev,
                inode: value.st_ino,
                mode: value.st_mode,
            };
            let fd_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            let status_flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
            let expected_access = if fd == libc::STDIN_FILENO {
                libc::O_RDONLY
            } else {
                libc::O_WRONLY
            };
            if facts[index].mode & libc::S_IFMT != libc::S_IFIFO
                || fd_flags != 0
                || status_flags < 0
                || status_flags & libc::O_ACCMODE != expected_access
                || status_flags & libc::O_NONBLOCK != 0
            {
                return false;
            }
        }
        if facts[0] == facts[1] || facts[0] == facts[2] || facts[1] == facts[2] {
            return false;
        }
        for fd in [3, 4, high_descriptor] {
            if unsafe { libc::fcntl(fd, libc::F_GETFD) } < 0 {
                return false;
            }
        }
        let mut byte = 0_u8;
        if unsafe { libc::read(libc::STDIN_FILENO, (&mut byte as *mut u8).cast(), 1) } != 0 {
            return false;
        }
        live_child_write_all(libc::STDOUT_FILENO, b"live-stdout\n")
            && live_child_write_all(libc::STDERR_FILENO, b"live-stderr\n")
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu",
        target_pointer_width = "64"
    ))]
    fn live_child_write_all(fd: RawFd, mut bytes: &[u8]) -> bool {
        while !bytes.is_empty() {
            let result = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
            if result > 0 {
                bytes = &bytes[result as usize..];
            } else if result < 0 && last_errno() == libc::EINTR {
                continue;
            } else {
                return false;
            }
        }
        true
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu",
        target_pointer_width = "64"
    ))]
    fn expected_live_stream_hash(stream: ProfileStreamV1, bytes: &[u8]) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(STREAM_HASH_DOMAIN_V1);
        hasher.update(match stream {
            ProfileStreamV1::Stdout => b"stdout",
            ProfileStreamV1::Stderr => b"stderr",
        });
        hasher.update(bytes);
        *hasher.finalize().as_bytes()
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu",
        target_pointer_width = "64"
    ))]
    fn assert_child_fault_is_reaped(
        primary: ChildStdioRawOperationV1,
        cleanup: Option<ChildStdioRawOperationV1>,
    ) {
        let session = open_profile_owned_stdio_v1().expect("live pipe construction");
        let (parent, mut child_half) = session
            .split_for_isolation_v1()
            .expect("pre-clone linear split");
        child_half.fault = ChildStdioFaultPlanV1 {
            primary: Some(primary),
            cleanup,
        };
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork disposable fault child");
        if child == 0 {
            let status = match child_half.continue_raw_v1() {
                Err(libc::EIO) => 0,
                Err(libc::EBUSY) => 121,
                Err(_) => 122,
                Ok(_) => 123,
            };
            unsafe { libc::_exit(status) }
        }
        drop(child_half);
        let report = parent
            .drain_capture_v1()
            .expect("fault child closes every pipe copy on exit");
        assert!(report.capture_complete());
        assert_eq!(report.stdout.drained_bytes(), 0);
        assert_eq!(report.stderr.drained_bytes(), 0);
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
        assert_eq!(
            unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) },
            -1
        );
        assert_eq!(last_errno(), libc::ECHILD);
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu",
        target_pointer_width = "64"
    ))]
    #[test]
    fn linux_child_operation_injection_reaps_every_partial_placement_and_preserves_first_error() {
        for (source, placed) in [
            (FdRoleV1::ChildStdin, FdRoleV1::PlacedStdin),
            (FdRoleV1::ChildStdout, FdRoleV1::PlacedStdout),
            (FdRoleV1::ChildStderr, FdRoleV1::PlacedStderr),
        ] {
            for operation in [
                ChildStdioRawOperationV1::SourceFstat(source),
                ChildStdioRawOperationV1::SourceGetFd(source),
                ChildStdioRawOperationV1::SourceGetFl(source),
                ChildStdioRawOperationV1::Dup3(placed),
                ChildStdioRawOperationV1::PlacedFstat(placed),
                ChildStdioRawOperationV1::PlacedGetFd(placed),
                ChildStdioRawOperationV1::PlacedGetFl(placed),
                ChildStdioRawOperationV1::CloseSource(source),
            ] {
                assert_child_fault_is_reaped(operation, None);
            }
        }
        assert_child_fault_is_reaped(
            ChildStdioRawOperationV1::PlacedFstat(FdRoleV1::PlacedStdin),
            Some(ChildStdioRawOperationV1::ClosePlaced(FdRoleV1::PlacedStdin)),
        );
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu",
        target_pointer_width = "64"
    ))]
    #[test]
    fn linux_live_preclone_split_places_stdio_preserves_protocol_fds_and_parent_reaps() {
        let session = open_profile_owned_stdio_v1().expect("live pipe construction");
        let (parent, child_half) = session
            .split_for_isolation_v1()
            .expect("pre-clone linear split");
        let protocol_report = File::open("/dev/null").expect("reserve report descriptor");
        let protocol_control = File::open("/dev/null").expect("reserve control descriptor");
        let high_raw =
            unsafe { libc::fcntl(protocol_report.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 127) };
        assert!(high_raw >= 127, "seed one sparse inherited descriptor");
        let high = unsafe { OwnedFd::from_raw_fd(high_raw) };
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork disposable stdio child");
        if child == 0 {
            if parent.discard_fork_copy_in_child_v1().is_err() {
                unsafe { libc::_exit(118) }
            }
            for (source, target) in [
                (protocol_report.as_raw_fd(), 3),
                (protocol_control.as_raw_fd(), 4),
            ] {
                if source != target
                    && unsafe { libc::syscall(libc::SYS_dup3, source, target, libc::O_CLOEXEC) }
                        != i64::from(target)
                {
                    unsafe { libc::_exit(119) }
                }
            }
            if child_half.continue_raw_v1().is_err() {
                unsafe { libc::_exit(120) }
            }
            let valid = live_child_descriptor_contract(high_raw);
            unsafe { libc::_exit(if valid { 0 } else { 121 }) };
        }

        drop(child_half);
        drop(high);
        drop(protocol_control);
        drop(protocol_report);
        let drain = parent.drain_capture_v1();
        let mut status = 0_i32;
        let waited = loop {
            let result = unsafe { libc::waitpid(child, &mut status, 0) };
            if result < 0 && last_errno() == libc::EINTR {
                continue;
            }
            break result;
        };
        assert_eq!(waited, child, "parent reaps the exact disposable child");
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
        assert_eq!(
            unsafe { libc::waitpid(child, &mut status, libc::WNOHANG) },
            -1
        );
        assert_eq!(last_errno(), libc::ECHILD);
        let report = drain.expect("parent drains both live child streams to EOF");
        assert_eq!(report.stdout.captured(), b"live-stdout\n");
        assert_eq!(report.stderr.captured(), b"live-stderr\n");
        assert_eq!(report.stdout.drained_bytes(), 12);
        assert_eq!(report.stderr.drained_bytes(), 12);
        assert_eq!(
            report.stdout.streaming_hash(),
            &expected_live_stream_hash(ProfileStreamV1::Stdout, b"live-stdout\n")
        );
        assert_eq!(
            report.stderr.streaming_hash(),
            &expected_live_stream_hash(ProfileStreamV1::Stderr, b"live-stderr\n")
        );
        assert!(report.capture_complete());
        assert!(!report.requires_execute_only_classification());
    }

    #[cfg(all(
        target_os = "linux",
        target_arch = "x86_64",
        target_env = "gnu",
        target_pointer_width = "64"
    ))]
    #[test]
    fn linux_live_profile_endpoints_authenticate_and_empty_drain_reaches_exact_eof() {
        let session = open_profile_owned_stdio_v1().expect("live pipe construction");
        let parent = session
            .into_parent_drain()
            .expect("parent ownership transition");
        let report = parent
            .drain(&mut CollectSinkV1::default())
            .expect("empty exact EOF");
        assert!(report.capture_complete());
        assert_eq!(report.stdout.drained_bytes, 0);
        assert_eq!(report.stderr.drained_bytes, 0);
    }
}
