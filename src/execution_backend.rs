//! Authority-minimal execution backend descriptors.
//!
//! This module intentionally does not contain a process launcher. In particular,
//! [`RootlessLinux`] cannot accept a command, while the gVisor and Firecracker
//! types remain configuration descriptors for future integrations only.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Stable execution backend identifiers used at the integration boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackendKind {
    AuditedLocalRead,
    RootlessLinux,
    GVisor,
    Firecracker,
    RemoteMcp,
}

/// Non-authoritative capability metadata emitted only by the constructors in
/// this module. It is presentation data, not an execution capability token.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackendAuthority {
    exact_local_read: bool,
    local_command_execution: bool,
    remote_tool_forwarding: bool,
}

impl BackendAuthority {
    const LOCAL_READ: Self = Self {
        exact_local_read: true,
        local_command_execution: false,
        remote_tool_forwarding: false,
    };
    const NONE: Self = Self {
        exact_local_read: false,
        local_command_execution: false,
        remote_tool_forwarding: false,
    };
    const REMOTE_MCP: Self = Self {
        exact_local_read: false,
        local_command_execution: false,
        remote_tool_forwarding: true,
    };

    #[must_use]
    pub const fn permits_exact_local_read(self) -> bool {
        self.exact_local_read
    }

    #[must_use]
    pub const fn permits_local_command_execution(self) -> bool {
        self.local_command_execution
    }

    #[must_use]
    pub const fn permits_remote_tool_forwarding(self) -> bool {
        self.remote_tool_forwarding
    }
}

/// Availability and authority metadata that Terminal A can inspect without
/// accidentally invoking a backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BackendDescriptor {
    kind: BackendKind,
    available: bool,
    authority: BackendAuthority,
    qualification: Qualification,
}

impl BackendDescriptor {
    #[must_use]
    pub const fn kind(self) -> BackendKind {
        self.kind
    }

    #[must_use]
    pub const fn is_available(self) -> bool {
        self.available
    }

    #[must_use]
    pub const fn authority(self) -> BackendAuthority {
        self.authority
    }

    #[must_use]
    pub const fn qualification(self) -> Qualification {
        self.qualification
    }

    /// Backend descriptors can inform routing but can never authorize a call.
    #[must_use]
    pub const fn is_authoritative(self) -> bool {
        false
    }
}

/// Qualification is deliberately explicit: configured is not qualified.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Qualification {
    Composable,
    CommandFree,
    DescriptorOnly,
    UpstreamPassThrough,
}

/// Non-authoritative syntactic classification used only to explain why a
/// developer command was denied storage and reuse. A shape never grants
/// execution authority, even when it describes an exact check-only argv.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeveloperCommandShapeV1 {
    ExactCheckOnlySyntax,
    CheckLikeButIncomplete,
    MutationCapable,
    InteractiveOrWatch,
    NetworkCapable,
    UnknownOrIncompletelyModeled,
}

/// The historical developer-command prototype omitted every one of these
/// authority bindings. Until a command-specific observer proves the complete
/// set, passthrough is the only sound disposition.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RequiredReuseBindingV1 {
    ResolvedExecutableIdentity,
    ToolchainIdentity,
    ExactArgv,
    CanonicalWorkingDirectory,
    NormalizedEnvironment,
    RepositoryState,
    Lockfiles,
    Configuration,
    Plugins,
    GeneratedInputs,
    CompleteDependencyClosure,
}

const ALL_REQUIRED_REUSE_BINDINGS_V1: &[RequiredReuseBindingV1] = &[
    RequiredReuseBindingV1::ResolvedExecutableIdentity,
    RequiredReuseBindingV1::ToolchainIdentity,
    RequiredReuseBindingV1::ExactArgv,
    RequiredReuseBindingV1::CanonicalWorkingDirectory,
    RequiredReuseBindingV1::NormalizedEnvironment,
    RequiredReuseBindingV1::RepositoryState,
    RequiredReuseBindingV1::Lockfiles,
    RequiredReuseBindingV1::Configuration,
    RequiredReuseBindingV1::Plugins,
    RequiredReuseBindingV1::GeneratedInputs,
    RequiredReuseBindingV1::CompleteDependencyClosure,
];

/// Conservative result for command families whose dependency authority is not
/// implemented. There is deliberately no reusable or storable variant.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeveloperCommandDispositionV1 {
    PassthroughWithoutStorage,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeveloperCommandAssessmentV1 {
    shape: DeveloperCommandShapeV1,
    disposition: DeveloperCommandDispositionV1,
    reason: &'static str,
}

impl DeveloperCommandAssessmentV1 {
    #[must_use]
    pub const fn shape(&self) -> DeveloperCommandShapeV1 {
        self.shape
    }

    #[must_use]
    pub const fn disposition(&self) -> DeveloperCommandDispositionV1 {
        self.disposition
    }

    #[must_use]
    pub const fn reason(&self) -> &'static str {
        self.reason
    }

    /// A classifier result is never an execution capability.
    #[must_use]
    pub const fn grants_execution_authority(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn permits_storage(&self) -> bool {
        false
    }

    #[must_use]
    pub const fn permits_reuse(&self) -> bool {
        false
    }

    /// The caller must use its ordinary execution path, with no cache lookup
    /// or publication derived from this assessment.
    #[must_use]
    pub const fn requires_normal_passthrough(&self) -> bool {
        true
    }

    #[must_use]
    pub const fn unproven_reuse_bindings(&self) -> &'static [RequiredReuseBindingV1] {
        ALL_REQUIRED_REUSE_BINDINGS_V1
    }
}

/// Explain an argv shape without resolving PATH, opening an executable,
/// selecting a toolchain, reading repository state, or granting authority.
/// Unknown flags and commands intentionally fall through to normal execution
/// without storage. The only cargo-fmt check spelling recognized here is the
/// exact reviewed `cargo fmt --all --check` syntax; even it remains passthrough
/// because syntax is not dependency authority.
#[must_use]
pub fn assess_developer_command_v1(argv: &[String]) -> DeveloperCommandAssessmentV1 {
    if argv.is_empty() {
        return developer_passthrough_v1(
            DeveloperCommandShapeV1::UnknownOrIncompletelyModeled,
            "empty argv has no command identity",
        );
    }

    if argv.iter().any(|argument| {
        matches!(
            argument.as_str(),
            "--watch" | "--watch-all" | "--watchAll" | "--interactive" | "--ui" | "--open" | "-i"
        )
    }) {
        return developer_passthrough_v1(
            DeveloperCommandShapeV1::InteractiveOrWatch,
            "interactive and watch modes are never qualified",
        );
    }

    if network_capable_shape_v1(argv) {
        return developer_passthrough_v1(
            DeveloperCommandShapeV1::NetworkCapable,
            "install, publish, fetch, update, and online modes are never qualified",
        );
    }

    if argv.iter().any(|argument| {
        matches!(
            argument.as_str(),
            "--fix"
                | "--fix-dry-run"
                | "--write"
                | "-w"
                | "--updateSnapshot"
                | "--update-snapshot"
                | "--update-snapshots"
                | "--acceptChanges"
                | "--accept-changes"
                | "--bless"
                | "-u"
        )
    }) {
        return developer_passthrough_v1(
            DeveloperCommandShapeV1::MutationCapable,
            "fix, write, snapshot-update, and acceptance modes are never qualified",
        );
    }

    if argv == ["cargo", "fmt", "--all", "--check"] {
        return developer_passthrough_v1(
            DeveloperCommandShapeV1::ExactCheckOnlySyntax,
            "exact check-only syntax still lacks executable and dependency authority",
        );
    }

    if argv.first().map(String::as_str) == Some("cargo")
        && argv.get(1).map(String::as_str) == Some("fmt")
    {
        let shape = if argv.iter().any(|argument| argument == "--check") {
            DeveloperCommandShapeV1::UnknownOrIncompletelyModeled
        } else {
            DeveloperCommandShapeV1::MutationCapable
        };
        return developer_passthrough_v1(
            shape,
            "cargo fmt is mutating outside the one exact reviewed check-only syntax",
        );
    }

    if check_like_exact_shape_v1(argv) {
        return developer_passthrough_v1(
            DeveloperCommandShapeV1::CheckLikeButIncomplete,
            "check-like command has no proven complete dependency closure",
        );
    }

    developer_passthrough_v1(
        DeveloperCommandShapeV1::UnknownOrIncompletelyModeled,
        "unknown command or flags execute normally without storage or reuse",
    )
}

fn developer_passthrough_v1(
    shape: DeveloperCommandShapeV1,
    reason: &'static str,
) -> DeveloperCommandAssessmentV1 {
    DeveloperCommandAssessmentV1 {
        shape,
        disposition: DeveloperCommandDispositionV1::PassthroughWithoutStorage,
        reason,
    }
}

fn network_capable_shape_v1(argv: &[String]) -> bool {
    matches!(
        (
            argv.first().map(String::as_str),
            argv.get(1).map(String::as_str)
        ),
        (
            Some("cargo"),
            Some("install" | "publish" | "fetch" | "update")
        ) | (
            Some("npm" | "pnpm" | "yarn"),
            Some("install" | "add" | "publish")
        ) | (Some("pip" | "pip3"), Some("install"))
            | (Some("go"), Some("get" | "install"))
    ) || argv.iter().any(|argument| {
        matches!(
            argument.as_str(),
            "--online" | "--registry" | "--publish" | "--install"
        )
    })
}

fn check_like_exact_shape_v1(argv: &[String]) -> bool {
    matches!(
        argv,
        [program, operation]
            if (program == "cargo" && matches!(operation.as_str(), "check" | "test" | "clippy"))
                || (program == "ruff" && operation == "check")
                || (program == "go" && operation == "vet")
    ) || matches!(argv, [program] if matches!(program.as_str(), "pytest" | "mypy" | "jest" | "vitest"))
        || matches!(argv, [program, flag] if program == "tsc" && flag == "--noEmit")
}

/// Typed refusal returned by unavailable or authority-free backends.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum BackendError {
    #[error("backend {backend:?} is unsupported: {reason}")]
    Unsupported {
        backend: BackendKind,
        reason: UnsupportedReason,
    },
    #[error("audited local read adapter failed: {message}")]
    AuditedRead { message: String },
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnsupportedReason {
    #[error("the current rootless Linux child is command-free")]
    RootlessLinuxIsCommandFree,
    #[error("this backend is a configuration descriptor only")]
    DescriptorOnly,
}

/// A request suitable for later composition with the existing exact-read
/// engine.  It has no command, argv, environment, or executable field.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditedReadRequest {
    pub logical_call_id: String,
    pub canonical_path: String,
    pub expected_fingerprint: String,
}

/// Result produced by a Terminal A adapter around the canonical exact-read
/// engine.  The bytes remain opaque to this abstraction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditedReadResult {
    pub bytes: Vec<u8>,
    pub observed_fingerprint: String,
}

/// Narrow adapter seam for the existing exact-read engine.
pub trait ExactReadAdapter: Send + Sync {
    fn read_exact(&self, request: &AuditedReadRequest) -> Result<AuditedReadResult, BackendError>;
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct AuditedLocalRead;

impl AuditedLocalRead {
    #[must_use]
    pub const fn descriptor(self) -> BackendDescriptor {
        BackendDescriptor {
            kind: BackendKind::AuditedLocalRead,
            available: true,
            authority: BackendAuthority::LOCAL_READ,
            qualification: Qualification::Composable,
        }
    }

    pub fn execute<A: ExactReadAdapter>(
        self,
        adapter: &A,
        request: &AuditedReadRequest,
    ) -> Result<AuditedReadResult, BackendError> {
        adapter.read_exact(request)
    }
}

/// The current rootless Linux child is intentionally incapable of accepting a
/// command. There is no execute method taking a command-like value.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RootlessLinux;

impl RootlessLinux {
    #[must_use]
    pub const fn descriptor(self) -> BackendDescriptor {
        BackendDescriptor {
            kind: BackendKind::RootlessLinux,
            available: false,
            authority: BackendAuthority::NONE,
            qualification: Qualification::CommandFree,
        }
    }

    pub const fn require_available(self) -> Result<(), BackendError> {
        Err(BackendError::Unsupported {
            backend: BackendKind::RootlessLinux,
            reason: UnsupportedReason::RootlessLinuxIsCommandFree,
        })
    }
}

/// Configuration descriptor only.  It does not shell out or qualify a runtime.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GVisor {
    pub runtime_name: String,
}

impl GVisor {
    #[must_use]
    pub const fn descriptor(&self) -> BackendDescriptor {
        BackendDescriptor {
            kind: BackendKind::GVisor,
            available: false,
            authority: BackendAuthority::NONE,
            qualification: Qualification::DescriptorOnly,
        }
    }

    pub const fn require_available(&self) -> Result<(), BackendError> {
        Err(BackendError::Unsupported {
            backend: BackendKind::GVisor,
            reason: UnsupportedReason::DescriptorOnly,
        })
    }
}

/// Configuration descriptor only.  It does not download, install, start, or
/// qualify a VMM.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Firecracker {
    pub profile_name: String,
}

impl Firecracker {
    #[must_use]
    pub const fn descriptor(&self) -> BackendDescriptor {
        BackendDescriptor {
            kind: BackendKind::Firecracker,
            available: false,
            authority: BackendAuthority::NONE,
            qualification: Qualification::DescriptorOnly,
        }
    }

    pub const fn require_available(&self) -> Result<(), BackendError> {
        Err(BackendError::Unsupported {
            backend: BackendKind::Firecracker,
            reason: UnsupportedReason::DescriptorOnly,
        })
    }
}

/// Remote MCP forwarding boundary.  Its pass-through helpers are identity
/// functions so an upstream success or error is not rewritten.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteMcp {
    pub provider_identity: String,
}

impl RemoteMcp {
    #[must_use]
    pub const fn descriptor(&self) -> BackendDescriptor {
        BackendDescriptor {
            kind: BackendKind::RemoteMcp,
            available: true,
            authority: BackendAuthority::REMOTE_MCP,
            qualification: Qualification::UpstreamPassThrough,
        }
    }

    pub fn preserve<T, E>(&self, upstream: Result<T, E>) -> Result<T, E> {
        upstream
    }
}
