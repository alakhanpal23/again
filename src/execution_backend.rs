//! Authority-minimal execution backend descriptors.
//!
//! This module intentionally does not contain a process launcher.  In particular,
//! [`RootlessLinux`] cannot accept a command, while the gVisor and Firecracker
//! types are configuration descriptors for future integrations only.

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

/// The exact authority a backend possesses in this sprint.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendAuthority {
    pub exact_local_read: bool,
    pub local_command_execution: bool,
    pub remote_tool_forwarding: bool,
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
}

/// Availability and authority metadata that Terminal A can inspect without
/// accidentally invoking a backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BackendDescriptor {
    pub kind: BackendKind,
    pub available: bool,
    pub authority: BackendAuthority,
    pub qualification: Qualification,
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
/// command.  There is no execute method taking a command-like value.
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
