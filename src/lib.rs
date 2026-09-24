pub mod agent_gateway;
pub mod agent_gateway_runtime;
#[cfg(all(feature = "daemon", unix))]
pub mod agent_gateway_service;
#[cfg(all(feature = "daemon", not(unix)))]
#[path = "agent_gateway_service_unsupported.rs"]
pub mod agent_gateway_service;
pub mod agent_gateway_setup;
pub mod brain;
pub mod code_intelligence;
pub mod effect;
pub mod engine;
pub mod executable;
pub mod execution_backend;
pub mod fingerprint;
#[cfg(feature = "hook")]
pub mod hook;
pub mod mcp_gateway;
pub mod observer_setup;
// Keep the disabled Linux pytest profile crate-private while its implementations
// are built behind the frozen interfaces.
#[cfg(feature = "linux-pytest")]
#[allow(dead_code)]
pub(crate) mod linux_pytest;
pub mod policy;
#[cfg(feature = "team-alpha")]
pub mod privacy;
#[cfg(feature = "team-alpha")]
pub mod remote;
#[cfg(feature = "team-alpha")]
pub(crate) mod runtime_attestation;
pub mod sandbox;
pub mod setup;
pub mod store;
pub mod task_lifecycle;
#[cfg(feature = "team-alpha")]
pub mod team;
#[cfg(feature = "team-alpha")]
pub(crate) mod team_admission;
#[cfg(feature = "team-alpha")]
pub(crate) mod team_cli;
#[cfg(feature = "team-alpha")]
pub(crate) mod team_clock;
#[cfg(feature = "team-alpha")]
pub mod team_config;
#[cfg(feature = "team-alpha")]
pub mod team_crypto;
#[cfg(feature = "team-alpha")]
pub(crate) mod team_inspect;
#[cfg(feature = "team-alpha")]
pub mod team_lookup_bundle;
#[cfg(feature = "team-alpha")]
pub mod team_manifest_v2;
#[cfg(feature = "team-alpha")]
pub(crate) mod team_publish;
#[cfg(feature = "team-alpha")]
pub mod team_pull;
#[cfg(feature = "team-alpha")]
pub mod team_request_key;
#[cfg(feature = "team-alpha")]
pub mod trust_bundle;
pub mod workspace_authority;

pub use engine::run_cli;
