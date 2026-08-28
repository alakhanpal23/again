//! Typed non-pass for targets without a reviewed local peer-credential API.
//!
//! The local daemon transport is intentionally absent on these targets. This
//! module exposes no listener, connector, socket, token, command, or fallback
//! network surface.

use thiserror::Error;

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum GatewayServiceError {
    #[error("gateway daemon peer authentication is unsupported on this platform")]
    UnsupportedPlatform,
}
