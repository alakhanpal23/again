//! Gate 3 namespace and blocked pre-exec handoff boundary.
//!
//! This module is reserved for isolation-session construction. It must not
//! grant execution authority until the main connector consumes its live,
//! cleanup-owning handoff together with runtime and stdio qualifications.
