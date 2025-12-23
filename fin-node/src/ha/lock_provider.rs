#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]
#![deny(clippy::float_cmp)]

//! Pluggable leader lock providers for HA mode.
//!
//! ## Design goals
//!
//! - **Semantics must match** the built-in sled TTL lease: acquire, renew, TTL expiry, and step-down.
//! - **No lock metadata** may affect deterministic execution or hashing (locks are operational only).
//! - **Failure modes must be explicit and observable** (typed errors + metrics + logs).
//!
//! ## How the supervisor uses this trait
//!
//! - On each tick, followers call `current_holder()` to publish a leader hint, and call `try_acquire()`
//!   only when the lease is missing/expired.
//! - Leaders call `renew()` periodically. Any error (or loss of ownership) causes a **safe step-down**.

use std::fmt;

pub type Result<T> = std::result::Result<T, LockProviderError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockState {
    /// This node holds leadership after the operation.
    Acquired,
    /// Another node holds leadership (or contention prevented acquisition).
    NotLeader,
    /// The lease expired (or vanished) and this node is not leader.
    Expired,
    /// Provider-specific error state (prefer returning `Err` with a typed `LockProviderError`).
    #[allow(dead_code)]
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaderInfo {
    pub node_id: String,
    pub expires_at_ms: u64,
}

#[allow(dead_code)]
#[derive(Debug, thiserror::Error)]
pub enum LockProviderError {
    #[error("timeout: {0}")]
    Timeout(String),
    #[error("connection error: {0}")]
    Connection(String),
    #[allow(dead_code)]
    #[error("permission error: {0}")]
    Permission(String),
    #[error("misconfigured: {0}")]
    Misconfigured(String),
    #[error("backend error: {0}")]
    Backend(String),
}

impl LockProviderError {
    pub fn reason(&self) -> &'static str {
        match self {
            LockProviderError::Timeout(_) => "timeout",
            LockProviderError::Connection(_) => "connection",
            LockProviderError::Permission(_) => "permission",
            LockProviderError::Misconfigured(_) => "misconfigured",
            LockProviderError::Backend(_) => "backend",
        }
    }
}

/// Provider-agnostic leader lock operations for HA supervision.
///
/// Implementations MUST:
/// - enforce a TTL lease (`expires_at_ms`) that eventually hands over leadership,
/// - verify ownership on renew/release (never renew/release if value != node_id),
/// - return typed errors for observability and explicit failure handling.
pub trait LeaderLockProvider: Send + Sync + fmt::Debug + 'static {
    /// Returns a stable provider label used for metrics tagging.
    ///
    /// Suggested values: `"sled"`, `"redis"`, `"consul"`.
    fn provider_type(&self) -> &'static str;

    fn try_acquire(&self, node_id: &str) -> Result<LockState>;
    fn renew(&self, node_id: &str) -> Result<LockState>;
    fn release(&self, node_id: &str) -> Result<()>;
    fn current_holder(&self) -> Result<Option<LeaderInfo>>;
}
