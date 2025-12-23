#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]
#![deny(clippy::float_cmp)]

//! Finality & reconciliation types shared across components.
//!
//! This module intentionally does **not** assume instant finality:
//! all submissions start as `Submitted` and must be advanced via explicit
//! inclusion/finality lookups.

use serde::{Deserialize, Serialize};

/// Shared submission lifecycle state for items submitted to L1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SubmitState {
    #[default]
    NotSubmitted,
    Submitted {
        /// Base64url-encoded 32-byte idempotency key.
        idempotency_key: String,
        /// Optional tx id returned by the L1 submit call.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        l1_tx_id: Option<String>,
    },
    Included {
        /// Opaque proof hash (implementation-defined; deterministic).
        proof_hash: String,
        /// Optional tx id resolved from inclusion proof.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        l1_tx_id: Option<String>,
    },
    Finalized {
        /// Opaque proof hash (implementation-defined; deterministic).
        proof_hash: String,
        /// Optional tx id resolved from finality proof.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        l1_tx_id: Option<String>,
    },
    Failed {
        /// Stable error code (not a verbose message).
        error_code: String,
    },
}
