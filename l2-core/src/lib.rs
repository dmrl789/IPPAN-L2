#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]
#![deny(clippy::float_cmp)]
#![deny(clippy::cast_precision_loss)]
#![deny(clippy::cast_possible_truncation)]
#![deny(clippy::cast_possible_wrap)]
#![deny(clippy::cast_sign_loss)]
#![deny(clippy::disallowed_types)]

//! Core types and primitives for IPPAN L2 Hubs.
//!
//! This crate defines shared abstractions for all IPPAN Hubs
//! (FIN, DATA, M2M, WORLD, BRIDGE) and their interaction with
//! the IPPAN CORE settlement layer.

/// Logical identifier for an IPPAN L2 Hub.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum L2HubId {
    /// IPPAN FIN – Finance / RWA / stablecoins.
    Fin,
    /// IPPAN DATA – Data / AI / InfoLAW.
    Data,
    /// IPPAN M2M – IoT and machine-to-machine payments.
    M2m,
    /// IPPAN WORLD – Applications and marketplaces.
    World,
    /// IPPAN BRIDGE – Cross-chain and interoperability.
    Bridge,
}

/// Identifier for an L2 batch (opaque for now, typically a hash or UUID).
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct L2BatchId(pub String);

/// Minimal representation of a batch of L2 transactions to be settled on CORE.
#[derive(Debug, Clone)]
pub struct L2Batch {
    /// The hub this batch belongs to.
    pub hub: L2HubId,
    /// The unique batch identifier.
    pub batch_id: L2BatchId,
    /// Number of transactions in this batch.
    pub tx_count: u64,
    /// Optional opaque commitment hash (e.g. Merkle root).
    pub commitment: Option<String>,
}

/// Minimal proof structure to be verified by IPPAN CORE.
#[derive(Debug, Clone)]
pub struct L2Proof {
    /// The hub this proof refers to.
    pub hub: L2HubId,
    /// The batch identifier.
    pub batch_id: L2BatchId,
    /// The committed state root after applying the batch.
    pub state_root: String,
}

/// Fixed-point amount type for L2, scaled by 1_000_000 (6 decimal places).
///
/// This is used for fees, token amounts and other quantitative values
/// where deterministic behaviour across architectures is required.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct FixedAmount {
    /// Underlying integer representation (scaled by SCALE).
    inner: i128,
}

/// Global scale factor for FixedAmount (1e6).
pub const FIXED_AMOUNT_SCALE: i128 = 1_000_000;

impl FixedAmount {
    /// Construct a FixedAmount from an integer representing the scaled value.
    pub const fn from_scaled(inner: i128) -> Self {
        Self { inner }
    }

    /// Return the scaled inner representation.
    pub const fn into_scaled(self) -> i128 {
        self.inner
    }

    /// Create from integral units (e.g., "1" token) with given decimals.
    /// Example: `from_units(1, 6)` = 1_000_000 scaled units.
    pub fn from_units(units: i128, decimals: u32) -> Self {
        let mut factor: i128 = 1;
        let mut i = 0;
        while i < decimals {
            factor *= 10;
            i += 1;
        }
        Self {
            inner: units * factor,
        }
    }

    /// Add two FixedAmount values, checking for overflow.
    pub fn checked_add(self, other: Self) -> Option<Self> {
        self.inner.checked_add(other.inner).map(Self::from_scaled)
    }

    /// Subtract two FixedAmount values, checking for overflow.
    pub fn checked_sub(self, other: Self) -> Option<Self> {
        self.inner.checked_sub(other.inner).map(Self::from_scaled)
    }
}

/// Request from an L2 Hub to settle a batch on IPPAN CORE.
#[derive(Debug, Clone)]
pub struct SettlementRequest {
    pub hub: L2HubId,
    pub batch: L2Batch,
    /// Total protocol fee to be paid for this batch (in IPN fixed units).
    pub fee: FixedAmount,
}

/// Result of L1 settlement for an L2 batch.
#[derive(Debug, Clone)]
pub struct SettlementResult {
    pub hub: L2HubId,
    pub batch_id: L2BatchId,
    /// Hash or identifier of the L1 transaction / commitment.
    pub l1_reference: String,
    /// True if settlement reached finality.
    pub finalised: bool,
}

/// Abstract client interface that an L2 Hub uses to talk to IPPAN CORE.
///
/// In production this will be backed by RPC calls to an L1 node;
/// in tests it can be mocked.
pub trait L1SettlementClient {
    /// Submit a settlement request and receive a settlement result.
    fn submit_settlement(
        &self,
        request: SettlementRequest,
    ) -> Result<SettlementResult, SettlementError>;
}

/// Errors that may occur when attempting L1 settlement.
#[derive(Debug, thiserror::Error)]
pub enum SettlementError {
    #[error("network error talking to IPPAN CORE: {0}")]
    Network(String),
    #[error("CORE rejected settlement: {0}")]
    Rejected(String),
    #[error("unexpected internal error: {0}")]
    Internal(String),
}

impl L2Batch {
    /// Create a new batch with the given hub, id and transaction count.
    pub fn new(hub: L2HubId, batch_id: L2BatchId, tx_count: u64) -> Self {
        Self {
            hub,
            batch_id,
            tx_count,
            commitment: None,
        }
    }

    /// Attach a commitment hash to the batch (builder-style).
    pub fn with_commitment(mut self, commitment: impl Into<String>) -> Self {
        self.commitment = Some(commitment.into());
        self
    }
}

impl L2Proof {
    /// Create a new L2 proof for a given hub and batch.
    pub fn new(hub: L2HubId, batch_id: L2BatchId, state_root: impl Into<String>) -> Self {
        Self {
            hub,
            batch_id,
            state_root: state_root.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_amount_basic_arithmetic() {
        let a = FixedAmount::from_units(1, 6); // 1.000000
        let b = FixedAmount::from_units(2, 6); // 2.000000
        let sum = a.checked_add(b).expect("overflow");
        assert_eq!(sum.into_scaled(), 3_000_000);
    }
}
