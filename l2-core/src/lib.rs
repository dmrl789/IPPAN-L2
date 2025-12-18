#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]
#![deny(clippy::float_cmp)]
#![deny(clippy::cast_precision_loss)]
#![deny(clippy::cast_possible_truncation)]
#![deny(clippy::cast_possible_wrap)]
#![deny(clippy::cast_sign_loss)]

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
