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

use serde::{Deserialize, Serialize};

pub mod batch_envelope;
pub mod canonical;
pub mod fees;
pub mod finality;
pub mod forced_inclusion;
pub mod hub_linkage;
pub mod l1_contract;
pub mod organiser;
pub mod policy;

pub use batch_envelope::{
    compute_tx_root, sign_envelope, verify_envelope, BatchEnvelope, BatchEnvelopeError,
    BatchPayload, BATCH_SIGNING_DOMAIN_V1,
};
pub use canonical::{
    canonical_decode, canonical_encode, canonical_hash, canonical_hash_bytes, Batch,
    CanonicalError, ChainId, Hash32, Receipt, Tx,
};
pub use organiser::{
    NoopOrganiser, Organiser, OrganiserDecision, OrganiserInputs, OrganiserPolicyBounds,
    OrganiserStatus, OrganiserVersion,
};

#[cfg(feature = "signed-envelopes")]
pub mod signing;

/// Optional operational encryption-at-rest primitives (feature: `encryption-at-rest`).
pub mod storage_encryption;

/// Generic transaction envelope shared by all IPPAN L2 hubs.
///
/// This structure provides a deterministic wrapper around a hub identifier,
/// a transaction id, and the hub-specific payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2TransactionEnvelope<T> {
    pub hub: L2HubId,
    pub tx_id: String,
    pub payload: T,
}

/// Logical identifier for an IPPAN L2 Hub.
///
/// The ordering is stable and deterministic for tie-breaking in scheduling:
/// Fin < Data < M2m < World < Bridge
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
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

/// All hub identifiers in deterministic order (for iteration and fairness).
pub const ALL_HUBS: [L2HubId; 5] = [
    L2HubId::Fin,
    L2HubId::Data,
    L2HubId::M2m,
    L2HubId::World,
    L2HubId::Bridge,
];

impl L2HubId {
    /// Get all hub identifiers in deterministic order.
    pub fn all() -> &'static [L2HubId] {
        &ALL_HUBS
    }

    /// Get the canonical string key for storage.
    pub fn as_str(&self) -> &'static str {
        match self {
            L2HubId::Fin => "fin",
            L2HubId::Data => "data",
            L2HubId::M2m => "m2m",
            L2HubId::World => "world",
            L2HubId::Bridge => "bridge",
        }
    }

    /// Parse from canonical string key.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "fin" => Some(L2HubId::Fin),
            "data" => Some(L2HubId::Data),
            "m2m" => Some(L2HubId::M2m),
            "world" => Some(L2HubId::World),
            "bridge" => Some(L2HubId::Bridge),
            _ => None,
        }
    }

    /// Check if this hub uses M2M fee logic.
    pub fn uses_m2m_fees(&self) -> bool {
        matches!(self, L2HubId::M2m)
    }

    /// Get the index of this hub in the deterministic ordering (0-4).
    pub fn index(&self) -> usize {
        match self {
            L2HubId::Fin => 0,
            L2HubId::Data => 1,
            L2HubId::M2m => 2,
            L2HubId::World => 3,
            L2HubId::Bridge => 4,
        }
    }
}

impl std::fmt::Display for L2HubId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Composite key for a hub on a specific chain.
///
/// Used for per-hub per-chain state tracking (batch numbers, hashes, etc.).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct HubKey {
    pub hub: L2HubId,
    pub chain_id: u64,
}

impl HubKey {
    /// Create a new HubKey.
    pub fn new(hub: L2HubId, chain_id: u64) -> Self {
        Self { hub, chain_id }
    }

    /// Get a storage key string for this HubKey.
    pub fn storage_key(&self) -> String {
        format!("{}:{}", self.hub.as_str(), self.chain_id)
    }
}

impl std::fmt::Display for HubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.hub, self.chain_id)
    }
}

/// Per-hub state for batch numbering and chaining.
///
/// Each hub maintains independent batch sequences to allow
/// parallel operation and isolated settlement tracking.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HubState {
    /// Current batch number for this hub (monotonically increasing).
    pub batch_number: u64,
    /// Hash of the last successfully posted batch (for chaining).
    pub last_batch_hash: Option<[u8; 32]>,
    /// Hash of the last finalised batch.
    pub last_finalised_hash: Option<[u8; 32]>,
    /// Timestamp of last batch creation (ms).
    pub last_batch_created_ms: Option<u64>,
    /// Current queue depth snapshot.
    pub queue_depth: u32,
    /// Current forced queue depth snapshot.
    pub forced_queue_depth: u32,
    /// Total fees finalised (scaled, M2M hub only).
    pub total_fees_finalised_scaled: u64,
}

impl HubState {
    /// Create a new empty hub state.
    pub fn new() -> Self {
        Self::default()
    }

    /// Increment batch number and return the new value.
    pub fn next_batch_number(&mut self) -> u64 {
        self.batch_number = self.batch_number.saturating_add(1);
        self.batch_number
    }

    /// Update the last batch hash after successful posting.
    pub fn set_last_batch_hash(&mut self, hash: [u8; 32]) {
        self.last_batch_hash = Some(hash);
    }

    /// Update the last finalised hash.
    pub fn set_last_finalised_hash(&mut self, hash: [u8; 32]) {
        self.last_finalised_hash = Some(hash);
    }

    /// Update queue depth snapshot.
    pub fn update_queue_depths(&mut self, queue: u32, forced: u32) {
        self.queue_depth = queue;
        self.forced_queue_depth = forced;
    }

    /// Add to total finalised fees (M2M hub).
    pub fn add_finalised_fees(&mut self, amount_scaled: u64) {
        self.total_fees_finalised_scaled = self
            .total_fees_finalised_scaled
            .saturating_add(amount_scaled);
    }
}

/// Identifier for an L2 batch (opaque for now, typically a hash or UUID).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct L2BatchId(pub String);

/// Minimal representation of a batch of L2 transactions to be settled on CORE.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L2Proof {
    /// The hub this proof refers to.
    pub hub: L2HubId,
    /// The batch identifier.
    pub batch_id: L2BatchId,
    /// The committed state root after applying the batch.
    pub state_root: String,
}

/// Opaque identifier for an account at L2 (hub-specific semantics).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AccountId(pub String);

/// Opaque identifier for a fungible or non-fungible asset at L2.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct AssetId(pub String);

/// Simple helper constructors for IDs.
impl AccountId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

impl AssetId {
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }
}

/// Fixed-point amount type for L2, scaled by 1_000_000 (6 decimal places).
///
/// This is used for fees, token amounts and other quantitative values
/// where deterministic behaviour across architectures is required.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementRequest {
    pub hub: L2HubId,
    pub batch: L2Batch,
    /// Total protocol fee to be paid for this batch (in IPN fixed units).
    pub fee: FixedAmount,
}

/// Result of L1 settlement for an L2 batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettlementResult {
    pub hub: L2HubId,
    pub batch_id: L2BatchId,
    /// Hash or identifier of the L1 transaction / commitment.
    pub l1_reference: String,
    /// True if settlement reached finality.
    pub finalised: bool,
}

/// Configuration for talking to an IPPAN CORE node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct L1EndpointConfig {
    /// Base URL for the L1 settlement endpoint, e.g. "http://127.0.0.1:8080".
    pub base_url: String,
    /// Optional API key or auth token if required by the endpoint.
    pub api_key: Option<String>,
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

    #[test]
    fn account_and_asset_ids_are_opaque() {
        let acc = AccountId::new("acc-001");
        let asset = AssetId::new("asset-xyz");
        assert_eq!(acc.0, "acc-001");
        assert_eq!(asset.0, "asset-xyz");
    }

    // ========== L2HubId Tests ==========

    #[test]
    fn hub_id_ordering_is_deterministic() {
        // Verify Fin < Data < M2m < World < Bridge
        assert!(L2HubId::Fin < L2HubId::Data);
        assert!(L2HubId::Data < L2HubId::M2m);
        assert!(L2HubId::M2m < L2HubId::World);
        assert!(L2HubId::World < L2HubId::Bridge);
    }

    #[test]
    fn hub_id_all_hubs_order() {
        let all = L2HubId::all();
        assert_eq!(all.len(), 5);
        assert_eq!(all[0], L2HubId::Fin);
        assert_eq!(all[1], L2HubId::Data);
        assert_eq!(all[2], L2HubId::M2m);
        assert_eq!(all[3], L2HubId::World);
        assert_eq!(all[4], L2HubId::Bridge);
    }

    #[test]
    fn hub_id_as_str_roundtrip() {
        for hub in L2HubId::all() {
            let s = hub.as_str();
            let parsed = L2HubId::parse(s).expect("should parse");
            assert_eq!(*hub, parsed);
        }
    }

    #[test]
    fn hub_id_from_str_case_insensitive() {
        assert_eq!(L2HubId::parse("FIN"), Some(L2HubId::Fin));
        assert_eq!(L2HubId::parse("Data"), Some(L2HubId::Data));
        assert_eq!(L2HubId::parse("M2M"), Some(L2HubId::M2m));
        assert_eq!(L2HubId::parse("WORLD"), Some(L2HubId::World));
        assert_eq!(L2HubId::parse("bridge"), Some(L2HubId::Bridge));
        assert_eq!(L2HubId::parse("invalid"), None);
    }

    #[test]
    fn hub_id_index_matches_order() {
        assert_eq!(L2HubId::Fin.index(), 0);
        assert_eq!(L2HubId::Data.index(), 1);
        assert_eq!(L2HubId::M2m.index(), 2);
        assert_eq!(L2HubId::World.index(), 3);
        assert_eq!(L2HubId::Bridge.index(), 4);
    }

    #[test]
    fn hub_id_uses_m2m_fees() {
        assert!(!L2HubId::Fin.uses_m2m_fees());
        assert!(!L2HubId::Data.uses_m2m_fees());
        assert!(L2HubId::M2m.uses_m2m_fees());
        assert!(!L2HubId::World.uses_m2m_fees());
        assert!(!L2HubId::Bridge.uses_m2m_fees());
    }

    #[test]
    fn hub_id_display() {
        assert_eq!(format!("{}", L2HubId::Fin), "fin");
        assert_eq!(format!("{}", L2HubId::M2m), "m2m");
    }

    // ========== HubKey Tests ==========

    #[test]
    fn hub_key_storage_key() {
        let key = HubKey::new(L2HubId::Fin, 1337);
        assert_eq!(key.storage_key(), "fin:1337");
    }

    #[test]
    fn hub_key_ordering() {
        let key1 = HubKey::new(L2HubId::Fin, 1);
        let key2 = HubKey::new(L2HubId::Fin, 2);
        let key3 = HubKey::new(L2HubId::Data, 1);

        // Same hub, different chain_id
        assert!(key1 < key2);
        // Different hub
        assert!(key1 < key3);
    }

    #[test]
    fn hub_key_display() {
        let key = HubKey::new(L2HubId::M2m, 42);
        assert_eq!(format!("{}", key), "m2m:42");
    }

    // ========== HubState Tests ==========

    #[test]
    fn hub_state_default() {
        let state = HubState::new();
        assert_eq!(state.batch_number, 0);
        assert!(state.last_batch_hash.is_none());
        assert!(state.last_finalised_hash.is_none());
        assert_eq!(state.queue_depth, 0);
        assert_eq!(state.forced_queue_depth, 0);
        assert_eq!(state.total_fees_finalised_scaled, 0);
    }

    #[test]
    fn hub_state_next_batch_number() {
        let mut state = HubState::new();
        assert_eq!(state.next_batch_number(), 1);
        assert_eq!(state.next_batch_number(), 2);
        assert_eq!(state.next_batch_number(), 3);
        assert_eq!(state.batch_number, 3);
    }

    #[test]
    fn hub_state_batch_hash() {
        let mut state = HubState::new();
        let hash = [0xAA; 32];

        state.set_last_batch_hash(hash);
        assert_eq!(state.last_batch_hash, Some(hash));

        let hash2 = [0xBB; 32];
        state.set_last_finalised_hash(hash2);
        assert_eq!(state.last_finalised_hash, Some(hash2));
    }

    #[test]
    fn hub_state_queue_depths() {
        let mut state = HubState::new();
        state.update_queue_depths(100, 5);
        assert_eq!(state.queue_depth, 100);
        assert_eq!(state.forced_queue_depth, 5);
    }

    #[test]
    fn hub_state_fees() {
        let mut state = HubState::new();
        state.add_finalised_fees(1_000_000);
        assert_eq!(state.total_fees_finalised_scaled, 1_000_000);
        state.add_finalised_fees(500_000);
        assert_eq!(state.total_fees_finalised_scaled, 1_500_000);
    }

    #[test]
    fn hub_state_fees_saturating() {
        let mut state = HubState::new();
        state.total_fees_finalised_scaled = u64::MAX - 100;
        state.add_finalised_fees(200);
        assert_eq!(state.total_fees_finalised_scaled, u64::MAX);
    }
}
