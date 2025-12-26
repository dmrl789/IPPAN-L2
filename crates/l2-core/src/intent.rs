//! Cross-Hub Intent Protocol types and canonical encoding.
//!
//! This module defines the core types for the deterministic two-phase commit
//! (2PC-style) intent protocol for atomic cross-hub operations.
//!
//! ## Intent Lifecycle
//!
//! ```text
//! Created -> Prepared -> Committed
//!    |          |
//!    +----------+---> Aborted
//! ```
//!
//! ## Canonical Intent ID
//!
//! `IntentId` is a `Hash32` computed as `blake3(canonical_bytes(intent))` where
//! `canonical_bytes` is the deterministic bincode encoding of the intent payload.
//!
//! ## Requirements
//!
//! - All timestamps are explicit integer milliseconds (no floats, no implicit timeouts)
//! - State transitions are monotonic and crash-safe
//! - Intent operations are deterministic and replayable

use crate::{canonical_encode, canonical_hash, CanonicalError, Hash32, L2HubId};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Intent identifier - a blake3 hash of the canonical intent bytes.
///
/// This is a newtype wrapper around `Hash32` for type safety and clarity.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct IntentId(pub Hash32);

impl IntentId {
    /// Create an IntentId from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Hash32(bytes))
    }

    /// Get the hex representation.
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Parse from hex string.
    pub fn from_hex(hex_str: &str) -> Result<Self, CanonicalError> {
        Hash32::from_hex(hex_str).map(IntentId)
    }
}

impl fmt::Display for IntentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Kind of cross-hub intent operation.
///
/// Uses explicit enum variants (not strings) for type safety and canonical encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IntentKind {
    /// Cross-hub transfer: debit from_hub, credit to_hub.
    /// Example: debit FIN, credit WORLD
    CrossHubTransfer,

    /// Lock-and-mint: lock asset in from_hub, mint representation in to_hub.
    /// Example: lock asset in FIN, mint wrapped asset in WORLD
    LockAndMint,

    /// Burn-and-unlock: burn representation in from_hub, unlock original in to_hub.
    /// Example: burn wrapped asset in WORLD, unlock original in FIN
    BurnAndUnlock,

    /// External lock-and-mint: verify external chain lock, mint representation in to_hub.
    ///
    /// This intent type requires an external proof to be verified before the
    /// prepare phase can proceed. The from_hub is set to BRIDGE, and the
    /// operation is gated on proof verification.
    ///
    /// Example: verify ETH lock on Ethereum, mint wETH in FIN
    ExternalLockAndMint,

    /// External burn-and-unlock: burn representation in from_hub, submit unlock to external chain.
    ///
    /// This intent type burns the wrapped asset and produces an unlock attestation
    /// that can be submitted to the external chain.
    ///
    /// Example: burn wETH in FIN, produce unlock attestation for Ethereum
    ExternalBurnAndUnlock,
}

impl IntentKind {
    /// Get the canonical string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            IntentKind::CrossHubTransfer => "cross_hub_transfer",
            IntentKind::LockAndMint => "lock_and_mint",
            IntentKind::BurnAndUnlock => "burn_and_unlock",
            IntentKind::ExternalLockAndMint => "external_lock_and_mint",
            IntentKind::ExternalBurnAndUnlock => "external_burn_and_unlock",
        }
    }

    /// Parse from canonical string.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "cross_hub_transfer" | "crosshubtransfer" => Some(IntentKind::CrossHubTransfer),
            "lock_and_mint" | "lockandmint" => Some(IntentKind::LockAndMint),
            "burn_and_unlock" | "burnandunlock" => Some(IntentKind::BurnAndUnlock),
            "external_lock_and_mint" | "externallockandmint" => {
                Some(IntentKind::ExternalLockAndMint)
            }
            "external_burn_and_unlock" | "externalburnandunlock" => {
                Some(IntentKind::ExternalBurnAndUnlock)
            }
            _ => None,
        }
    }

    /// Check if this intent kind requires external proof verification.
    pub fn requires_external_proof(&self) -> bool {
        matches!(self, IntentKind::ExternalLockAndMint)
    }

    /// Check if this is an external chain operation.
    pub fn is_external(&self) -> bool {
        matches!(
            self,
            IntentKind::ExternalLockAndMint | IntentKind::ExternalBurnAndUnlock
        )
    }
}

impl fmt::Display for IntentKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// Phase of an intent in the 2PC protocol.
///
/// State transitions are monotonic:
/// - Created -> Prepared -> Committed
/// - Created -> Aborted
/// - Prepared -> Aborted
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum IntentPhase {
    /// Intent has been created but not yet prepared.
    Prepared,

    /// Intent has been prepared (locks acquired on both hubs).
    Committed,

    /// Intent has been aborted (locks released, operation cancelled).
    Aborted,
}

impl IntentPhase {
    /// Get the canonical string representation.
    pub fn as_str(&self) -> &'static str {
        match self {
            IntentPhase::Prepared => "prepared",
            IntentPhase::Committed => "committed",
            IntentPhase::Aborted => "aborted",
        }
    }

    /// Parse from canonical string.
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "prepared" => Some(IntentPhase::Prepared),
            "committed" => Some(IntentPhase::Committed),
            "aborted" => Some(IntentPhase::Aborted),
            _ => None,
        }
    }

    /// Check if this is a terminal phase.
    pub fn is_terminal(&self) -> bool {
        matches!(self, IntentPhase::Committed | IntentPhase::Aborted)
    }
}

impl fmt::Display for IntentPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.as_str())
    }
}

/// A cross-hub intent for atomic operations across IPPAN hubs.
///
/// The intent defines what operation should be performed atomically
/// across the from_hub and to_hub.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Intent {
    /// Kind of operation.
    pub kind: IntentKind,

    /// Timestamp when the intent was created (ms since epoch, informational).
    pub created_ms: u64,

    /// Timestamp when the intent expires (ms since epoch, policy).
    /// After this time, the intent can only be aborted.
    pub expires_ms: u64,

    /// Source hub for the operation.
    pub from_hub: L2HubId,

    /// Destination hub for the operation.
    pub to_hub: L2HubId,

    /// Initiator account (who requested this intent).
    pub initiator: String,

    /// Hub-specific payload (canonical bytes).
    /// Contains asset IDs, amounts, recipients, etc.
    pub payload: Vec<u8>,
}

impl Intent {
    /// Compute the canonical intent ID (blake3 hash of canonical bytes).
    pub fn compute_id(&self) -> Result<IntentId, CanonicalError> {
        let hash = canonical_hash(self)?;
        Ok(IntentId(hash))
    }

    /// Encode to canonical bytes.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        canonical_encode(self)
    }

    /// Check if the intent has expired.
    pub fn is_expired(&self, current_ms: u64) -> bool {
        current_ms >= self.expires_ms
    }

    /// Get the duration until expiry (ms), or 0 if expired.
    pub fn time_until_expiry(&self, current_ms: u64) -> u64 {
        self.expires_ms.saturating_sub(current_ms)
    }

    /// Validate the intent structure.
    pub fn validate(&self) -> Result<(), IntentValidationError> {
        // from_hub and to_hub must be different
        if self.from_hub == self.to_hub {
            return Err(IntentValidationError::SameHubTransfer);
        }

        // expires_ms must be after created_ms
        if self.expires_ms <= self.created_ms {
            return Err(IntentValidationError::InvalidExpiry {
                created_ms: self.created_ms,
                expires_ms: self.expires_ms,
            });
        }

        // initiator must not be empty
        if self.initiator.is_empty() {
            return Err(IntentValidationError::EmptyInitiator);
        }

        Ok(())
    }
}

/// Validation errors for intent structure.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IntentValidationError {
    /// Cannot transfer to the same hub.
    SameHubTransfer,
    /// Expiry must be after creation.
    InvalidExpiry { created_ms: u64, expires_ms: u64 },
    /// Initiator account must not be empty.
    EmptyInitiator,
}

impl fmt::Display for IntentValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IntentValidationError::SameHubTransfer => {
                write!(f, "from_hub and to_hub must be different")
            }
            IntentValidationError::InvalidExpiry {
                created_ms,
                expires_ms,
            } => {
                write!(
                    f,
                    "expires_ms ({}) must be after created_ms ({})",
                    expires_ms, created_ms
                )
            }
            IntentValidationError::EmptyInitiator => {
                write!(f, "initiator must not be empty")
            }
        }
    }
}

impl std::error::Error for IntentValidationError {}

/// Receipt for a prepare operation on a single hub.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrepareReceipt {
    /// The intent ID this receipt is for.
    pub intent_id: IntentId,

    /// Hub that issued this receipt.
    pub hub: L2HubId,

    /// Timestamp when prepare was executed (ms since epoch).
    pub prepared_ms: u64,

    /// Hash of the lock/reserve operation result.
    pub lock_hash: Hash32,

    /// Optional details about what was locked/reserved.
    pub details: Option<String>,
}

impl PrepareReceipt {
    /// Compute a deterministic hash of this receipt.
    pub fn hash(&self) -> Result<Hash32, CanonicalError> {
        canonical_hash(self)
    }
}

/// Receipt for a commit operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitReceipt {
    /// The intent ID this receipt is for.
    pub intent_id: IntentId,

    /// Hub that issued this receipt.
    pub hub: L2HubId,

    /// Timestamp when commit was executed (ms since epoch).
    pub committed_ms: u64,

    /// Hash of the finalization operation result.
    pub finalize_hash: Hash32,

    /// Optional details about what was finalized.
    pub details: Option<String>,
}

impl CommitReceipt {
    /// Compute a deterministic hash of this receipt.
    pub fn hash(&self) -> Result<Hash32, CanonicalError> {
        canonical_hash(self)
    }
}

/// Payload for a cross-hub transfer intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossHubTransferPayload {
    /// Asset identifier.
    pub asset_id: String,

    /// Amount to transfer (in smallest units, scaled).
    pub amount: u64,

    /// Sender account on from_hub.
    pub sender: String,

    /// Recipient account on to_hub.
    pub recipient: String,

    /// Optional memo/reference.
    pub memo: Option<String>,
}

impl CrossHubTransferPayload {
    /// Encode to canonical bytes for embedding in Intent.payload.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        canonical_encode(self)
    }

    /// Decode from canonical bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CanonicalError> {
        crate::canonical_decode(bytes)
    }
}

/// Payload for a lock-and-mint intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockAndMintPayload {
    /// Original asset identifier on from_hub.
    pub original_asset_id: String,

    /// Wrapped/synthetic asset identifier on to_hub.
    pub wrapped_asset_id: String,

    /// Amount to lock/mint (in smallest units, scaled).
    pub amount: u64,

    /// Account that owns the locked asset.
    pub locker: String,

    /// Account that receives the minted asset.
    pub minter: String,

    /// Optional memo/reference.
    pub memo: Option<String>,
}

impl LockAndMintPayload {
    /// Encode to canonical bytes for embedding in Intent.payload.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        canonical_encode(self)
    }

    /// Decode from canonical bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CanonicalError> {
        crate::canonical_decode(bytes)
    }
}

/// Payload for a burn-and-unlock intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BurnAndUnlockPayload {
    /// Wrapped/synthetic asset identifier on from_hub (to burn).
    pub wrapped_asset_id: String,

    /// Original asset identifier on to_hub (to unlock).
    pub original_asset_id: String,

    /// Amount to burn/unlock (in smallest units, scaled).
    pub amount: u64,

    /// Account that burns the wrapped asset.
    pub burner: String,

    /// Account that receives the unlocked asset.
    pub unlocker: String,

    /// Optional memo/reference.
    pub memo: Option<String>,
}

impl BurnAndUnlockPayload {
    /// Encode to canonical bytes for embedding in Intent.payload.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        canonical_encode(self)
    }

    /// Decode from canonical bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CanonicalError> {
        crate::canonical_decode(bytes)
    }
}

/// Payload for an external lock-and-mint intent.
///
/// This represents a lock event on an external chain (e.g., Ethereum) that
/// should result in minting a wrapped asset on an IPPAN hub.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalLockAndMintPayload {
    /// External chain identifier (e.g., EthereumMainnet).
    pub external_chain: String,

    /// Asset identifier on the external chain (e.g., contract address).
    pub external_asset: String,

    /// Amount locked on the external chain (in smallest units).
    pub amount: u64,

    /// Recipient account on the IPPAN hub.
    pub recipient: String,

    /// Wrapped/synthetic asset identifier to mint on the IPPAN hub.
    pub wrapped_asset_id: String,

    /// External proof ID that verifies the lock event.
    ///
    /// This proof must be in Verified state before the intent can be prepared.
    pub proof_id: String,

    /// Optional memo/reference.
    pub memo: Option<String>,
}

impl ExternalLockAndMintPayload {
    /// Encode to canonical bytes for embedding in Intent.payload.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        canonical_encode(self)
    }

    /// Decode from canonical bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CanonicalError> {
        crate::canonical_decode(bytes)
    }

    /// Get the proof ID as bytes (for lookup).
    pub fn proof_id_bytes(&self) -> Result<[u8; 32], CanonicalError> {
        let bytes = hex::decode(&self.proof_id)
            .map_err(|e| CanonicalError::FromHex(format!("invalid proof_id hex: {}", e)))?;
        if bytes.len() != 32 {
            return Err(CanonicalError::FromHex(format!(
                "expected 32-byte proof_id, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

/// Payload for an external burn-and-unlock intent.
///
/// This represents burning a wrapped asset on an IPPAN hub to produce
/// an unlock attestation for the external chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExternalBurnAndUnlockPayload {
    /// External chain identifier to unlock on.
    pub external_chain: String,

    /// Wrapped asset identifier on the IPPAN hub (to burn).
    pub wrapped_asset_id: String,

    /// Original asset identifier on the external chain.
    pub external_asset: String,

    /// Amount to burn/unlock (in smallest units).
    pub amount: u64,

    /// Account burning the wrapped asset on the IPPAN hub.
    pub burner: String,

    /// Recipient address on the external chain.
    pub external_recipient: String,

    /// Optional memo/reference.
    pub memo: Option<String>,
}

impl ExternalBurnAndUnlockPayload {
    /// Encode to canonical bytes for embedding in Intent.payload.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        canonical_encode(self)
    }

    /// Decode from canonical bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CanonicalError> {
        crate::canonical_decode(bytes)
    }
}

/// Hub transaction types for intent phase transitions.
///
/// These are emitted as regular L2 transactions that get batched
/// and settled on L1, providing the deterministic anchor for
/// intent state progression.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum IntentHubTx {
    /// Intent has been prepared on this hub.
    IntentPrepared {
        intent_id: IntentId,
        /// Hash of all prepare receipts.
        receipts_hash: Hash32,
        prepared_ms: u64,
    },

    /// Intent has been committed on this hub.
    IntentCommitted {
        intent_id: IntentId,
        /// Hash of all commit receipts.
        receipts_hash: Hash32,
        committed_ms: u64,
    },

    /// Intent has been aborted on this hub.
    IntentAborted {
        intent_id: IntentId,
        /// Hash of the abort reason.
        reason_hash: Hash32,
        aborted_ms: u64,
    },
}

impl IntentHubTx {
    /// Get the intent ID for this hub tx.
    pub fn intent_id(&self) -> &IntentId {
        match self {
            IntentHubTx::IntentPrepared { intent_id, .. } => intent_id,
            IntentHubTx::IntentCommitted { intent_id, .. } => intent_id,
            IntentHubTx::IntentAborted { intent_id, .. } => intent_id,
        }
    }

    /// Encode to canonical bytes.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        canonical_encode(self)
    }

    /// Get the timestamp for this hub tx.
    pub fn timestamp_ms(&self) -> u64 {
        match self {
            IntentHubTx::IntentPrepared { prepared_ms, .. } => *prepared_ms,
            IntentHubTx::IntentCommitted { committed_ms, .. } => *committed_ms,
            IntentHubTx::IntentAborted { aborted_ms, .. } => *aborted_ms,
        }
    }

    /// Get the phase name for logging/metrics.
    pub fn phase_name(&self) -> &'static str {
        match self {
            IntentHubTx::IntentPrepared { .. } => "prepared",
            IntentHubTx::IntentCommitted { .. } => "committed",
            IntentHubTx::IntentAborted { .. } => "aborted",
        }
    }

    /// Convert to an L2 transaction for batch inclusion.
    ///
    /// Intent hub transactions are settled via the existing batch posting mechanism.
    /// Each phase transition is recorded as a normal L2 transaction that gets
    /// included in per-hub batches and settled on L1.
    pub fn to_l2_tx(
        &self,
        chain_id: crate::ChainId,
        from: &str,
        nonce: u64,
    ) -> Result<crate::Tx, CanonicalError> {
        Ok(crate::Tx {
            chain_id,
            nonce,
            from: from.to_string(),
            payload: self.to_canonical_bytes()?,
        })
    }

    /// Compute a unique transaction hash for this hub tx.
    pub fn tx_hash(&self) -> Result<Hash32, CanonicalError> {
        canonical_hash(self)
    }
}

/// Wrapper for tracking intent hub tx settlement.
///
/// This is used by the batcher to track the settlement status of intent
/// phase transitions alongside the normal batch settlement flow.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntentSettlementTx {
    /// The hub tx payload.
    pub hub_tx: IntentHubTx,
    /// Which hub this tx was emitted for (BRIDGE for all intents).
    pub hub: L2HubId,
    /// Batch hash where this tx was included (after batching).
    pub batch_hash: Option<Hash32>,
    /// Whether the batch containing this tx has been finalised on L1.
    pub is_finalised: bool,
}

impl IntentSettlementTx {
    /// Create a new intent settlement tx.
    pub fn new(hub_tx: IntentHubTx, hub: L2HubId) -> Self {
        Self {
            hub_tx,
            hub,
            batch_hash: None,
            is_finalised: false,
        }
    }

    /// Mark as included in a batch.
    pub fn set_batch_hash(&mut self, batch_hash: Hash32) {
        self.batch_hash = Some(batch_hash);
    }

    /// Mark as finalised.
    pub fn mark_finalised(&mut self) {
        self.is_finalised = true;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::canonical_hash_bytes;

    // ========== Intent Creation and Validation ==========

    #[test]
    fn intent_creation() {
        let intent = Intent {
            kind: IntentKind::CrossHubTransfer,
            created_ms: 1_700_000_000_000,
            expires_ms: 1_700_000_600_000, // +10 minutes
            from_hub: L2HubId::Fin,
            to_hub: L2HubId::World,
            initiator: "alice".to_string(),
            payload: vec![1, 2, 3, 4],
        };

        assert!(intent.validate().is_ok());
        assert!(!intent.is_expired(1_700_000_300_000));
        assert!(intent.is_expired(1_700_000_600_001));
    }

    #[test]
    fn intent_validation_same_hub() {
        let intent = Intent {
            kind: IntentKind::CrossHubTransfer,
            created_ms: 1_700_000_000_000,
            expires_ms: 1_700_000_600_000,
            from_hub: L2HubId::Fin,
            to_hub: L2HubId::Fin, // Same as from_hub
            initiator: "alice".to_string(),
            payload: vec![],
        };

        assert_eq!(
            intent.validate(),
            Err(IntentValidationError::SameHubTransfer)
        );
    }

    #[test]
    fn intent_validation_invalid_expiry() {
        let intent = Intent {
            kind: IntentKind::CrossHubTransfer,
            created_ms: 1_700_000_600_000,
            expires_ms: 1_700_000_000_000, // Before created
            from_hub: L2HubId::Fin,
            to_hub: L2HubId::World,
            initiator: "alice".to_string(),
            payload: vec![],
        };

        assert!(matches!(
            intent.validate(),
            Err(IntentValidationError::InvalidExpiry { .. })
        ));
    }

    #[test]
    fn intent_validation_empty_initiator() {
        let intent = Intent {
            kind: IntentKind::CrossHubTransfer,
            created_ms: 1_700_000_000_000,
            expires_ms: 1_700_000_600_000,
            from_hub: L2HubId::Fin,
            to_hub: L2HubId::World,
            initiator: String::new(),
            payload: vec![],
        };

        assert_eq!(
            intent.validate(),
            Err(IntentValidationError::EmptyInitiator)
        );
    }

    // ========== Intent ID Golden Vectors ==========

    #[test]
    fn intent_id_golden_vector_cross_hub_transfer() {
        // Fixed intent for golden test
        let intent = Intent {
            kind: IntentKind::CrossHubTransfer,
            created_ms: 1_700_000_000_000,
            expires_ms: 1_700_000_600_000,
            from_hub: L2HubId::Fin,
            to_hub: L2HubId::World,
            initiator: "alice".to_string(),
            payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };

        let intent_id = intent.compute_id().expect("compute_id");

        // This hash should remain stable across versions
        assert_eq!(
            intent_id.to_hex(),
            "b4236ab9ff0057b3d72772c9edca94a7a6b1f0a50058ee47a79951be0de7de41"
        );
    }

    #[test]
    fn intent_id_golden_vector_lock_and_mint() {
        let intent = Intent {
            kind: IntentKind::LockAndMint,
            created_ms: 1_700_000_000_000,
            expires_ms: 1_700_000_600_000,
            from_hub: L2HubId::Fin,
            to_hub: L2HubId::World,
            initiator: "bob".to_string(),
            payload: vec![0xCA, 0xFE],
        };

        let intent_id = intent.compute_id().expect("compute_id");

        assert_eq!(
            intent_id.to_hex(),
            "34f39db9189117d8435a1e265aecae741c631f4a78f3ca4b9cf2a24ab4fd2625"
        );
    }

    #[test]
    fn intent_id_golden_vector_burn_and_unlock() {
        let intent = Intent {
            kind: IntentKind::BurnAndUnlock,
            created_ms: 1_700_000_000_000,
            expires_ms: 1_700_000_600_000,
            from_hub: L2HubId::World,
            to_hub: L2HubId::Fin,
            initiator: "charlie".to_string(),
            payload: vec![0x00, 0x11, 0x22],
        };

        let intent_id = intent.compute_id().expect("compute_id");

        assert_eq!(
            intent_id.to_hex(),
            "3fb1f4e5eb53b885bc7f4fa12fc822caa7d380a23c7c19889fa5e85c609f8eb8"
        );
    }

    // ========== Intent ID Determinism ==========

    #[test]
    fn intent_id_is_deterministic() {
        let intent1 = Intent {
            kind: IntentKind::CrossHubTransfer,
            created_ms: 1_700_000_000_000,
            expires_ms: 1_700_000_600_000,
            from_hub: L2HubId::Fin,
            to_hub: L2HubId::World,
            initiator: "alice".to_string(),
            payload: vec![1, 2, 3],
        };

        let intent2 = Intent {
            kind: IntentKind::CrossHubTransfer,
            created_ms: 1_700_000_000_000,
            expires_ms: 1_700_000_600_000,
            from_hub: L2HubId::Fin,
            to_hub: L2HubId::World,
            initiator: "alice".to_string(),
            payload: vec![1, 2, 3],
        };

        let id1 = intent1.compute_id().unwrap();
        let id2 = intent2.compute_id().unwrap();

        assert_eq!(id1, id2);
    }

    #[test]
    fn intent_id_changes_with_any_field() {
        let base = Intent {
            kind: IntentKind::CrossHubTransfer,
            created_ms: 1_700_000_000_000,
            expires_ms: 1_700_000_600_000,
            from_hub: L2HubId::Fin,
            to_hub: L2HubId::World,
            initiator: "alice".to_string(),
            payload: vec![1, 2, 3],
        };

        let base_id = base.compute_id().unwrap();

        // Different kind
        let mut changed = base.clone();
        changed.kind = IntentKind::LockAndMint;
        assert_ne!(changed.compute_id().unwrap(), base_id);

        // Different created_ms
        let mut changed = base.clone();
        changed.created_ms = 1_700_000_000_001;
        assert_ne!(changed.compute_id().unwrap(), base_id);

        // Different expires_ms
        let mut changed = base.clone();
        changed.expires_ms = 1_700_000_600_001;
        assert_ne!(changed.compute_id().unwrap(), base_id);

        // Different from_hub
        let mut changed = base.clone();
        changed.from_hub = L2HubId::Data;
        assert_ne!(changed.compute_id().unwrap(), base_id);

        // Different to_hub
        let mut changed = base.clone();
        changed.to_hub = L2HubId::M2m;
        assert_ne!(changed.compute_id().unwrap(), base_id);

        // Different initiator
        let mut changed = base.clone();
        changed.initiator = "bob".to_string();
        assert_ne!(changed.compute_id().unwrap(), base_id);

        // Different payload
        let mut changed = base.clone();
        changed.payload = vec![4, 5, 6];
        assert_ne!(changed.compute_id().unwrap(), base_id);
    }

    // ========== Intent Phase Tests ==========

    #[test]
    fn intent_phase_terminal() {
        assert!(!IntentPhase::Prepared.is_terminal());
        assert!(IntentPhase::Committed.is_terminal());
        assert!(IntentPhase::Aborted.is_terminal());
    }

    #[test]
    fn intent_phase_roundtrip() {
        for phase in [
            IntentPhase::Prepared,
            IntentPhase::Committed,
            IntentPhase::Aborted,
        ] {
            let s = phase.as_str();
            let parsed = IntentPhase::parse(s).expect("parse");
            assert_eq!(parsed, phase);
        }
    }

    // ========== IntentKind Tests ==========

    #[test]
    fn intent_kind_roundtrip() {
        for kind in [
            IntentKind::CrossHubTransfer,
            IntentKind::LockAndMint,
            IntentKind::BurnAndUnlock,
        ] {
            let s = kind.as_str();
            let parsed = IntentKind::parse(s).expect("parse");
            assert_eq!(parsed, kind);
        }
    }

    // ========== Payload Tests ==========

    #[test]
    fn cross_hub_transfer_payload_roundtrip() {
        let payload = CrossHubTransferPayload {
            asset_id: "IPN".to_string(),
            amount: 1_000_000,
            sender: "alice".to_string(),
            recipient: "bob".to_string(),
            memo: Some("test transfer".to_string()),
        };

        let bytes = payload.to_canonical_bytes().expect("encode");
        let decoded = CrossHubTransferPayload::from_canonical_bytes(&bytes).expect("decode");

        assert_eq!(decoded, payload);
    }

    #[test]
    fn lock_and_mint_payload_roundtrip() {
        let payload = LockAndMintPayload {
            original_asset_id: "IPN".to_string(),
            wrapped_asset_id: "wIPN".to_string(),
            amount: 500_000,
            locker: "alice".to_string(),
            minter: "alice_world".to_string(),
            memo: None,
        };

        let bytes = payload.to_canonical_bytes().expect("encode");
        let decoded = LockAndMintPayload::from_canonical_bytes(&bytes).expect("decode");

        assert_eq!(decoded, payload);
    }

    #[test]
    fn burn_and_unlock_payload_roundtrip() {
        let payload = BurnAndUnlockPayload {
            wrapped_asset_id: "wIPN".to_string(),
            original_asset_id: "IPN".to_string(),
            amount: 250_000,
            burner: "alice_world".to_string(),
            unlocker: "alice".to_string(),
            memo: Some("redeem".to_string()),
        };

        let bytes = payload.to_canonical_bytes().expect("encode");
        let decoded = BurnAndUnlockPayload::from_canonical_bytes(&bytes).expect("decode");

        assert_eq!(decoded, payload);
    }

    // ========== Receipt Tests ==========

    #[test]
    fn prepare_receipt_hash_is_deterministic() {
        let receipt = PrepareReceipt {
            intent_id: IntentId(Hash32([0xAA; 32])),
            hub: L2HubId::Fin,
            prepared_ms: 1_700_000_100_000,
            lock_hash: Hash32([0xBB; 32]),
            details: Some("locked 1000 IPN".to_string()),
        };

        let hash1 = receipt.hash().unwrap();
        let hash2 = receipt.hash().unwrap();

        assert_eq!(hash1, hash2);
    }

    #[test]
    fn commit_receipt_hash_is_deterministic() {
        let receipt = CommitReceipt {
            intent_id: IntentId(Hash32([0xAA; 32])),
            hub: L2HubId::World,
            committed_ms: 1_700_000_200_000,
            finalize_hash: Hash32([0xCC; 32]),
            details: Some("credited 1000 IPN".to_string()),
        };

        let hash1 = receipt.hash().unwrap();
        let hash2 = receipt.hash().unwrap();

        assert_eq!(hash1, hash2);
    }

    // ========== Hub Transaction Tests ==========

    #[test]
    fn intent_hub_tx_canonical_bytes() {
        let tx = IntentHubTx::IntentPrepared {
            intent_id: IntentId(Hash32([0xAA; 32])),
            receipts_hash: Hash32([0xBB; 32]),
            prepared_ms: 1_700_000_100_000,
        };

        let bytes = tx.to_canonical_bytes().expect("encode");
        assert!(!bytes.is_empty());
    }

    #[test]
    fn intent_hub_tx_intent_id() {
        let id = IntentId(Hash32([0xAA; 32]));

        let prepared = IntentHubTx::IntentPrepared {
            intent_id: id,
            receipts_hash: Hash32([0xBB; 32]),
            prepared_ms: 1_700_000_100_000,
        };
        assert_eq!(prepared.intent_id(), &id);

        let committed = IntentHubTx::IntentCommitted {
            intent_id: id,
            receipts_hash: Hash32([0xCC; 32]),
            committed_ms: 1_700_000_200_000,
        };
        assert_eq!(committed.intent_id(), &id);

        let aborted = IntentHubTx::IntentAborted {
            intent_id: id,
            reason_hash: Hash32(canonical_hash_bytes(b"expired")),
            aborted_ms: 1_700_000_300_000,
        };
        assert_eq!(aborted.intent_id(), &id);
    }

    // ========== IntentHubTx to L2 Tx ==========

    #[test]
    fn intent_hub_tx_to_l2_tx() {
        let hub_tx = IntentHubTx::IntentPrepared {
            intent_id: IntentId(Hash32([0xAA; 32])),
            receipts_hash: Hash32([0xBB; 32]),
            prepared_ms: 1_700_000_100_000,
        };

        let l2_tx = hub_tx
            .to_l2_tx(crate::ChainId(1337), "bridge_coordinator", 42)
            .unwrap();

        assert_eq!(l2_tx.chain_id.0, 1337);
        assert_eq!(l2_tx.from, "bridge_coordinator");
        assert_eq!(l2_tx.nonce, 42);
        assert!(!l2_tx.payload.is_empty());
    }

    #[test]
    fn intent_hub_tx_phase_name() {
        let prepared = IntentHubTx::IntentPrepared {
            intent_id: IntentId(Hash32([0xAA; 32])),
            receipts_hash: Hash32([0xBB; 32]),
            prepared_ms: 1_700_000_100_000,
        };
        assert_eq!(prepared.phase_name(), "prepared");

        let committed = IntentHubTx::IntentCommitted {
            intent_id: IntentId(Hash32([0xAA; 32])),
            receipts_hash: Hash32([0xCC; 32]),
            committed_ms: 1_700_000_200_000,
        };
        assert_eq!(committed.phase_name(), "committed");

        let aborted = IntentHubTx::IntentAborted {
            intent_id: IntentId(Hash32([0xAA; 32])),
            reason_hash: Hash32(canonical_hash_bytes(b"expired")),
            aborted_ms: 1_700_000_300_000,
        };
        assert_eq!(aborted.phase_name(), "aborted");
    }

    #[test]
    fn intent_hub_tx_timestamp() {
        let tx = IntentHubTx::IntentPrepared {
            intent_id: IntentId(Hash32([0xAA; 32])),
            receipts_hash: Hash32([0xBB; 32]),
            prepared_ms: 1_700_000_100_000,
        };
        assert_eq!(tx.timestamp_ms(), 1_700_000_100_000);
    }

    #[test]
    fn intent_hub_tx_hash_is_deterministic() {
        let tx = IntentHubTx::IntentPrepared {
            intent_id: IntentId(Hash32([0xAA; 32])),
            receipts_hash: Hash32([0xBB; 32]),
            prepared_ms: 1_700_000_100_000,
        };

        let hash1 = tx.tx_hash().unwrap();
        let hash2 = tx.tx_hash().unwrap();

        assert_eq!(hash1, hash2);
    }

    // ========== IntentSettlementTx ==========

    #[test]
    fn intent_settlement_tx_creation() {
        let hub_tx = IntentHubTx::IntentPrepared {
            intent_id: IntentId(Hash32([0xAA; 32])),
            receipts_hash: Hash32([0xBB; 32]),
            prepared_ms: 1_700_000_100_000,
        };

        let mut settlement_tx = IntentSettlementTx::new(hub_tx, L2HubId::Bridge);

        assert_eq!(settlement_tx.hub, L2HubId::Bridge);
        assert!(settlement_tx.batch_hash.is_none());
        assert!(!settlement_tx.is_finalised);

        // Set batch hash
        let batch_hash = Hash32([0xCC; 32]);
        settlement_tx.set_batch_hash(batch_hash);
        assert_eq!(settlement_tx.batch_hash, Some(batch_hash));

        // Mark finalised
        settlement_tx.mark_finalised();
        assert!(settlement_tx.is_finalised);
    }

    // ========== IntentId Serialization ==========

    #[test]
    fn intent_id_hex_roundtrip() {
        let id = IntentId(Hash32([0x12; 32]));
        let hex_str = id.to_hex();
        let parsed = IntentId::from_hex(&hex_str).expect("parse");
        assert_eq!(parsed, id);
    }

    #[test]
    fn intent_id_display() {
        let id = IntentId(Hash32([0xAB; 32]));
        let display = format!("{}", id);
        assert_eq!(display, id.to_hex());
    }

    // ========== Time Until Expiry ==========

    #[test]
    fn time_until_expiry() {
        let intent = Intent {
            kind: IntentKind::CrossHubTransfer,
            created_ms: 1_700_000_000_000,
            expires_ms: 1_700_000_600_000,
            from_hub: L2HubId::Fin,
            to_hub: L2HubId::World,
            initiator: "alice".to_string(),
            payload: vec![],
        };

        assert_eq!(intent.time_until_expiry(1_700_000_000_000), 600_000);
        assert_eq!(intent.time_until_expiry(1_700_000_300_000), 300_000);
        assert_eq!(intent.time_until_expiry(1_700_000_600_000), 0);
        assert_eq!(intent.time_until_expiry(1_700_000_700_000), 0);
    }
}
