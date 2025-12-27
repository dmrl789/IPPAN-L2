//! Ethereum PoS Sync Committee Light Client Types.
//!
//! This module provides types for Ethereum PoS light client verification
//! using sync committees (EIP-4788/Beacon chain model).
//!
//! ## Design Principles
//!
//! - **Deterministic**: All hashing and validation is deterministic
//! - **Versioned**: Types are versioned (V1) for future upgrades
//! - **Bounded**: All variable-length fields have explicit bounds
//! - **Canonical**: Types support canonical encoding for hashing
//!
//! ## Trust Model
//!
//! This light client uses:
//! - **Trusted bootstrap**: Initial trusted beacon state + sync committee
//! - **Sync committee signatures**: BLS aggregate signatures for header attestations
//! - **Merkle proofs**: SSZ Merkle proofs for state transitions
//!
//! Unlike the checkpoint-based MVP, this provides cryptographic finality verification
//! without trusted third parties (other than the initial bootstrap).

use serde::{Deserialize, Serialize};
use thiserror::Error;

// ============== Constants ==============

/// Size of a sync committee (512 validators).
pub const SYNC_COMMITTEE_SIZE: usize = 512;

/// Number of bits in sync committee participation bitmap.
pub const SYNC_COMMITTEE_BITS_SIZE: usize = 64; // 512 / 8

/// Slots per epoch in Ethereum PoS.
pub const SLOTS_PER_EPOCH: u64 = 32;

/// Epochs per sync committee period.
pub const EPOCHS_PER_SYNC_COMMITTEE_PERIOD: u64 = 256;

/// Slots per sync committee period.
pub const SLOTS_PER_SYNC_COMMITTEE_PERIOD: u64 = SLOTS_PER_EPOCH * EPOCHS_PER_SYNC_COMMITTEE_PERIOD;

/// Minimum sync committee participants (2/3 majority).
pub const MIN_SYNC_COMMITTEE_PARTICIPANTS: u32 = 342; // 512 * 2 / 3

/// Maximum depth for Merkle proofs.
pub const MAX_MERKLE_PROOF_DEPTH: usize = 64;

/// Domain type for sync committee signatures.
pub const DOMAIN_SYNC_COMMITTEE: [u8; 4] = [0x07, 0x00, 0x00, 0x00];

/// Finalized root proof depth in beacon state.
pub const FINALIZED_ROOT_PROOF_DEPTH: usize = 6;

/// Next sync committee proof depth in beacon state.
pub const NEXT_SYNC_COMMITTEE_PROOF_DEPTH: usize = 5;

/// Execution payload proof depth.
pub const EXECUTION_PAYLOAD_PROOF_DEPTH: usize = 4;

// ============== Errors ==============

/// Errors from light client operations.
#[derive(Debug, Error)]
pub enum LightClientError {
    #[error("invalid beacon block header: {0}")]
    InvalidBeaconHeader(String),

    #[error("invalid execution payload header: {0}")]
    InvalidExecutionHeader(String),

    #[error("invalid sync committee: {0}")]
    InvalidSyncCommittee(String),

    #[error("invalid signature: {0}")]
    InvalidSignature(String),

    #[error("invalid merkle proof: {0}")]
    InvalidMerkleProof(String),

    #[error("insufficient participation: {got} < {required}")]
    InsufficientParticipation { got: u32, required: u32 },

    #[error("slot not finalized: {slot}")]
    SlotNotFinalized { slot: u64 },

    #[error("update not applicable: {0}")]
    UpdateNotApplicable(String),

    #[error("bootstrap already applied")]
    BootstrapAlreadyApplied,

    #[error("no bootstrap applied")]
    NoBootstrapApplied,

    #[error("feature not enabled: eth-lightclient")]
    FeatureNotEnabled,
}

// ============== Core Types ==============

/// 32-byte hash type (used for roots, block hashes, etc.).
pub type Root = [u8; 32];

/// 48-byte BLS public key.
pub type BLSPubkey = [u8; 48];

/// 96-byte BLS signature.
pub type BLSSignature = [u8; 96];

/// Beacon block header (V1 - Deneb compatible).
///
/// This is the consensus-layer block header that contains:
/// - Slot and proposer information
/// - Parent root and state root
/// - Body root (SSZ hash of block body)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BeaconBlockHeaderV1 {
    /// Slot number.
    pub slot: u64,

    /// Proposer validator index.
    pub proposer_index: u64,

    /// Parent block root (SSZ hash of parent header).
    #[serde(with = "hex_32")]
    pub parent_root: Root,

    /// State root after applying this block.
    #[serde(with = "hex_32")]
    pub state_root: Root,

    /// Body root (SSZ hash of block body).
    #[serde(with = "hex_32")]
    pub body_root: Root,
}

impl BeaconBlockHeaderV1 {
    /// Get the slot number.
    pub fn slot(&self) -> u64 {
        self.slot
    }

    /// Get the sync committee period for this slot.
    pub fn sync_committee_period(&self) -> u64 {
        self.slot / SLOTS_PER_SYNC_COMMITTEE_PERIOD
    }

    /// Get the epoch for this slot.
    pub fn epoch(&self) -> u64 {
        self.slot / SLOTS_PER_EPOCH
    }

    /// Validate basic structural properties.
    pub fn validate_basic(&self) -> Result<(), LightClientError> {
        // Parent root must not be zero (except for genesis)
        // State root must not be zero
        if self.state_root == [0u8; 32] {
            return Err(LightClientError::InvalidBeaconHeader(
                "state_root is zero".to_string(),
            ));
        }

        // Body root must not be zero
        if self.body_root == [0u8; 32] {
            return Err(LightClientError::InvalidBeaconHeader(
                "body_root is zero".to_string(),
            ));
        }

        Ok(())
    }
}

/// Execution payload header (V1 - Deneb compatible).
///
/// This is the execution-layer header embedded in the beacon block.
/// Contains all the fields needed to anchor receipt proofs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionPayloadHeaderV1 {
    /// Parent block hash (keccak256).
    #[serde(with = "hex_32")]
    pub parent_hash: Root,

    /// Fee recipient address.
    #[serde(with = "hex_20")]
    pub fee_recipient: [u8; 20],

    /// State root.
    #[serde(with = "hex_32")]
    pub state_root: Root,

    /// Receipts root (for Merkle proofs).
    #[serde(with = "hex_32")]
    pub receipts_root: Root,

    /// Logs bloom filter.
    #[serde(with = "hex_256")]
    pub logs_bloom: [u8; 256],

    /// Previous RANDAO value.
    #[serde(with = "hex_32")]
    pub prev_randao: Root,

    /// Block number (height).
    pub block_number: u64,

    /// Gas limit.
    pub gas_limit: u64,

    /// Gas used.
    pub gas_used: u64,

    /// Block timestamp.
    pub timestamp: u64,

    /// Extra data (max 32 bytes).
    #[serde(with = "hex_vec")]
    pub extra_data: Vec<u8>,

    /// Base fee per gas.
    pub base_fee_per_gas: u64,

    /// Block hash (keccak256 of execution header RLP).
    #[serde(with = "hex_32")]
    pub block_hash: Root,

    /// Transactions root.
    #[serde(with = "hex_32")]
    pub transactions_root: Root,

    /// Withdrawals root (post-Shanghai).
    #[serde(with = "hex_32")]
    pub withdrawals_root: Root,

    /// Blob gas used (post-Cancun).
    #[serde(default)]
    pub blob_gas_used: u64,

    /// Excess blob gas (post-Cancun).
    #[serde(default)]
    pub excess_blob_gas: u64,
}

impl ExecutionPayloadHeaderV1 {
    /// Get the block number.
    pub fn block_number(&self) -> u64 {
        self.block_number
    }

    /// Get the block hash.
    pub fn block_hash(&self) -> &Root {
        &self.block_hash
    }

    /// Get the receipts root.
    pub fn receipts_root(&self) -> &Root {
        &self.receipts_root
    }

    /// Get the timestamp.
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Validate basic structural properties.
    pub fn validate_basic(&self) -> Result<(), LightClientError> {
        // Block hash must not be zero
        if self.block_hash == [0u8; 32] {
            return Err(LightClientError::InvalidExecutionHeader(
                "block_hash is zero".to_string(),
            ));
        }

        // Block number must be > 0 (post-merge)
        // Note: This is a simplification; genesis handling would be different

        // Gas used must not exceed gas limit
        if self.gas_used > self.gas_limit {
            return Err(LightClientError::InvalidExecutionHeader(format!(
                "gas_used ({}) > gas_limit ({})",
                self.gas_used, self.gas_limit
            )));
        }

        // Extra data must not exceed 32 bytes
        if self.extra_data.len() > 32 {
            return Err(LightClientError::InvalidExecutionHeader(format!(
                "extra_data too large: {} > 32",
                self.extra_data.len()
            )));
        }

        Ok(())
    }
}

/// Sync committee (V1).
///
/// A sync committee is a group of 512 validators that attest to beacon block headers.
/// Committees rotate every ~27 hours (256 epochs).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncCommitteeV1 {
    /// Public keys of the 512 committee members.
    #[serde(with = "hex_pubkeys")]
    pub pubkeys: Vec<BLSPubkey>,

    /// Aggregate public key of the committee.
    #[serde(with = "hex_48")]
    pub aggregate_pubkey: BLSPubkey,
}

impl SyncCommitteeV1 {
    /// Validate the sync committee.
    pub fn validate(&self) -> Result<(), LightClientError> {
        if self.pubkeys.len() != SYNC_COMMITTEE_SIZE {
            return Err(LightClientError::InvalidSyncCommittee(format!(
                "expected {} pubkeys, got {}",
                SYNC_COMMITTEE_SIZE,
                self.pubkeys.len()
            )));
        }

        // Aggregate pubkey must not be zero
        if self.aggregate_pubkey == [0u8; 48] {
            return Err(LightClientError::InvalidSyncCommittee(
                "aggregate_pubkey is zero".to_string(),
            ));
        }

        Ok(())
    }
}

/// Light client bootstrap data (V1).
///
/// This is the initial data needed to bootstrap a light client.
/// Obtained from a trusted source (e.g., checkpoint sync provider).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LightClientBootstrapV1 {
    /// The trusted beacon block header.
    pub header: BeaconBlockHeaderV1,

    /// The current sync committee for the header's period.
    pub current_sync_committee: SyncCommitteeV1,

    /// Merkle proof from state root to current sync committee.
    #[serde(with = "hex_proof")]
    pub current_sync_committee_branch: Vec<Root>,
}

impl LightClientBootstrapV1 {
    /// Validate the bootstrap data.
    pub fn validate_basic(&self) -> Result<(), LightClientError> {
        self.header.validate_basic()?;
        self.current_sync_committee.validate()?;

        // Proof depth should be appropriate
        if self.current_sync_committee_branch.len() > MAX_MERKLE_PROOF_DEPTH {
            return Err(LightClientError::InvalidMerkleProof(format!(
                "sync committee branch too deep: {}",
                self.current_sync_committee_branch.len()
            )));
        }

        Ok(())
    }

    /// Get the sync committee period for this bootstrap.
    pub fn sync_committee_period(&self) -> u64 {
        self.header.sync_committee_period()
    }

    /// Compute a deterministic ID for this bootstrap.
    pub fn bootstrap_id(&self) -> Root {
        let mut data = Vec::new();
        data.extend_from_slice(&self.header.slot.to_le_bytes());
        data.extend_from_slice(&self.header.state_root);
        blake3::hash(&data).into()
    }
}

/// Sync aggregate (committee signature data).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SyncAggregateV1 {
    /// Participation bits (which validators signed).
    #[serde(with = "hex_vec")]
    pub sync_committee_bits: Vec<u8>,

    /// Aggregate BLS signature.
    #[serde(with = "hex_96")]
    pub sync_committee_signature: BLSSignature,
}

impl SyncAggregateV1 {
    /// Count the number of participants (set bits).
    pub fn num_participants(&self) -> u32 {
        self.sync_committee_bits
            .iter()
            .map(|b| b.count_ones())
            .sum()
    }

    /// Check if participation meets the minimum threshold.
    pub fn has_sufficient_participation(&self) -> bool {
        self.num_participants() >= MIN_SYNC_COMMITTEE_PARTICIPANTS
    }

    /// Validate the sync aggregate.
    pub fn validate(&self) -> Result<(), LightClientError> {
        // Bits must be exactly 64 bytes (512 bits)
        if self.sync_committee_bits.len() != SYNC_COMMITTEE_BITS_SIZE {
            return Err(LightClientError::InvalidSignature(format!(
                "expected {} bytes for sync_committee_bits, got {}",
                SYNC_COMMITTEE_BITS_SIZE,
                self.sync_committee_bits.len()
            )));
        }

        // Signature must not be zero
        if self.sync_committee_signature == [0u8; 96] {
            return Err(LightClientError::InvalidSignature(
                "signature is zero".to_string(),
            ));
        }

        Ok(())
    }
}

/// Light client update (V1).
///
/// Contains the data needed to advance the light client state.
/// Includes attested header, finalized header, and optional sync committee update.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LightClientUpdateV1 {
    /// The header being attested to by the sync committee.
    pub attested_header: BeaconBlockHeaderV1,

    /// The next sync committee (if this update crosses a period boundary).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_sync_committee: Option<SyncCommitteeV1>,

    /// Merkle proof for next sync committee (if present).
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "hex_proof_opt"
    )]
    pub next_sync_committee_branch: Option<Vec<Root>>,

    /// The finalized header (must be ancestor of attested header).
    pub finalized_header: BeaconBlockHeaderV1,

    /// Merkle proof from attested state to finalized checkpoint root.
    #[serde(with = "hex_proof")]
    pub finality_branch: Vec<Root>,

    /// The sync committee aggregate signature.
    pub sync_aggregate: SyncAggregateV1,

    /// The slot at which the sync committee signed.
    pub signature_slot: u64,
}

impl LightClientUpdateV1 {
    /// Validate the update structure (not cryptographic validity).
    pub fn validate_basic(&self) -> Result<(), LightClientError> {
        self.attested_header.validate_basic()?;
        self.finalized_header.validate_basic()?;
        self.sync_aggregate.validate()?;

        // Check participation threshold
        if !self.sync_aggregate.has_sufficient_participation() {
            return Err(LightClientError::InsufficientParticipation {
                got: self.sync_aggregate.num_participants(),
                required: MIN_SYNC_COMMITTEE_PARTICIPANTS,
            });
        }

        // Finalized header must be at or before attested header
        if self.finalized_header.slot > self.attested_header.slot {
            return Err(LightClientError::InvalidBeaconHeader(
                "finalized_header.slot > attested_header.slot".to_string(),
            ));
        }

        // Signature slot must be after attested header slot
        if self.signature_slot <= self.attested_header.slot {
            return Err(LightClientError::InvalidSignature(
                "signature_slot must be after attested_header.slot".to_string(),
            ));
        }

        // Finality branch must have appropriate depth
        if self.finality_branch.len() > MAX_MERKLE_PROOF_DEPTH {
            return Err(LightClientError::InvalidMerkleProof(format!(
                "finality branch too deep: {}",
                self.finality_branch.len()
            )));
        }

        // If next sync committee is present, branch must also be present
        if self.next_sync_committee.is_some() != self.next_sync_committee_branch.is_some() {
            return Err(LightClientError::InvalidSyncCommittee(
                "next_sync_committee and branch must both be present or absent".to_string(),
            ));
        }

        // Validate next sync committee if present
        if let Some(ref committee) = self.next_sync_committee {
            committee.validate()?;
        }

        Ok(())
    }

    /// Get the sync committee period for the attested header.
    pub fn attested_period(&self) -> u64 {
        self.attested_header.sync_committee_period()
    }

    /// Get the sync committee period for the signature slot.
    pub fn signature_period(&self) -> u64 {
        self.signature_slot / SLOTS_PER_SYNC_COMMITTEE_PERIOD
    }

    /// Get the sync committee period for the finalized header.
    pub fn finalized_period(&self) -> u64 {
        self.finalized_header.sync_committee_period()
    }

    /// Check if this update includes a sync committee rotation.
    pub fn has_sync_committee_update(&self) -> bool {
        self.next_sync_committee.is_some()
    }

    /// Compute a deterministic ID for this update.
    pub fn update_id(&self) -> Root {
        let mut data = Vec::new();
        data.extend_from_slice(&self.attested_header.slot.to_le_bytes());
        data.extend_from_slice(&self.attested_header.state_root);
        data.extend_from_slice(&self.finalized_header.slot.to_le_bytes());
        data.extend_from_slice(&self.finalized_header.state_root);
        data.extend_from_slice(&self.signature_slot.to_le_bytes());
        blake3::hash(&data).into()
    }
}

/// Light client finality update (simplified update without sync committee rotation).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LightClientFinalityUpdateV1 {
    /// The header being attested to.
    pub attested_header: BeaconBlockHeaderV1,

    /// The finalized header.
    pub finalized_header: BeaconBlockHeaderV1,

    /// Merkle proof for finalized checkpoint.
    #[serde(with = "hex_proof")]
    pub finality_branch: Vec<Root>,

    /// The sync aggregate.
    pub sync_aggregate: SyncAggregateV1,

    /// Signature slot.
    pub signature_slot: u64,
}

impl LightClientFinalityUpdateV1 {
    /// Convert to a full update (without sync committee rotation).
    pub fn to_full_update(&self) -> LightClientUpdateV1 {
        LightClientUpdateV1 {
            attested_header: self.attested_header.clone(),
            next_sync_committee: None,
            next_sync_committee_branch: None,
            finalized_header: self.finalized_header.clone(),
            finality_branch: self.finality_branch.clone(),
            sync_aggregate: self.sync_aggregate.clone(),
            signature_slot: self.signature_slot,
        }
    }
}

/// Trusted bootstrap configuration.
///
/// This is the initial trusted state for bootstrapping the light client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedBootstrap {
    /// The trusted beacon block root.
    #[serde(with = "hex_32")]
    pub beacon_block_root: Root,

    /// The slot of the trusted block.
    pub slot: u64,

    /// The sync committee period.
    pub sync_committee_period: u64,

    /// Optional: genesis validators root for domain computation.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "hex_32_opt")]
    pub genesis_validators_root: Option<Root>,

    /// Chain identifier.
    #[serde(default)]
    pub chain_id: u64,
}

impl TrustedBootstrap {
    /// Create a new trusted bootstrap.
    pub fn new(beacon_block_root: Root, slot: u64, chain_id: u64) -> Self {
        Self {
            beacon_block_root,
            slot,
            sync_committee_period: slot / SLOTS_PER_SYNC_COMMITTEE_PERIOD,
            genesis_validators_root: None,
            chain_id,
        }
    }

    /// With genesis validators root.
    pub fn with_genesis_validators_root(mut self, root: Root) -> Self {
        self.genesis_validators_root = Some(root);
        self
    }
}

/// Light client store state (what we persist).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LightClientStoreV1 {
    /// The finalized beacon block header.
    pub finalized_header: BeaconBlockHeaderV1,

    /// The current sync committee.
    pub current_sync_committee: SyncCommitteeV1,

    /// The next sync committee (if known).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_sync_committee: Option<SyncCommitteeV1>,

    /// The optimistic header (best unfinalized).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optimistic_header: Option<BeaconBlockHeaderV1>,

    /// The latest finalized execution payload header.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finalized_execution_header: Option<ExecutionPayloadHeaderV1>,

    /// Timestamp when this state was last updated (ms since epoch).
    pub updated_at_ms: u64,
}

impl LightClientStoreV1 {
    /// Get the current sync committee period.
    pub fn current_period(&self) -> u64 {
        self.finalized_header.sync_committee_period()
    }

    /// Get the finalized slot.
    pub fn finalized_slot(&self) -> u64 {
        self.finalized_header.slot
    }

    /// Get the finalized execution block number.
    pub fn finalized_execution_block_number(&self) -> Option<u64> {
        self.finalized_execution_header
            .as_ref()
            .map(|h| h.block_number)
    }

    /// Get the finalized execution block hash.
    pub fn finalized_execution_block_hash(&self) -> Option<&Root> {
        self.finalized_execution_header
            .as_ref()
            .map(|h| &h.block_hash)
    }
}

/// Summary of light client state for API responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightClientStatusV1 {
    /// Whether bootstrap has been applied.
    pub bootstrapped: bool,

    /// Current sync committee period.
    pub current_period: u64,

    /// Finalized beacon slot.
    pub finalized_slot: u64,

    /// Finalized execution block number.
    pub finalized_execution_number: Option<u64>,

    /// Finalized execution block hash.
    #[serde(default, skip_serializing_if = "Option::is_none", with = "hex_32_opt")]
    pub finalized_execution_hash: Option<Root>,

    /// Whether next sync committee is known.
    pub has_next_sync_committee: bool,

    /// Number of updates applied.
    pub updates_applied: u64,

    /// Last update timestamp (ms).
    pub last_update_ms: Option<u64>,
}

// ============== Helper Types ==============

/// Update applicability result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UpdateApplicability {
    /// Update can be applied.
    Applicable,
    /// Update is for a future period (need to wait).
    FuturePeriod { current: u64, update: u64 },
    /// Update is for a past period (already processed).
    PastPeriod { current: u64, update: u64 },
    /// Update is already applied (idempotent).
    AlreadyApplied,
    /// Update has insufficient participation.
    InsufficientParticipation { got: u32, required: u32 },
}

impl UpdateApplicability {
    /// Check if the update is applicable.
    pub fn is_applicable(&self) -> bool {
        matches!(self, Self::Applicable)
    }
}

// ============== Serde Helpers ==============

mod hex_32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.strip_prefix("0x").unwrap_or(&s);
        let raw = hex::decode(s).map_err(serde::de::Error::custom)?;
        if raw.len() != 32 {
            return Err(serde::de::Error::custom(format!(
                "expected 32 bytes, got {}",
                raw.len()
            )));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&raw);
        Ok(out)
    }
}

mod hex_32_opt {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match bytes {
            Some(b) => serializer.serialize_some(&hex::encode(b)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                let s = s.strip_prefix("0x").unwrap_or(&s);
                let raw = hex::decode(s).map_err(serde::de::Error::custom)?;
                if raw.len() != 32 {
                    return Err(serde::de::Error::custom(format!(
                        "expected 32 bytes, got {}",
                        raw.len()
                    )));
                }
                let mut out = [0u8; 32];
                out.copy_from_slice(&raw);
                Ok(Some(out))
            }
            None => Ok(None),
        }
    }
}

mod hex_20 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 20], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 20], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.strip_prefix("0x").unwrap_or(&s);
        let raw = hex::decode(s).map_err(serde::de::Error::custom)?;
        if raw.len() != 20 {
            return Err(serde::de::Error::custom(format!(
                "expected 20 bytes, got {}",
                raw.len()
            )));
        }
        let mut out = [0u8; 20];
        out.copy_from_slice(&raw);
        Ok(out)
    }
}

mod hex_48 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 48], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 48], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.strip_prefix("0x").unwrap_or(&s);
        let raw = hex::decode(s).map_err(serde::de::Error::custom)?;
        if raw.len() != 48 {
            return Err(serde::de::Error::custom(format!(
                "expected 48 bytes, got {}",
                raw.len()
            )));
        }
        let mut out = [0u8; 48];
        out.copy_from_slice(&raw);
        Ok(out)
    }
}

mod hex_96 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 96], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 96], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.strip_prefix("0x").unwrap_or(&s);
        let raw = hex::decode(s).map_err(serde::de::Error::custom)?;
        if raw.len() != 96 {
            return Err(serde::de::Error::custom(format!(
                "expected 96 bytes, got {}",
                raw.len()
            )));
        }
        let mut out = [0u8; 96];
        out.copy_from_slice(&raw);
        Ok(out)
    }
}

mod hex_256 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 256], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 256], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.strip_prefix("0x").unwrap_or(&s);
        let raw = hex::decode(s).map_err(serde::de::Error::custom)?;
        if raw.len() != 256 {
            return Err(serde::de::Error::custom(format!(
                "expected 256 bytes, got {}",
                raw.len()
            )));
        }
        let mut out = [0u8; 256];
        out.copy_from_slice(&raw);
        Ok(out)
    }
}

mod hex_vec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.strip_prefix("0x").unwrap_or(&s);
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}

mod hex_pubkeys {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(pubkeys: &[[u8; 48]], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(pubkeys.len()))?;
        for pk in pubkeys {
            seq.serialize_element(&hex::encode(pk))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<[u8; 48]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let strings: Vec<String> = Vec::deserialize(deserializer)?;
        strings
            .into_iter()
            .map(|s| {
                let s = s.strip_prefix("0x").unwrap_or(&s);
                let raw = hex::decode(s).map_err(serde::de::Error::custom)?;
                if raw.len() != 48 {
                    return Err(serde::de::Error::custom(format!(
                        "expected 48 bytes, got {}",
                        raw.len()
                    )));
                }
                let mut out = [0u8; 48];
                out.copy_from_slice(&raw);
                Ok(out)
            })
            .collect()
    }
}

mod hex_proof {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(proof: &[[u8; 32]], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(proof.len()))?;
        for node in proof {
            seq.serialize_element(&hex::encode(node))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let strings: Vec<String> = Vec::deserialize(deserializer)?;
        strings
            .into_iter()
            .map(|s| {
                let s = s.strip_prefix("0x").unwrap_or(&s);
                let raw = hex::decode(s).map_err(serde::de::Error::custom)?;
                if raw.len() != 32 {
                    return Err(serde::de::Error::custom(format!(
                        "expected 32 bytes, got {}",
                        raw.len()
                    )));
                }
                let mut out = [0u8; 32];
                out.copy_from_slice(&raw);
                Ok(out)
            })
            .collect()
    }
}

mod hex_proof_opt {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(proof: &Option<Vec<[u8; 32]>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match proof {
            Some(p) => {
                use serde::ser::SerializeSeq;
                let mut seq = serializer.serialize_seq(Some(p.len()))?;
                for node in p {
                    seq.serialize_element(&hex::encode(node))?;
                }
                seq.end()
            }
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Vec<[u8; 32]>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<Vec<String>> = Option::deserialize(deserializer)?;
        match opt {
            Some(strings) => {
                let proof: Result<Vec<[u8; 32]>, _> = strings
                    .into_iter()
                    .map(|s| {
                        let s = s.strip_prefix("0x").unwrap_or(&s);
                        let raw = hex::decode(s).map_err(serde::de::Error::custom)?;
                        if raw.len() != 32 {
                            return Err(serde::de::Error::custom(format!(
                                "expected 32 bytes, got {}",
                                raw.len()
                            )));
                        }
                        let mut out = [0u8; 32];
                        out.copy_from_slice(&raw);
                        Ok(out)
                    })
                    .collect();
                Ok(Some(proof?))
            }
            None => Ok(None),
        }
    }
}

// ============== Tests ==============

#[cfg(test)]
mod tests {
    use super::*;

    fn test_beacon_header() -> BeaconBlockHeaderV1 {
        BeaconBlockHeaderV1 {
            slot: 8_000_000,
            proposer_index: 12345,
            parent_root: [0x11; 32],
            state_root: [0x22; 32],
            body_root: [0x33; 32],
        }
    }

    fn test_execution_header() -> ExecutionPayloadHeaderV1 {
        ExecutionPayloadHeaderV1 {
            parent_hash: [0x11; 32],
            fee_recipient: [0x22; 20],
            state_root: [0x33; 32],
            receipts_root: [0x44; 32],
            logs_bloom: [0x00; 256],
            prev_randao: [0x55; 32],
            block_number: 18_000_000,
            gas_limit: 30_000_000,
            gas_used: 15_000_000,
            timestamp: 1_700_000_000,
            extra_data: vec![],
            base_fee_per_gas: 10_000_000_000,
            block_hash: [0x66; 32],
            transactions_root: [0x77; 32],
            withdrawals_root: [0x88; 32],
            blob_gas_used: 0,
            excess_blob_gas: 0,
        }
    }

    fn test_sync_committee() -> SyncCommitteeV1 {
        SyncCommitteeV1 {
            pubkeys: vec![[0xAA; 48]; SYNC_COMMITTEE_SIZE],
            aggregate_pubkey: [0xBB; 48],
        }
    }

    #[test]
    fn beacon_header_validate_basic() {
        let header = test_beacon_header();
        assert!(header.validate_basic().is_ok());
    }

    #[test]
    fn beacon_header_validate_zero_state_root() {
        let mut header = test_beacon_header();
        header.state_root = [0; 32];
        assert!(header.validate_basic().is_err());
    }

    #[test]
    fn beacon_header_sync_committee_period() {
        let mut header = test_beacon_header();
        header.slot = SLOTS_PER_SYNC_COMMITTEE_PERIOD * 5;
        assert_eq!(header.sync_committee_period(), 5);
    }

    #[test]
    fn execution_header_validate_basic() {
        let header = test_execution_header();
        assert!(header.validate_basic().is_ok());
    }

    #[test]
    fn execution_header_validate_gas_overflow() {
        let mut header = test_execution_header();
        header.gas_used = 40_000_000;
        assert!(header.validate_basic().is_err());
    }

    #[test]
    fn sync_committee_validate() {
        let committee = test_sync_committee();
        assert!(committee.validate().is_ok());
    }

    #[test]
    fn sync_committee_validate_wrong_size() {
        let mut committee = test_sync_committee();
        committee.pubkeys.pop();
        assert!(committee.validate().is_err());
    }

    #[test]
    fn sync_aggregate_participation() {
        let mut aggregate = SyncAggregateV1 {
            sync_committee_bits: vec![0xFF; SYNC_COMMITTEE_BITS_SIZE],
            sync_committee_signature: [0xCC; 96],
        };

        // All bits set = 512 participants
        assert_eq!(aggregate.num_participants(), 512);
        assert!(aggregate.has_sufficient_participation());

        // Reduce to 300 participants (below threshold)
        aggregate.sync_committee_bits = vec![0; SYNC_COMMITTEE_BITS_SIZE];
        for i in 0..37 {
            // 37 * 8 = 296, plus some
            aggregate.sync_committee_bits[i] = 0xFF;
        }
        aggregate.sync_committee_bits[37] = 0x0F; // 4 more
        assert_eq!(aggregate.num_participants(), 300);
        assert!(!aggregate.has_sufficient_participation());
    }

    #[test]
    fn light_client_update_validate_basic() {
        let update = LightClientUpdateV1 {
            attested_header: test_beacon_header(),
            next_sync_committee: None,
            next_sync_committee_branch: None,
            finalized_header: BeaconBlockHeaderV1 {
                slot: 7_999_900,
                ..test_beacon_header()
            },
            finality_branch: vec![[0xDD; 32]; 6],
            sync_aggregate: SyncAggregateV1 {
                sync_committee_bits: vec![0xFF; SYNC_COMMITTEE_BITS_SIZE],
                sync_committee_signature: [0xEE; 96],
            },
            signature_slot: 8_000_001,
        };

        assert!(update.validate_basic().is_ok());
    }

    #[test]
    fn light_client_update_validate_finalized_after_attested() {
        let update = LightClientUpdateV1 {
            attested_header: test_beacon_header(),
            next_sync_committee: None,
            next_sync_committee_branch: None,
            finalized_header: BeaconBlockHeaderV1 {
                slot: 9_000_000, // After attested
                ..test_beacon_header()
            },
            finality_branch: vec![[0xDD; 32]; 6],
            sync_aggregate: SyncAggregateV1 {
                sync_committee_bits: vec![0xFF; SYNC_COMMITTEE_BITS_SIZE],
                sync_committee_signature: [0xEE; 96],
            },
            signature_slot: 8_000_001,
        };

        assert!(update.validate_basic().is_err());
    }

    #[test]
    fn update_id_deterministic() {
        let update = LightClientUpdateV1 {
            attested_header: test_beacon_header(),
            next_sync_committee: None,
            next_sync_committee_branch: None,
            finalized_header: test_beacon_header(),
            finality_branch: vec![],
            sync_aggregate: SyncAggregateV1 {
                sync_committee_bits: vec![0xFF; SYNC_COMMITTEE_BITS_SIZE],
                sync_committee_signature: [0; 96],
            },
            signature_slot: 8_000_001,
        };

        let id1 = update.update_id();
        let id2 = update.update_id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn bootstrap_id_deterministic() {
        let bootstrap = LightClientBootstrapV1 {
            header: test_beacon_header(),
            current_sync_committee: test_sync_committee(),
            current_sync_committee_branch: vec![[0xFF; 32]; 5],
        };

        let id1 = bootstrap.bootstrap_id();
        let id2 = bootstrap.bootstrap_id();
        assert_eq!(id1, id2);
    }

    #[test]
    fn json_roundtrip_beacon_header() {
        let header = test_beacon_header();
        let json = serde_json::to_string(&header).expect("serialize");
        let parsed: BeaconBlockHeaderV1 = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(header, parsed);
    }

    #[test]
    fn json_roundtrip_execution_header() {
        let header = test_execution_header();
        let json = serde_json::to_string(&header).expect("serialize");
        let parsed: ExecutionPayloadHeaderV1 = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(header, parsed);
    }

    #[test]
    fn json_roundtrip_sync_committee() {
        let committee = test_sync_committee();
        let json = serde_json::to_string(&committee).expect("serialize");
        let parsed: SyncCommitteeV1 = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(committee, parsed);
    }
}
