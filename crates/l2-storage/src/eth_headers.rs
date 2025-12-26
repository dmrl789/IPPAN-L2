//! Ethereum Header Chain Storage.
//!
//! This module provides persistent storage for Ethereum block headers,
//! enabling deterministic header chain verification for the IPPAN bridge.
//!
//! ## Features
//!
//! - Store headers by hash
//! - Track parent-child relationships
//! - Maintain best tip (highest block on verified chain)
//! - Compute confirmations deterministically
//! - Handle reorgs with deterministic tie-breaking
//!
//! ## Trust Model
//!
//! Headers are stored with explicit verification state. Only headers
//! descending from trusted checkpoints are considered "verified".
//!
//! ## Fork Choice Rule
//!
//! The best tip is selected deterministically:
//! 1. Highest block number wins
//! 2. Tie-break by lexicographically smaller hash (deterministic)

use l2_core::eth_header::{EthereumHeaderV1, HeaderId, Hash256};
use sled::Tree;
use std::cmp::Ordering;
use thiserror::Error;
use tracing::{debug, info};

/// JSON encode for storage (more flexible than bincode for complex types).
fn json_encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, EthHeaderStorageError> {
    serde_json::to_vec(value)
        .map_err(|e| EthHeaderStorageError::ValidationFailed(format!("json encode: {}", e)))
}

/// JSON decode from storage.
fn json_decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, EthHeaderStorageError> {
    serde_json::from_slice(bytes)
        .map_err(|e| EthHeaderStorageError::ValidationFailed(format!("json decode: {}", e)))
}

/// Errors from Ethereum header storage operations.
#[derive(Debug, Error)]
pub enum EthHeaderStorageError {
    #[error("storage error: {0}")]
    Sled(#[from] sled::Error),

    #[error("canonical encoding error: {0}")]
    Canonical(#[from] l2_core::CanonicalError),

    #[error("header not found: {0}")]
    NotFound(String),

    #[error("invalid parent: expected {expected}, got {got}")]
    InvalidParent { expected: String, got: String },

    #[error("header validation failed: {0}")]
    ValidationFailed(String),

    #[error("chain not verified: header {0} not descending from checkpoint")]
    NotVerified(String),
}

/// Verification state for a stored header.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum HeaderVerificationState {
    /// Header is stored but not on a verified chain.
    Unverified,

    /// Header is on a verified chain (descends from a trusted checkpoint).
    Verified,

    /// Header is a trusted checkpoint (explicitly trusted).
    Checkpoint,
}

impl HeaderVerificationState {
    /// Check if this header is verified or better.
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified | Self::Checkpoint)
    }

    /// Check if this is a checkpoint.
    pub fn is_checkpoint(&self) -> bool {
        matches!(self, Self::Checkpoint)
    }

    /// Get the state name as a string.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Unverified => "unverified",
            Self::Verified => "verified",
            Self::Checkpoint => "checkpoint",
        }
    }
}

/// Stored header with metadata.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct StoredHeader {
    /// The header data.
    pub header: EthereumHeaderV1,

    /// Computed header hash.
    #[serde(with = "hex_32")]
    pub header_hash: Hash256,

    /// Verification state.
    pub state: HeaderVerificationState,

    /// Timestamp when stored (ms since epoch).
    pub stored_at_ms: u64,
}

/// Entry for listing headers.
#[derive(Debug, Clone)]
pub struct HeaderEntry {
    /// Header ID (hash).
    pub id: HeaderId,

    /// Block number.
    pub number: u64,

    /// Parent hash.
    pub parent_hash: Hash256,

    /// Verification state.
    pub state: HeaderVerificationState,

    /// Timestamp.
    pub timestamp: u64,
}

/// Counts of headers by verification state.
#[derive(Debug, Clone, Default)]
pub struct HeaderCounts {
    pub unverified: u64,
    pub verified: u64,
    pub checkpoints: u64,
}

impl HeaderCounts {
    /// Total number of headers stored.
    pub fn total(&self) -> u64 {
        self.unverified
            .saturating_add(self.verified)
            .saturating_add(self.checkpoints)
    }
}

/// Best tip information.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BestTip {
    /// Header hash of the best tip.
    #[serde(with = "hex_32")]
    pub header_hash: Hash256,

    /// Block number.
    pub number: u64,

    /// Timestamp when tip was updated (ms since epoch).
    pub updated_at_ms: u64,
}

/// Ethereum header chain storage.
///
/// Provides crash-safe storage with parent linking and best tip tracking.
pub struct EthHeaderStorage {
    /// Headers by hash (header_hash_hex -> StoredHeader).
    headers: Tree,

    /// Height index (be_number_bytes || header_hash -> "").
    /// Used for efficient height queries and fork detection.
    height_index: Tree,

    /// Best tip metadata.
    best_tip: Tree,

    /// Checkpoints (header_hash_hex -> "").
    checkpoints: Tree,

    /// Chain ID for this storage (e.g., 1 for mainnet).
    chain_id: u64,
}

impl EthHeaderStorage {
    /// Create a new EthHeaderStorage from a sled database.
    ///
    /// Each chain ID gets separate trees to support multi-chain operation.
    pub fn new(db: &sled::Db, chain_id: u64) -> Result<Self, EthHeaderStorageError> {
        let prefix = format!("eth_headers_{}", chain_id);
        Ok(Self {
            headers: db.open_tree(format!("{}_headers", prefix))?,
            height_index: db.open_tree(format!("{}_height", prefix))?,
            best_tip: db.open_tree(format!("{}_best_tip", prefix))?,
            checkpoints: db.open_tree(format!("{}_checkpoints", prefix))?,
            chain_id,
        })
    }

    /// Get the chain ID for this storage.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Add a trusted checkpoint.
    ///
    /// Checkpoints are the roots of trust for the header chain.
    /// Headers descending from checkpoints are considered verified.
    pub fn add_checkpoint(
        &self,
        header: &EthereumHeaderV1,
        stored_at_ms: u64,
    ) -> Result<HeaderId, EthHeaderStorageError> {
        // Compute header hash
        let header_hash = header.header_hash();
        let id = HeaderId(header_hash);

        // Store as checkpoint
        let stored = StoredHeader {
            header: header.clone(),
            header_hash,
            state: HeaderVerificationState::Checkpoint,
            stored_at_ms,
        };

        let key = hex::encode(header_hash);
        let bytes = json_encode(&stored)?;
        self.headers.insert(key.as_bytes(), bytes)?;

        // Add to checkpoints set
        self.checkpoints.insert(key.as_bytes(), &[])?;

        // Add to height index
        self.add_to_height_index(header.number, &header_hash)?;

        // Update best tip if this is higher
        self.maybe_update_best_tip(&header_hash, header.number, stored_at_ms)?;

        info!(
            chain_id = self.chain_id,
            header_hash = %hex::encode(header_hash),
            number = header.number,
            "added checkpoint header"
        );

        Ok(id)
    }

    /// Store a header.
    ///
    /// The header is validated for structural correctness and parent linking.
    /// Verification state is determined by ancestry from checkpoints.
    ///
    /// Returns `Ok(true)` if the header was new, `Ok(false)` if it already existed.
    pub fn put_header(
        &self,
        header: &EthereumHeaderV1,
        stored_at_ms: u64,
    ) -> Result<bool, EthHeaderStorageError> {
        // Validate basic structure
        header
            .validate_basic()
            .map_err(|e| EthHeaderStorageError::ValidationFailed(e.to_string()))?;

        // Compute header hash
        let header_hash = header.header_hash();
        let key = hex::encode(header_hash);

        // Check if already exists
        if self.headers.contains_key(key.as_bytes())? {
            return Ok(false);
        }

        // Check parent exists (unless this is block 0 / genesis)
        let state = if header.number == 0 {
            // Genesis block - treat as unverified unless it's a checkpoint
            if self.checkpoints.contains_key(key.as_bytes())? {
                HeaderVerificationState::Checkpoint
            } else {
                HeaderVerificationState::Unverified
            }
        } else {
            // Check parent
            let parent_key = hex::encode(header.parent_hash);
            match self.get_header_internal(&parent_key)? {
                Some(parent_stored) => {
                    // Parent exists - verify number increments
                    if parent_stored.header.number + 1 != header.number {
                        return Err(EthHeaderStorageError::ValidationFailed(format!(
                            "number mismatch: parent={}, this={}",
                            parent_stored.header.number, header.number
                        )));
                    }

                    // Verify timestamp >= parent timestamp
                    if header.timestamp < parent_stored.header.timestamp {
                        return Err(EthHeaderStorageError::ValidationFailed(format!(
                            "timestamp {} < parent timestamp {}",
                            header.timestamp, parent_stored.header.timestamp
                        )));
                    }

                    // Inherit verification state from parent
                    if parent_stored.state.is_verified() {
                        HeaderVerificationState::Verified
                    } else {
                        HeaderVerificationState::Unverified
                    }
                }
                None => {
                    // Parent doesn't exist - store as unverified
                    debug!(
                        parent_hash = %hex::encode(header.parent_hash),
                        "storing header with unknown parent"
                    );
                    HeaderVerificationState::Unverified
                }
            }
        };

        // Store the header
        let stored = StoredHeader {
            header: header.clone(),
            header_hash,
            state,
            stored_at_ms,
        };

        let bytes = json_encode(&stored)?;
        self.headers.insert(key.as_bytes(), bytes)?;

        // Add to height index
        self.add_to_height_index(header.number, &header_hash)?;

        // Update best tip if verified and higher
        if state.is_verified() {
            self.maybe_update_best_tip(&header_hash, header.number, stored_at_ms)?;
        }

        debug!(
            chain_id = self.chain_id,
            header_hash = %hex::encode(header_hash),
            number = header.number,
            state = ?state,
            "stored header"
        );

        Ok(true)
    }

    /// Get a header by hash.
    pub fn get_header(&self, id: &HeaderId) -> Result<Option<StoredHeader>, EthHeaderStorageError> {
        let key = hex::encode(id.0);
        self.get_header_internal(&key)
    }

    /// Get a header by hash (hex string key).
    fn get_header_internal(&self, key: &str) -> Result<Option<StoredHeader>, EthHeaderStorageError> {
        match self.headers.get(key.as_bytes())? {
            Some(bytes) => {
                let stored: StoredHeader = json_decode(&bytes)?;
                Ok(Some(stored))
            }
            None => Ok(None),
        }
    }

    /// Check if a header exists.
    pub fn header_exists(&self, id: &HeaderId) -> Result<bool, EthHeaderStorageError> {
        let key = hex::encode(id.0);
        Ok(self.headers.contains_key(key.as_bytes())?)
    }

    /// Get the best tip (highest verified block).
    pub fn get_best_tip(&self) -> Result<Option<BestTip>, EthHeaderStorageError> {
        match self.best_tip.get(b"best")? {
            Some(bytes) => {
                let tip: BestTip = json_decode(&bytes)?;
                Ok(Some(tip))
            }
            None => Ok(None),
        }
    }

    /// Set the best tip explicitly.
    ///
    /// Use with caution - normally best tip is updated automatically.
    pub fn set_best_tip(
        &self,
        header_hash: &Hash256,
        number: u64,
        updated_at_ms: u64,
    ) -> Result<(), EthHeaderStorageError> {
        let tip = BestTip {
            header_hash: *header_hash,
            number,
            updated_at_ms,
        };
        let bytes = json_encode(&tip)?;
        self.best_tip.insert(b"best", bytes)?;
        Ok(())
    }

    /// Compute confirmations for a block.
    ///
    /// Returns `None` if the block is not on the best verified chain.
    /// Returns `Some(1)` for the tip itself.
    pub fn confirmations(&self, block_hash: &Hash256) -> Result<Option<u64>, EthHeaderStorageError> {
        // Get the header
        let id = HeaderId(*block_hash);
        let stored = match self.get_header(&id)? {
            Some(h) => h,
            None => return Ok(None),
        };

        // Must be verified
        if !stored.state.is_verified() {
            return Ok(None);
        }

        // Get best tip
        let tip = match self.get_best_tip()? {
            Some(t) => t,
            None => return Ok(None),
        };

        // Check if on same chain (ancestor check)
        if !self.is_ancestor_of(block_hash, &tip.header_hash, 10000)? {
            // Not on best chain
            return Ok(None);
        }

        // Compute confirmations: tip_number - block_number + 1
        let block_number = stored.header.number;
        if tip.number >= block_number {
            Ok(Some(tip.number - block_number + 1))
        } else {
            // Block is ahead of tip (shouldn't happen if on same chain)
            Ok(None)
        }
    }

    /// Check if `ancestor_hash` is an ancestor of `descendant_hash`.
    ///
    /// Walks backward from descendant up to `max_depth` blocks.
    pub fn is_ancestor_of(
        &self,
        ancestor_hash: &Hash256,
        descendant_hash: &Hash256,
        max_depth: u64,
    ) -> Result<bool, EthHeaderStorageError> {
        if ancestor_hash == descendant_hash {
            return Ok(true);
        }

        let mut current_hash = *descendant_hash;
        let mut depth = 0u64;

        while depth < max_depth {
            let id = HeaderId(current_hash);
            let stored = match self.get_header(&id)? {
                Some(h) => h,
                None => return Ok(false),
            };

            if stored.header.parent_hash == *ancestor_hash {
                return Ok(true);
            }

            if stored.header.number == 0 {
                // Reached genesis
                return Ok(false);
            }

            current_hash = stored.header.parent_hash;
            depth += 1;
        }

        // Exceeded max depth
        Ok(false)
    }

    /// Get headers at a specific height.
    ///
    /// Returns all headers at the given block number (may be multiple for forks).
    pub fn get_headers_at_height(
        &self,
        number: u64,
    ) -> Result<Vec<HeaderId>, EthHeaderStorageError> {
        let prefix = number.to_be_bytes();
        let mut ids = Vec::new();

        for result in self.height_index.scan_prefix(prefix) {
            let (key, _) = result?;
            if key.len() == 40 {
                // 8 bytes number + 32 bytes hash
                let hash_bytes = &key[8..40];
                let mut hash = [0u8; 32];
                hash.copy_from_slice(hash_bytes);
                ids.push(HeaderId(hash));
            }
        }

        Ok(ids)
    }

    /// List verified headers in a range.
    pub fn list_verified_headers(
        &self,
        from_number: u64,
        to_number: u64,
        limit: usize,
    ) -> Result<Vec<HeaderEntry>, EthHeaderStorageError> {
        let mut entries = Vec::new();

        for number in from_number..=to_number {
            if entries.len() >= limit {
                break;
            }

            let ids = self.get_headers_at_height(number)?;
            for id in ids {
                if entries.len() >= limit {
                    break;
                }

                if let Some(stored) = self.get_header(&id)? {
                    if stored.state.is_verified() {
                        entries.push(HeaderEntry {
                            id,
                            number: stored.header.number,
                            parent_hash: stored.header.parent_hash,
                            state: stored.state,
                            timestamp: stored.header.timestamp,
                        });
                    }
                }
            }
        }

        Ok(entries)
    }

    /// Count headers by state.
    pub fn count_headers(&self) -> Result<HeaderCounts, EthHeaderStorageError> {
        let mut counts = HeaderCounts::default();

        for result in self.headers.iter() {
            let (_, value) = result?;
            let stored: StoredHeader = json_decode(&value)?;
            match stored.state {
                HeaderVerificationState::Unverified => counts.unverified += 1,
                HeaderVerificationState::Verified => counts.verified += 1,
                HeaderVerificationState::Checkpoint => counts.checkpoints += 1,
            }
        }

        Ok(counts)
    }

    /// Delete a header.
    ///
    /// Use with caution - only for cleanup/testing.
    pub fn delete_header(&self, id: &HeaderId) -> Result<bool, EthHeaderStorageError> {
        let key = hex::encode(id.0);

        // Get the header first to remove from height index
        if let Some(stored) = self.get_header(id)? {
            // Remove from height index
            self.remove_from_height_index(stored.header.number, &id.0)?;

            // Remove from checkpoints if applicable
            self.checkpoints.remove(key.as_bytes())?;
        }

        let existed = self.headers.remove(key.as_bytes())?.is_some();
        Ok(existed)
    }

    /// Re-verify headers descending from checkpoints.
    ///
    /// Call this after adding new checkpoints to update verification state.
    pub fn reverify_from_checkpoints(&self) -> Result<u64, EthHeaderStorageError> {
        let mut updated = 0u64;

        // Get all checkpoint hashes
        let mut checkpoint_hashes: Vec<Hash256> = Vec::new();
        for result in self.checkpoints.iter() {
            let (key, _) = result?;
            let key_str = String::from_utf8_lossy(&key);
            if let Ok(id) = HeaderId::from_hex(&key_str) {
                checkpoint_hashes.push(id.0);
            }
        }

        // For each header, check if it descends from a checkpoint
        for result in self.headers.iter() {
            let (key, value) = result?;
            let mut stored: StoredHeader = json_decode(&value)?;

            if stored.state == HeaderVerificationState::Unverified {
                // Check if this header descends from any checkpoint
                for checkpoint_hash in &checkpoint_hashes {
                    if self.is_ancestor_of(checkpoint_hash, &stored.header_hash, 10000)? {
                        stored.state = HeaderVerificationState::Verified;
                        let new_bytes = json_encode(&stored)?;
                        self.headers.insert(&key, new_bytes)?;
                        updated += 1;

                        // Update best tip if needed
                        let now_ms = std::time::SystemTime::now()
                            .duration_since(std::time::UNIX_EPOCH)
                            .unwrap_or_default()
                            .as_millis();
                        let now_ms = u64::try_from(now_ms).unwrap_or(u64::MAX);
                        self.maybe_update_best_tip(&stored.header_hash, stored.header.number, now_ms)?;

                        break;
                    }
                }
            }
        }

        if updated > 0 {
            info!(
                chain_id = self.chain_id,
                updated = updated,
                "re-verified headers from checkpoints"
            );
        }

        Ok(updated)
    }

    // ============== Internal helpers ==============

    /// Add header to height index.
    fn add_to_height_index(
        &self,
        number: u64,
        hash: &Hash256,
    ) -> Result<(), EthHeaderStorageError> {
        let mut key = Vec::with_capacity(40);
        key.extend_from_slice(&number.to_be_bytes());
        key.extend_from_slice(hash);
        self.height_index.insert(key, &[])?;
        Ok(())
    }

    /// Remove header from height index.
    fn remove_from_height_index(
        &self,
        number: u64,
        hash: &Hash256,
    ) -> Result<(), EthHeaderStorageError> {
        let mut key = Vec::with_capacity(40);
        key.extend_from_slice(&number.to_be_bytes());
        key.extend_from_slice(hash);
        self.height_index.remove(key)?;
        Ok(())
    }

    /// Maybe update best tip if the new block is better.
    fn maybe_update_best_tip(
        &self,
        header_hash: &Hash256,
        number: u64,
        now_ms: u64,
    ) -> Result<(), EthHeaderStorageError> {
        let current_tip = self.get_best_tip()?;

        let should_update = match current_tip {
            None => true,
            Some(ref tip) => {
                // Fork choice: highest number wins, tie-break by smaller hash
                match number.cmp(&tip.number) {
                    Ordering::Greater => true,
                    Ordering::Less => false,
                    Ordering::Equal => {
                        // Tie-break by hash (smaller wins, deterministic)
                        header_hash < &tip.header_hash
                    }
                }
            }
        };

        if should_update {
            self.set_best_tip(header_hash, number, now_ms)?;

            if let Some(old_tip) = current_tip {
                if old_tip.header_hash != *header_hash {
                    debug!(
                        chain_id = self.chain_id,
                        old_tip = %hex::encode(old_tip.header_hash),
                        new_tip = %hex::encode(header_hash),
                        old_number = old_tip.number,
                        new_number = number,
                        "best tip updated"
                    );
                }
            } else {
                debug!(
                    chain_id = self.chain_id,
                    tip = %hex::encode(header_hash),
                    number = number,
                    "best tip initialized"
                );
            }
        }

        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_db() -> sled::Db {
        let dir = tempdir().expect("tmpdir");
        sled::open(dir.path()).expect("open")
    }

    fn test_header(number: u64, parent_hash: Hash256) -> EthereumHeaderV1 {
        EthereumHeaderV1 {
            parent_hash,
            uncle_hash: [0x22; 32],
            coinbase: [0x33; 20],
            state_root: [0x44; 32],
            transactions_root: [0x55; 32],
            receipts_root: [0x66; 32],
            logs_bloom: [0x00; 256],
            difficulty: 0,
            number,
            gas_limit: 30_000_000,
            gas_used: 15_000_000,
            timestamp: 1_700_000_000 + number,
            extra_data: vec![],
            mix_hash: [0x77; 32],
            nonce: 0,
            base_fee_per_gas: Some(10_000_000_000),
            withdrawals_root: Some([0x88; 32]),
            blob_gas_used: None,
            excess_blob_gas: None,
            parent_beacon_block_root: None,
        }
    }

    #[test]
    fn storage_new() {
        let db = test_db();
        let storage = EthHeaderStorage::new(&db, 1).expect("create");
        assert_eq!(storage.chain_id(), 1);
    }

    #[test]
    fn add_checkpoint() {
        let db = test_db();
        let storage = EthHeaderStorage::new(&db, 1).expect("create");

        let header = test_header(18_000_000, [0x11; 32]);
        let id = storage.add_checkpoint(&header, 1_700_000_000_000).expect("add");

        // Verify it's stored
        let stored = storage.get_header(&id).expect("get").expect("present");
        assert_eq!(stored.state, HeaderVerificationState::Checkpoint);
        assert_eq!(stored.header.number, 18_000_000);

        // Verify it's the best tip
        let tip = storage.get_best_tip().expect("tip").expect("present");
        assert_eq!(tip.header_hash, id.0);
        assert_eq!(tip.number, 18_000_000);
    }

    #[test]
    fn put_header_with_parent() {
        let db = test_db();
        let storage = EthHeaderStorage::new(&db, 1).expect("create");

        // Add checkpoint
        let checkpoint = test_header(18_000_000, [0x11; 32]);
        let checkpoint_id = storage
            .add_checkpoint(&checkpoint, 1_700_000_000_000)
            .expect("add checkpoint");

        // Add child header
        let child = test_header(18_000_001, checkpoint_id.0);
        let was_new = storage
            .put_header(&child, 1_700_000_001_000)
            .expect("put child");
        assert!(was_new);

        // Verify child is verified (inherits from checkpoint)
        let child_id = HeaderId(child.header_hash());
        let stored = storage.get_header(&child_id).expect("get").expect("present");
        assert_eq!(stored.state, HeaderVerificationState::Verified);

        // Verify best tip is updated
        let tip = storage.get_best_tip().expect("tip").expect("present");
        assert_eq!(tip.number, 18_000_001);
    }

    #[test]
    fn put_header_orphan() {
        let db = test_db();
        let storage = EthHeaderStorage::new(&db, 1).expect("create");

        // Add header without parent
        let header = test_header(18_000_000, [0xFF; 32]); // Unknown parent
        let was_new = storage.put_header(&header, 1_700_000_000_000).expect("put");
        assert!(was_new);

        // Should be unverified
        let id = HeaderId(header.header_hash());
        let stored = storage.get_header(&id).expect("get").expect("present");
        assert_eq!(stored.state, HeaderVerificationState::Unverified);

        // Should not be best tip (unverified)
        assert!(storage.get_best_tip().expect("tip").is_none());
    }

    #[test]
    fn put_header_idempotent() {
        let db = test_db();
        let storage = EthHeaderStorage::new(&db, 1).expect("create");

        let header = test_header(18_000_000, [0x11; 32]);
        storage.add_checkpoint(&header, 1_700_000_000_000).expect("add");

        // Try to add again
        let was_new = storage.put_header(&header, 1_700_000_001_000).expect("put");
        assert!(!was_new);
    }

    #[test]
    fn confirmations_basic() {
        let db = test_db();
        let storage = EthHeaderStorage::new(&db, 1).expect("create");

        // Add chain: checkpoint -> h1 -> h2 -> h3 (tip)
        let checkpoint = test_header(100, [0x00; 32]);
        let checkpoint_id = storage.add_checkpoint(&checkpoint, 1_700_000_000_000).expect("add");

        let h1 = test_header(101, checkpoint_id.0);
        storage.put_header(&h1, 1_700_000_001_000).expect("put h1");
        let h1_hash = h1.header_hash();

        let h2 = test_header(102, h1_hash);
        storage.put_header(&h2, 1_700_000_002_000).expect("put h2");
        let h2_hash = h2.header_hash();

        let h3 = test_header(103, h2_hash);
        storage.put_header(&h3, 1_700_000_003_000).expect("put h3");
        let h3_hash = h3.header_hash();

        // Check confirmations
        assert_eq!(storage.confirmations(&h3_hash).expect("conf"), Some(1)); // tip
        assert_eq!(storage.confirmations(&h2_hash).expect("conf"), Some(2));
        assert_eq!(storage.confirmations(&h1_hash).expect("conf"), Some(3));
        assert_eq!(storage.confirmations(&checkpoint_id.0).expect("conf"), Some(4));
    }

    #[test]
    fn confirmations_unverified_returns_none() {
        let db = test_db();
        let storage = EthHeaderStorage::new(&db, 1).expect("create");

        // Add unverified header
        let header = test_header(100, [0xFF; 32]);
        storage.put_header(&header, 1_700_000_000_000).expect("put");

        let hash = header.header_hash();
        assert_eq!(storage.confirmations(&hash).expect("conf"), None);
    }

    #[test]
    fn is_ancestor_of_basic() {
        let db = test_db();
        let storage = EthHeaderStorage::new(&db, 1).expect("create");

        // Add chain: h1 -> h2 -> h3
        let h1 = test_header(100, [0x00; 32]);
        let h1_id = storage.add_checkpoint(&h1, 1_700_000_000_000).expect("add");

        let h2 = test_header(101, h1_id.0);
        storage.put_header(&h2, 1_700_000_001_000).expect("put");
        let h2_hash = h2.header_hash();

        let h3 = test_header(102, h2_hash);
        storage.put_header(&h3, 1_700_000_002_000).expect("put");
        let h3_hash = h3.header_hash();

        // h1 is ancestor of h3
        assert!(storage.is_ancestor_of(&h1_id.0, &h3_hash, 100).expect("check"));

        // h3 is NOT ancestor of h1
        assert!(!storage.is_ancestor_of(&h3_hash, &h1_id.0, 100).expect("check"));

        // Same block is ancestor of itself
        assert!(storage.is_ancestor_of(&h2_hash, &h2_hash, 100).expect("check"));
    }

    #[test]
    fn fork_choice_higher_number_wins() {
        let db = test_db();
        let storage = EthHeaderStorage::new(&db, 1).expect("create");

        // Add checkpoint
        let checkpoint = test_header(100, [0x00; 32]);
        let cp_id = storage.add_checkpoint(&checkpoint, 1_700_000_000_000).expect("add");

        // Add two forks from checkpoint
        let fork_a = test_header(101, cp_id.0);
        let fork_b = test_header(101, cp_id.0);

        // Make fork_b different by changing extra_data
        let mut fork_b = fork_b;
        fork_b.extra_data = vec![0x01];

        storage.put_header(&fork_a, 1_700_000_001_000).expect("put a");
        let fork_a_hash = fork_a.header_hash();

        storage.put_header(&fork_b, 1_700_000_001_000).expect("put b");

        // Extend fork_a to height 102
        let fork_a_child = test_header(102, fork_a_hash);
        storage.put_header(&fork_a_child, 1_700_000_002_000).expect("put a_child");

        // Best tip should be fork_a_child (higher number)
        let tip = storage.get_best_tip().expect("tip").expect("present");
        assert_eq!(tip.number, 102);
    }

    #[test]
    fn fork_choice_tie_break_by_hash() {
        let db = test_db();
        let storage = EthHeaderStorage::new(&db, 1).expect("create");

        // Add checkpoint
        let checkpoint = test_header(100, [0x00; 32]);
        let cp_id = storage.add_checkpoint(&checkpoint, 1_700_000_000_000).expect("add");

        // Add two forks at same height with different hashes
        let fork_a = test_header(101, cp_id.0);
        let mut fork_b = test_header(101, cp_id.0);
        fork_b.extra_data = vec![0x01]; // Different hash

        storage.put_header(&fork_a, 1_700_000_001_000).expect("put a");
        let fork_a_hash = fork_a.header_hash();

        storage.put_header(&fork_b, 1_700_000_001_000).expect("put b");
        let fork_b_hash = fork_b.header_hash();

        // Best tip should be the one with smaller hash
        let tip = storage.get_best_tip().expect("tip").expect("present");
        let expected_hash = if fork_a_hash < fork_b_hash {
            fork_a_hash
        } else {
            fork_b_hash
        };
        assert_eq!(tip.header_hash, expected_hash);
    }

    #[test]
    fn get_headers_at_height() {
        let db = test_db();
        let storage = EthHeaderStorage::new(&db, 1).expect("create");

        // Add checkpoint
        let checkpoint = test_header(100, [0x00; 32]);
        let cp_id = storage.add_checkpoint(&checkpoint, 1_700_000_000_000).expect("add");

        // Add two blocks at height 101
        let h1 = test_header(101, cp_id.0);
        let mut h2 = test_header(101, cp_id.0);
        h2.extra_data = vec![0x01];

        storage.put_header(&h1, 1_700_000_001_000).expect("put h1");
        storage.put_header(&h2, 1_700_000_001_000).expect("put h2");

        // Should return both
        let headers_at_101 = storage.get_headers_at_height(101).expect("get");
        assert_eq!(headers_at_101.len(), 2);

        // Height 100 should have 1 (checkpoint)
        let headers_at_100 = storage.get_headers_at_height(100).expect("get");
        assert_eq!(headers_at_100.len(), 1);

        // Height 102 should be empty
        let headers_at_102 = storage.get_headers_at_height(102).expect("get");
        assert!(headers_at_102.is_empty());
    }

    #[test]
    fn count_headers() {
        let db = test_db();
        let storage = EthHeaderStorage::new(&db, 1).expect("create");

        // Add checkpoint
        let checkpoint = test_header(100, [0x00; 32]);
        let cp_id = storage.add_checkpoint(&checkpoint, 1_700_000_000_000).expect("add");

        // Add verified child
        let h1 = test_header(101, cp_id.0);
        storage.put_header(&h1, 1_700_000_001_000).expect("put");

        // Add orphan (unverified)
        let orphan = test_header(200, [0xFF; 32]);
        storage.put_header(&orphan, 1_700_000_002_000).expect("put");

        let counts = storage.count_headers().expect("count");
        assert_eq!(counts.checkpoints, 1);
        assert_eq!(counts.verified, 1);
        assert_eq!(counts.unverified, 1);
        assert_eq!(counts.total(), 3);
    }

    #[test]
    fn delete_header() {
        let db = test_db();
        let storage = EthHeaderStorage::new(&db, 1).expect("create");

        let header = test_header(100, [0x00; 32]);
        let id = storage.add_checkpoint(&header, 1_700_000_000_000).expect("add");

        assert!(storage.header_exists(&id).expect("exists"));

        let deleted = storage.delete_header(&id).expect("delete");
        assert!(deleted);

        assert!(!storage.header_exists(&id).expect("exists"));

        // Delete again returns false
        let deleted_again = storage.delete_header(&id).expect("delete");
        assert!(!deleted_again);
    }

    #[test]
    fn header_validation_number_mismatch() {
        let db = test_db();
        let storage = EthHeaderStorage::new(&db, 1).expect("create");

        // Add checkpoint at 100
        let checkpoint = test_header(100, [0x00; 32]);
        let cp_id = storage.add_checkpoint(&checkpoint, 1_700_000_000_000).expect("add");

        // Try to add header claiming to be at 102 but with parent at 100
        let bad_header = test_header(102, cp_id.0); // Should be 101

        let result = storage.put_header(&bad_header, 1_700_000_001_000);
        assert!(matches!(
            result,
            Err(EthHeaderStorageError::ValidationFailed(_))
        ));
    }

    #[test]
    fn header_validation_timestamp() {
        let db = test_db();
        let storage = EthHeaderStorage::new(&db, 1).expect("create");

        // Add checkpoint
        let checkpoint = test_header(100, [0x00; 32]);
        let cp_id = storage.add_checkpoint(&checkpoint, 1_700_000_000_000).expect("add");

        // Try to add header with earlier timestamp
        let mut bad_header = test_header(101, cp_id.0);
        bad_header.timestamp = 100; // Earlier than parent

        let result = storage.put_header(&bad_header, 1_700_000_001_000);
        assert!(matches!(
            result,
            Err(EthHeaderStorageError::ValidationFailed(_))
        ));
    }

    // ========== Reorg Handling Tests ==========

    #[test]
    fn reorg_handling_switch_to_longer_chain() {
        let db = test_db();
        let storage = EthHeaderStorage::new(&db, 1).expect("create");

        // Build initial chain: checkpoint -> A1 -> A2
        let checkpoint = test_header(100, [0x00; 32]);
        let cp_id = storage.add_checkpoint(&checkpoint, 1_700_000_000_000).expect("add");

        let a1 = test_header(101, cp_id.0);
        let a1_hash = a1.header_hash();
        storage.put_header(&a1, 1_700_000_001_000).expect("put");

        let a2 = test_header(102, a1_hash);
        let a2_hash = a2.header_hash();
        storage.put_header(&a2, 1_700_000_002_000).expect("put");

        // Best tip is A2
        let tip = storage.get_best_tip().expect("tip").expect("present");
        assert_eq!(tip.number, 102);
        assert_eq!(tip.header_hash, a2_hash);

        // Build competing chain: checkpoint -> B1 -> B2 -> B3 (longer)
        let mut b1 = test_header(101, cp_id.0);
        b1.extra_data = vec![0x42]; // Different hash
        let b1_hash = b1.header_hash();
        storage.put_header(&b1, 1_700_000_003_000).expect("put");

        let mut b2 = test_header(102, b1_hash);
        b2.extra_data = vec![0x42];
        let b2_hash = b2.header_hash();
        storage.put_header(&b2, 1_700_000_004_000).expect("put");

        // At this point, A2 and B2 are tied. Best tip should be the one with smaller hash.
        let tip = storage.get_best_tip().expect("tip").expect("present");
        assert_eq!(tip.number, 102);
        // Don't assert specific hash - depends on which is smaller

        // Now extend B chain to B3 (longer)
        let mut b3 = test_header(103, b2_hash);
        b3.extra_data = vec![0x42];
        let b3_hash = b3.header_hash();
        storage.put_header(&b3, 1_700_000_005_000).expect("put");

        // Best tip should now be B3 (highest number wins)
        let tip = storage.get_best_tip().expect("tip").expect("present");
        assert_eq!(tip.number, 103);
        assert_eq!(tip.header_hash, b3_hash);
    }

    #[test]
    fn confirmations_change_during_reorg() {
        let db = test_db();
        let storage = EthHeaderStorage::new(&db, 1).expect("create");

        // Build chain: checkpoint -> H1 -> H2 -> H3
        let checkpoint = test_header(100, [0x00; 32]);
        let cp_id = storage.add_checkpoint(&checkpoint, 1_700_000_000_000).expect("add");

        let h1 = test_header(101, cp_id.0);
        let h1_hash = h1.header_hash();
        storage.put_header(&h1, 1_700_000_001_000).expect("put");

        let h2 = test_header(102, h1_hash);
        let h2_hash = h2.header_hash();
        storage.put_header(&h2, 1_700_000_002_000).expect("put");

        let h3 = test_header(103, h2_hash);
        storage.put_header(&h3, 1_700_000_003_000).expect("put");

        // Confirm H1 has 3 confirmations (tip is 103, H1 is 101)
        assert_eq!(storage.confirmations(&h1_hash).expect("conf"), Some(3));

        // Build competing longer chain from checkpoint
        let mut fork_h1 = test_header(101, cp_id.0);
        fork_h1.extra_data = vec![0xF0];
        let fork_h1_hash = fork_h1.header_hash();
        storage.put_header(&fork_h1, 1_700_000_004_000).expect("put");

        let mut fork_h2 = test_header(102, fork_h1_hash);
        fork_h2.extra_data = vec![0xF0];
        let fork_h2_hash = fork_h2.header_hash();
        storage.put_header(&fork_h2, 1_700_000_005_000).expect("put");

        let mut fork_h3 = test_header(103, fork_h2_hash);
        fork_h3.extra_data = vec![0xF0];
        let fork_h3_hash = fork_h3.header_hash();
        storage.put_header(&fork_h3, 1_700_000_006_000).expect("put");

        let mut fork_h4 = test_header(104, fork_h3_hash);
        fork_h4.extra_data = vec![0xF0];
        storage.put_header(&fork_h4, 1_700_000_007_000).expect("put");

        // Now fork is longer (104 vs 103)
        let tip = storage.get_best_tip().expect("tip").expect("present");
        assert_eq!(tip.number, 104);

        // H1 from original chain is NOT on the best chain anymore
        // confirmations returns None because H1 is not an ancestor of the fork tip
        assert_eq!(storage.confirmations(&h1_hash).expect("conf"), None);

        // fork_h1 IS on the best chain and has 4 confirmations
        assert_eq!(storage.confirmations(&fork_h1_hash).expect("conf"), Some(4));
    }

    #[test]
    fn multiple_forks_from_same_parent() {
        let db = test_db();
        let storage = EthHeaderStorage::new(&db, 1).expect("create");

        // Checkpoint at 100
        let checkpoint = test_header(100, [0x00; 32]);
        let cp_id = storage.add_checkpoint(&checkpoint, 1_700_000_000_000).expect("add");

        // Create 3 forks from checkpoint
        let mut fork_a = test_header(101, cp_id.0);
        fork_a.extra_data = vec![0xAA];
        let fork_a_hash = fork_a.header_hash();
        storage.put_header(&fork_a, 1_700_000_001_000).expect("put");

        let mut fork_b = test_header(101, cp_id.0);
        fork_b.extra_data = vec![0xBB];
        let fork_b_hash = fork_b.header_hash();
        storage.put_header(&fork_b, 1_700_000_002_000).expect("put");

        let mut fork_c = test_header(101, cp_id.0);
        fork_c.extra_data = vec![0xCC];
        let fork_c_hash = fork_c.header_hash();
        storage.put_header(&fork_c, 1_700_000_003_000).expect("put");

        // All forks are verified (descend from checkpoint)
        let stored_a = storage.get_header(&HeaderId(fork_a_hash)).expect("get").expect("a");
        let stored_b = storage.get_header(&HeaderId(fork_b_hash)).expect("get").expect("b");
        let stored_c = storage.get_header(&HeaderId(fork_c_hash)).expect("get").expect("c");

        assert!(stored_a.state.is_verified());
        assert!(stored_b.state.is_verified());
        assert!(stored_c.state.is_verified());

        // Best tip should be whichever has the smallest hash (tie-break)
        let tip = storage.get_best_tip().expect("tip").expect("present");
        let hashes = [fork_a_hash, fork_b_hash, fork_c_hash];
        let min_hash = hashes.iter().min().unwrap();
        assert_eq!(&tip.header_hash, min_hash);

        // Get headers at height 101 - should return all 3
        let at_101 = storage.get_headers_at_height(101).expect("height");
        assert_eq!(at_101.len(), 3);
    }

    #[test]
    fn unverified_orphan_chain() {
        let db = test_db();
        let storage = EthHeaderStorage::new(&db, 1).expect("create");

        // Add checkpoint at 100
        let checkpoint = test_header(100, [0x00; 32]);
        let cp_id = storage.add_checkpoint(&checkpoint, 1_700_000_000_000).expect("add");

        // Add orphan chain starting from unknown parent
        let orphan1 = test_header(200, [0xFF; 32]); // Unknown parent
        let orphan1_hash = orphan1.header_hash();
        storage.put_header(&orphan1, 1_700_000_001_000).expect("put");

        let orphan2 = test_header(201, orphan1_hash);
        let orphan2_hash = orphan2.header_hash();
        storage.put_header(&orphan2, 1_700_000_002_000).expect("put");

        // Orphans should be Unverified
        let stored_orphan1 = storage.get_header(&HeaderId(orphan1_hash)).expect("get").expect("o1");
        let stored_orphan2 = storage.get_header(&HeaderId(orphan2_hash)).expect("get").expect("o2");

        assert!(!stored_orphan1.state.is_verified());
        assert!(!stored_orphan2.state.is_verified());

        // Best tip should still be checkpoint (orphans are unverified)
        let tip = storage.get_best_tip().expect("tip").expect("present");
        assert_eq!(tip.number, 100);
        assert_eq!(tip.header_hash, cp_id.0);

        // Orphans should not have confirmations (not on verified chain)
        assert_eq!(storage.confirmations(&orphan1_hash).expect("conf"), None);
        assert_eq!(storage.confirmations(&orphan2_hash).expect("conf"), None);
    }

    #[test]
    fn chain_statistics_with_forks() {
        let db = test_db();
        let storage = EthHeaderStorage::new(&db, 1).expect("create");

        // Initial state - empty
        let counts = storage.count_headers().expect("count");
        assert_eq!(counts.total(), 0);

        // Add checkpoint
        let checkpoint = test_header(100, [0x00; 32]);
        let cp_id = storage.add_checkpoint(&checkpoint, 1_700_000_000_000).expect("add");

        let counts = storage.count_headers().expect("count");
        assert_eq!(counts.total(), 1);
        assert_eq!(counts.checkpoints, 1);

        // Add verified chain
        let h1 = test_header(101, cp_id.0);
        storage.put_header(&h1, 1_700_000_001_000).expect("put");

        let counts = storage.count_headers().expect("count");
        assert_eq!(counts.total(), 2);
        assert_eq!(counts.verified, 1); // Not counting checkpoint
        assert_eq!(counts.checkpoints, 1);

        // Add orphan
        let orphan = test_header(200, [0xFF; 32]);
        storage.put_header(&orphan, 1_700_000_002_000).expect("put");

        let counts = storage.count_headers().expect("count");
        assert_eq!(counts.total(), 3);
        assert_eq!(counts.verified, 1);
        assert_eq!(counts.unverified, 1);
        assert_eq!(counts.checkpoints, 1);
    }
}
