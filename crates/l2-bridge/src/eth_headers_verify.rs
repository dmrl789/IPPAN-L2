//! Ethereum Header Verification (Light Client MVP).
//!
//! This module provides structural verification of Ethereum block headers
//! with explicit trusted checkpoints.
//!
//! ## Trust Model
//!
//! This is a **MVP light client** that uses:
//! - Explicit trusted checkpoints (bootstrap headers)
//! - Structural validation (RLP decoding, parent linking, timestamps)
//! - Deterministic best-chain selection
//!
//! ## What This Does NOT Verify
//!
//! - PoS sync committee signatures (future enhancement)
//! - Difficulty/hashpower (not applicable to PoS)
//! - State trie validity
//!
//! ## What This DOES Verify
//!
//! - Header RLP decodes correctly
//! - Header hash matches keccak256(RLP)
//! - Block number increments by 1 from parent
//! - Timestamp >= parent timestamp
//! - Headers descend from trusted checkpoints
//!
//! ## Configuration
//!
//! Checkpoints can be configured via:
//! - `ETH_BOOTSTRAP_CHECKPOINTS` env var (comma-separated hash:number pairs)
//! - Programmatic configuration at startup

use l2_core::eth_header::{EthereumHeaderV1, HeaderId, Hash256};
use l2_storage::eth_headers::{EthHeaderStorage, EthHeaderStorageError};
use std::collections::HashMap;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, info, warn};

/// Errors from header verification.
#[derive(Debug, Error)]
pub enum HeaderVerifyError {
    #[error("storage error: {0}")]
    Storage(#[from] EthHeaderStorageError),

    #[error("header error: {0}")]
    Header(#[from] l2_core::eth_header::EthHeaderError),

    #[error("verification failed: {0}")]
    VerificationFailed(String),

    #[error("checkpoint not found for chain {0}")]
    NoCheckpoint(u64),

    #[error("header not on verified chain: {0}")]
    NotOnVerifiedChain(String),

    #[error("insufficient confirmations: got {got}, need {need}")]
    InsufficientConfirmations { got: u64, need: u64 },
}

/// Configuration for the header verifier.
#[derive(Debug, Clone)]
pub struct HeaderVerifierConfig {
    /// Trusted checkpoint headers by chain ID.
    /// Format: chain_id -> [(header_hash, block_number)]
    pub checkpoints: HashMap<u64, Vec<(Hash256, u64)>>,

    /// Minimum confirmations required for mainnet.
    pub min_confirmations_mainnet: u64,

    /// Minimum confirmations required for testnet.
    pub min_confirmations_testnet: u64,

    /// Whether to allow headers from chains without checkpoints (devnet mode).
    pub allow_uncheckpointed: bool,
}

impl Default for HeaderVerifierConfig {
    fn default() -> Self {
        Self {
            checkpoints: HashMap::new(),
            min_confirmations_mainnet: 12,
            min_confirmations_testnet: 6,
            allow_uncheckpointed: false,
        }
    }
}

impl HeaderVerifierConfig {
    /// Create from environment variables.
    ///
    /// Reads:
    /// - `ETH_BOOTSTRAP_CHECKPOINTS`: Comma-separated `chain_id:hash:number` entries
    /// - `ETH_MIN_CONFIRMATIONS_MAINNET`: Minimum confirmations for mainnet (default: 12)
    /// - `ETH_MIN_CONFIRMATIONS_TESTNET`: Minimum confirmations for testnet (default: 6)
    /// - `ETH_HEADER_ALLOW_UNCHECKPOINTED`: Allow headers without checkpoints (devnet mode)
    pub fn from_env() -> Self {
        let mut config = Self::default();

        // Parse checkpoints
        if let Ok(checkpoints_str) = std::env::var("ETH_BOOTSTRAP_CHECKPOINTS") {
            for entry in checkpoints_str.split(',') {
                let entry = entry.trim();
                if entry.is_empty() {
                    continue;
                }

                // Format: chain_id:hash:number
                let parts: Vec<&str> = entry.split(':').collect();
                if parts.len() != 3 {
                    warn!(entry = entry, "invalid checkpoint format, expected chain_id:hash:number");
                    continue;
                }

                let chain_id: u64 = match parts[0].parse() {
                    Ok(id) => id,
                    Err(e) => {
                        warn!(entry = entry, error = %e, "invalid chain_id in checkpoint");
                        continue;
                    }
                };

                let hash_hex = parts[1].strip_prefix("0x").unwrap_or(parts[1]);
                let hash_bytes = match hex::decode(hash_hex) {
                    Ok(b) if b.len() == 32 => {
                        let mut arr = [0u8; 32];
                        arr.copy_from_slice(&b);
                        arr
                    }
                    _ => {
                        warn!(entry = entry, "invalid hash in checkpoint");
                        continue;
                    }
                };

                let number: u64 = match parts[2].parse() {
                    Ok(n) => n,
                    Err(e) => {
                        warn!(entry = entry, error = %e, "invalid number in checkpoint");
                        continue;
                    }
                };

                config
                    .checkpoints
                    .entry(chain_id)
                    .or_default()
                    .push((hash_bytes, number));

                info!(
                    chain_id = chain_id,
                    hash = %hex::encode(hash_bytes),
                    number = number,
                    "loaded bootstrap checkpoint"
                );
            }
        }

        // Parse confirmation thresholds
        if let Ok(val) = std::env::var("ETH_MIN_CONFIRMATIONS_MAINNET") {
            if let Ok(n) = val.parse() {
                config.min_confirmations_mainnet = n;
            }
        }

        if let Ok(val) = std::env::var("ETH_MIN_CONFIRMATIONS_TESTNET") {
            if let Ok(n) = val.parse() {
                config.min_confirmations_testnet = n;
            }
        }

        // Parse devnet mode
        if let Ok(val) = std::env::var("ETH_HEADER_ALLOW_UNCHECKPOINTED") {
            config.allow_uncheckpointed = val.to_lowercase() == "true" || val == "1";
        }

        config
    }

    /// Add a checkpoint for a chain.
    pub fn add_checkpoint(&mut self, chain_id: u64, hash: Hash256, number: u64) {
        self.checkpoints
            .entry(chain_id)
            .or_default()
            .push((hash, number));
    }

    /// Get checkpoints for a chain.
    pub fn get_checkpoints(&self, chain_id: u64) -> Option<&[(Hash256, u64)]> {
        self.checkpoints.get(&chain_id).map(|v| v.as_slice())
    }

    /// Get minimum confirmations for a chain.
    pub fn min_confirmations(&self, chain_id: u64) -> u64 {
        // Mainnet = 1, testnets are everything else
        if chain_id == 1 {
            self.min_confirmations_mainnet
        } else {
            self.min_confirmations_testnet
        }
    }
}

/// Result of header verification.
#[derive(Debug, Clone)]
pub struct HeaderVerifyResult {
    /// The header ID (hash).
    pub header_id: HeaderId,

    /// Block number.
    pub number: u64,

    /// Whether this header is on a verified chain.
    pub verified: bool,

    /// Whether this is a new header (was stored).
    pub was_new: bool,

    /// Current confirmations (if verified).
    pub confirmations: Option<u64>,
}

/// Ethereum header verifier.
///
/// Provides structural verification and checkpoint-based chain validation.
pub struct HeaderVerifier {
    /// Configuration.
    config: HeaderVerifierConfig,
}

impl HeaderVerifier {
    /// Create a new verifier with the given configuration.
    pub fn new(config: HeaderVerifierConfig) -> Self {
        Self { config }
    }

    /// Create a verifier from environment variables.
    pub fn from_env() -> Self {
        Self::new(HeaderVerifierConfig::from_env())
    }

    /// Get the configuration.
    pub fn config(&self) -> &HeaderVerifierConfig {
        &self.config
    }

    /// Initialize storage with checkpoints.
    ///
    /// This should be called once at startup to bootstrap the header chain.
    /// Checkpoint headers must be provided separately (e.g., from config or hardcoded).
    pub fn init_checkpoints(
        &self,
        storage: &EthHeaderStorage,
        checkpoint_headers: &[(EthereumHeaderV1, u64)], // (header, chain_id)
    ) -> Result<u32, HeaderVerifyError> {
        let mut added = 0u32;

        for (header, chain_id) in checkpoint_headers {
            if storage.chain_id() != *chain_id {
                continue;
            }

            let header_hash = header.header_hash();

            // Check if this is a configured checkpoint
            let is_checkpoint = self.config.checkpoints.get(chain_id).map_or(false, |cps| {
                cps.iter().any(|(hash, num)| *hash == header_hash && *num == header.number)
            });

            if !is_checkpoint && !self.config.allow_uncheckpointed {
                debug!(
                    header_hash = %hex::encode(header_hash),
                    number = header.number,
                    "skipping non-checkpoint header"
                );
                continue;
            }

            let now_ms = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis();
            let now_ms = u64::try_from(now_ms).unwrap_or(u64::MAX);

            storage.add_checkpoint(header, now_ms)?;
            added += 1;
        }

        Ok(added)
    }

    /// Verify and store a header.
    ///
    /// This performs structural validation and stores the header if valid.
    /// The header's verification state depends on whether it descends from a checkpoint.
    pub fn verify_and_store(
        &self,
        storage: &EthHeaderStorage,
        header: &EthereumHeaderV1,
    ) -> Result<HeaderVerifyResult, HeaderVerifyError> {
        // Basic structural validation
        header.validate_basic()?;

        // Compute header hash
        let header_hash = header.header_hash();
        let header_id = HeaderId(header_hash);

        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let now_ms = u64::try_from(now_ms).unwrap_or(u64::MAX);

        // Store the header
        let was_new = storage.put_header(header, now_ms)?;

        // Get the stored header to check verification state
        let stored = storage
            .get_header(&header_id)?
            .ok_or_else(|| HeaderVerifyError::Storage(EthHeaderStorageError::NotFound(hex::encode(header_hash))))?;

        // Get confirmations if verified
        let confirmations = if stored.state.is_verified() {
            storage.confirmations(&header_hash)?
        } else {
            None
        };

        Ok(HeaderVerifyResult {
            header_id,
            number: header.number,
            verified: stored.state.is_verified(),
            was_new,
            confirmations,
        })
    }

    /// Verify a header from RLP bytes.
    ///
    /// This decodes the RLP, validates the hash, and stores the header.
    pub fn verify_from_rlp(
        &self,
        storage: &EthHeaderStorage,
        rlp_bytes: &[u8],
        expected_hash: Option<&Hash256>,
    ) -> Result<HeaderVerifyResult, HeaderVerifyError> {
        // Decode RLP
        let header = EthereumHeaderV1::from_rlp(rlp_bytes)?;

        // Verify hash if provided
        if let Some(expected) = expected_hash {
            header.verify_hash(expected)?;
        }

        // Verify and store
        self.verify_and_store(storage, &header)
    }

    /// Check if a block has sufficient confirmations.
    pub fn check_confirmations(
        &self,
        storage: &EthHeaderStorage,
        block_hash: &Hash256,
    ) -> Result<u64, HeaderVerifyError> {
        let min_confirmations = self.config.min_confirmations(storage.chain_id());

        let confirmations = storage
            .confirmations(block_hash)?
            .ok_or_else(|| {
                HeaderVerifyError::NotOnVerifiedChain(hex::encode(block_hash))
            })?;

        if confirmations < min_confirmations {
            return Err(HeaderVerifyError::InsufficientConfirmations {
                got: confirmations,
                need: min_confirmations,
            });
        }

        Ok(confirmations)
    }

    /// Check if a header is on the verified chain.
    pub fn is_on_verified_chain(
        &self,
        storage: &EthHeaderStorage,
        block_hash: &Hash256,
    ) -> Result<bool, HeaderVerifyError> {
        let header_id = HeaderId(*block_hash);
        match storage.get_header(&header_id)? {
            Some(stored) => Ok(stored.state.is_verified()),
            None => Ok(false),
        }
    }

    /// Get the receipts root for a verified block.
    ///
    /// This is used to anchor Merkle receipt proofs to verified headers.
    pub fn get_verified_receipts_root(
        &self,
        storage: &EthHeaderStorage,
        block_hash: &Hash256,
    ) -> Result<Hash256, HeaderVerifyError> {
        let header_id = HeaderId(*block_hash);
        let stored = storage
            .get_header(&header_id)?
            .ok_or_else(|| HeaderVerifyError::NotOnVerifiedChain(hex::encode(block_hash)))?;

        if !stored.state.is_verified() {
            return Err(HeaderVerifyError::NotOnVerifiedChain(hex::encode(block_hash)));
        }

        Ok(*stored.header.receipts_root())
    }
}

/// Multi-chain header verifier manager.
///
/// Manages header storage and verification for multiple chains.
pub struct MultiChainHeaderVerifier {
    /// Per-chain storage.
    storages: HashMap<u64, Arc<EthHeaderStorage>>,

    /// Shared verifier config.
    verifier: HeaderVerifier,
}

impl MultiChainHeaderVerifier {
    /// Create a new multi-chain verifier.
    pub fn new(config: HeaderVerifierConfig) -> Self {
        Self {
            storages: HashMap::new(),
            verifier: HeaderVerifier::new(config),
        }
    }

    /// Create from environment variables.
    pub fn from_env() -> Self {
        Self::new(HeaderVerifierConfig::from_env())
    }

    /// Add storage for a chain.
    pub fn add_chain(&mut self, chain_id: u64, storage: Arc<EthHeaderStorage>) {
        self.storages.insert(chain_id, storage);
    }

    /// Get storage for a chain.
    pub fn get_storage(&self, chain_id: u64) -> Option<&Arc<EthHeaderStorage>> {
        self.storages.get(&chain_id)
    }

    /// Get the verifier.
    pub fn verifier(&self) -> &HeaderVerifier {
        &self.verifier
    }

    /// Verify and store a header for a specific chain.
    pub fn verify_and_store(
        &self,
        chain_id: u64,
        header: &EthereumHeaderV1,
    ) -> Result<HeaderVerifyResult, HeaderVerifyError> {
        let storage = self
            .storages
            .get(&chain_id)
            .ok_or(HeaderVerifyError::NoCheckpoint(chain_id))?;

        self.verifier.verify_and_store(storage, header)
    }

    /// Check confirmations for a block on a specific chain.
    pub fn check_confirmations(
        &self,
        chain_id: u64,
        block_hash: &Hash256,
    ) -> Result<u64, HeaderVerifyError> {
        let storage = self
            .storages
            .get(&chain_id)
            .ok_or(HeaderVerifyError::NoCheckpoint(chain_id))?;

        self.verifier.check_confirmations(storage, block_hash)
    }

    /// Get verified receipts root for a block on a specific chain.
    pub fn get_verified_receipts_root(
        &self,
        chain_id: u64,
        block_hash: &Hash256,
    ) -> Result<Hash256, HeaderVerifyError> {
        let storage = self
            .storages
            .get(&chain_id)
            .ok_or(HeaderVerifyError::NoCheckpoint(chain_id))?;

        self.verifier.get_verified_receipts_root(storage, block_hash)
    }

    /// Get best tip for a chain.
    pub fn get_best_tip(&self, chain_id: u64) -> Result<Option<l2_storage::BestTip>, HeaderVerifyError> {
        let storage = self
            .storages
            .get(&chain_id)
            .ok_or(HeaderVerifyError::NoCheckpoint(chain_id))?;

        Ok(storage.get_best_tip()?)
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
    fn config_default() {
        let config = HeaderVerifierConfig::default();
        assert!(config.checkpoints.is_empty());
        assert_eq!(config.min_confirmations_mainnet, 12);
        assert_eq!(config.min_confirmations_testnet, 6);
        assert!(!config.allow_uncheckpointed);
    }

    #[test]
    fn config_add_checkpoint() {
        let mut config = HeaderVerifierConfig::default();
        config.add_checkpoint(1, [0xAA; 32], 18_000_000);
        config.add_checkpoint(1, [0xBB; 32], 18_100_000);
        config.add_checkpoint(11155111, [0xCC; 32], 5_000_000);

        assert_eq!(config.get_checkpoints(1).unwrap().len(), 2);
        assert_eq!(config.get_checkpoints(11155111).unwrap().len(), 1);
        assert!(config.get_checkpoints(999).is_none());
    }

    #[test]
    fn config_min_confirmations() {
        let config = HeaderVerifierConfig::default();
        assert_eq!(config.min_confirmations(1), 12); // Mainnet
        assert_eq!(config.min_confirmations(11155111), 6); // Sepolia
        assert_eq!(config.min_confirmations(17000), 6); // Holesky
    }

    #[test]
    fn verifier_new() {
        let config = HeaderVerifierConfig::default();
        let verifier = HeaderVerifier::new(config);
        assert!(verifier.config().checkpoints.is_empty());
    }

    #[test]
    fn verify_and_store_basic() {
        let db = test_db();
        let storage = EthHeaderStorage::new(&db, 1).expect("storage");

        // Create verifier with devnet mode (allow uncheckpointed)
        let mut config = HeaderVerifierConfig::default();
        config.allow_uncheckpointed = true;
        let verifier = HeaderVerifier::new(config);

        // Create and store a checkpoint
        let checkpoint = test_header(100, [0x00; 32]);

        let now_ms = 1_700_000_000_000u64;
        let cp_id = storage.add_checkpoint(&checkpoint, now_ms).expect("add checkpoint");

        // Verify and store a child header
        let child = test_header(101, cp_id.0);
        let result = verifier.verify_and_store(&storage, &child).expect("verify");

        assert!(result.was_new);
        assert!(result.verified);
        assert_eq!(result.number, 101);
        assert!(result.confirmations.is_some());
    }

    #[test]
    fn verify_from_rlp() {
        let db = test_db();
        let storage = EthHeaderStorage::new(&db, 1).expect("storage");

        let mut config = HeaderVerifierConfig::default();
        config.allow_uncheckpointed = true;
        let verifier = HeaderVerifier::new(config);

        // Create a header and encode to RLP
        let header = test_header(100, [0x00; 32]);
        let rlp = header.rlp_encode();
        let expected_hash = header.header_hash();

        // Add as checkpoint first
        storage.add_checkpoint(&header, 1_700_000_000_000).expect("add");

        // Verify from RLP
        let result = verifier
            .verify_from_rlp(&storage, &rlp, Some(&expected_hash))
            .expect("verify");

        assert_eq!(result.number, 100);
        assert!(result.verified);
    }

    #[test]
    fn verify_from_rlp_hash_mismatch() {
        let db = test_db();
        let storage = EthHeaderStorage::new(&db, 1).expect("storage");

        let config = HeaderVerifierConfig::default();
        let verifier = HeaderVerifier::new(config);

        let header = test_header(100, [0x00; 32]);
        let rlp = header.rlp_encode();
        let wrong_hash = [0xFF; 32];

        let result = verifier.verify_from_rlp(&storage, &rlp, Some(&wrong_hash));
        assert!(matches!(result, Err(HeaderVerifyError::Header(_))));
    }

    #[test]
    fn check_confirmations_basic() {
        let db = test_db();
        let storage = EthHeaderStorage::new(&db, 1).expect("storage");

        let config = HeaderVerifierConfig {
            min_confirmations_mainnet: 3,
            ..Default::default()
        };
        let verifier = HeaderVerifier::new(config);

        // Build a chain: checkpoint -> h1 -> h2 -> h3 (tip)
        let checkpoint = test_header(100, [0x00; 32]);
        let cp_id = storage.add_checkpoint(&checkpoint, 1_700_000_000_000).expect("add");

        let h1 = test_header(101, cp_id.0);
        let h1_hash = h1.header_hash();
        storage.put_header(&h1, 1_700_000_001_000).expect("put");

        let h2 = test_header(102, h1_hash);
        let h2_hash = h2.header_hash();
        storage.put_header(&h2, 1_700_000_002_000).expect("put");

        let h3 = test_header(103, h2_hash);
        let h3_hash = h3.header_hash();
        storage.put_header(&h3, 1_700_000_003_000).expect("put");

        // Verify best tip is h3
        let tip = storage.get_best_tip().expect("tip").expect("has tip");
        assert_eq!(tip.number, 103, "best tip should be h3");

        // h1 has 3 confirmations (tip is 103, h1 is 101) - meets threshold
        let confs = verifier.check_confirmations(&storage, &h1_hash).expect("check h1");
        assert_eq!(confs, 3);

        // checkpoint has 4 confirmations - meets threshold  
        let cp_confs = verifier.check_confirmations(&storage, &cp_id.0).expect("check cp");
        assert_eq!(cp_confs, 4);

        // h2 has 2 confirmations - insufficient (need 3)
        let result = verifier.check_confirmations(&storage, &h2_hash);
        assert!(matches!(
            result,
            Err(HeaderVerifyError::InsufficientConfirmations { got: 2, need: 3 })
        ));

        // h3 has 1 confirmation (tip) - insufficient (need 3)
        let result = verifier.check_confirmations(&storage, &h3_hash);
        assert!(matches!(
            result,
            Err(HeaderVerifyError::InsufficientConfirmations { got: 1, need: 3 })
        ));
    }

    #[test]
    fn get_verified_receipts_root() {
        let db = test_db();
        let storage = EthHeaderStorage::new(&db, 1).expect("storage");

        let mut config = HeaderVerifierConfig::default();
        config.allow_uncheckpointed = true;
        let verifier = HeaderVerifier::new(config);

        let header = test_header(100, [0x00; 32]);
        let hash = header.header_hash();
        storage.add_checkpoint(&header, 1_700_000_000_000).expect("add");

        let receipts_root = verifier
            .get_verified_receipts_root(&storage, &hash)
            .expect("get");

        assert_eq!(receipts_root, [0x66; 32]); // From test_header
    }

    #[test]
    fn get_verified_receipts_root_unverified() {
        let db = test_db();
        let storage = EthHeaderStorage::new(&db, 1).expect("storage");

        let config = HeaderVerifierConfig::default();
        let verifier = HeaderVerifier::new(config);

        // Add orphan header (no parent, unverified)
        let header = test_header(100, [0xFF; 32]);
        let hash = header.header_hash();
        storage.put_header(&header, 1_700_000_000_000).expect("put");

        let result = verifier.get_verified_receipts_root(&storage, &hash);
        assert!(matches!(result, Err(HeaderVerifyError::NotOnVerifiedChain(_))));
    }

    #[test]
    fn multi_chain_verifier() {
        let db = test_db();
        let storage_mainnet = Arc::new(EthHeaderStorage::new(&db, 1).expect("storage"));
        let storage_sepolia = Arc::new(EthHeaderStorage::new(&db, 11155111).expect("storage"));

        let mut config = HeaderVerifierConfig::default();
        config.allow_uncheckpointed = true;

        let mut verifier = MultiChainHeaderVerifier::new(config);
        verifier.add_chain(1, storage_mainnet.clone());
        verifier.add_chain(11155111, storage_sepolia.clone());

        // Add checkpoints to both
        let mainnet_cp = test_header(18_000_000, [0x00; 32]);
        let mainnet_cp_id = storage_mainnet.add_checkpoint(&mainnet_cp, 1_700_000_000_000).expect("add");

        let sepolia_cp = test_header(5_000_000, [0x00; 32]);
        let sepolia_cp_id = storage_sepolia.add_checkpoint(&sepolia_cp, 1_700_000_000_000).expect("add");

        // Verify headers on both chains
        let mainnet_child = test_header(18_000_001, mainnet_cp_id.0);
        let result = verifier.verify_and_store(1, &mainnet_child).expect("verify");
        assert!(result.verified);

        let sepolia_child = test_header(5_000_001, sepolia_cp_id.0);
        let result = verifier.verify_and_store(11155111, &sepolia_child).expect("verify");
        assert!(result.verified);

        // Query best tips
        let mainnet_tip = verifier.get_best_tip(1).expect("tip").expect("present");
        assert_eq!(mainnet_tip.number, 18_000_001);

        let sepolia_tip = verifier.get_best_tip(11155111).expect("tip").expect("present");
        assert_eq!(sepolia_tip.number, 5_000_001);
    }
}
