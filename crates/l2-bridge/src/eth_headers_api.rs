//! Ethereum Header Chain API handlers.
//!
//! This module provides HTTP API handlers for the Ethereum light client header chain.
//!
//! ## Endpoints
//!
//! - `POST /bridge/eth/headers` - Submit one or many headers (devnet initially)
//! - `GET /bridge/eth/headers/best_tip` - Get current best tip
//! - `GET /bridge/eth/headers/:hash` - Get header by hash
//! - `GET /bridge/eth/confirmations/:block_hash` - Get confirmations for a block
//! - `GET /bridge/eth/headers/stats` - Get header chain statistics
//!
//! ## Trust Model
//!
//! This API is initially gated behind `DEVNET=1` for security.
//! In production, headers should be submitted through trusted channels
//! or verified via sync committees.

use crate::eth_headers_verify::{HeaderVerifier, HeaderVerifyError, HeaderVerifyResult};
use l2_core::eth_header::{EthereumHeaderV1, Hash256, HeaderId};
use l2_storage::eth_headers::{EthHeaderStorage, StoredHeader};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use tracing::warn;

/// Ethereum Header API configuration.
#[derive(Debug, Clone)]
pub struct EthHeaderApiConfig {
    /// Chain ID for this header API.
    pub chain_id: u64,

    /// Whether devnet mode is enabled (allows header submission).
    pub devnet_enabled: bool,

    /// Maximum headers per submission request.
    pub max_headers_per_request: usize,
}

impl Default for EthHeaderApiConfig {
    fn default() -> Self {
        Self {
            chain_id: 1, // Mainnet
            devnet_enabled: false,
            max_headers_per_request: 100,
        }
    }
}

impl EthHeaderApiConfig {
    /// Create from environment variables.
    ///
    /// Reads:
    /// - `ETH_CHAIN_ID`: Chain ID (default: 1)
    /// - `DEVNET`: Enable devnet mode for header submission
    /// - `ETH_MAX_HEADERS_PER_REQUEST`: Max headers per request (default: 100)
    pub fn from_env() -> Self {
        let chain_id = std::env::var("ETH_CHAIN_ID")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);

        let devnet_enabled = std::env::var("DEVNET")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false);

        let max_headers_per_request = std::env::var("ETH_MAX_HEADERS_PER_REQUEST")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(100);

        Self {
            chain_id,
            devnet_enabled,
            max_headers_per_request,
        }
    }
}

/// Ethereum Header API error.
#[derive(Debug, Error)]
pub enum EthHeaderApiError {
    #[error("storage error: {0}")]
    Storage(#[from] l2_storage::eth_headers::EthHeaderStorageError),

    #[error("verification error: {0}")]
    Verification(#[from] HeaderVerifyError),

    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("devnet mode required")]
    DevnetRequired,

    #[error("header error: {0}")]
    Header(#[from] l2_core::eth_header::EthHeaderError),
}

/// Ethereum Header API service.
pub struct EthHeaderApi {
    storage: Arc<EthHeaderStorage>,
    verifier: Arc<HeaderVerifier>,
    config: EthHeaderApiConfig,
}

impl EthHeaderApi {
    /// Create a new EthHeaderApi.
    pub fn new(
        storage: Arc<EthHeaderStorage>,
        verifier: Arc<HeaderVerifier>,
        config: EthHeaderApiConfig,
    ) -> Self {
        Self {
            storage,
            verifier,
            config,
        }
    }

    /// Get the configuration.
    pub fn config(&self) -> &EthHeaderApiConfig {
        &self.config
    }

    /// Get the storage.
    pub fn storage(&self) -> &Arc<EthHeaderStorage> {
        &self.storage
    }

    /// Get the verifier.
    pub fn verifier(&self) -> &Arc<HeaderVerifier> {
        &self.verifier
    }

    // ========== API Handlers ==========

    /// Submit one or more headers.
    ///
    /// POST /bridge/eth/headers
    ///
    /// Requires `DEVNET=1` to be set.
    pub fn submit_headers(
        &self,
        request: SubmitHeadersRequest,
    ) -> Result<SubmitHeadersResponse, EthHeaderApiError> {
        // Check devnet mode
        if !self.config.devnet_enabled {
            return Err(EthHeaderApiError::DevnetRequired);
        }

        // Validate request size
        if request.headers.len() > self.config.max_headers_per_request {
            return Err(EthHeaderApiError::InvalidRequest(format!(
                "too many headers: {} > {}",
                request.headers.len(),
                self.config.max_headers_per_request
            )));
        }

        let mut results = Vec::with_capacity(request.headers.len());

        for header_input in &request.headers {
            let result = self.process_header_input(header_input);
            results.push(result);
        }

        // Get current best tip
        let best_tip = self.storage.get_best_tip()?.map(|t| BestTipResponse {
            header_hash: hex::encode(t.header_hash),
            number: t.number,
            updated_at_ms: t.updated_at_ms,
        });

        let accepted = results.iter().filter(|r| r.accepted).count();
        let rejected = results.iter().filter(|r| !r.accepted).count();

        Ok(SubmitHeadersResponse {
            accepted,
            rejected,
            results,
            best_tip,
        })
    }

    /// Process a single header input.
    fn process_header_input(&self, input: &HeaderInput) -> HeaderSubmitResult {
        match self.process_header_input_inner(input) {
            Ok(verify_result) => HeaderSubmitResult {
                header_hash: verify_result.header_id.to_hex(),
                number: verify_result.number,
                accepted: true,
                verified: verify_result.verified,
                was_new: verify_result.was_new,
                error: None,
            },
            Err(e) => {
                warn!(error = %e, "header submission failed");
                HeaderSubmitResult {
                    header_hash: input.expected_hash.clone().unwrap_or_default(),
                    number: 0,
                    accepted: false,
                    verified: false,
                    was_new: false,
                    error: Some(e.to_string()),
                }
            }
        }
    }

    /// Inner function to process header input.
    fn process_header_input_inner(
        &self,
        input: &HeaderInput,
    ) -> Result<HeaderVerifyResult, EthHeaderApiError> {
        // If RLP provided, use that
        if let Some(rlp_hex) = &input.rlp {
            let rlp_bytes =
                hex::decode(rlp_hex.strip_prefix("0x").unwrap_or(rlp_hex)).map_err(|e| {
                    EthHeaderApiError::InvalidRequest(format!("invalid RLP hex: {}", e))
                })?;

            let expected_hash = if let Some(h) = &input.expected_hash {
                let hash_bytes = hex::decode(h.strip_prefix("0x").unwrap_or(h)).map_err(|e| {
                    EthHeaderApiError::InvalidRequest(format!("invalid hash hex: {}", e))
                })?;
                if hash_bytes.len() != 32 {
                    return Err(EthHeaderApiError::InvalidRequest(
                        "hash must be 32 bytes".into(),
                    ));
                }
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&hash_bytes);
                Some(arr)
            } else {
                None
            };

            let result =
                self.verifier
                    .verify_from_rlp(&self.storage, &rlp_bytes, expected_hash.as_ref())?;

            return Ok(result);
        }

        // Otherwise, expect structured header
        if let Some(header) = &input.header {
            let result = self.verifier.verify_and_store(&self.storage, header)?;
            return Ok(result);
        }

        Err(EthHeaderApiError::InvalidRequest(
            "must provide either 'rlp' or 'header'".into(),
        ))
    }

    /// Get the best tip.
    ///
    /// GET /bridge/eth/headers/best_tip
    pub fn get_best_tip(&self) -> Result<Option<BestTipResponse>, EthHeaderApiError> {
        let tip = self.storage.get_best_tip()?;
        Ok(tip.map(|t| BestTipResponse {
            header_hash: hex::encode(t.header_hash),
            number: t.number,
            updated_at_ms: t.updated_at_ms,
        }))
    }

    /// Get a header by hash.
    ///
    /// GET /bridge/eth/headers/:hash
    pub fn get_header(&self, hash_hex: &str) -> Result<HeaderResponse, EthHeaderApiError> {
        let hash_bytes = hex::decode(hash_hex.strip_prefix("0x").unwrap_or(hash_hex))
            .map_err(|e| EthHeaderApiError::InvalidRequest(format!("invalid hash hex: {}", e)))?;

        if hash_bytes.len() != 32 {
            return Err(EthHeaderApiError::InvalidRequest(
                "hash must be 32 bytes".into(),
            ));
        }

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hash_bytes);

        let id = HeaderId(hash);
        let stored = self
            .storage
            .get_header(&id)?
            .ok_or_else(|| EthHeaderApiError::NotFound(hash_hex.to_string()))?;

        Ok(HeaderResponse::from_stored(&stored))
    }

    /// Get confirmations for a block.
    ///
    /// GET /bridge/eth/confirmations/:block_hash
    pub fn get_confirmations(
        &self,
        block_hash_hex: &str,
    ) -> Result<ConfirmationsResponse, EthHeaderApiError> {
        let hash_bytes = hex::decode(block_hash_hex.strip_prefix("0x").unwrap_or(block_hash_hex))
            .map_err(|e| {
            EthHeaderApiError::InvalidRequest(format!("invalid hash hex: {}", e))
        })?;

        if hash_bytes.len() != 32 {
            return Err(EthHeaderApiError::InvalidRequest(
                "hash must be 32 bytes".into(),
            ));
        }

        let mut hash = [0u8; 32];
        hash.copy_from_slice(&hash_bytes);

        let id = HeaderId(hash);

        // Check if header exists and is verified
        let stored = self.storage.get_header(&id)?;
        let is_verified = stored
            .as_ref()
            .map(|s| s.state.is_verified())
            .unwrap_or(false);

        // Get confirmations
        let confirmations = self.storage.confirmations(&hash)?;

        // Get min confirmations requirement
        let min_confirmations = self
            .verifier
            .config()
            .min_confirmations(self.config.chain_id);

        Ok(ConfirmationsResponse {
            block_hash: block_hash_hex.to_string(),
            confirmations,
            is_verified,
            min_required: min_confirmations,
            meets_threshold: confirmations
                .map(|c| c >= min_confirmations)
                .unwrap_or(false),
        })
    }

    /// Get header chain statistics.
    ///
    /// GET /bridge/eth/headers/stats
    pub fn get_stats(&self) -> Result<HeaderStatsResponse, EthHeaderApiError> {
        let counts = self.storage.count_headers()?;
        let best_tip = self.storage.get_best_tip()?;

        Ok(HeaderStatsResponse {
            chain_id: self.config.chain_id,
            total_headers: counts.total(),
            verified_headers: counts.verified,
            checkpoint_headers: counts.checkpoints,
            unverified_headers: counts.unverified,
            best_tip: best_tip.map(|t| BestTipResponse {
                header_hash: hex::encode(t.header_hash),
                number: t.number,
                updated_at_ms: t.updated_at_ms,
            }),
            devnet_enabled: self.config.devnet_enabled,
        })
    }

    /// Check if a block hash has sufficient confirmations.
    ///
    /// This is used by other components to verify blocks before accepting proofs.
    pub fn check_confirmations(&self, block_hash: &Hash256) -> Result<u64, EthHeaderApiError> {
        let confirmations = self
            .verifier
            .check_confirmations(&self.storage, block_hash)?;
        Ok(confirmations)
    }

    /// Get the receipts root for a verified block.
    ///
    /// This is used to anchor Merkle receipt proofs to verified headers.
    pub fn get_verified_receipts_root(
        &self,
        block_hash: &Hash256,
    ) -> Result<Hash256, EthHeaderApiError> {
        let receipts_root = self
            .verifier
            .get_verified_receipts_root(&self.storage, block_hash)?;
        Ok(receipts_root)
    }
}

// ========== Request/Response Types ==========

/// Request to submit headers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitHeadersRequest {
    /// Headers to submit.
    pub headers: Vec<HeaderInput>,
}

/// Input for a single header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderInput {
    /// RLP-encoded header (hex string, with or without 0x prefix).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rlp: Option<String>,

    /// Structured header (alternative to RLP).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<EthereumHeaderV1>,

    /// Expected hash (optional, for verification).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_hash: Option<String>,
}

/// Response from header submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitHeadersResponse {
    /// Number of accepted headers.
    pub accepted: usize,

    /// Number of rejected headers.
    pub rejected: usize,

    /// Per-header results.
    pub results: Vec<HeaderSubmitResult>,

    /// Current best tip after submission.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub best_tip: Option<BestTipResponse>,
}

/// Result for a single header submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderSubmitResult {
    /// Header hash.
    pub header_hash: String,

    /// Block number.
    pub number: u64,

    /// Whether the header was accepted.
    pub accepted: bool,

    /// Whether the header is on a verified chain.
    pub verified: bool,

    /// Whether this was a new header (not a duplicate).
    pub was_new: bool,

    /// Error message (if rejected).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Best tip response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BestTipResponse {
    /// Header hash of the best tip.
    pub header_hash: String,

    /// Block number.
    pub number: u64,

    /// Timestamp when tip was updated.
    pub updated_at_ms: u64,
}

/// Response for a single header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderResponse {
    /// Header hash.
    pub header_hash: String,

    /// Block number.
    pub number: u64,

    /// Parent hash.
    pub parent_hash: String,

    /// Receipts root.
    pub receipts_root: String,

    /// State root.
    pub state_root: String,

    /// Timestamp.
    pub timestamp: u64,

    /// Verification state.
    pub verification_state: String,

    /// Whether verified (on verified chain).
    pub is_verified: bool,

    /// Stored at timestamp.
    pub stored_at_ms: u64,
}

impl HeaderResponse {
    /// Create from a stored header.
    pub fn from_stored(stored: &StoredHeader) -> Self {
        Self {
            header_hash: hex::encode(stored.header_hash),
            number: stored.header.number,
            parent_hash: hex::encode(stored.header.parent_hash),
            receipts_root: hex::encode(stored.header.receipts_root),
            state_root: hex::encode(stored.header.state_root),
            timestamp: stored.header.timestamp,
            verification_state: stored.state.name().to_string(),
            is_verified: stored.state.is_verified(),
            stored_at_ms: stored.stored_at_ms,
        }
    }
}

/// Response for confirmations query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfirmationsResponse {
    /// Block hash.
    pub block_hash: String,

    /// Number of confirmations (None if not on verified chain).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmations: Option<u64>,

    /// Whether the block is verified.
    pub is_verified: bool,

    /// Minimum confirmations required.
    pub min_required: u64,

    /// Whether the block meets the confirmation threshold.
    pub meets_threshold: bool,
}

/// Response for header chain statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeaderStatsResponse {
    /// Chain ID.
    pub chain_id: u64,

    /// Total headers stored.
    pub total_headers: u64,

    /// Verified headers.
    pub verified_headers: u64,

    /// Checkpoint headers.
    pub checkpoint_headers: u64,

    /// Unverified headers.
    pub unverified_headers: u64,

    /// Current best tip.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub best_tip: Option<BestTipResponse>,

    /// Whether devnet mode is enabled.
    pub devnet_enabled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use l2_storage::eth_headers::EthHeaderStorage;
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

    fn create_test_api(devnet_enabled: bool) -> (EthHeaderApi, sled::Db) {
        let db = test_db();
        let storage = Arc::new(EthHeaderStorage::new(&db, 1).expect("storage"));

        let verifier_config = crate::eth_headers_verify::HeaderVerifierConfig {
            allow_uncheckpointed: true,
            min_confirmations_mainnet: 3,
            ..Default::default()
        };
        let verifier = Arc::new(HeaderVerifier::new(verifier_config));

        let api_config = EthHeaderApiConfig {
            chain_id: 1,
            devnet_enabled,
            max_headers_per_request: 100,
        };

        let api = EthHeaderApi::new(storage, verifier, api_config);
        (api, db)
    }

    #[test]
    fn devnet_guard() {
        let (api, _db) = create_test_api(false);

        let request = SubmitHeadersRequest {
            headers: vec![HeaderInput {
                rlp: None,
                header: Some(test_header(100, [0x00; 32])),
                expected_hash: None,
            }],
        };

        let result = api.submit_headers(request);
        assert!(matches!(result, Err(EthHeaderApiError::DevnetRequired)));
    }

    #[test]
    fn submit_structured_header() {
        let (api, _db) = create_test_api(true);

        // First add a checkpoint
        let checkpoint = test_header(100, [0x00; 32]);
        let cp_id = api
            .storage
            .add_checkpoint(&checkpoint, 1_700_000_000_000)
            .expect("add");

        // Submit child header
        let request = SubmitHeadersRequest {
            headers: vec![HeaderInput {
                rlp: None,
                header: Some(test_header(101, cp_id.0)),
                expected_hash: None,
            }],
        };

        let response = api.submit_headers(request).expect("submit");
        assert_eq!(response.accepted, 1);
        assert_eq!(response.rejected, 0);
        assert!(response.results[0].accepted);
        assert!(response.results[0].verified);
    }

    #[test]
    fn submit_rlp_header() {
        let (api, _db) = create_test_api(true);

        // First add a checkpoint
        let checkpoint = test_header(100, [0x00; 32]);
        let cp_id = api
            .storage
            .add_checkpoint(&checkpoint, 1_700_000_000_000)
            .expect("add");

        // Create child and encode to RLP
        let child = test_header(101, cp_id.0);
        let rlp = child.rlp_encode();
        let expected_hash = hex::encode(child.header_hash());

        let request = SubmitHeadersRequest {
            headers: vec![HeaderInput {
                rlp: Some(hex::encode(&rlp)),
                header: None,
                expected_hash: Some(expected_hash),
            }],
        };

        let response = api.submit_headers(request).expect("submit");
        assert_eq!(response.accepted, 1);
        assert!(response.results[0].verified);
    }

    #[test]
    fn get_best_tip() {
        let (api, _db) = create_test_api(true);

        // No tip initially
        let tip = api.get_best_tip().expect("get");
        assert!(tip.is_none());

        // Add checkpoint
        let checkpoint = test_header(100, [0x00; 32]);
        api.storage
            .add_checkpoint(&checkpoint, 1_700_000_000_000)
            .expect("add");

        // Now we have a tip
        let tip = api.get_best_tip().expect("get").expect("tip");
        assert_eq!(tip.number, 100);
    }

    #[test]
    fn get_header_by_hash() {
        let (api, _db) = create_test_api(true);

        let checkpoint = test_header(100, [0x00; 32]);
        let cp_id = api
            .storage
            .add_checkpoint(&checkpoint, 1_700_000_000_000)
            .expect("add");

        let hash_hex = hex::encode(cp_id.0);
        let response = api.get_header(&hash_hex).expect("get");

        assert_eq!(response.number, 100);
        assert!(response.is_verified);
        assert_eq!(response.verification_state, "checkpoint");
    }

    #[test]
    fn get_confirmations() {
        let (api, _db) = create_test_api(true);

        // Add chain: checkpoint -> h1 -> h2
        let checkpoint = test_header(100, [0x00; 32]);
        let cp_id = api
            .storage
            .add_checkpoint(&checkpoint, 1_700_000_000_000)
            .expect("add");

        let h1 = test_header(101, cp_id.0);
        api.storage.put_header(&h1, 1_700_000_001_000).expect("put");
        let h1_hash = h1.header_hash();

        let h2 = test_header(102, h1_hash);
        api.storage.put_header(&h2, 1_700_000_002_000).expect("put");

        // Check confirmations for checkpoint (3 confirmations, meets threshold)
        let resp = api.get_confirmations(&hex::encode(cp_id.0)).expect("get");
        assert_eq!(resp.confirmations, Some(3));
        assert!(resp.meets_threshold);

        // Check confirmations for h1 (2 confirmations, doesn't meet threshold)
        let resp = api.get_confirmations(&hex::encode(h1_hash)).expect("get");
        assert_eq!(resp.confirmations, Some(2));
        assert!(!resp.meets_threshold);
    }

    #[test]
    fn get_stats() {
        let (api, _db) = create_test_api(true);

        // Empty stats
        let stats = api.get_stats().expect("stats");
        assert_eq!(stats.total_headers, 0);
        assert!(stats.devnet_enabled);

        // Add checkpoint
        let checkpoint = test_header(100, [0x00; 32]);
        api.storage
            .add_checkpoint(&checkpoint, 1_700_000_000_000)
            .expect("add");

        let stats = api.get_stats().expect("stats");
        assert_eq!(stats.total_headers, 1);
        assert_eq!(stats.checkpoint_headers, 1);
        assert!(stats.best_tip.is_some());
    }
}
