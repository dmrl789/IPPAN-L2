//! Ethereum PoS Light Client API handlers.
//!
//! This module provides HTTP API handlers for the Ethereum sync committee light client.
//!
//! ## Endpoints
//!
//! - `POST /bridge/eth/lightclient/bootstrap` - Initialize light client with trusted bootstrap
//! - `POST /bridge/eth/lightclient/update` - Submit a light client update
//! - `GET /bridge/eth/lightclient/status` - Get current light client status
//! - `GET /bridge/eth/lightclient/finalized/:block_hash` - Check if execution header is finalized
//! - `POST /bridge/eth/execution_headers` - Submit bulk execution headers (devnet only)
//!
//! ## Trust Model
//!
//! - Bootstrap can only be applied once (unless devnet reset is enabled)
//! - Updates are verified cryptographically using BLS signatures
//! - Finalized execution headers are deterministically derived from verified beacon blocks
//!
//! ## Execution Header Flow
//!
//! When a Merkle proof arrives before the execution header is available for the block,
//! the proof stays in "pending" (Unverified) state. Execution headers can be submitted via:
//! 1. The `execution_header` field in bootstrap/update requests
//! 2. The `submit_execution_header` method in the reconciler handle
//! 3. The bulk `POST /bridge/eth/execution_headers` endpoint (devnet only)

use crate::eth_lightclient_verify::{
    LightClientVerifier, LightClientVerifierConfig, LightClientVerifyError,
};
use l2_core::eth_lightclient::{
    ExecutionPayloadHeaderV1, LightClientBootstrapV1, LightClientStatusV1, LightClientUpdateV1,
    Root,
};
use l2_storage::eth_lightclient::{EthLightClientStorage, EthLightClientStorageError};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, info};

/// Light Client API configuration.
#[derive(Debug, Clone)]
pub struct LightClientApiConfig {
    /// Chain ID for this light client.
    pub chain_id: u64,

    /// Whether devnet mode is enabled (allows bootstrap reset).
    pub devnet_enabled: bool,

    /// Whether to skip cryptographic verification (devnet only).
    pub skip_verification: bool,
}

impl Default for LightClientApiConfig {
    fn default() -> Self {
        Self {
            chain_id: 1, // Mainnet
            devnet_enabled: false,
            skip_verification: false,
        }
    }
}

impl LightClientApiConfig {
    /// Create from environment variables.
    ///
    /// Reads:
    /// - `ETH_CHAIN_ID`: Chain ID (default: 1)
    /// - `DEVNET`: Enable devnet mode for bootstrap reset
    /// - `SKIP_LC_VERIFICATION`: Skip BLS/Merkle verification (devnet only)
    pub fn from_env() -> Self {
        let chain_id = std::env::var("ETH_CHAIN_ID")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(1);

        let devnet_enabled = std::env::var("DEVNET")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false);

        let skip_verification = std::env::var("SKIP_LC_VERIFICATION")
            .map(|v| v == "1" || v.to_lowercase() == "true")
            .unwrap_or(false);

        Self {
            chain_id,
            devnet_enabled,
            skip_verification,
        }
    }

    /// Create a mainnet configuration.
    pub fn mainnet() -> Self {
        Self {
            chain_id: 1,
            devnet_enabled: false,
            skip_verification: false,
        }
    }

    /// Create a sepolia testnet configuration.
    pub fn sepolia() -> Self {
        Self {
            chain_id: 11155111,
            devnet_enabled: false,
            skip_verification: false,
        }
    }

    /// Create a devnet configuration (insecure).
    pub fn devnet() -> Self {
        Self {
            chain_id: 0,
            devnet_enabled: true,
            skip_verification: true,
        }
    }
}

/// Light Client API error.
#[derive(Debug, Error)]
pub enum LightClientApiError {
    #[error("storage error: {0}")]
    Storage(#[from] EthLightClientStorageError),

    #[error("verification error: {0}")]
    Verification(#[from] LightClientVerifyError),

    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("not bootstrapped")]
    NotBootstrapped,

    #[error("already bootstrapped (use devnet mode to reset)")]
    AlreadyBootstrapped,

    #[error("light client error: {0}")]
    LightClient(#[from] l2_core::eth_lightclient::LightClientError),
}

// ========== Request/Response Types ==========

/// Request to bootstrap the light client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapRequest {
    /// The bootstrap data (trusted beacon header + sync committee).
    pub bootstrap: LightClientBootstrapV1,

    /// Optional execution header to store alongside bootstrap.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_header: Option<ExecutionPayloadHeaderV1>,
}

/// Response from bootstrap.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapResponse {
    /// Whether bootstrap was accepted.
    pub accepted: bool,

    /// Bootstrap ID (for idempotency tracking).
    #[serde(with = "hex_root")]
    pub bootstrap_id: Root,

    /// The sync committee period.
    pub period: u64,

    /// The finalized slot.
    pub finalized_slot: u64,

    /// Verification details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification: Option<VerificationDetails>,

    /// Error message if not accepted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Request to submit a light client update.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateRequest {
    /// The light client update.
    pub update: LightClientUpdateV1,

    /// Optional execution header to store.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub execution_header: Option<ExecutionPayloadHeaderV1>,
}

/// Response from update submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateResponse {
    /// Whether update was accepted.
    pub accepted: bool,

    /// Update ID (for idempotency tracking).
    #[serde(with = "hex_root")]
    pub update_id: Root,

    /// The new finalized slot.
    pub finalized_slot: u64,

    /// Whether this update included a sync committee rotation.
    pub has_sync_committee_update: bool,

    /// Number of sync committee signers.
    pub num_signers: u32,

    /// Verification details.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification: Option<VerificationDetails>,

    /// Error message if not accepted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

/// Verification details for responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationDetails {
    /// Whether BLS signature was verified.
    pub signature_verified: bool,

    /// Whether Merkle proofs were verified.
    pub proofs_verified: bool,
}

/// Response for light client status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StatusResponse {
    /// Whether the light client is bootstrapped.
    pub bootstrapped: bool,

    /// Current status (if bootstrapped).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<LightClientStatusV1>,

    /// Chain ID.
    pub chain_id: u64,

    /// Whether devnet mode is enabled.
    pub devnet_enabled: bool,
}

/// Response for finalized header query.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizedHeaderResponse {
    /// Whether the header is finalized.
    pub is_finalized: bool,

    /// The finalized execution header (if found).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<ExecutionPayloadHeaderV1>,

    /// Confirmations (finalized tip number - this block number + 1).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confirmations: Option<u64>,
}

// ========== Bulk Execution Header Submission (devnet) ==========

/// Default maximum execution headers per bulk request.
pub const DEFAULT_MAX_EXECUTION_HEADERS_PER_REQUEST: usize = 100;

/// Default maximum total bytes for bulk execution header requests.
pub const DEFAULT_MAX_EXECUTION_HEADERS_BYTES: usize = 1024 * 1024; // 1 MiB

/// Request to submit bulk execution headers.
///
/// POST /bridge/eth/execution_headers
///
/// This endpoint allows submitting execution headers for blocks that were
/// finalized by earlier beacon updates but whose execution headers were not
/// available at the time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkExecutionHeadersRequest {
    /// List of execution headers to submit.
    pub headers: Vec<ExecutionPayloadHeaderV1>,
}

/// Result for a single execution header submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionHeaderResult {
    /// Block hash of this header.
    #[serde(with = "hex_root")]
    pub block_hash: Root,

    /// Block number of this header.
    pub block_number: u64,

    /// Whether the header was accepted.
    pub accepted: bool,

    /// Reason if not accepted.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

/// Response from bulk execution header submission.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BulkExecutionHeadersResponse {
    /// Number of headers accepted.
    pub accepted_count: usize,

    /// Number of headers skipped (already stored or not yet finalized).
    pub skipped_count: usize,

    /// Number of headers rejected (validation errors).
    pub rejected_count: usize,

    /// Individual results for each header.
    pub results: Vec<ExecutionHeaderResult>,
}

// ========== Serde Helpers ==========

mod hex_root {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(root: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(root))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes =
            hex::decode(s.strip_prefix("0x").unwrap_or(&s)).map_err(serde::de::Error::custom)?;
        if bytes.len() != 32 {
            return Err(serde::de::Error::custom("expected 32 bytes"));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

// ========== API Implementation ==========

/// Ethereum PoS Light Client API service.
pub struct LightClientApi {
    storage: Arc<EthLightClientStorage>,
    verifier: Arc<LightClientVerifier>,
    config: LightClientApiConfig,
}

impl LightClientApi {
    /// Create a new LightClientApi.
    pub fn new(
        storage: Arc<EthLightClientStorage>,
        verifier: Arc<LightClientVerifier>,
        config: LightClientApiConfig,
    ) -> Self {
        Self {
            storage,
            verifier,
            config,
        }
    }

    /// Create a new LightClientApi with auto-configured verifier.
    pub fn with_default_verifier(
        storage: Arc<EthLightClientStorage>,
        config: LightClientApiConfig,
    ) -> Self {
        let verifier_config = if config.skip_verification {
            LightClientVerifierConfig::devnet_insecure()
        } else {
            match config.chain_id {
                1 => LightClientVerifierConfig::mainnet(),
                11155111 => LightClientVerifierConfig::sepolia(),
                17000 => LightClientVerifierConfig::holesky(),
                _ => LightClientVerifierConfig::default().with_chain_id(config.chain_id),
            }
        };

        let verifier = Arc::new(LightClientVerifier::new(verifier_config));
        Self::new(storage, verifier, config)
    }

    /// Get the configuration.
    pub fn config(&self) -> &LightClientApiConfig {
        &self.config
    }

    /// Get the storage.
    pub fn storage(&self) -> &Arc<EthLightClientStorage> {
        &self.storage
    }

    /// Get the verifier.
    pub fn verifier(&self) -> &Arc<LightClientVerifier> {
        &self.verifier
    }

    // ========== API Handlers ==========

    /// Bootstrap the light client.
    ///
    /// POST /bridge/eth/lightclient/bootstrap
    ///
    /// Bootstrap can only be applied once unless devnet mode is enabled.
    pub fn bootstrap(
        &self,
        request: BootstrapRequest,
    ) -> Result<BootstrapResponse, LightClientApiError> {
        let now_ms = current_time_ms();

        // Validate the bootstrap
        request.bootstrap.validate_basic()?;

        // Verify cryptographically
        let verify_result = self.verifier.verify_bootstrap(&request.bootstrap)?;

        debug!(
            bootstrap_id = %hex::encode(verify_result.header_root),
            period = verify_result.period,
            "verified bootstrap"
        );

        // Apply to storage
        match self.storage.apply_bootstrap(
            &request.bootstrap,
            request.execution_header.as_ref(),
            now_ms,
            self.config.devnet_enabled, // allow_reset in devnet
        ) {
            Ok(()) => {
                info!(
                    bootstrap_id = %hex::encode(verify_result.header_root),
                    period = verify_result.period,
                    slot = request.bootstrap.header.slot,
                    "light client bootstrapped"
                );

                Ok(BootstrapResponse {
                    accepted: true,
                    bootstrap_id: verify_result.header_root,
                    period: verify_result.period,
                    finalized_slot: request.bootstrap.header.slot,
                    verification: Some(VerificationDetails {
                        signature_verified: true, // Bootstrap doesn't have signature
                        proofs_verified: verify_result.committee_proof_verified,
                    }),
                    error: None,
                })
            }
            Err(EthLightClientStorageError::AlreadyBootstrapped) => {
                // Return idempotent response if same bootstrap
                if let Some(stored_id) = self.storage.get_bootstrap_id()? {
                    if stored_id == verify_result.header_root {
                        let status = self.storage.get_status()?;
                        return Ok(BootstrapResponse {
                            accepted: true, // Idempotent success
                            bootstrap_id: stored_id,
                            period: verify_result.period,
                            finalized_slot: status.finalized_slot,
                            verification: None,
                            error: None,
                        });
                    }
                }

                Err(LightClientApiError::AlreadyBootstrapped)
            }
            Err(e) => Err(e.into()),
        }
    }

    /// Submit a light client update.
    ///
    /// POST /bridge/eth/lightclient/update
    pub fn submit_update(
        &self,
        request: UpdateRequest,
    ) -> Result<UpdateResponse, LightClientApiError> {
        let now_ms = current_time_ms();

        // Check bootstrapped
        if !self.storage.is_bootstrapped()? {
            return Err(LightClientApiError::NotBootstrapped);
        }

        // Validate the update
        request.update.validate_basic()?;

        // Get current store for verification
        let store = self
            .storage
            .get_lc_state()?
            .ok_or(LightClientApiError::NotBootstrapped)?;

        // Verify cryptographically
        let verify_result = self.verifier.verify_update(&request.update, &store)?;

        debug!(
            update_id = %hex::encode(verify_result.update_id),
            finalized_slot = verify_result.finalized_slot,
            num_signers = verify_result.num_signers,
            "verified update"
        );

        // Check idempotency
        if self.storage.is_update_applied(&verify_result.update_id)? {
            info!(
                update_id = %hex::encode(verify_result.update_id),
                "update already applied (idempotent)"
            );
            return Ok(UpdateResponse {
                accepted: true,
                update_id: verify_result.update_id,
                finalized_slot: verify_result.finalized_slot,
                has_sync_committee_update: verify_result.has_sync_committee_update,
                num_signers: verify_result.num_signers,
                verification: None,
                error: None,
            });
        }

        // Apply to storage
        self.storage
            .apply_update(&request.update, request.execution_header.as_ref(), now_ms)?;

        info!(
            update_id = %hex::encode(verify_result.update_id),
            finalized_slot = verify_result.finalized_slot,
            has_sync_committee_update = verify_result.has_sync_committee_update,
            "light client update applied"
        );

        Ok(UpdateResponse {
            accepted: true,
            update_id: verify_result.update_id,
            finalized_slot: verify_result.finalized_slot,
            has_sync_committee_update: verify_result.has_sync_committee_update,
            num_signers: verify_result.num_signers,
            verification: Some(VerificationDetails {
                signature_verified: verify_result.signature_verified,
                proofs_verified: verify_result.finality_proof_verified,
            }),
            error: None,
        })
    }

    /// Get light client status.
    ///
    /// GET /bridge/eth/lightclient/status
    pub fn get_status(&self) -> Result<StatusResponse, LightClientApiError> {
        let bootstrapped = self.storage.is_bootstrapped()?;
        let status = self.storage.get_status()?;

        // Convert to Option for API response (None if not bootstrapped)
        let status_opt = if status.bootstrapped {
            Some(status)
        } else {
            None
        };

        Ok(StatusResponse {
            bootstrapped,
            status: status_opt,
            chain_id: self.config.chain_id,
            devnet_enabled: self.config.devnet_enabled,
        })
    }

    /// Check if an execution header is finalized.
    ///
    /// GET /bridge/eth/lightclient/finalized/:block_hash
    pub fn get_finalized_header(
        &self,
        block_hash: &Root,
    ) -> Result<FinalizedHeaderResponse, LightClientApiError> {
        let is_finalized = self.storage.is_execution_header_finalized(block_hash)?;

        if !is_finalized {
            return Ok(FinalizedHeaderResponse {
                is_finalized: false,
                header: None,
                confirmations: None,
            });
        }

        let header = self.storage.get_finalized_execution_header(block_hash)?;
        let confirmations = self.storage.execution_confirmations(block_hash)?;

        Ok(FinalizedHeaderResponse {
            is_finalized: true,
            header,
            confirmations,
        })
    }

    /// Get confirmations for an execution block hash.
    pub fn get_confirmations(&self, block_hash: &Root) -> Result<Option<u64>, LightClientApiError> {
        Ok(self.storage.execution_confirmations(block_hash)?)
    }

    /// Get the finalized execution tip.
    pub fn get_finalized_tip(&self) -> Result<Option<(u64, Root)>, LightClientApiError> {
        Ok(self.storage.finalized_execution_tip()?)
    }

    /// Check if ready to verify proofs at a given block.
    pub fn can_verify_at_block(&self, block_hash: &Root) -> Result<bool, LightClientApiError> {
        Ok(self.storage.is_execution_header_finalized(block_hash)?)
    }

    /// Submit bulk execution headers.
    ///
    /// POST /bridge/eth/execution_headers
    ///
    /// This endpoint allows submitting execution headers for blocks whose
    /// block numbers are within the finalized range (i.e., block_number <= finalized tip).
    /// Headers are validated and stored if they pass validation.
    ///
    /// ## Caps (DoS protection)
    ///
    /// - Maximum headers per request: `DEFAULT_MAX_EXECUTION_HEADERS_PER_REQUEST` (100)
    /// - Only available in devnet mode (to prevent abuse in prod)
    ///
    /// ## Use Case
    ///
    /// When a Merkle proof arrives before the execution header is available,
    /// the proof stays in "pending" (Unverified) state. This endpoint allows
    /// external systems to submit the missing execution header, enabling the
    /// reconciler to verify the proof on its next cycle.
    pub fn submit_execution_headers(
        &self,
        request: BulkExecutionHeadersRequest,
    ) -> Result<BulkExecutionHeadersResponse, LightClientApiError> {
        // Check devnet mode
        if !self.config.devnet_enabled {
            return Err(LightClientApiError::InvalidRequest(
                "bulk execution header submission is only available in devnet mode".to_string(),
            ));
        }

        // Check cap on number of headers
        if request.headers.len() > DEFAULT_MAX_EXECUTION_HEADERS_PER_REQUEST {
            return Err(LightClientApiError::InvalidRequest(format!(
                "too many headers: {} (max {})",
                request.headers.len(),
                DEFAULT_MAX_EXECUTION_HEADERS_PER_REQUEST
            )));
        }

        // Check bootstrapped
        if !self.storage.is_bootstrapped()? {
            return Err(LightClientApiError::NotBootstrapped);
        }

        let mut accepted_count = 0;
        let mut skipped_count = 0;
        let mut rejected_count = 0;
        let mut results = Vec::with_capacity(request.headers.len());

        for header in &request.headers {
            // Basic validation
            if let Err(e) = header.validate_basic() {
                results.push(ExecutionHeaderResult {
                    block_hash: header.block_hash,
                    block_number: header.block_number,
                    accepted: false,
                    reason: Some(format!("validation failed: {}", e)),
                });
                rejected_count += 1;
                continue;
            }

            // Check if already stored first (for accurate reporting)
            let already_stored = self
                .storage
                .is_execution_header_finalized(&header.block_hash)?;

            if already_stored {
                results.push(ExecutionHeaderResult {
                    block_hash: header.block_hash,
                    block_number: header.block_number,
                    accepted: false,
                    reason: Some("header already stored".to_string()),
                });
                skipped_count += 1;
                continue;
            }

            // Try to store if within finalized range
            match self.storage.store_execution_header_if_finalized(header) {
                Ok(true) => {
                    results.push(ExecutionHeaderResult {
                        block_hash: header.block_hash,
                        block_number: header.block_number,
                        accepted: true,
                        reason: None,
                    });
                    accepted_count += 1;
                    debug!(
                        block_hash = %hex::encode(header.block_hash),
                        block_number = header.block_number,
                        "stored execution header via bulk API"
                    );
                }
                Ok(false) => {
                    // Block not yet finalized
                    results.push(ExecutionHeaderResult {
                        block_hash: header.block_hash,
                        block_number: header.block_number,
                        accepted: false,
                        reason: Some("block not yet finalized".to_string()),
                    });
                    skipped_count += 1;
                }
                Err(e) => {
                    results.push(ExecutionHeaderResult {
                        block_hash: header.block_hash,
                        block_number: header.block_number,
                        accepted: false,
                        reason: Some(format!("storage error: {}", e)),
                    });
                    rejected_count += 1;
                }
            }
        }

        info!(
            accepted = accepted_count,
            skipped = skipped_count,
            rejected = rejected_count,
            "processed bulk execution headers"
        );

        Ok(BulkExecutionHeadersResponse {
            accepted_count,
            skipped_count,
            rejected_count,
            results,
        })
    }
}

/// Get current time in milliseconds.
fn current_time_ms() -> u64 {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    u64::try_from(ms).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use l2_core::eth_lightclient::{
        BeaconBlockHeaderV1, SyncAggregateV1, SyncCommitteeV1, SYNC_COMMITTEE_BITS_SIZE,
        SYNC_COMMITTEE_SIZE,
    };
    use tempfile::tempdir;

    fn test_beacon_header() -> BeaconBlockHeaderV1 {
        BeaconBlockHeaderV1 {
            slot: 8_000_000,
            proposer_index: 12345,
            parent_root: [0x11; 32],
            state_root: [0x22; 32],
            body_root: [0x33; 32],
        }
    }

    fn test_sync_committee() -> SyncCommitteeV1 {
        SyncCommitteeV1 {
            pubkeys: vec![[0xAA; 48]; SYNC_COMMITTEE_SIZE],
            aggregate_pubkey: [0xBB; 48],
        }
    }

    fn test_sync_aggregate() -> SyncAggregateV1 {
        SyncAggregateV1 {
            sync_committee_bits: vec![0xFF; SYNC_COMMITTEE_BITS_SIZE],
            sync_committee_signature: [0xCC; 96],
        }
    }

    fn test_bootstrap() -> LightClientBootstrapV1 {
        LightClientBootstrapV1 {
            header: test_beacon_header(),
            current_sync_committee: test_sync_committee(),
            current_sync_committee_branch: vec![[0xDD; 32]; 5],
        }
    }

    fn test_update() -> LightClientUpdateV1 {
        LightClientUpdateV1 {
            attested_header: BeaconBlockHeaderV1 {
                slot: 8_001_000,
                ..test_beacon_header()
            },
            next_sync_committee: None,
            next_sync_committee_branch: None,
            finalized_header: BeaconBlockHeaderV1 {
                slot: 8_000_900,
                ..test_beacon_header()
            },
            finality_branch: vec![[0xDD; 32]; 6],
            sync_aggregate: test_sync_aggregate(),
            signature_slot: 8_001_001,
        }
    }

    fn setup_api() -> LightClientApi {
        let dir = tempdir().expect("tmpdir");
        let db = sled::open(dir.path()).expect("open sled");
        let storage = Arc::new(EthLightClientStorage::new(&db, 1).expect("storage"));
        let config = LightClientApiConfig::devnet();
        LightClientApi::with_default_verifier(storage, config)
    }

    #[test]
    fn status_not_bootstrapped() {
        let api = setup_api();
        let status = api.get_status().expect("status");
        assert!(!status.bootstrapped);
        assert!(status.status.is_none());
    }

    #[test]
    fn bootstrap_success() {
        let api = setup_api();

        let request = BootstrapRequest {
            bootstrap: test_bootstrap(),
            execution_header: None,
        };

        let response = api.bootstrap(request).expect("bootstrap");
        assert!(response.accepted);
        assert_eq!(response.finalized_slot, 8_000_000);

        // Check status
        let status = api.get_status().expect("status");
        assert!(status.bootstrapped);
        assert!(status.status.is_some());
    }

    #[test]
    fn bootstrap_idempotent() {
        let api = setup_api();

        let request = BootstrapRequest {
            bootstrap: test_bootstrap(),
            execution_header: None,
        };

        let response1 = api.bootstrap(request.clone()).expect("bootstrap 1");
        let response2 = api.bootstrap(request).expect("bootstrap 2");

        assert!(response1.accepted);
        assert!(response2.accepted);
        assert_eq!(response1.bootstrap_id, response2.bootstrap_id);
    }

    #[test]
    fn update_requires_bootstrap() {
        let api = setup_api();

        let request = UpdateRequest {
            update: test_update(),
            execution_header: None,
        };

        let result = api.submit_update(request);
        assert!(matches!(result, Err(LightClientApiError::NotBootstrapped)));
    }

    #[test]
    fn update_success() {
        let api = setup_api();

        // Bootstrap first
        let bootstrap_request = BootstrapRequest {
            bootstrap: test_bootstrap(),
            execution_header: None,
        };
        api.bootstrap(bootstrap_request).expect("bootstrap");

        // Submit update
        let update_request = UpdateRequest {
            update: test_update(),
            execution_header: None,
        };
        let response = api.submit_update(update_request).expect("update");

        assert!(response.accepted);
        assert_eq!(response.finalized_slot, 8_000_900);
    }

    #[test]
    fn update_idempotent() {
        let api = setup_api();

        // Bootstrap first
        let bootstrap_request = BootstrapRequest {
            bootstrap: test_bootstrap(),
            execution_header: None,
        };
        api.bootstrap(bootstrap_request).expect("bootstrap");

        // Submit update twice
        let update_request = UpdateRequest {
            update: test_update(),
            execution_header: None,
        };
        let response1 = api.submit_update(update_request.clone()).expect("update 1");
        let response2 = api.submit_update(update_request).expect("update 2");

        assert!(response1.accepted);
        assert!(response2.accepted);
        assert_eq!(response1.update_id, response2.update_id);
    }

    #[test]
    fn finalized_header_not_found() {
        let api = setup_api();

        let block_hash = [0xAA; 32];
        let response = api.get_finalized_header(&block_hash).expect("query");

        assert!(!response.is_finalized);
        assert!(response.header.is_none());
    }

    #[test]
    fn config_from_env() {
        std::env::set_var("ETH_CHAIN_ID", "11155111");
        std::env::set_var("DEVNET", "1");

        let config = LightClientApiConfig::from_env();

        assert_eq!(config.chain_id, 11155111);
        assert!(config.devnet_enabled);

        // Clean up
        std::env::remove_var("ETH_CHAIN_ID");
        std::env::remove_var("DEVNET");
    }

    // ========== Bulk Execution Header Tests ==========

    fn test_execution_header(block_number: u64) -> ExecutionPayloadHeaderV1 {
        ExecutionPayloadHeaderV1 {
            parent_hash: [0x11; 32],
            fee_recipient: [0x22; 20],
            state_root: [0x33; 32],
            receipts_root: [0x44; 32],
            logs_bloom: [0x00; 256],
            prev_randao: [0x55; 32],
            block_number,
            gas_limit: 30_000_000,
            gas_used: 15_000_000,
            timestamp: 1_700_000_000 + block_number,
            extra_data: vec![],
            base_fee_per_gas: 10_000_000_000,
            block_hash: {
                // Make hash unique based on block number
                let mut hash = [0x66; 32];
                hash[0..8].copy_from_slice(&block_number.to_le_bytes());
                hash
            },
            transactions_root: [0x77; 32],
            withdrawals_root: [0x88; 32],
            blob_gas_used: 0,
            excess_blob_gas: 0,
        }
    }

    #[test]
    fn bulk_execution_headers_requires_bootstrap() {
        let api = setup_api();

        let request = BulkExecutionHeadersRequest {
            headers: vec![test_execution_header(18_000_000)],
        };

        let result = api.submit_execution_headers(request);
        assert!(matches!(result, Err(LightClientApiError::NotBootstrapped)));
    }

    #[test]
    fn bulk_execution_headers_empty_request() {
        let api = setup_api();

        // Bootstrap first with an execution header to establish finalized tip
        let exec_header = test_execution_header(18_000_000);
        let bootstrap_request = BootstrapRequest {
            bootstrap: test_bootstrap(),
            execution_header: Some(exec_header),
        };
        api.bootstrap(bootstrap_request).expect("bootstrap");

        // Submit empty request
        let request = BulkExecutionHeadersRequest { headers: vec![] };
        let response = api.submit_execution_headers(request).expect("submit");

        assert_eq!(response.accepted_count, 0);
        assert_eq!(response.skipped_count, 0);
        assert_eq!(response.rejected_count, 0);
        assert!(response.results.is_empty());
    }

    #[test]
    fn bulk_execution_headers_accepts_finalized_blocks() {
        let api = setup_api();

        // Bootstrap with execution header at block 18_000_000
        let exec_header = test_execution_header(18_000_000);
        let bootstrap_request = BootstrapRequest {
            bootstrap: test_bootstrap(),
            execution_header: Some(exec_header),
        };
        api.bootstrap(bootstrap_request).expect("bootstrap");

        // Submit update to advance finalized tip to include more blocks
        let update_exec = test_execution_header(18_000_100);
        let update_request = UpdateRequest {
            update: test_update(),
            execution_header: Some(update_exec),
        };
        api.submit_update(update_request).expect("update");

        // Now submit execution headers for blocks in between (18_000_001 to 18_000_010)
        let headers: Vec<_> = (1..=10)
            .map(|i| test_execution_header(18_000_000 + i))
            .collect();
        let request = BulkExecutionHeadersRequest { headers };
        let response = api.submit_execution_headers(request).expect("submit");

        // All should be accepted since they're within finalized range
        assert_eq!(response.accepted_count, 10);
        assert_eq!(response.skipped_count, 0);
        assert_eq!(response.rejected_count, 0);
    }

    #[test]
    fn bulk_execution_headers_skips_not_finalized() {
        let api = setup_api();

        // Bootstrap with execution header at block 18_000_000
        let exec_header = test_execution_header(18_000_000);
        let bootstrap_request = BootstrapRequest {
            bootstrap: test_bootstrap(),
            execution_header: Some(exec_header),
        };
        api.bootstrap(bootstrap_request).expect("bootstrap");

        // Submit headers for blocks beyond finalized tip
        let headers: Vec<_> = (1..=5)
            .map(|i| test_execution_header(18_000_000 + i))
            .collect();
        let request = BulkExecutionHeadersRequest { headers };
        let response = api.submit_execution_headers(request).expect("submit");

        // All should be skipped since they're beyond finalized tip
        assert_eq!(response.accepted_count, 0);
        assert_eq!(response.skipped_count, 5);
        assert_eq!(response.rejected_count, 0);
        for result in &response.results {
            assert!(!result.accepted);
            assert!(result
                .reason
                .as_ref()
                .unwrap()
                .contains("not yet finalized"));
        }
    }

    #[test]
    fn bulk_execution_headers_skips_already_stored() {
        let api = setup_api();

        // Bootstrap with execution header
        let exec_header = test_execution_header(18_000_000);
        let bootstrap_request = BootstrapRequest {
            bootstrap: test_bootstrap(),
            execution_header: Some(exec_header.clone()),
        };
        api.bootstrap(bootstrap_request).expect("bootstrap");

        // Try to submit the same header again
        let request = BulkExecutionHeadersRequest {
            headers: vec![exec_header],
        };
        let response = api.submit_execution_headers(request).expect("submit");

        assert_eq!(response.accepted_count, 0);
        assert_eq!(response.skipped_count, 1);
        assert_eq!(response.rejected_count, 0);
        assert!(response.results[0]
            .reason
            .as_ref()
            .unwrap()
            .contains("already stored"));
    }

    #[test]
    fn bulk_execution_headers_cap_enforced() {
        let api = setup_api();

        // Bootstrap
        let exec_header = test_execution_header(18_000_000);
        let bootstrap_request = BootstrapRequest {
            bootstrap: test_bootstrap(),
            execution_header: Some(exec_header),
        };
        api.bootstrap(bootstrap_request).expect("bootstrap");

        // Create request with too many headers
        let headers: Vec<_> = (0..DEFAULT_MAX_EXECUTION_HEADERS_PER_REQUEST + 1)
            .map(|i| test_execution_header(18_000_000 + i as u64))
            .collect();
        let request = BulkExecutionHeadersRequest { headers };

        let result = api.submit_execution_headers(request);
        assert!(matches!(
            result,
            Err(LightClientApiError::InvalidRequest(_))
        ));
    }

    #[test]
    fn bulk_execution_headers_devnet_only() {
        // Create a prod-mode API (skip verification for test data, but devnet_enabled=false)
        let dir = tempdir().expect("tmpdir");
        let db = sled::open(dir.path()).expect("open sled");
        let storage = Arc::new(EthLightClientStorage::new(&db, 1).expect("storage"));
        let config = LightClientApiConfig {
            chain_id: 1,
            devnet_enabled: false,   // This is the key - prod mode
            skip_verification: true, // Skip verification for test data
        };
        let api = LightClientApi::with_default_verifier(storage, config);

        // Bootstrap
        let bootstrap_request = BootstrapRequest {
            bootstrap: test_bootstrap(),
            execution_header: None,
        };
        api.bootstrap(bootstrap_request).expect("bootstrap");

        // Try to submit headers - should fail because devnet is not enabled
        let request = BulkExecutionHeadersRequest {
            headers: vec![test_execution_header(18_000_000)],
        };
        let result = api.submit_execution_headers(request);
        assert!(matches!(
            result,
            Err(LightClientApiError::InvalidRequest(_))
        ));
        if let Err(LightClientApiError::InvalidRequest(msg)) = result {
            assert!(msg.contains("devnet"), "error should mention devnet");
        }
    }
}
