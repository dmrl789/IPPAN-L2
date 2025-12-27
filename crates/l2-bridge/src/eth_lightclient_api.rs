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
//!
//! ## Trust Model
//!
//! - Bootstrap can only be applied once (unless devnet reset is enabled)
//! - Updates are verified cryptographically using BLS signatures
//! - Finalized execution headers are deterministically derived from verified beacon blocks

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
}
