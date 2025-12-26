//! External Proof API handlers.
//!
//! This module provides HTTP API handlers for external chain proofs.
//!
//! ## Endpoints
//!
//! - `POST /bridge/proofs` - Submit a new external proof
//! - `GET /bridge/proofs/:proof_id` - Get proof status
//! - `GET /bridge/proofs?state=unverified` - List proofs by state
//! - `POST /bridge/proofs/:proof_id/bind/:intent_id` - Bind proof to intent

use l2_core::{
    EthReceiptAttestationV1, EthReceiptMerkleProofV1, ExternalChainId, ExternalEventProofV1,
    ExternalProofId, IntentId,
};
use l2_storage::ExternalProofStorage;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use thiserror::Error;

/// External Proof API service.
pub struct ExternalProofApi {
    storage: Arc<ExternalProofStorage>,
}

impl ExternalProofApi {
    /// Create a new ExternalProofApi.
    pub fn new(storage: Arc<ExternalProofStorage>) -> Self {
        Self { storage }
    }

    // ========== API Handlers ==========

    /// Submit a new external proof.
    ///
    /// POST /bridge/proofs
    pub fn submit_proof(
        &self,
        request: SubmitProofRequest,
    ) -> Result<SubmitProofResponse, ExternalProofApiError> {
        let now_ms = now_ms();

        // Parse the proof from the request
        let proof = request.to_proof()?;

        // Compute proof ID
        let proof_id = proof.proof_id()?;

        // Basic validation
        proof.validate_basic().map_err(|e| {
            ExternalProofApiError::InvalidRequest(format!("validation failed: {}", e))
        })?;

        // Store (idempotent)
        let was_new = self.storage.put_proof_if_absent(&proof, now_ms)?;

        Ok(SubmitProofResponse {
            proof_id: proof_id.to_hex(),
            was_new,
            chain: proof.chain().to_string(),
            proof_type: proof.proof_type().to_string(),
            verification_mode: proof.verification_mode().name().to_string(),
            block_number: proof.block_number(),
        })
    }

    /// Get proof status.
    ///
    /// GET /bridge/proofs/:proof_id
    pub fn get_proof(
        &self,
        proof_id_hex: &str,
    ) -> Result<ProofStatusResponse, ExternalProofApiError> {
        let proof_id = ExternalProofId::from_hex(proof_id_hex).map_err(|e| {
            ExternalProofApiError::InvalidRequest(format!("invalid proof_id: {}", e))
        })?;

        let entry = self
            .storage
            .get_proof(&proof_id)?
            .ok_or_else(|| ExternalProofApiError::NotFound(proof_id_hex.to_string()))?;

        Ok(ProofStatusResponse {
            proof_id: proof_id_hex.to_string(),
            chain: entry.proof.chain().to_string(),
            proof_type: entry.proof.proof_type().to_string(),
            verification_mode: entry.verification_mode.name().to_string(),
            block_number: entry.proof.block_number(),
            tx_hash: hex::encode(entry.proof.tx_hash()),
            state: entry.state.name().to_string(),
            is_verified: entry.state.is_verified(),
            is_rejected: entry.state.is_rejected(),
            rejection_reason: match &entry.state {
                l2_core::ExternalProofState::Rejected { reason, .. } => Some(reason.clone()),
                _ => None,
            },
        })
    }

    /// List proofs with optional filters.
    ///
    /// GET /bridge/proofs?state=unverified&limit=100
    pub fn list_proofs(
        &self,
        query: ListProofsQuery,
    ) -> Result<ListProofsResponse, ExternalProofApiError> {
        let limit = query.limit.unwrap_or(100).min(1000);

        let entries = match query.state.as_deref() {
            Some("unverified") => self.storage.list_unverified_proofs(limit)?,
            Some("verified") => self.storage.list_verified_proofs(limit)?,
            Some("rejected") => self.storage.list_rejected_proofs(limit)?,
            Some(other) => {
                return Err(ExternalProofApiError::InvalidRequest(format!(
                    "invalid state filter: {}",
                    other
                )));
            }
            None => self.storage.list_unverified_proofs(limit)?,
        };

        let proofs: Vec<ProofListItem> = entries
            .into_iter()
            .map(|e| ProofListItem {
                proof_id: e.proof_id.to_hex(),
                chain: e.proof.chain().to_string(),
                proof_type: e.proof.proof_type().to_string(),
                block_number: e.proof.block_number(),
                state: e.state.name().to_string(),
            })
            .collect();

        let total = proofs.len();
        Ok(ListProofsResponse { proofs, total })
    }

    /// Bind a proof to an intent.
    ///
    /// POST /bridge/proofs/:proof_id/bind/:intent_id
    pub fn bind_proof_to_intent(
        &self,
        proof_id_hex: &str,
        intent_id_hex: &str,
    ) -> Result<BindProofResponse, ExternalProofApiError> {
        let proof_id = ExternalProofId::from_hex(proof_id_hex).map_err(|e| {
            ExternalProofApiError::InvalidRequest(format!("invalid proof_id: {}", e))
        })?;

        let intent_id = IntentId::from_hex(intent_id_hex).map_err(|e| {
            ExternalProofApiError::InvalidRequest(format!("invalid intent_id: {}", e))
        })?;

        let now_ms = now_ms();

        // Verify proof exists
        if !self.storage.proof_exists(&proof_id)? {
            return Err(ExternalProofApiError::NotFound(format!(
                "proof {} not found",
                proof_id_hex
            )));
        }

        // Bind
        self.storage
            .bind_proof_to_intent(&proof_id, &intent_id, now_ms)?;

        Ok(BindProofResponse {
            proof_id: proof_id_hex.to_string(),
            intent_id: intent_id_hex.to_string(),
            bound_at_ms: now_ms,
        })
    }

    /// List proofs bound to an intent.
    ///
    /// GET /bridge/intents/:intent_id/proofs
    pub fn list_proofs_for_intent(
        &self,
        intent_id_hex: &str,
        limit: Option<usize>,
    ) -> Result<ListProofsResponse, ExternalProofApiError> {
        let intent_id = IntentId::from_hex(intent_id_hex).map_err(|e| {
            ExternalProofApiError::InvalidRequest(format!("invalid intent_id: {}", e))
        })?;

        let limit = limit.unwrap_or(100).min(1000);

        let entries = self.storage.list_proofs_for_intent(&intent_id, limit)?;

        let proofs: Vec<ProofListItem> = entries
            .into_iter()
            .map(|e| ProofListItem {
                proof_id: e.proof_id.to_hex(),
                chain: e.proof.chain().to_string(),
                proof_type: e.proof.proof_type().to_string(),
                block_number: e.proof.block_number(),
                state: e.state.name().to_string(),
            })
            .collect();

        let total = proofs.len();
        Ok(ListProofsResponse { proofs, total })
    }

    /// Check if all proofs for an intent are verified.
    ///
    /// GET /bridge/intents/:intent_id/proofs/verified
    pub fn check_intent_proofs_verified(
        &self,
        intent_id_hex: &str,
    ) -> Result<IntentProofsVerifiedResponse, ExternalProofApiError> {
        let intent_id = IntentId::from_hex(intent_id_hex).map_err(|e| {
            ExternalProofApiError::InvalidRequest(format!("invalid intent_id: {}", e))
        })?;

        let all_verified = self.storage.all_proofs_verified_for_intent(&intent_id)?;
        let proofs = self.storage.list_proofs_for_intent(&intent_id, 100)?;

        let total_proofs = proofs.len();
        let verified_count = proofs.iter().filter(|p| p.state.is_verified()).count();
        let unverified_count = proofs.iter().filter(|p| p.state.is_unverified()).count();
        let rejected_count = proofs.iter().filter(|p| p.state.is_rejected()).count();

        Ok(IntentProofsVerifiedResponse {
            intent_id: intent_id_hex.to_string(),
            all_verified,
            total_proofs,
            verified_count,
            unverified_count,
            rejected_count,
        })
    }

    /// Get proof counts for /status endpoint.
    pub fn get_counts(&self) -> Result<ProofCountsResponse, ExternalProofApiError> {
        let counts = self.storage.count_proofs()?;
        Ok(ProofCountsResponse {
            unverified: counts.unverified,
            verified: counts.verified,
            rejected: counts.rejected,
            total: counts.total(),
        })
    }
}

// ========== Request/Response Types ==========

/// Request to submit a new external proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitProofRequest {
    /// Proof type: "eth_receipt_attestation_v1" or "eth_receipt_merkle_v1"
    pub proof_type: String,

    /// Chain identifier: "ethereum_mainnet", "ethereum_sepolia", etc.
    pub chain: String,

    /// Transaction hash (hex, 32 bytes).
    pub tx_hash: String,

    /// Log index within the transaction.
    pub log_index: u32,

    /// Contract address (hex, 20 bytes).
    pub contract: String,

    /// Event signature / topic0 (hex, 32 bytes).
    pub topic0: String,

    /// Blake3 hash of event data (hex, 32 bytes).
    pub data_hash: String,

    /// Block number.
    pub block_number: u64,

    /// Block hash (hex, 32 bytes).
    pub block_hash: String,

    /// Number of confirmations (attestation only, optional for merkle).
    #[serde(default)]
    pub confirmations: Option<u32>,

    /// Attestor public key (hex, 32 bytes, attestation only).
    #[serde(default)]
    pub attestor_pubkey: Option<String>,

    /// Attestor signature (hex, 64 bytes, attestation only).
    #[serde(default)]
    pub signature: Option<String>,

    // ========== Merkle proof fields ==========
    /// Transaction index in block (merkle proof only).
    #[serde(default)]
    pub tx_index: Option<u32>,

    /// RLP-encoded block header (hex, merkle proof only).
    #[serde(default)]
    pub header_rlp: Option<String>,

    /// RLP-encoded receipt (hex, merkle proof only).
    #[serde(default)]
    pub receipt_rlp: Option<String>,

    /// Merkle proof nodes (array of hex strings, merkle proof only).
    #[serde(default)]
    pub proof_nodes: Option<Vec<String>>,

    /// Tip block number at proof creation time (optional, for RPC-assisted confirmations).
    #[serde(default)]
    pub tip_block_number: Option<u64>,
}

impl SubmitProofRequest {
    fn to_proof(&self) -> Result<ExternalEventProofV1, ExternalProofApiError> {
        match self.proof_type.as_str() {
            "eth_receipt_attestation_v1" => {
                let chain = self.parse_chain()?;
                let tx_hash = parse_hex_32(&self.tx_hash, "tx_hash")?;
                let contract = parse_hex_20(&self.contract, "contract")?;
                let topic0 = parse_hex_32(&self.topic0, "topic0")?;
                let data_hash = parse_hex_32(&self.data_hash, "data_hash")?;
                let block_hash = parse_hex_32(&self.block_hash, "block_hash")?;

                let confirmations = self.confirmations.ok_or_else(|| {
                    ExternalProofApiError::InvalidRequest(
                        "confirmations required for attestation".to_string(),
                    )
                })?;

                let attestor_pubkey = self.attestor_pubkey.as_ref().ok_or_else(|| {
                    ExternalProofApiError::InvalidRequest(
                        "attestor_pubkey required for attestation".to_string(),
                    )
                })?;
                let attestor_pubkey = parse_hex_32(attestor_pubkey, "attestor_pubkey")?;

                let signature = self.signature.as_ref().ok_or_else(|| {
                    ExternalProofApiError::InvalidRequest(
                        "signature required for attestation".to_string(),
                    )
                })?;
                let signature = parse_hex_64(signature, "signature")?;

                Ok(ExternalEventProofV1::EthReceiptAttestationV1(
                    EthReceiptAttestationV1 {
                        chain,
                        tx_hash,
                        log_index: self.log_index,
                        contract,
                        topic0,
                        data_hash,
                        block_number: self.block_number,
                        block_hash,
                        confirmations,
                        attestor_pubkey,
                        signature,
                    },
                ))
            }
            "eth_receipt_merkle_v1" => {
                let chain = self.parse_chain()?;
                let tx_hash = parse_hex_32(&self.tx_hash, "tx_hash")?;
                let contract = parse_hex_20(&self.contract, "contract")?;
                let topic0 = parse_hex_32(&self.topic0, "topic0")?;
                let data_hash = parse_hex_32(&self.data_hash, "data_hash")?;
                let block_hash = parse_hex_32(&self.block_hash, "block_hash")?;

                let tx_index = self.tx_index.ok_or_else(|| {
                    ExternalProofApiError::InvalidRequest(
                        "tx_index required for merkle proof".to_string(),
                    )
                })?;

                let header_rlp = self.header_rlp.as_ref().ok_or_else(|| {
                    ExternalProofApiError::InvalidRequest(
                        "header_rlp required for merkle proof".to_string(),
                    )
                })?;
                let header_rlp = parse_hex_vec(header_rlp, "header_rlp")?;

                let receipt_rlp = self.receipt_rlp.as_ref().ok_or_else(|| {
                    ExternalProofApiError::InvalidRequest(
                        "receipt_rlp required for merkle proof".to_string(),
                    )
                })?;
                let receipt_rlp = parse_hex_vec(receipt_rlp, "receipt_rlp")?;

                let proof_nodes = self.proof_nodes.as_ref().ok_or_else(|| {
                    ExternalProofApiError::InvalidRequest(
                        "proof_nodes required for merkle proof".to_string(),
                    )
                })?;
                let proof_nodes: Result<Vec<Vec<u8>>, ExternalProofApiError> = proof_nodes
                    .iter()
                    .enumerate()
                    .map(|(i, s)| parse_hex_vec(s, &format!("proof_nodes[{}]", i)))
                    .collect();
                let proof_nodes = proof_nodes?;

                Ok(ExternalEventProofV1::EthReceiptMerkleProofV1(
                    EthReceiptMerkleProofV1 {
                        chain,
                        tx_hash,
                        block_number: self.block_number,
                        block_hash,
                        header_rlp,
                        receipt_rlp,
                        proof_nodes,
                        tx_index,
                        log_index: self.log_index,
                        contract,
                        topic0,
                        data_hash,
                        confirmations: self.confirmations,
                        tip_block_number: self.tip_block_number,
                    },
                ))
            }
            other => Err(ExternalProofApiError::InvalidRequest(format!(
                "unknown proof_type: {}",
                other
            ))),
        }
    }

    fn parse_chain(&self) -> Result<ExternalChainId, ExternalProofApiError> {
        match self.chain.to_lowercase().as_str() {
            "ethereum_mainnet" | "ethereum" | "mainnet" => Ok(ExternalChainId::EthereumMainnet),
            "ethereum_sepolia" | "sepolia" => Ok(ExternalChainId::EthereumSepolia),
            "ethereum_holesky" | "holesky" => Ok(ExternalChainId::EthereumHolesky),
            other => {
                // Try to parse as "chain_id:name"
                if let Some((chain_id_str, name)) = other.split_once(':') {
                    let chain_id: u64 = chain_id_str.parse().map_err(|_| {
                        ExternalProofApiError::InvalidRequest(format!(
                            "invalid chain_id: {}",
                            other
                        ))
                    })?;
                    Ok(ExternalChainId::Other {
                        chain_id,
                        name: name.to_string(),
                    })
                } else {
                    Err(ExternalProofApiError::InvalidRequest(format!(
                        "unknown chain: {}",
                        other
                    )))
                }
            }
        }
    }
}

/// Response from submitting a proof.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SubmitProofResponse {
    pub proof_id: String,
    pub was_new: bool,
    pub chain: String,
    pub proof_type: String,
    pub verification_mode: String,
    pub block_number: u64,
}

/// Response with proof status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofStatusResponse {
    pub proof_id: String,
    pub chain: String,
    pub proof_type: String,
    pub verification_mode: String,
    pub block_number: u64,
    pub tx_hash: String,
    pub state: String,
    pub is_verified: bool,
    pub is_rejected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rejection_reason: Option<String>,
}

/// Query parameters for listing proofs.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ListProofsQuery {
    /// Filter by state (unverified, verified, rejected).
    #[serde(default)]
    pub state: Option<String>,
    /// Maximum number of proofs to return.
    #[serde(default)]
    pub limit: Option<usize>,
}

/// Single proof in list response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofListItem {
    pub proof_id: String,
    pub chain: String,
    pub proof_type: String,
    pub block_number: u64,
    pub state: String,
}

/// Response with list of proofs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListProofsResponse {
    pub proofs: Vec<ProofListItem>,
    pub total: usize,
}

/// Response from binding a proof to an intent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BindProofResponse {
    pub proof_id: String,
    pub intent_id: String,
    pub bound_at_ms: u64,
}

/// Response with intent proof verification status.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntentProofsVerifiedResponse {
    pub intent_id: String,
    pub all_verified: bool,
    pub total_proofs: usize,
    pub verified_count: usize,
    pub unverified_count: usize,
    pub rejected_count: usize,
}

/// Response with proof counts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofCountsResponse {
    pub unverified: u64,
    pub verified: u64,
    pub rejected: u64,
    pub total: u64,
}

// ========== Error Types ==========

/// API error type.
#[derive(Debug, Error)]
pub enum ExternalProofApiError {
    #[error("invalid request: {0}")]
    InvalidRequest(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("storage error: {0}")]
    Storage(#[from] l2_storage::ExternalProofStorageError),

    #[error("canonical error: {0}")]
    Canonical(#[from] l2_core::CanonicalError),

    #[error("internal error: {0}")]
    Internal(String),
}

impl ExternalProofApiError {
    /// Get HTTP status code for this error.
    pub fn status_code(&self) -> u16 {
        match self {
            ExternalProofApiError::InvalidRequest(_) => 400,
            ExternalProofApiError::NotFound(_) => 404,
            ExternalProofApiError::Storage(_) => 500,
            ExternalProofApiError::Canonical(_) => 400,
            ExternalProofApiError::Internal(_) => 500,
        }
    }

    /// Get error code for this error.
    pub fn error_code(&self) -> &'static str {
        match self {
            ExternalProofApiError::InvalidRequest(_) => "invalid_request",
            ExternalProofApiError::NotFound(_) => "not_found",
            ExternalProofApiError::Storage(_) => "storage_error",
            ExternalProofApiError::Canonical(_) => "encoding_error",
            ExternalProofApiError::Internal(_) => "internal_error",
        }
    }
}

// ========== Helpers ==========

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

fn parse_hex_32(s: &str, field: &str) -> Result<[u8; 32], ExternalProofApiError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| {
        ExternalProofApiError::InvalidRequest(format!("invalid {} hex: {}", field, e))
    })?;
    if bytes.len() != 32 {
        return Err(ExternalProofApiError::InvalidRequest(format!(
            "{} must be 32 bytes, got {}",
            field,
            bytes.len()
        )));
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn parse_hex_20(s: &str, field: &str) -> Result<[u8; 20], ExternalProofApiError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| {
        ExternalProofApiError::InvalidRequest(format!("invalid {} hex: {}", field, e))
    })?;
    if bytes.len() != 20 {
        return Err(ExternalProofApiError::InvalidRequest(format!(
            "{} must be 20 bytes, got {}",
            field,
            bytes.len()
        )));
    }
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn parse_hex_64(s: &str, field: &str) -> Result<[u8; 64], ExternalProofApiError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s).map_err(|e| {
        ExternalProofApiError::InvalidRequest(format!("invalid {} hex: {}", field, e))
    })?;
    if bytes.len() != 64 {
        return Err(ExternalProofApiError::InvalidRequest(format!(
            "{} must be 64 bytes, got {}",
            field,
            bytes.len()
        )));
    }
    let mut arr = [0u8; 64];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

fn parse_hex_vec(s: &str, field: &str) -> Result<Vec<u8>, ExternalProofApiError> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    hex::decode(s)
        .map_err(|e| ExternalProofApiError::InvalidRequest(format!("invalid {} hex: {}", field, e)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_db() -> sled::Db {
        let dir = tempdir().expect("tmpdir");
        sled::open(dir.path()).expect("open")
    }

    fn setup_api() -> ExternalProofApi {
        let db = test_db();
        let storage = Arc::new(ExternalProofStorage::new(&db).unwrap());
        ExternalProofApi::new(storage)
    }

    fn test_submit_request() -> SubmitProofRequest {
        SubmitProofRequest {
            proof_type: "eth_receipt_attestation_v1".to_string(),
            chain: "ethereum_mainnet".to_string(),
            tx_hash: hex::encode([0xAA; 32]),
            log_index: 0,
            contract: hex::encode([0xBB; 20]),
            topic0: hex::encode([0xCC; 32]),
            data_hash: hex::encode([0xDD; 32]),
            block_number: 18_000_000,
            block_hash: hex::encode([0xEE; 32]),
            confirmations: Some(12),
            attestor_pubkey: Some(hex::encode([0x11; 32])),
            signature: Some(hex::encode([0x22; 64])),
            // Merkle proof fields (not used for attestations)
            tx_index: None,
            header_rlp: None,
            receipt_rlp: None,
            proof_nodes: None,
            tip_block_number: None,
        }
    }

    #[test]
    fn submit_proof() {
        let api = setup_api();
        let request = test_submit_request();

        let response = api.submit_proof(request).unwrap();

        assert!(!response.proof_id.is_empty());
        assert!(response.was_new);
        assert_eq!(response.chain, "ethereum:1");
        assert_eq!(response.proof_type, "eth_receipt_attestation_v1");
        assert_eq!(response.verification_mode, "attestation");
        assert_eq!(response.block_number, 18_000_000);
    }

    #[test]
    fn submit_proof_idempotent() {
        let api = setup_api();
        let request = test_submit_request();

        let response1 = api.submit_proof(request.clone()).unwrap();
        assert!(response1.was_new);

        let response2 = api.submit_proof(request).unwrap();
        assert!(!response2.was_new);
        assert_eq!(response1.proof_id, response2.proof_id);
    }

    #[test]
    fn get_proof() {
        let api = setup_api();
        let request = test_submit_request();

        let submit_response = api.submit_proof(request).unwrap();
        let status = api.get_proof(&submit_response.proof_id).unwrap();

        assert_eq!(status.proof_id, submit_response.proof_id);
        assert_eq!(status.verification_mode, "attestation");
        assert_eq!(status.state, "unverified");
        assert!(!status.is_verified);
        assert!(!status.is_rejected);
    }

    #[test]
    fn get_proof_not_found() {
        let api = setup_api();
        let result = api.get_proof(&hex::encode([0xFF; 32]));
        assert!(matches!(result, Err(ExternalProofApiError::NotFound(_))));
    }

    #[test]
    fn list_proofs() {
        let api = setup_api();

        // Submit some proofs (start at 1 to avoid zero tx_hash)
        for i in 1u8..6 {
            let mut request = test_submit_request();
            request.tx_hash = hex::encode([i; 32]);
            api.submit_proof(request).unwrap();
        }

        // List unverified
        let query = ListProofsQuery {
            state: Some("unverified".to_string()),
            limit: Some(10),
        };
        let response = api.list_proofs(query).unwrap();
        assert_eq!(response.total, 5);
    }

    #[test]
    fn bind_proof_to_intent() {
        let api = setup_api();
        let request = test_submit_request();

        let submit_response = api.submit_proof(request).unwrap();
        let intent_id = hex::encode([0x01; 32]);

        let bind_response = api
            .bind_proof_to_intent(&submit_response.proof_id, &intent_id)
            .unwrap();

        assert_eq!(bind_response.proof_id, submit_response.proof_id);
        assert_eq!(bind_response.intent_id, intent_id);
    }

    #[test]
    fn list_proofs_for_intent() {
        let api = setup_api();
        let intent_id = hex::encode([0x01; 32]);

        // Submit and bind some proofs (start at 1 to avoid zero tx_hash)
        for i in 1u8..4 {
            let mut request = test_submit_request();
            request.tx_hash = hex::encode([i; 32]);
            let response = api.submit_proof(request).unwrap();
            api.bind_proof_to_intent(&response.proof_id, &intent_id)
                .unwrap();
        }

        let response = api.list_proofs_for_intent(&intent_id, None).unwrap();
        assert_eq!(response.total, 3);
    }

    #[test]
    fn check_intent_proofs_verified() {
        let api = setup_api();
        let intent_id = hex::encode([0x01; 32]);

        // No proofs - should be false
        let response = api.check_intent_proofs_verified(&intent_id).unwrap();
        assert!(!response.all_verified);
        assert_eq!(response.total_proofs, 0);

        // Submit and bind a proof (unverified)
        let request = test_submit_request();
        let proof_response = api.submit_proof(request).unwrap();
        api.bind_proof_to_intent(&proof_response.proof_id, &intent_id)
            .unwrap();

        let response = api.check_intent_proofs_verified(&intent_id).unwrap();
        assert!(!response.all_verified);
        assert_eq!(response.total_proofs, 1);
        assert_eq!(response.unverified_count, 1);
    }

    #[test]
    fn get_counts() {
        let api = setup_api();

        // Submit some proofs (start at 1 to avoid zero tx_hash)
        for i in 1u8..6 {
            let mut request = test_submit_request();
            request.tx_hash = hex::encode([i; 32]);
            api.submit_proof(request).unwrap();
        }

        let counts = api.get_counts().unwrap();
        assert_eq!(counts.unverified, 5);
        assert_eq!(counts.verified, 0);
        assert_eq!(counts.rejected, 0);
        assert_eq!(counts.total, 5);
    }

    #[test]
    fn parse_chain_variants() {
        let request = SubmitProofRequest {
            proof_type: "eth_receipt_attestation_v1".to_string(),
            chain: "ethereum_mainnet".to_string(),
            tx_hash: hex::encode([0xAA; 32]),
            log_index: 0,
            contract: hex::encode([0xBB; 20]),
            topic0: hex::encode([0xCC; 32]),
            data_hash: hex::encode([0xDD; 32]),
            block_number: 18_000_000,
            block_hash: hex::encode([0xEE; 32]),
            confirmations: Some(12),
            attestor_pubkey: Some(hex::encode([0x11; 32])),
            signature: Some(hex::encode([0x22; 64])),
            tx_index: None,
            header_rlp: None,
            receipt_rlp: None,
            proof_nodes: None,
            tip_block_number: None,
        };

        assert!(matches!(
            request.parse_chain(),
            Ok(ExternalChainId::EthereumMainnet)
        ));

        let mut sepolia = request.clone();
        sepolia.chain = "sepolia".to_string();
        assert!(matches!(
            sepolia.parse_chain(),
            Ok(ExternalChainId::EthereumSepolia)
        ));

        let mut custom = request.clone();
        custom.chain = "42161:arbitrum".to_string();
        assert!(matches!(
            custom.parse_chain(),
            Ok(ExternalChainId::Other {
                chain_id: 42161,
                ..
            })
        ));
    }

    #[test]
    fn error_codes() {
        let err = ExternalProofApiError::InvalidRequest("test".to_string());
        assert_eq!(err.status_code(), 400);
        assert_eq!(err.error_code(), "invalid_request");

        let err = ExternalProofApiError::NotFound("test".to_string());
        assert_eq!(err.status_code(), 404);
        assert_eq!(err.error_code(), "not_found");
    }
}
