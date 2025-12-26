//! Ethereum Adapter for External Proof Verification.
//!
//! This module provides verification of Ethereum-based external proofs.
//!
//! ## MVP: Signed Attestation Verification
//!
//! The MVP verifier supports `EthReceiptAttestationV1` proofs:
//! - Verifies Ed25519 signature over canonical attestation bytes
//! - Verifies confirmations >= minimum threshold
//! - Verifies event binding (topic0/contract/data_hash match)
//!
//! ## Trust Model
//!
//! IPPAN does not "trust Ethereum" - it records verifiable statements.
//! The attestor is the trust anchor for MVP attestations.
//!
//! ## Upgrade Path
//!
//! Future: Merkle proof verification against block headers (light client).

use l2_core::{
    EthReceiptAttestationV1, ExternalChainId, ExternalEventProofV1, ExternalProofId,
    ExternalProofValidationError,
};
use std::collections::HashSet;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, warn};

/// Minimum confirmations for Ethereum mainnet (conservative).
pub const DEFAULT_MIN_CONFIRMATIONS_MAINNET: u32 = 12;

/// Minimum confirmations for Ethereum testnets.
pub const DEFAULT_MIN_CONFIRMATIONS_TESTNET: u32 = 6;

/// Errors from the external verifier.
#[derive(Debug, Error)]
pub enum ExternalVerifyError {
    #[error("basic validation failed: {0}")]
    BasicValidation(#[from] ExternalProofValidationError),

    #[error("signature verification failed: {0}")]
    SignatureVerification(String),

    #[error("attestor not in allowlist: {pubkey_hex}")]
    AttestorNotAllowed { pubkey_hex: String },

    #[error("insufficient confirmations: got {got}, need {need}")]
    InsufficientConfirmations { got: u32, need: u32 },

    #[error("chain mismatch: expected {expected}, got {got}")]
    ChainMismatch { expected: String, got: String },

    #[error("event binding mismatch: {field}: expected {expected}, got {got}")]
    EventBindingMismatch {
        field: String,
        expected: String,
        got: String,
    },

    #[error("unsupported proof type: {0}")]
    UnsupportedProofType(String),

    #[error("canonical encoding error: {0}")]
    Canonical(#[from] l2_core::CanonicalError),

    #[error("internal error: {0}")]
    Internal(String),
}

/// Result of successful proof verification.
#[derive(Debug, Clone)]
pub struct VerifiedEvent {
    /// The proof ID that was verified.
    pub proof_id: ExternalProofId,

    /// The external chain the event occurred on.
    pub chain: ExternalChainId,

    /// The transaction hash.
    pub tx_hash: [u8; 32],

    /// The log index within the transaction.
    pub log_index: u32,

    /// The contract address that emitted the event.
    pub contract: [u8; 20],

    /// The event signature (topic0).
    pub topic0: [u8; 32],

    /// The data hash of the event.
    pub data_hash: [u8; 32],

    /// The block number.
    pub block_number: u64,

    /// Number of confirmations at verification time.
    pub confirmations: u32,

    /// The attestor public key (for attestation proofs).
    pub attestor_pubkey: Option<[u8; 32]>,
}

/// Expected event binding for verification.
///
/// Used to verify that the proof matches the expected event parameters
/// for a specific intent.
#[derive(Debug, Clone)]
pub struct ExpectedEventBinding {
    /// Expected contract address (optional - if None, any contract is allowed).
    pub contract: Option<[u8; 20]>,

    /// Expected event signature (topic0, optional).
    pub topic0: Option<[u8; 32]>,

    /// Expected data hash (optional).
    pub data_hash: Option<[u8; 32]>,

    /// Expected chain (optional).
    pub chain: Option<ExternalChainId>,
}

impl ExpectedEventBinding {
    /// Create a new binding with no expectations (any event is valid).
    pub fn any() -> Self {
        Self {
            contract: None,
            topic0: None,
            data_hash: None,
            chain: None,
        }
    }

    /// Create a binding with a specific contract address.
    pub fn with_contract(mut self, contract: [u8; 20]) -> Self {
        self.contract = Some(contract);
        self
    }

    /// Create a binding with a specific topic0.
    pub fn with_topic0(mut self, topic0: [u8; 32]) -> Self {
        self.topic0 = Some(topic0);
        self
    }

    /// Create a binding with a specific data hash.
    pub fn with_data_hash(mut self, data_hash: [u8; 32]) -> Self {
        self.data_hash = Some(data_hash);
        self
    }

    /// Create a binding with a specific chain.
    pub fn with_chain(mut self, chain: ExternalChainId) -> Self {
        self.chain = Some(chain);
        self
    }
}

/// Trait for external proof verification.
///
/// Implementations verify different proof types with different trust assumptions.
pub trait ExternalVerifier: Send + Sync {
    /// Verify an external proof.
    ///
    /// Returns the verified event data on success.
    fn verify(
        &self,
        proof: &ExternalEventProofV1,
        binding: Option<&ExpectedEventBinding>,
    ) -> Result<VerifiedEvent, ExternalVerifyError>;
}

/// Configuration for the Ethereum attestation verifier.
#[derive(Debug, Clone)]
pub struct EthAttestationVerifierConfig {
    /// Allowlist of attestor public keys (hex-encoded).
    ///
    /// If empty, all attestors are rejected (fail-closed).
    pub attestor_pubkeys: HashSet<String>,

    /// Minimum confirmations required for mainnet.
    pub min_confirmations_mainnet: u32,

    /// Minimum confirmations required for testnets.
    pub min_confirmations_testnet: u32,
}

impl Default for EthAttestationVerifierConfig {
    fn default() -> Self {
        Self {
            attestor_pubkeys: HashSet::new(),
            min_confirmations_mainnet: DEFAULT_MIN_CONFIRMATIONS_MAINNET,
            min_confirmations_testnet: DEFAULT_MIN_CONFIRMATIONS_TESTNET,
        }
    }
}

impl EthAttestationVerifierConfig {
    /// Create from environment variables.
    ///
    /// - `BRIDGE_ATTESTOR_KEYS`: Comma-separated list of hex-encoded public keys.
    /// - `BRIDGE_MIN_CONFIRMATIONS_MAINNET`: Minimum confirmations for mainnet.
    /// - `BRIDGE_MIN_CONFIRMATIONS_TESTNET`: Minimum confirmations for testnets.
    pub fn from_env() -> Self {
        let attestor_pubkeys = std::env::var("BRIDGE_ATTESTOR_KEYS")
            .ok()
            .map(|s| {
                s.split(',')
                    .map(|k| k.trim().to_lowercase())
                    .filter(|k| !k.is_empty())
                    .collect()
            })
            .unwrap_or_default();

        let min_confirmations_mainnet = std::env::var("BRIDGE_MIN_CONFIRMATIONS_MAINNET")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_MIN_CONFIRMATIONS_MAINNET);

        let min_confirmations_testnet = std::env::var("BRIDGE_MIN_CONFIRMATIONS_TESTNET")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_MIN_CONFIRMATIONS_TESTNET);

        Self {
            attestor_pubkeys,
            min_confirmations_mainnet,
            min_confirmations_testnet,
        }
    }

    /// Add an attestor public key to the allowlist.
    pub fn add_attestor(&mut self, pubkey_hex: &str) {
        self.attestor_pubkeys.insert(pubkey_hex.to_lowercase());
    }

    /// Remove an attestor public key from the allowlist.
    pub fn remove_attestor(&mut self, pubkey_hex: &str) {
        self.attestor_pubkeys.remove(&pubkey_hex.to_lowercase());
    }

    /// Check if an attestor is in the allowlist.
    pub fn is_attestor_allowed(&self, pubkey: &[u8; 32]) -> bool {
        let pubkey_hex = hex::encode(pubkey);
        self.attestor_pubkeys.contains(&pubkey_hex)
    }

    /// Get minimum confirmations for a chain.
    pub fn min_confirmations(&self, chain: &ExternalChainId) -> u32 {
        match chain {
            ExternalChainId::EthereumMainnet => self.min_confirmations_mainnet,
            ExternalChainId::EthereumSepolia | ExternalChainId::EthereumHolesky => {
                self.min_confirmations_testnet
            }
            ExternalChainId::Other { .. } => self.min_confirmations_testnet,
        }
    }
}

/// Ethereum attestation verifier.
///
/// Verifies `EthReceiptAttestationV1` proofs by:
/// 1. Validating basic structure
/// 2. Checking attestor is in allowlist
/// 3. Verifying Ed25519 signature
/// 4. Checking confirmation threshold
/// 5. Optionally verifying event binding
pub struct EthAttestationVerifier {
    config: EthAttestationVerifierConfig,
}

impl EthAttestationVerifier {
    /// Create a new attestation verifier with the given config.
    pub fn new(config: EthAttestationVerifierConfig) -> Self {
        Self { config }
    }

    /// Create a verifier from environment variables.
    pub fn from_env() -> Self {
        Self::new(EthAttestationVerifierConfig::from_env())
    }

    /// Get the configuration.
    pub fn config(&self) -> &EthAttestationVerifierConfig {
        &self.config
    }

    /// Verify an attestation proof.
    fn verify_attestation(
        &self,
        attestation: &EthReceiptAttestationV1,
        binding: Option<&ExpectedEventBinding>,
    ) -> Result<VerifiedEvent, ExternalVerifyError> {
        // Step 1: Basic validation
        attestation.validate_basic()?;

        // Step 2: Check attestor is in allowlist
        if !self.config.is_attestor_allowed(&attestation.attestor_pubkey) {
            let pubkey_hex = hex::encode(attestation.attestor_pubkey);
            warn!(
                pubkey = %pubkey_hex,
                "attestor not in allowlist"
            );
            return Err(ExternalVerifyError::AttestorNotAllowed { pubkey_hex });
        }

        // Step 3: Verify Ed25519 signature
        self.verify_signature(attestation)?;

        // Step 4: Check confirmations
        let min_confirmations = self.config.min_confirmations(&attestation.chain);
        if attestation.confirmations < min_confirmations {
            warn!(
                got = attestation.confirmations,
                need = min_confirmations,
                chain = %attestation.chain,
                "insufficient confirmations"
            );
            return Err(ExternalVerifyError::InsufficientConfirmations {
                got: attestation.confirmations,
                need: min_confirmations,
            });
        }

        // Step 5: Check event binding (if provided)
        if let Some(binding) = binding {
            self.verify_event_binding(attestation, binding)?;
        }

        // Build verified event
        let proof_id = ExternalEventProofV1::EthReceiptAttestationV1(attestation.clone())
            .proof_id()?;

        debug!(
            proof_id = %proof_id,
            tx_hash = %hex::encode(attestation.tx_hash),
            block_number = attestation.block_number,
            confirmations = attestation.confirmations,
            "attestation verified"
        );

        Ok(VerifiedEvent {
            proof_id,
            chain: attestation.chain.clone(),
            tx_hash: attestation.tx_hash,
            log_index: attestation.log_index,
            contract: attestation.contract,
            topic0: attestation.topic0,
            data_hash: attestation.data_hash,
            block_number: attestation.block_number,
            confirmations: attestation.confirmations,
            attestor_pubkey: Some(attestation.attestor_pubkey),
        })
    }

    /// Verify the Ed25519 signature over the attestation data.
    #[cfg(feature = "signed-envelopes")]
    fn verify_signature(
        &self,
        attestation: &EthReceiptAttestationV1,
    ) -> Result<(), ExternalVerifyError> {
        use ed25519_dalek::{Signature, Verifier, VerifyingKey};

        // Build the signing message
        let message = attestation.signing_message()?;

        // Parse the public key
        let pubkey = VerifyingKey::from_bytes(&attestation.attestor_pubkey).map_err(|e| {
            ExternalVerifyError::SignatureVerification(format!("invalid pubkey: {}", e))
        })?;

        // Parse the signature
        let signature = Signature::from_bytes(&attestation.signature);

        // Verify
        pubkey.verify(&message, &signature).map_err(|e| {
            ExternalVerifyError::SignatureVerification(format!("signature mismatch: {}", e))
        })?;

        Ok(())
    }

    /// Verify the Ed25519 signature over the attestation data.
    ///
    /// When the `signed-envelopes` feature is not enabled, this is a no-op
    /// that always succeeds. Use only for testing without crypto dependencies.
    #[cfg(not(feature = "signed-envelopes"))]
    fn verify_signature(
        &self,
        _attestation: &EthReceiptAttestationV1,
    ) -> Result<(), ExternalVerifyError> {
        // Without the signed-envelopes feature, we cannot verify signatures.
        // This should only be used in tests or when signature verification
        // is handled externally.
        warn!("signature verification skipped (signed-envelopes feature not enabled)");
        Ok(())
    }

    /// Verify the event binding matches expectations.
    fn verify_event_binding(
        &self,
        attestation: &EthReceiptAttestationV1,
        binding: &ExpectedEventBinding,
    ) -> Result<(), ExternalVerifyError> {
        // Check chain
        if let Some(expected_chain) = &binding.chain {
            if &attestation.chain != expected_chain {
                return Err(ExternalVerifyError::ChainMismatch {
                    expected: expected_chain.to_string(),
                    got: attestation.chain.to_string(),
                });
            }
        }

        // Check contract
        if let Some(expected_contract) = &binding.contract {
            if &attestation.contract != expected_contract {
                return Err(ExternalVerifyError::EventBindingMismatch {
                    field: "contract".to_string(),
                    expected: hex::encode(expected_contract),
                    got: hex::encode(attestation.contract),
                });
            }
        }

        // Check topic0
        if let Some(expected_topic0) = &binding.topic0 {
            if &attestation.topic0 != expected_topic0 {
                return Err(ExternalVerifyError::EventBindingMismatch {
                    field: "topic0".to_string(),
                    expected: hex::encode(expected_topic0),
                    got: hex::encode(attestation.topic0),
                });
            }
        }

        // Check data_hash
        if let Some(expected_data_hash) = &binding.data_hash {
            if &attestation.data_hash != expected_data_hash {
                return Err(ExternalVerifyError::EventBindingMismatch {
                    field: "data_hash".to_string(),
                    expected: hex::encode(expected_data_hash),
                    got: hex::encode(attestation.data_hash),
                });
            }
        }

        Ok(())
    }
}

impl ExternalVerifier for EthAttestationVerifier {
    fn verify(
        &self,
        proof: &ExternalEventProofV1,
        binding: Option<&ExpectedEventBinding>,
    ) -> Result<VerifiedEvent, ExternalVerifyError> {
        match proof {
            ExternalEventProofV1::EthReceiptAttestationV1(attestation) => {
                self.verify_attestation(attestation, binding)
            }
            ExternalEventProofV1::EthReceiptMerkleProofV1(_) => {
                // Not yet implemented - stub for future
                Err(ExternalVerifyError::UnsupportedProofType(
                    "merkle proofs not yet supported".to_string(),
                ))
            }
        }
    }
}

/// Composite verifier that tries multiple verifiers in order.
pub struct CompositeVerifier {
    verifiers: Vec<Arc<dyn ExternalVerifier>>,
}

impl CompositeVerifier {
    /// Create a new composite verifier.
    pub fn new() -> Self {
        Self {
            verifiers: Vec::new(),
        }
    }

    /// Add a verifier to the chain.
    pub fn add_verifier(mut self, verifier: Arc<dyn ExternalVerifier>) -> Self {
        self.verifiers.push(verifier);
        self
    }
}

impl Default for CompositeVerifier {
    fn default() -> Self {
        Self::new()
    }
}

impl ExternalVerifier for CompositeVerifier {
    fn verify(
        &self,
        proof: &ExternalEventProofV1,
        binding: Option<&ExpectedEventBinding>,
    ) -> Result<VerifiedEvent, ExternalVerifyError> {
        if self.verifiers.is_empty() {
            return Err(ExternalVerifyError::Internal(
                "no verifiers configured".to_string(),
            ));
        }

        // Try each verifier
        let mut last_error = None;
        for verifier in &self.verifiers {
            match verifier.verify(proof, binding) {
                Ok(event) => return Ok(event),
                Err(e) => {
                    last_error = Some(e);
                }
            }
        }

        // All verifiers failed
        Err(last_error.unwrap_or_else(|| {
            ExternalVerifyError::Internal("verification failed".to_string())
        }))
    }
}

/// Mock verifier for testing.
pub struct MockVerifier {
    /// Whether to accept all proofs.
    pub accept_all: bool,
    /// Specific proof IDs to reject.
    pub reject_ids: HashSet<String>,
}

impl Default for MockVerifier {
    fn default() -> Self {
        Self {
            accept_all: true,
            reject_ids: HashSet::new(),
        }
    }
}

impl MockVerifier {
    /// Create a verifier that accepts all proofs.
    pub fn accepting() -> Self {
        Self::default()
    }

    /// Create a verifier that rejects all proofs.
    pub fn rejecting() -> Self {
        Self {
            accept_all: false,
            reject_ids: HashSet::new(),
        }
    }

    /// Add a proof ID to reject.
    pub fn reject(mut self, proof_id_hex: &str) -> Self {
        self.reject_ids.insert(proof_id_hex.to_string());
        self
    }
}

impl ExternalVerifier for MockVerifier {
    fn verify(
        &self,
        proof: &ExternalEventProofV1,
        _binding: Option<&ExpectedEventBinding>,
    ) -> Result<VerifiedEvent, ExternalVerifyError> {
        let proof_id = proof.proof_id()?;

        // Check rejection list
        if self.reject_ids.contains(&proof_id.to_hex()) {
            return Err(ExternalVerifyError::SignatureVerification(
                "mock: proof in reject list".to_string(),
            ));
        }

        // Check accept_all
        if !self.accept_all {
            return Err(ExternalVerifyError::SignatureVerification(
                "mock: rejecting all proofs".to_string(),
            ));
        }

        // Build verified event from proof
        Ok(VerifiedEvent {
            proof_id,
            chain: proof.chain().clone(),
            tx_hash: *proof.tx_hash(),
            log_index: match proof {
                ExternalEventProofV1::EthReceiptAttestationV1(a) => a.log_index,
                ExternalEventProofV1::EthReceiptMerkleProofV1(m) => m.log_index,
            },
            contract: match proof {
                ExternalEventProofV1::EthReceiptAttestationV1(a) => a.contract,
                ExternalEventProofV1::EthReceiptMerkleProofV1(m) => m.contract,
            },
            topic0: match proof {
                ExternalEventProofV1::EthReceiptAttestationV1(a) => a.topic0,
                ExternalEventProofV1::EthReceiptMerkleProofV1(m) => m.topic0,
            },
            data_hash: match proof {
                ExternalEventProofV1::EthReceiptAttestationV1(a) => a.data_hash,
                ExternalEventProofV1::EthReceiptMerkleProofV1(m) => m.data_hash,
            },
            block_number: proof.block_number(),
            confirmations: match proof {
                ExternalEventProofV1::EthReceiptAttestationV1(a) => a.confirmations,
                ExternalEventProofV1::EthReceiptMerkleProofV1(_) => 0,
            },
            attestor_pubkey: match proof {
                ExternalEventProofV1::EthReceiptAttestationV1(a) => Some(a.attestor_pubkey),
                ExternalEventProofV1::EthReceiptMerkleProofV1(_) => None,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use l2_core::EthReceiptAttestationV1;

    fn test_attestation() -> EthReceiptAttestationV1 {
        EthReceiptAttestationV1 {
            chain: ExternalChainId::EthereumMainnet,
            tx_hash: [0xAA; 32],
            log_index: 0,
            contract: [0xBB; 20],
            topic0: [0xCC; 32],
            data_hash: [0xDD; 32],
            block_number: 18_000_000,
            block_hash: [0xEE; 32],
            confirmations: 12,
            attestor_pubkey: [0x11; 32],
            signature: [0x22; 64],
        }
    }

    // ========== Config Tests ==========

    #[test]
    fn config_default() {
        let config = EthAttestationVerifierConfig::default();
        assert!(config.attestor_pubkeys.is_empty());
        assert_eq!(
            config.min_confirmations_mainnet,
            DEFAULT_MIN_CONFIRMATIONS_MAINNET
        );
        assert_eq!(
            config.min_confirmations_testnet,
            DEFAULT_MIN_CONFIRMATIONS_TESTNET
        );
    }

    #[test]
    fn config_attestor_allowlist() {
        let mut config = EthAttestationVerifierConfig::default();

        let pubkey = [0x11; 32];
        let pubkey_hex = hex::encode(pubkey);

        assert!(!config.is_attestor_allowed(&pubkey));

        config.add_attestor(&pubkey_hex);
        assert!(config.is_attestor_allowed(&pubkey));

        config.remove_attestor(&pubkey_hex);
        assert!(!config.is_attestor_allowed(&pubkey));
    }

    #[test]
    fn config_min_confirmations() {
        let config = EthAttestationVerifierConfig::default();

        assert_eq!(
            config.min_confirmations(&ExternalChainId::EthereumMainnet),
            DEFAULT_MIN_CONFIRMATIONS_MAINNET
        );
        assert_eq!(
            config.min_confirmations(&ExternalChainId::EthereumSepolia),
            DEFAULT_MIN_CONFIRMATIONS_TESTNET
        );
        assert_eq!(
            config.min_confirmations(&ExternalChainId::Other {
                chain_id: 42161,
                name: "arbitrum".to_string()
            }),
            DEFAULT_MIN_CONFIRMATIONS_TESTNET
        );
    }

    // ========== Verifier Tests ==========

    #[test]
    fn verify_attestor_not_in_allowlist() {
        let config = EthAttestationVerifierConfig::default();
        let verifier = EthAttestationVerifier::new(config);

        let attestation = test_attestation();
        let proof = ExternalEventProofV1::EthReceiptAttestationV1(attestation);

        let result = verifier.verify(&proof, None);
        assert!(matches!(
            result,
            Err(ExternalVerifyError::AttestorNotAllowed { .. })
        ));
    }

    #[test]
    fn verify_insufficient_confirmations() {
        let mut config = EthAttestationVerifierConfig::default();
        config.add_attestor(&hex::encode([0x11; 32]));
        config.min_confirmations_mainnet = 20; // Higher than attestation's 12

        let verifier = EthAttestationVerifier::new(config);

        let attestation = test_attestation();
        let proof = ExternalEventProofV1::EthReceiptAttestationV1(attestation);

        let result = verifier.verify(&proof, None);
        assert!(matches!(
            result,
            Err(ExternalVerifyError::InsufficientConfirmations { got: 12, need: 20 })
        ));
    }

    #[test]
    fn verify_event_binding_contract_mismatch() {
        let mut config = EthAttestationVerifierConfig::default();
        config.add_attestor(&hex::encode([0x11; 32]));
        config.min_confirmations_mainnet = 1;

        let verifier = EthAttestationVerifier::new(config);

        let attestation = test_attestation();
        let proof = ExternalEventProofV1::EthReceiptAttestationV1(attestation);

        let binding = ExpectedEventBinding::any().with_contract([0xFF; 20]); // Different contract

        let result = verifier.verify(&proof, Some(&binding));
        assert!(matches!(
            result,
            Err(ExternalVerifyError::EventBindingMismatch { field, .. }) if field == "contract"
        ));
    }

    #[test]
    fn verify_event_binding_topic0_mismatch() {
        let mut config = EthAttestationVerifierConfig::default();
        config.add_attestor(&hex::encode([0x11; 32]));
        config.min_confirmations_mainnet = 1;

        let verifier = EthAttestationVerifier::new(config);

        let attestation = test_attestation();
        let proof = ExternalEventProofV1::EthReceiptAttestationV1(attestation);

        let binding = ExpectedEventBinding::any().with_topic0([0xFF; 32]); // Different topic0

        let result = verifier.verify(&proof, Some(&binding));
        assert!(matches!(
            result,
            Err(ExternalVerifyError::EventBindingMismatch { field, .. }) if field == "topic0"
        ));
    }

    #[test]
    fn verify_event_binding_chain_mismatch() {
        let mut config = EthAttestationVerifierConfig::default();
        config.add_attestor(&hex::encode([0x11; 32]));
        config.min_confirmations_mainnet = 1;

        let verifier = EthAttestationVerifier::new(config);

        let attestation = test_attestation();
        let proof = ExternalEventProofV1::EthReceiptAttestationV1(attestation);

        let binding = ExpectedEventBinding::any().with_chain(ExternalChainId::EthereumSepolia);

        let result = verifier.verify(&proof, Some(&binding));
        assert!(matches!(
            result,
            Err(ExternalVerifyError::ChainMismatch { .. })
        ));
    }

    #[test]
    fn verify_merkle_proof_unsupported() {
        let config = EthAttestationVerifierConfig::default();
        let verifier = EthAttestationVerifier::new(config);

        let proof = ExternalEventProofV1::EthReceiptMerkleProofV1(
            l2_core::EthReceiptMerkleProofV1 {
                chain: ExternalChainId::EthereumMainnet,
                tx_hash: [0xAA; 32],
                log_index: 0,
                contract: [0xBB; 20],
                topic0: [0xCC; 32],
                data_hash: [0xDD; 32],
                block_number: 18_000_000,
                block_hash: [0xEE; 32],
                receipt_rlp: vec![0x01],
                proof_nodes: vec![vec![0x02]],
                tx_index: 0,
            },
        );

        let result = verifier.verify(&proof, None);
        assert!(matches!(
            result,
            Err(ExternalVerifyError::UnsupportedProofType(_))
        ));
    }

    // ========== Mock Verifier Tests ==========

    #[test]
    fn mock_verifier_accepts() {
        let verifier = MockVerifier::accepting();

        let attestation = test_attestation();
        let proof = ExternalEventProofV1::EthReceiptAttestationV1(attestation);

        let result = verifier.verify(&proof, None);
        assert!(result.is_ok());
    }

    #[test]
    fn mock_verifier_rejects() {
        let verifier = MockVerifier::rejecting();

        let attestation = test_attestation();
        let proof = ExternalEventProofV1::EthReceiptAttestationV1(attestation);

        let result = verifier.verify(&proof, None);
        assert!(result.is_err());
    }

    #[test]
    fn mock_verifier_selective_reject() {
        let attestation = test_attestation();
        let proof = ExternalEventProofV1::EthReceiptAttestationV1(attestation);
        let proof_id = proof.proof_id().unwrap();

        let verifier = MockVerifier::accepting().reject(&proof_id.to_hex());

        let result = verifier.verify(&proof, None);
        assert!(result.is_err());
    }

    // ========== Composite Verifier Tests ==========

    #[test]
    fn composite_verifier_empty() {
        let verifier = CompositeVerifier::new();

        let attestation = test_attestation();
        let proof = ExternalEventProofV1::EthReceiptAttestationV1(attestation);

        let result = verifier.verify(&proof, None);
        assert!(matches!(result, Err(ExternalVerifyError::Internal(_))));
    }

    #[test]
    fn composite_verifier_first_succeeds() {
        let verifier = CompositeVerifier::new()
            .add_verifier(Arc::new(MockVerifier::accepting()))
            .add_verifier(Arc::new(MockVerifier::rejecting()));

        let attestation = test_attestation();
        let proof = ExternalEventProofV1::EthReceiptAttestationV1(attestation);

        let result = verifier.verify(&proof, None);
        assert!(result.is_ok());
    }

    #[test]
    fn composite_verifier_fallback() {
        let verifier = CompositeVerifier::new()
            .add_verifier(Arc::new(MockVerifier::rejecting()))
            .add_verifier(Arc::new(MockVerifier::accepting()));

        let attestation = test_attestation();
        let proof = ExternalEventProofV1::EthReceiptAttestationV1(attestation);

        let result = verifier.verify(&proof, None);
        assert!(result.is_ok());
    }

    // ========== Expected Binding Tests ==========

    #[test]
    fn expected_binding_builder() {
        let binding = ExpectedEventBinding::any()
            .with_contract([0xAA; 20])
            .with_topic0([0xBB; 32])
            .with_data_hash([0xCC; 32])
            .with_chain(ExternalChainId::EthereumMainnet);

        assert_eq!(binding.contract, Some([0xAA; 20]));
        assert_eq!(binding.topic0, Some([0xBB; 32]));
        assert_eq!(binding.data_hash, Some([0xCC; 32]));
        assert_eq!(binding.chain, Some(ExternalChainId::EthereumMainnet));
    }

    // ========== Verified Event Tests ==========

    #[test]
    fn verified_event_from_mock() {
        let verifier = MockVerifier::accepting();

        let attestation = test_attestation();
        let proof = ExternalEventProofV1::EthReceiptAttestationV1(attestation.clone());

        let event = verifier.verify(&proof, None).unwrap();

        assert_eq!(event.chain, attestation.chain);
        assert_eq!(event.tx_hash, attestation.tx_hash);
        assert_eq!(event.log_index, attestation.log_index);
        assert_eq!(event.contract, attestation.contract);
        assert_eq!(event.topic0, attestation.topic0);
        assert_eq!(event.data_hash, attestation.data_hash);
        assert_eq!(event.block_number, attestation.block_number);
        assert_eq!(event.confirmations, attestation.confirmations);
        assert_eq!(event.attestor_pubkey, Some(attestation.attestor_pubkey));
    }
}
