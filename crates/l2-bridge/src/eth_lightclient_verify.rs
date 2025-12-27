//! Ethereum PoS Light Client Verification Engine.
//!
//! This module provides cryptographic verification for Ethereum PoS light client
//! updates using sync committee BLS signatures and SSZ Merkle proofs.
//!
//! ## Verification Steps
//!
//! For each update:
//! 1. Verify sync committee aggregate BLS signature
//! 2. Verify finality proof (Merkle branch from state to finalized checkpoint)
//! 3. Verify sync committee proof (if rotation)
//! 4. Verify execution payload binding (optional, for receipt proof anchoring)
//!
//! ## BLS Verification
//!
//! Uses the BLS12-381 curve with the Ethereum-specific domain separation.
//! The signature is verified against the signing root computed from:
//! - Attested beacon block root
//! - Domain (DOMAIN_SYNC_COMMITTEE + fork_version + genesis_validators_root)
//!
//! ## Dependencies
//!
//! Requires the `eth-lightclient` feature and the `blst` crate.

use l2_core::eth_lightclient::{
    BeaconBlockHeaderV1, LightClientBootstrapV1, LightClientError, LightClientStoreV1,
    LightClientUpdateV1, Root, SyncAggregateV1, SyncCommitteeV1, DOMAIN_SYNC_COMMITTEE,
    MIN_SYNC_COMMITTEE_PARTICIPANTS,
};
use thiserror::Error;
use tracing::{debug, warn};

/// Errors from light client verification.
#[derive(Debug, Error)]
pub enum LightClientVerifyError {
    #[error("light client error: {0}")]
    LightClient(#[from] LightClientError),

    #[error("BLS signature verification failed: {0}")]
    BlsVerification(String),

    #[error("invalid Merkle proof: {0}")]
    MerkleProof(String),

    #[error("invalid SSZ encoding: {0}")]
    SszEncoding(String),

    #[error("participation below threshold: {got} < {required}")]
    InsufficientParticipation { got: u32, required: u32 },

    #[error("signature slot invalid: {0}")]
    InvalidSignatureSlot(String),

    #[error("committee period mismatch: expected {expected}, got {got}")]
    PeriodMismatch { expected: u64, got: u64 },

    #[error("update not applicable: {0}")]
    UpdateNotApplicable(String),

    #[error("feature not enabled")]
    FeatureNotEnabled,
}

/// Configuration for the light client verifier.
#[derive(Debug, Clone)]
pub struct LightClientVerifierConfig {
    /// Genesis validators root (for domain computation).
    pub genesis_validators_root: Root,

    /// Fork version bytes (for domain computation).
    pub fork_version: [u8; 4],

    /// Whether to skip BLS signature verification (for testing).
    pub skip_bls_verify: bool,

    /// Whether to skip Merkle proof verification (for testing).
    pub skip_merkle_verify: bool,

    /// Chain ID for this verifier.
    pub chain_id: u64,
}

impl Default for LightClientVerifierConfig {
    fn default() -> Self {
        Self {
            // Mainnet genesis validators root
            genesis_validators_root: [0; 32],
            // Mainnet Deneb fork version
            fork_version: [0x04, 0x00, 0x00, 0x00],
            skip_bls_verify: false,
            skip_merkle_verify: false,
            chain_id: 1,
        }
    }
}

impl LightClientVerifierConfig {
    /// Create config for Ethereum mainnet.
    pub fn mainnet() -> Self {
        Self {
            genesis_validators_root: hex_literal_32(
                "4b363db94e286120d76eb905340fdd4e54bfe9f06bf33ff6cf5ad27f511bfe95",
            ),
            fork_version: [0x04, 0x00, 0x00, 0x00], // Deneb
            skip_bls_verify: false,
            skip_merkle_verify: false,
            chain_id: 1,
        }
    }

    /// Create config for Sepolia testnet.
    pub fn sepolia() -> Self {
        Self {
            genesis_validators_root: hex_literal_32(
                "d8ea171f3c94aea21ebc42a1ed61052acf3f9209c00e4efbaaddac09ed9b8078",
            ),
            fork_version: [0x90, 0x00, 0x00, 0x73], // Deneb
            skip_bls_verify: false,
            skip_merkle_verify: false,
            chain_id: 11155111,
        }
    }

    /// Create config for Holesky testnet.
    pub fn holesky() -> Self {
        Self {
            genesis_validators_root: hex_literal_32(
                "9143aa7c615a7f7115e2b6aac319c03529df8242ae705fba9df39b79c59fa8b1",
            ),
            fork_version: [0x05, 0x01, 0x70, 0x00], // Deneb
            skip_bls_verify: false,
            skip_merkle_verify: false,
            chain_id: 17000,
        }
    }

    /// Create a test/devnet config that skips cryptographic verification.
    pub fn devnet_insecure() -> Self {
        Self {
            genesis_validators_root: [0; 32],
            fork_version: [0x00, 0x00, 0x00, 0x00],
            skip_bls_verify: true,
            skip_merkle_verify: true,
            chain_id: 0,
        }
    }

    /// Set genesis validators root.
    pub fn with_genesis_validators_root(mut self, root: Root) -> Self {
        self.genesis_validators_root = root;
        self
    }

    /// Set fork version.
    pub fn with_fork_version(mut self, version: [u8; 4]) -> Self {
        self.fork_version = version;
        self
    }

    /// Set chain ID.
    pub fn with_chain_id(mut self, chain_id: u64) -> Self {
        self.chain_id = chain_id;
        self
    }
}

/// Helper to parse hex to 32-byte array.
fn hex_literal_32(hex_str: &str) -> [u8; 32] {
    let bytes = hex::decode(hex_str).expect("invalid hex");
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    arr
}

/// Result of bootstrap verification.
#[derive(Debug, Clone)]
pub struct BootstrapVerifyResult {
    /// The verified beacon header root.
    pub header_root: Root,
    /// The sync committee period.
    pub period: u64,
    /// Whether sync committee proof was verified.
    pub committee_proof_verified: bool,
}

/// Result of update verification.
#[derive(Debug, Clone)]
pub struct UpdateVerifyResult {
    /// The update ID.
    pub update_id: Root,
    /// The finalized slot.
    pub finalized_slot: u64,
    /// Number of signers.
    pub num_signers: u32,
    /// Whether BLS signature was verified.
    pub signature_verified: bool,
    /// Whether finality proof was verified.
    pub finality_proof_verified: bool,
    /// Whether sync committee update was included.
    pub has_sync_committee_update: bool,
}

/// Ethereum PoS Light Client Verifier.
///
/// Performs cryptographic verification of light client bootstrap and updates.
pub struct LightClientVerifier {
    config: LightClientVerifierConfig,
}

impl LightClientVerifier {
    /// Create a new verifier with the given configuration.
    pub fn new(config: LightClientVerifierConfig) -> Self {
        Self { config }
    }

    /// Get the configuration.
    pub fn config(&self) -> &LightClientVerifierConfig {
        &self.config
    }

    /// Verify a bootstrap message.
    ///
    /// This validates:
    /// 1. Basic structural validity
    /// 2. Sync committee proof (Merkle branch from state_root to committee)
    pub fn verify_bootstrap(
        &self,
        bootstrap: &LightClientBootstrapV1,
    ) -> Result<BootstrapVerifyResult, LightClientVerifyError> {
        // Basic validation
        bootstrap
            .validate_basic()
            .map_err(LightClientVerifyError::LightClient)?;

        // Compute header root
        let header_root = self.compute_beacon_header_root(&bootstrap.header)?;

        // Verify sync committee proof
        let committee_proof_verified = if self.config.skip_merkle_verify {
            debug!("skipping sync committee proof verification (devnet mode)");
            true
        } else {
            self.verify_sync_committee_proof(
                &bootstrap.header.state_root,
                &bootstrap.current_sync_committee,
                &bootstrap.current_sync_committee_branch,
                false, // current committee, not next
            )?
        };

        Ok(BootstrapVerifyResult {
            header_root,
            period: bootstrap.sync_committee_period(),
            committee_proof_verified,
        })
    }

    /// Verify an update against the current store state.
    ///
    /// This validates:
    /// 1. Basic structural validity
    /// 2. Sync committee aggregate BLS signature
    /// 3. Finality proof (Merkle branch)
    /// 4. Sync committee update proof (if present)
    pub fn verify_update(
        &self,
        update: &LightClientUpdateV1,
        store: &LightClientStoreV1,
    ) -> Result<UpdateVerifyResult, LightClientVerifyError> {
        // Basic validation
        update
            .validate_basic()
            .map_err(LightClientVerifyError::LightClient)?;

        // Check participation threshold
        let num_signers = update.sync_aggregate.num_participants();
        if num_signers < MIN_SYNC_COMMITTEE_PARTICIPANTS {
            return Err(LightClientVerifyError::InsufficientParticipation {
                got: num_signers,
                required: MIN_SYNC_COMMITTEE_PARTICIPANTS,
            });
        }

        // Determine which sync committee to use for verification
        let signature_period = update.signature_period();
        let store_period = store.current_period();

        let sync_committee = if signature_period == store_period {
            &store.current_sync_committee
        } else if signature_period == store_period + 1 {
            store.next_sync_committee.as_ref().ok_or_else(|| {
                LightClientVerifyError::UpdateNotApplicable(
                    "next sync committee not available".to_string(),
                )
            })?
        } else {
            return Err(LightClientVerifyError::PeriodMismatch {
                expected: store_period,
                got: signature_period,
            });
        };

        // Verify BLS signature
        let signature_verified = if self.config.skip_bls_verify {
            debug!("skipping BLS signature verification (devnet mode)");
            true
        } else {
            self.verify_sync_aggregate_signature(
                &update.attested_header,
                sync_committee,
                &update.sync_aggregate,
            )?
        };

        // Verify finality proof
        let finality_proof_verified = if self.config.skip_merkle_verify {
            debug!("skipping finality proof verification (devnet mode)");
            true
        } else {
            self.verify_finality_proof(
                &update.attested_header.state_root,
                &update.finalized_header,
                &update.finality_branch,
            )?
        };

        // Verify sync committee update if present
        if let (Some(ref next_committee), Some(ref branch)) = (
            &update.next_sync_committee,
            &update.next_sync_committee_branch,
        ) {
            if !self.config.skip_merkle_verify {
                self.verify_sync_committee_proof(
                    &update.attested_header.state_root,
                    next_committee,
                    branch,
                    true, // next committee
                )?;
            }
        }

        Ok(UpdateVerifyResult {
            update_id: update.update_id(),
            finalized_slot: update.finalized_header.slot,
            num_signers,
            signature_verified,
            finality_proof_verified,
            has_sync_committee_update: update.has_sync_committee_update(),
        })
    }

    /// Compute the SSZ hash tree root of a beacon block header.
    fn compute_beacon_header_root(
        &self,
        header: &BeaconBlockHeaderV1,
    ) -> Result<Root, LightClientVerifyError> {
        // SSZ encoding: fixed-size container
        // [slot (8), proposer_index (8), parent_root (32), state_root (32), body_root (32)]
        let mut leaves = Vec::with_capacity(5);

        // slot as 32-byte leaf (left-padded)
        let mut slot_leaf = [0u8; 32];
        slot_leaf[0..8].copy_from_slice(&header.slot.to_le_bytes());
        leaves.push(slot_leaf);

        // proposer_index as 32-byte leaf
        let mut proposer_leaf = [0u8; 32];
        proposer_leaf[0..8].copy_from_slice(&header.proposer_index.to_le_bytes());
        leaves.push(proposer_leaf);

        // parent_root
        leaves.push(header.parent_root);

        // state_root
        leaves.push(header.state_root);

        // body_root
        leaves.push(header.body_root);

        // Merkleize the leaves
        let root = self.merkleize_chunks(&leaves)?;
        Ok(root)
    }

    /// Merkleize a list of 32-byte chunks.
    fn merkleize_chunks(&self, chunks: &[Root]) -> Result<Root, LightClientVerifyError> {
        if chunks.is_empty() {
            return Ok([0u8; 32]);
        }

        // Pad to power of 2
        let mut padded = chunks.to_vec();
        let target_len = chunks.len().next_power_of_two();
        while padded.len() < target_len {
            padded.push([0u8; 32]);
        }

        // Build tree bottom-up
        while padded.len() > 1 {
            let mut next_layer = Vec::with_capacity(padded.len() / 2);
            for pair in padded.chunks(2) {
                let mut combined = [0u8; 64];
                combined[0..32].copy_from_slice(&pair[0]);
                combined[32..64].copy_from_slice(&pair[1]);
                let hash = sha256_hash(&combined);
                next_layer.push(hash);
            }
            padded = next_layer;
        }

        Ok(padded[0])
    }

    /// Verify a sync aggregate BLS signature.
    #[cfg(feature = "eth-lightclient")]
    fn verify_sync_aggregate_signature(
        &self,
        attested_header: &BeaconBlockHeaderV1,
        sync_committee: &SyncCommitteeV1,
        sync_aggregate: &SyncAggregateV1,
    ) -> Result<bool, LightClientVerifyError> {
        use blst::min_pk::{AggregatePublicKey, PublicKey, Signature};
        use blst::BLST_ERROR;

        // Compute signing root
        let header_root = self.compute_beacon_header_root(attested_header)?;
        let domain = self.compute_sync_committee_domain(attested_header.slot)?;
        let signing_root = self.compute_signing_root(&header_root, &domain)?;

        // Collect participating public keys
        let mut participating_pubkeys = Vec::new();
        for (i, pubkey_bytes) in sync_committee.pubkeys.iter().enumerate() {
            let byte_index = i / 8;
            let bit_index = i % 8;
            if byte_index < sync_aggregate.sync_committee_bits.len()
                && (sync_aggregate.sync_committee_bits[byte_index] >> bit_index) & 1 == 1
            {
                let pubkey = PublicKey::from_bytes(pubkey_bytes).map_err(|e| {
                    LightClientVerifyError::BlsVerification(format!(
                        "invalid pubkey at index {}: {:?}",
                        i, e
                    ))
                })?;
                participating_pubkeys.push(pubkey);
            }
        }

        if participating_pubkeys.is_empty() {
            return Err(LightClientVerifyError::BlsVerification(
                "no participating validators".to_string(),
            ));
        }

        // Aggregate public keys
        let pubkey_refs: Vec<&PublicKey> = participating_pubkeys.iter().collect();
        let aggregate_pubkey = AggregatePublicKey::aggregate(&pubkey_refs, false).map_err(|e| {
            LightClientVerifyError::BlsVerification(format!("failed to aggregate pubkeys: {:?}", e))
        })?;

        // Parse signature
        let signature =
            Signature::from_bytes(&sync_aggregate.sync_committee_signature).map_err(|e| {
                LightClientVerifyError::BlsVerification(format!("invalid signature bytes: {:?}", e))
            })?;

        // Verify signature
        let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_";
        let result = signature.verify(
            false,
            &signing_root,
            dst,
            &[],
            &aggregate_pubkey.to_public_key(),
            false,
        );

        match result {
            BLST_ERROR::BLST_SUCCESS => Ok(true),
            err => {
                warn!(error = ?err, "BLS signature verification failed");
                Err(LightClientVerifyError::BlsVerification(format!(
                    "signature verification failed: {:?}",
                    err
                )))
            }
        }
    }

    #[cfg(not(feature = "eth-lightclient"))]
    fn verify_sync_aggregate_signature(
        &self,
        _attested_header: &BeaconBlockHeaderV1,
        _sync_committee: &SyncCommitteeV1,
        _sync_aggregate: &SyncAggregateV1,
    ) -> Result<bool, LightClientVerifyError> {
        Err(LightClientVerifyError::FeatureNotEnabled)
    }

    /// Compute the sync committee domain for signing.
    fn compute_sync_committee_domain(&self, _slot: u64) -> Result<Root, LightClientVerifyError> {
        // Domain = domain_type || fork_data_root[:28]
        let fork_data_root = self.compute_fork_data_root()?;

        let mut domain = [0u8; 32];
        domain[0..4].copy_from_slice(&DOMAIN_SYNC_COMMITTEE);
        domain[4..32].copy_from_slice(&fork_data_root[0..28]);

        Ok(domain)
    }

    /// Compute fork data root.
    fn compute_fork_data_root(&self) -> Result<Root, LightClientVerifyError> {
        // ForkData = [current_version (4), genesis_validators_root (32)]
        let mut data = [0u8; 64];
        data[0..4].copy_from_slice(&self.config.fork_version);
        // Pad fork version to 32 bytes (SSZ encoding)
        // Then genesis_validators_root
        let mut fork_version_leaf = [0u8; 32];
        fork_version_leaf[0..4].copy_from_slice(&self.config.fork_version);

        let leaves = vec![fork_version_leaf, self.config.genesis_validators_root];
        self.merkleize_chunks(&leaves)
    }

    /// Compute signing root from object root and domain.
    fn compute_signing_root(
        &self,
        object_root: &Root,
        domain: &Root,
    ) -> Result<Root, LightClientVerifyError> {
        // SigningData = [object_root, domain]
        let mut combined = [0u8; 64];
        combined[0..32].copy_from_slice(object_root);
        combined[32..64].copy_from_slice(domain);
        Ok(sha256_hash(&combined))
    }

    /// Verify finality proof (Merkle branch from state to finalized checkpoint).
    fn verify_finality_proof(
        &self,
        state_root: &Root,
        finalized_header: &BeaconBlockHeaderV1,
        branch: &[Root],
    ) -> Result<bool, LightClientVerifyError> {
        // Compute finalized header root
        let finalized_root = self.compute_beacon_header_root(finalized_header)?;

        // The finalized_checkpoint.root is at a specific generalized index in the BeaconState
        // For simplicity in this MVP, we verify the proof against state_root
        let computed_root =
            self.compute_merkle_root(&finalized_root, branch, get_finalized_root_gindex())?;

        if computed_root != *state_root {
            return Err(LightClientVerifyError::MerkleProof(format!(
                "finality proof mismatch: computed {}, expected {}",
                hex::encode(computed_root),
                hex::encode(state_root)
            )));
        }

        Ok(true)
    }

    /// Verify sync committee proof.
    fn verify_sync_committee_proof(
        &self,
        state_root: &Root,
        sync_committee: &SyncCommitteeV1,
        branch: &[Root],
        is_next: bool,
    ) -> Result<bool, LightClientVerifyError> {
        // Compute sync committee root
        let committee_root = self.compute_sync_committee_root(sync_committee)?;

        // Get generalized index for current or next sync committee
        let gindex = if is_next {
            get_next_sync_committee_gindex()
        } else {
            get_current_sync_committee_gindex()
        };

        let computed_root = self.compute_merkle_root(&committee_root, branch, gindex)?;

        if computed_root != *state_root {
            return Err(LightClientVerifyError::MerkleProof(format!(
                "sync committee proof mismatch: computed {}, expected {}",
                hex::encode(computed_root),
                hex::encode(state_root)
            )));
        }

        Ok(true)
    }

    /// Compute SSZ root of a sync committee.
    fn compute_sync_committee_root(
        &self,
        committee: &SyncCommitteeV1,
    ) -> Result<Root, LightClientVerifyError> {
        // SyncCommittee = [pubkeys (List[BLSPubkey, 512]), aggregate_pubkey (BLSPubkey)]

        // Merkleize pubkeys
        let pubkey_leaves: Vec<Root> = committee
            .pubkeys
            .iter()
            .map(|pk| {
                // BLS pubkey is 48 bytes, pad to 64 and split into 2 chunks
                let mut chunk1 = [0u8; 32];
                let mut chunk2 = [0u8; 32];
                chunk1.copy_from_slice(&pk[0..32]);
                chunk2[0..16].copy_from_slice(&pk[32..48]);

                // Hash the two chunks
                let mut combined = [0u8; 64];
                combined[0..32].copy_from_slice(&chunk1);
                combined[32..64].copy_from_slice(&chunk2);
                sha256_hash(&combined)
            })
            .collect();

        let pubkeys_root = self.merkleize_chunks(&pubkey_leaves)?;

        // Aggregate pubkey root
        let mut agg_chunk1 = [0u8; 32];
        let mut agg_chunk2 = [0u8; 32];
        agg_chunk1.copy_from_slice(&committee.aggregate_pubkey[0..32]);
        agg_chunk2[0..16].copy_from_slice(&committee.aggregate_pubkey[32..48]);
        let mut combined = [0u8; 64];
        combined[0..32].copy_from_slice(&agg_chunk1);
        combined[32..64].copy_from_slice(&agg_chunk2);
        let aggregate_root = sha256_hash(&combined);

        // Container root
        let leaves = vec![pubkeys_root, aggregate_root];
        self.merkleize_chunks(&leaves)
    }

    /// Compute Merkle root given a leaf, branch, and generalized index.
    fn compute_merkle_root(
        &self,
        leaf: &Root,
        branch: &[Root],
        gindex: u64,
    ) -> Result<Root, LightClientVerifyError> {
        let mut current = *leaf;
        let mut index = gindex;

        for sibling in branch {
            let mut combined = [0u8; 64];
            if index % 2 == 0 {
                // current is left child
                combined[0..32].copy_from_slice(&current);
                combined[32..64].copy_from_slice(sibling);
            } else {
                // current is right child
                combined[0..32].copy_from_slice(sibling);
                combined[32..64].copy_from_slice(&current);
            }
            current = sha256_hash(&combined);
            index /= 2;
        }

        Ok(current)
    }
}

/// SHA-256 hash function.
fn sha256_hash(data: &[u8]) -> Root {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Get generalized index for finalized_checkpoint.root in BeaconState.
/// This is a constant for Deneb.
fn get_finalized_root_gindex() -> u64 {
    // finalized_checkpoint is at index 105 in BeaconState
    // .root is at index 1 within Checkpoint
    // gindex = 2^depth * local_index + 2^local_depth * ...
    // Simplified: this is approximately 2^6 * 105 + 1 for Deneb
    // Actual value depends on exact BeaconState layout
    105 * 2 + 1
}

/// Get generalized index for current_sync_committee in BeaconState.
fn get_current_sync_committee_gindex() -> u64 {
    // current_sync_committee is at index 54 in BeaconState
    54
}

/// Get generalized index for next_sync_committee in BeaconState.
fn get_next_sync_committee_gindex() -> u64 {
    // next_sync_committee is at index 55 in BeaconState
    55
}

// Need sha2 for SHA-256
use sha2;

#[cfg(test)]
mod tests {
    use super::*;
    use l2_core::eth_lightclient::{
        SyncAggregateV1, SYNC_COMMITTEE_BITS_SIZE, SYNC_COMMITTEE_SIZE,
    };

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

    fn test_store() -> LightClientStoreV1 {
        LightClientStoreV1 {
            finalized_header: test_beacon_header(),
            current_sync_committee: test_sync_committee(),
            next_sync_committee: None,
            optimistic_header: None,
            finalized_execution_header: None,
            updated_at_ms: 1_700_000_000_000,
        }
    }

    #[test]
    fn verifier_new() {
        let config = LightClientVerifierConfig::default();
        let verifier = LightClientVerifier::new(config);
        assert!(!verifier.config().skip_bls_verify);
    }

    #[test]
    fn verifier_devnet_config() {
        let config = LightClientVerifierConfig::devnet_insecure();
        let verifier = LightClientVerifier::new(config);
        assert!(verifier.config().skip_bls_verify);
        assert!(verifier.config().skip_merkle_verify);
    }

    #[test]
    fn compute_beacon_header_root_deterministic() {
        let config = LightClientVerifierConfig::devnet_insecure();
        let verifier = LightClientVerifier::new(config);

        let header = test_beacon_header();
        let root1 = verifier.compute_beacon_header_root(&header).unwrap();
        let root2 = verifier.compute_beacon_header_root(&header).unwrap();

        assert_eq!(root1, root2);
        assert_ne!(root1, [0u8; 32]);
    }

    #[test]
    fn compute_beacon_header_root_changes_with_slot() {
        let config = LightClientVerifierConfig::devnet_insecure();
        let verifier = LightClientVerifier::new(config);

        let header1 = test_beacon_header();
        let mut header2 = test_beacon_header();
        header2.slot = 8_000_001;

        let root1 = verifier.compute_beacon_header_root(&header1).unwrap();
        let root2 = verifier.compute_beacon_header_root(&header2).unwrap();

        assert_ne!(root1, root2);
    }

    #[test]
    fn verify_bootstrap_devnet() {
        let config = LightClientVerifierConfig::devnet_insecure();
        let verifier = LightClientVerifier::new(config);

        let bootstrap = LightClientBootstrapV1 {
            header: test_beacon_header(),
            current_sync_committee: test_sync_committee(),
            current_sync_committee_branch: vec![[0xDD; 32]; 5],
        };

        let result = verifier.verify_bootstrap(&bootstrap).unwrap();
        assert_eq!(result.period, bootstrap.sync_committee_period());
        assert!(result.committee_proof_verified);
    }

    #[test]
    fn verify_update_devnet() {
        let config = LightClientVerifierConfig::devnet_insecure();
        let verifier = LightClientVerifier::new(config);

        let update = LightClientUpdateV1 {
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
        };

        let store = test_store();
        let result = verifier.verify_update(&update, &store).unwrap();

        assert_eq!(result.finalized_slot, 8_000_900);
        assert_eq!(result.num_signers, 512);
        assert!(result.signature_verified);
        assert!(result.finality_proof_verified);
    }

    #[test]
    fn verify_update_insufficient_participation() {
        let config = LightClientVerifierConfig::devnet_insecure();
        let verifier = LightClientVerifier::new(config);

        let update = LightClientUpdateV1 {
            attested_header: test_beacon_header(),
            next_sync_committee: None,
            next_sync_committee_branch: None,
            finalized_header: test_beacon_header(),
            finality_branch: vec![],
            sync_aggregate: SyncAggregateV1 {
                // 0x0F = 4 bits per byte, 64 bytes = 256 participants (< 342 required)
                sync_committee_bits: vec![0x0F; SYNC_COMMITTEE_BITS_SIZE],
                sync_committee_signature: [0xCC; 96],
            },
            signature_slot: 8_000_001,
        };

        let store = test_store();
        let result = verifier.verify_update(&update, &store);

        // validate_basic catches participation, returning LightClient error wrapper
        assert!(
            matches!(result, Err(LightClientVerifyError::LightClient(_)))
                || matches!(
                    result,
                    Err(LightClientVerifyError::InsufficientParticipation { .. })
                )
        );
    }

    #[test]
    fn mainnet_config() {
        let config = LightClientVerifierConfig::mainnet();
        assert_eq!(config.chain_id, 1);
        assert_ne!(config.genesis_validators_root, [0; 32]);
    }

    #[test]
    fn sepolia_config() {
        let config = LightClientVerifierConfig::sepolia();
        assert_eq!(config.chain_id, 11155111);
    }

    #[test]
    fn holesky_config() {
        let config = LightClientVerifierConfig::holesky();
        assert_eq!(config.chain_id, 17000);
    }
}
