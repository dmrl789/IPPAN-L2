//! External Proof Cache and Intent Bindings.
//!
//! This module provides persistent storage for external chain proofs
//! (Ethereum, etc.) with verification state tracking and intent bindings.
//!
//! ## Storage Model
//!
//! - Proofs are stored by `proof_id` (blake3 hash of canonical bytes)
//! - Each proof has a verification state (Unverified/Verified/Rejected)
//! - Proofs can be bound to intents for gating prepare phase
//!
//! ## Operations
//!
//! - `put_proof_if_absent`: Idempotent proof insertion
//! - `set_proof_state`: Update verification state
//! - `bind_proof_to_intent`: Associate proof with intent
//! - `list_unverified_proofs`: Get proofs needing verification

use l2_core::{
    canonical_decode, canonical_encode, ExternalEventProofV1, ExternalProofId, ExternalProofState,
    IntentId,
};
use sled::Tree;
use std::fmt;
use thiserror::Error;

/// Storage errors for external proofs.
#[derive(Debug, Error)]
pub enum ExternalProofStorageError {
    #[error("storage error: {0}")]
    Sled(#[from] sled::Error),
    #[error("canonical encoding error: {0}")]
    Canonical(#[from] l2_core::CanonicalError),
    #[error("proof not found: {0}")]
    NotFound(String),
    #[error("proof already exists: {0}")]
    AlreadyExists(String),
    #[error("invalid state transition: {0}")]
    InvalidTransition(String),
}

/// Entry in the proof storage for listing.
#[derive(Debug, Clone)]
pub struct ExternalProofEntry {
    /// The proof ID.
    pub proof_id: ExternalProofId,
    /// The proof data.
    pub proof: ExternalEventProofV1,
    /// Current verification state.
    pub state: ExternalProofState,
}

/// Entry for proof-to-intent bindings.
#[derive(Debug, Clone)]
pub struct ProofIntentBinding {
    /// The proof ID.
    pub proof_id: ExternalProofId,
    /// The intent ID this proof is bound to.
    pub intent_id: IntentId,
    /// Timestamp when binding was created (ms since epoch).
    pub bound_at_ms: u64,
}

/// Counts of proofs by verification state.
#[derive(Debug, Clone, Default)]
pub struct ExternalProofCounts {
    pub unverified: u64,
    pub verified: u64,
    pub rejected: u64,
}

impl ExternalProofCounts {
    /// Total number of proofs tracked.
    pub fn total(&self) -> u64 {
        self.unverified
            .saturating_add(self.verified)
            .saturating_add(self.rejected)
    }
}

impl fmt::Display for ExternalProofCounts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unverified={}, verified={}, rejected={}, total={}",
            self.unverified,
            self.verified,
            self.rejected,
            self.total()
        )
    }
}

/// Stored proof data (proof + state).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct StoredProof {
    proof: ExternalEventProofV1,
    state: ExternalProofState,
    /// Timestamp when proof was first stored (ms since epoch).
    stored_at_ms: u64,
}

/// Stored binding data.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct StoredBinding {
    intent_id_hex: String,
    bound_at_ms: u64,
}

/// Persistent storage for external chain proofs.
///
/// Provides crash-safe storage with verification state tracking
/// and intent bindings for proof-gated operations.
pub struct ExternalProofStorage {
    /// Main proof storage (proof_id_hex -> StoredProof).
    proofs: Tree,
    /// Proof state index (state:proof_id_hex -> "").
    state_index: Tree,
    /// Proof to intent bindings (proof_id_hex:intent_id_hex -> StoredBinding).
    proof_intent_bindings: Tree,
    /// Intent to proof bindings (intent_id_hex:proof_id_hex -> "").
    intent_proof_index: Tree,
}

impl ExternalProofStorage {
    /// Create a new ExternalProofStorage from a sled database.
    pub fn new(db: &sled::Db) -> Result<Self, ExternalProofStorageError> {
        Ok(Self {
            proofs: db.open_tree("external_proofs")?,
            state_index: db.open_tree("external_proofs_state")?,
            proof_intent_bindings: db.open_tree("external_proof_intent_bindings")?,
            intent_proof_index: db.open_tree("external_intent_proof_index")?,
        })
    }

    /// Store a proof if it doesn't already exist.
    ///
    /// Returns `Ok(true)` if the proof was stored, `Ok(false)` if it already existed.
    /// Initial state is always `Unverified`.
    pub fn put_proof_if_absent(
        &self,
        proof: &ExternalEventProofV1,
        stored_at_ms: u64,
    ) -> Result<bool, ExternalProofStorageError> {
        let proof_id = proof.proof_id()?;
        let key = proof_id.to_hex();

        // Check if already exists
        if self.proofs.contains_key(key.as_bytes())? {
            return Ok(false);
        }

        // Store with initial Unverified state
        let stored = StoredProof {
            proof: proof.clone(),
            state: ExternalProofState::Unverified,
            stored_at_ms,
        };

        let bytes = canonical_encode(&stored)?;
        self.proofs.insert(key.as_bytes(), bytes)?;

        // Update state index
        let state_key = format!("unverified:{}", key);
        self.state_index.insert(state_key.as_bytes(), &[])?;

        Ok(true)
    }

    /// Get a proof by ID.
    pub fn get_proof(
        &self,
        proof_id: &ExternalProofId,
    ) -> Result<Option<ExternalProofEntry>, ExternalProofStorageError> {
        let key = proof_id.to_hex();
        match self.proofs.get(key.as_bytes())? {
            Some(bytes) => {
                let stored: StoredProof = canonical_decode(&bytes)?;
                Ok(Some(ExternalProofEntry {
                    proof_id: *proof_id,
                    proof: stored.proof,
                    state: stored.state,
                }))
            }
            None => Ok(None),
        }
    }

    /// Check if a proof exists.
    pub fn proof_exists(
        &self,
        proof_id: &ExternalProofId,
    ) -> Result<bool, ExternalProofStorageError> {
        let key = proof_id.to_hex();
        Ok(self.proofs.contains_key(key.as_bytes())?)
    }

    /// Get the verification state of a proof.
    pub fn get_proof_state(
        &self,
        proof_id: &ExternalProofId,
    ) -> Result<Option<ExternalProofState>, ExternalProofStorageError> {
        let key = proof_id.to_hex();
        match self.proofs.get(key.as_bytes())? {
            Some(bytes) => {
                let stored: StoredProof = canonical_decode(&bytes)?;
                Ok(Some(stored.state))
            }
            None => Ok(None),
        }
    }

    /// Update the verification state of a proof.
    ///
    /// State transitions must be from Unverified to Verified/Rejected.
    /// Once Verified or Rejected, the state cannot change.
    pub fn set_proof_state(
        &self,
        proof_id: &ExternalProofId,
        new_state: ExternalProofState,
    ) -> Result<(), ExternalProofStorageError> {
        let key = proof_id.to_hex();

        // Get current stored proof
        let bytes = self
            .proofs
            .get(key.as_bytes())?
            .ok_or_else(|| ExternalProofStorageError::NotFound(key.clone()))?;

        let mut stored: StoredProof = canonical_decode(&bytes)?;

        // Validate state transition
        match (&stored.state, &new_state) {
            (ExternalProofState::Unverified, ExternalProofState::Verified { .. })
            | (ExternalProofState::Unverified, ExternalProofState::Rejected { .. }) => {
                // Valid transitions
            }
            (from, to) if from == to => {
                // Idempotent - same state
                return Ok(());
            }
            (from, to) => {
                return Err(ExternalProofStorageError::InvalidTransition(format!(
                    "cannot transition from {} to {}",
                    from.name(),
                    to.name()
                )));
            }
        }

        // Remove old state index
        let old_state_key = format!("{}:{}", stored.state.name(), key);
        self.state_index.remove(old_state_key.as_bytes())?;

        // Update state
        stored.state = new_state.clone();

        // Store updated proof
        let new_bytes = canonical_encode(&stored)?;
        self.proofs.insert(key.as_bytes(), new_bytes)?;

        // Add new state index
        let new_state_key = format!("{}:{}", stored.state.name(), key);
        self.state_index.insert(new_state_key.as_bytes(), &[])?;

        Ok(())
    }

    /// Bind a proof to an intent.
    ///
    /// A proof can be bound to multiple intents, and an intent can have multiple proofs.
    pub fn bind_proof_to_intent(
        &self,
        proof_id: &ExternalProofId,
        intent_id: &IntentId,
        bound_at_ms: u64,
    ) -> Result<(), ExternalProofStorageError> {
        // Verify proof exists
        if !self.proof_exists(proof_id)? {
            return Err(ExternalProofStorageError::NotFound(proof_id.to_hex()));
        }

        let proof_key = proof_id.to_hex();
        let intent_key = intent_id.to_hex();

        // Store binding (proof -> intent)
        let binding_key = format!("{}:{}", proof_key, intent_key);
        let binding = StoredBinding {
            intent_id_hex: intent_key.clone(),
            bound_at_ms,
        };
        let binding_bytes = canonical_encode(&binding)?;
        self.proof_intent_bindings
            .insert(binding_key.as_bytes(), binding_bytes)?;

        // Store reverse index (intent -> proof)
        let reverse_key = format!("{}:{}", intent_key, proof_key);
        self.intent_proof_index
            .insert(reverse_key.as_bytes(), &[])?;

        Ok(())
    }

    /// List proofs bound to an intent.
    pub fn list_proofs_for_intent(
        &self,
        intent_id: &IntentId,
        limit: usize,
    ) -> Result<Vec<ExternalProofEntry>, ExternalProofStorageError> {
        let prefix = format!("{}:", intent_id.to_hex());
        let mut entries = Vec::new();

        for result in self.intent_proof_index.scan_prefix(prefix.as_bytes()) {
            if entries.len() >= limit {
                break;
            }
            let (key, _) = result?;
            let key_str = String::from_utf8_lossy(&key);
            // Key format is "intent_id_hex:proof_id_hex"
            if let Some(proof_id_hex) = key_str.split(':').nth(1) {
                if let Ok(proof_id) = ExternalProofId::from_hex(proof_id_hex) {
                    if let Some(entry) = self.get_proof(&proof_id)? {
                        entries.push(entry);
                    }
                }
            }
        }

        Ok(entries)
    }

    /// List intents bound to a proof.
    pub fn list_intents_for_proof(
        &self,
        proof_id: &ExternalProofId,
        limit: usize,
    ) -> Result<Vec<IntentId>, ExternalProofStorageError> {
        let prefix = format!("{}:", proof_id.to_hex());
        let mut intents = Vec::new();

        for result in self.proof_intent_bindings.scan_prefix(prefix.as_bytes()) {
            if intents.len() >= limit {
                break;
            }
            let (_, value) = result?;
            let binding: StoredBinding = canonical_decode(&value)?;
            if let Ok(intent_id) = IntentId::from_hex(&binding.intent_id_hex) {
                intents.push(intent_id);
            }
        }

        Ok(intents)
    }

    /// Check if all proofs for an intent are verified.
    ///
    /// Returns `Ok(true)` if there are proofs and all are verified.
    /// Returns `Ok(false)` if there are no proofs or any are not verified.
    pub fn all_proofs_verified_for_intent(
        &self,
        intent_id: &IntentId,
    ) -> Result<bool, ExternalProofStorageError> {
        let proofs = self.list_proofs_for_intent(intent_id, usize::MAX)?;

        if proofs.is_empty() {
            return Ok(false);
        }

        for entry in &proofs {
            if !entry.state.is_verified() {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// List unverified proofs.
    pub fn list_unverified_proofs(
        &self,
        limit: usize,
    ) -> Result<Vec<ExternalProofEntry>, ExternalProofStorageError> {
        self.list_by_state("unverified", limit)
    }

    /// List verified proofs.
    pub fn list_verified_proofs(
        &self,
        limit: usize,
    ) -> Result<Vec<ExternalProofEntry>, ExternalProofStorageError> {
        self.list_by_state("verified", limit)
    }

    /// List rejected proofs.
    pub fn list_rejected_proofs(
        &self,
        limit: usize,
    ) -> Result<Vec<ExternalProofEntry>, ExternalProofStorageError> {
        self.list_by_state("rejected", limit)
    }

    /// Count proofs by state.
    pub fn count_proofs(&self) -> Result<ExternalProofCounts, ExternalProofStorageError> {
        let mut counts = ExternalProofCounts::default();

        for result in self.proofs.iter() {
            let (_, value) = result?;
            let stored: StoredProof = canonical_decode(&value)?;
            match stored.state {
                ExternalProofState::Unverified => counts.unverified += 1,
                ExternalProofState::Verified { .. } => counts.verified += 1,
                ExternalProofState::Rejected { .. } => counts.rejected += 1,
            }
        }

        Ok(counts)
    }

    /// Delete a proof and all its bindings.
    ///
    /// Use only for cleanup/tests. Returns true if proof existed.
    pub fn delete_proof(
        &self,
        proof_id: &ExternalProofId,
    ) -> Result<bool, ExternalProofStorageError> {
        let key = proof_id.to_hex();

        // Get current state for index cleanup
        if let Some(entry) = self.get_proof(proof_id)? {
            // Remove state index
            let state_key = format!("{}:{}", entry.state.name(), key);
            self.state_index.remove(state_key.as_bytes())?;

            // Remove all bindings for this proof
            let prefix = format!("{}:", key);
            let to_remove: Vec<_> = self
                .proof_intent_bindings
                .scan_prefix(prefix.as_bytes())
                .filter_map(|r| r.ok().map(|(k, v)| (k.to_vec(), v.to_vec())))
                .collect();

            for (binding_key, value) in to_remove {
                self.proof_intent_bindings.remove(&binding_key)?;
                // Also remove reverse index
                if let Ok(binding) = canonical_decode::<StoredBinding>(&value) {
                    let reverse_key = format!("{}:{}", binding.intent_id_hex, key);
                    self.intent_proof_index.remove(reverse_key.as_bytes())?;
                }
            }
        }

        let existed = self.proofs.remove(key.as_bytes())?.is_some();
        Ok(existed)
    }

    // ========== Internal helpers ==========

    fn list_by_state(
        &self,
        state_name: &str,
        limit: usize,
    ) -> Result<Vec<ExternalProofEntry>, ExternalProofStorageError> {
        let prefix = format!("{}:", state_name);
        let mut entries = Vec::new();

        for result in self.state_index.scan_prefix(prefix.as_bytes()) {
            if entries.len() >= limit {
                break;
            }
            let (key, _) = result?;
            let key_str = String::from_utf8_lossy(&key);
            // Key format is "state:proof_id_hex"
            if let Some(proof_id_hex) = key_str.split(':').nth(1) {
                if let Ok(proof_id) = ExternalProofId::from_hex(proof_id_hex) {
                    if let Some(entry) = self.get_proof(&proof_id)? {
                        entries.push(entry);
                    }
                }
            }
        }

        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use l2_core::{EthReceiptAttestationV1, ExternalChainId, Hash32};
    use tempfile::tempdir;

    fn test_db() -> sled::Db {
        let dir = tempdir().expect("tmpdir");
        sled::open(dir.path()).expect("open")
    }

    fn test_attestation(suffix: u8) -> ExternalEventProofV1 {
        ExternalEventProofV1::EthReceiptAttestationV1(EthReceiptAttestationV1 {
            chain: ExternalChainId::EthereumMainnet,
            tx_hash: [suffix; 32],
            log_index: 0,
            contract: [0xBB; 20],
            topic0: [0xCC; 32],
            data_hash: [0xDD; 32],
            block_number: 18_000_000,
            block_hash: [0xEE; 32],
            confirmations: 12,
            attestor_pubkey: [0x11; 32],
            signature: [0x22; 64],
        })
    }

    fn test_intent_id(n: u8) -> IntentId {
        IntentId(Hash32([n; 32]))
    }

    // ========== Basic Storage Tests ==========

    #[test]
    fn put_and_get_proof() {
        let db = test_db();
        let storage = ExternalProofStorage::new(&db).unwrap();

        let proof = test_attestation(0xAA);
        let proof_id = proof.proof_id().unwrap();

        // Store proof
        let stored = storage
            .put_proof_if_absent(&proof, 1_700_000_000_000)
            .unwrap();
        assert!(stored);

        // Get proof
        let entry = storage.get_proof(&proof_id).unwrap().unwrap();
        assert_eq!(entry.proof_id, proof_id);
        assert!(entry.state.is_unverified());
    }

    #[test]
    fn put_proof_idempotent() {
        let db = test_db();
        let storage = ExternalProofStorage::new(&db).unwrap();

        let proof = test_attestation(0xAA);

        // Store first time
        let stored1 = storage
            .put_proof_if_absent(&proof, 1_700_000_000_000)
            .unwrap();
        assert!(stored1);

        // Store second time - should return false
        let stored2 = storage
            .put_proof_if_absent(&proof, 1_700_000_000_001)
            .unwrap();
        assert!(!stored2);
    }

    #[test]
    fn proof_exists() {
        let db = test_db();
        let storage = ExternalProofStorage::new(&db).unwrap();

        let proof = test_attestation(0xAA);
        let proof_id = proof.proof_id().unwrap();

        assert!(!storage.proof_exists(&proof_id).unwrap());

        storage
            .put_proof_if_absent(&proof, 1_700_000_000_000)
            .unwrap();

        assert!(storage.proof_exists(&proof_id).unwrap());
    }

    // ========== State Transition Tests ==========

    #[test]
    fn state_transition_to_verified() {
        let db = test_db();
        let storage = ExternalProofStorage::new(&db).unwrap();

        let proof = test_attestation(0xAA);
        let proof_id = proof.proof_id().unwrap();

        storage
            .put_proof_if_absent(&proof, 1_700_000_000_000)
            .unwrap();

        // Transition to Verified
        storage
            .set_proof_state(&proof_id, ExternalProofState::verified(1_700_000_001_000))
            .unwrap();

        let state = storage.get_proof_state(&proof_id).unwrap().unwrap();
        assert!(state.is_verified());
    }

    #[test]
    fn state_transition_to_rejected() {
        let db = test_db();
        let storage = ExternalProofStorage::new(&db).unwrap();

        let proof = test_attestation(0xAA);
        let proof_id = proof.proof_id().unwrap();

        storage
            .put_proof_if_absent(&proof, 1_700_000_000_000)
            .unwrap();

        // Transition to Rejected
        storage
            .set_proof_state(
                &proof_id,
                ExternalProofState::rejected("invalid signature".to_string(), 1_700_000_001_000),
            )
            .unwrap();

        let state = storage.get_proof_state(&proof_id).unwrap().unwrap();
        assert!(state.is_rejected());
    }

    #[test]
    fn state_transition_invalid() {
        let db = test_db();
        let storage = ExternalProofStorage::new(&db).unwrap();

        let proof = test_attestation(0xAA);
        let proof_id = proof.proof_id().unwrap();

        storage
            .put_proof_if_absent(&proof, 1_700_000_000_000)
            .unwrap();

        // Transition to Verified
        storage
            .set_proof_state(&proof_id, ExternalProofState::verified(1_700_000_001_000))
            .unwrap();

        // Try to go back to Unverified - should fail
        let result = storage.set_proof_state(&proof_id, ExternalProofState::Unverified);
        assert!(result.is_err());
    }

    #[test]
    fn state_transition_idempotent() {
        let db = test_db();
        let storage = ExternalProofStorage::new(&db).unwrap();

        let proof = test_attestation(0xAA);
        let proof_id = proof.proof_id().unwrap();

        storage
            .put_proof_if_absent(&proof, 1_700_000_000_000)
            .unwrap();

        let verified_state = ExternalProofState::verified(1_700_000_001_000);

        // Transition to Verified
        storage
            .set_proof_state(&proof_id, verified_state.clone())
            .unwrap();

        // Set same state again - should succeed (idempotent)
        storage.set_proof_state(&proof_id, verified_state).unwrap();

        let state = storage.get_proof_state(&proof_id).unwrap().unwrap();
        assert!(state.is_verified());
    }

    // ========== Binding Tests ==========

    #[test]
    fn bind_proof_to_intent() {
        let db = test_db();
        let storage = ExternalProofStorage::new(&db).unwrap();

        let proof = test_attestation(0xAA);
        let proof_id = proof.proof_id().unwrap();
        let intent_id = test_intent_id(0x01);

        storage
            .put_proof_if_absent(&proof, 1_700_000_000_000)
            .unwrap();

        // Bind proof to intent
        storage
            .bind_proof_to_intent(&proof_id, &intent_id, 1_700_000_001_000)
            .unwrap();

        // List proofs for intent
        let proofs = storage.list_proofs_for_intent(&intent_id, 10).unwrap();
        assert_eq!(proofs.len(), 1);
        assert_eq!(proofs[0].proof_id, proof_id);

        // List intents for proof
        let intents = storage.list_intents_for_proof(&proof_id, 10).unwrap();
        assert_eq!(intents.len(), 1);
        assert_eq!(intents[0], intent_id);
    }

    #[test]
    fn multiple_proofs_per_intent() {
        let db = test_db();
        let storage = ExternalProofStorage::new(&db).unwrap();

        let proof1 = test_attestation(0xAA);
        let proof2 = test_attestation(0xBB);
        let proof_id1 = proof1.proof_id().unwrap();
        let proof_id2 = proof2.proof_id().unwrap();
        let intent_id = test_intent_id(0x01);

        storage
            .put_proof_if_absent(&proof1, 1_700_000_000_000)
            .unwrap();
        storage
            .put_proof_if_absent(&proof2, 1_700_000_000_001)
            .unwrap();

        storage
            .bind_proof_to_intent(&proof_id1, &intent_id, 1_700_000_001_000)
            .unwrap();
        storage
            .bind_proof_to_intent(&proof_id2, &intent_id, 1_700_000_001_001)
            .unwrap();

        let proofs = storage.list_proofs_for_intent(&intent_id, 10).unwrap();
        assert_eq!(proofs.len(), 2);
    }

    #[test]
    fn all_proofs_verified_for_intent() {
        let db = test_db();
        let storage = ExternalProofStorage::new(&db).unwrap();

        let proof1 = test_attestation(0xAA);
        let proof2 = test_attestation(0xBB);
        let proof_id1 = proof1.proof_id().unwrap();
        let proof_id2 = proof2.proof_id().unwrap();
        let intent_id = test_intent_id(0x01);

        storage
            .put_proof_if_absent(&proof1, 1_700_000_000_000)
            .unwrap();
        storage
            .put_proof_if_absent(&proof2, 1_700_000_000_001)
            .unwrap();

        storage
            .bind_proof_to_intent(&proof_id1, &intent_id, 1_700_000_001_000)
            .unwrap();
        storage
            .bind_proof_to_intent(&proof_id2, &intent_id, 1_700_000_001_001)
            .unwrap();

        // Initially not all verified
        assert!(!storage.all_proofs_verified_for_intent(&intent_id).unwrap());

        // Verify first proof
        storage
            .set_proof_state(&proof_id1, ExternalProofState::verified(1_700_000_002_000))
            .unwrap();
        assert!(!storage.all_proofs_verified_for_intent(&intent_id).unwrap());

        // Verify second proof
        storage
            .set_proof_state(&proof_id2, ExternalProofState::verified(1_700_000_002_001))
            .unwrap();
        assert!(storage.all_proofs_verified_for_intent(&intent_id).unwrap());
    }

    #[test]
    fn no_proofs_means_not_verified() {
        let db = test_db();
        let storage = ExternalProofStorage::new(&db).unwrap();

        let intent_id = test_intent_id(0x01);

        // No proofs bound - should return false
        assert!(!storage.all_proofs_verified_for_intent(&intent_id).unwrap());
    }

    // ========== Listing Tests ==========

    #[test]
    fn list_unverified_proofs() {
        let db = test_db();
        let storage = ExternalProofStorage::new(&db).unwrap();

        // Add some proofs
        for i in 0u8..5 {
            let proof = test_attestation(i);
            storage
                .put_proof_if_absent(&proof, 1_700_000_000_000)
                .unwrap();
        }

        // All should be unverified
        let unverified = storage.list_unverified_proofs(10).unwrap();
        assert_eq!(unverified.len(), 5);

        // Verify one
        let proof0 = test_attestation(0);
        let proof_id0 = proof0.proof_id().unwrap();
        storage
            .set_proof_state(&proof_id0, ExternalProofState::verified(1_700_000_001_000))
            .unwrap();

        // Should have 4 unverified now
        let unverified = storage.list_unverified_proofs(10).unwrap();
        assert_eq!(unverified.len(), 4);

        // Should have 1 verified
        let verified = storage.list_verified_proofs(10).unwrap();
        assert_eq!(verified.len(), 1);
    }

    #[test]
    fn list_with_limit() {
        let db = test_db();
        let storage = ExternalProofStorage::new(&db).unwrap();

        // Add 10 proofs
        for i in 0u8..10 {
            let proof = test_attestation(i);
            storage
                .put_proof_if_absent(&proof, 1_700_000_000_000)
                .unwrap();
        }

        // List with limit
        let limited = storage.list_unverified_proofs(3).unwrap();
        assert_eq!(limited.len(), 3);
    }

    // ========== Count Tests ==========

    #[test]
    fn count_proofs() {
        let db = test_db();
        let storage = ExternalProofStorage::new(&db).unwrap();

        // Add some proofs
        for i in 0u8..5 {
            let proof = test_attestation(i);
            storage
                .put_proof_if_absent(&proof, 1_700_000_000_000)
                .unwrap();
        }

        // Verify some, reject some
        let proof0 = test_attestation(0);
        let proof1 = test_attestation(1);
        let proof2 = test_attestation(2);

        storage
            .set_proof_state(
                &proof0.proof_id().unwrap(),
                ExternalProofState::verified(1_700_000_001_000),
            )
            .unwrap();
        storage
            .set_proof_state(
                &proof1.proof_id().unwrap(),
                ExternalProofState::verified(1_700_000_001_000),
            )
            .unwrap();
        storage
            .set_proof_state(
                &proof2.proof_id().unwrap(),
                ExternalProofState::rejected("bad".to_string(), 1_700_000_001_000),
            )
            .unwrap();

        let counts = storage.count_proofs().unwrap();
        assert_eq!(counts.unverified, 2);
        assert_eq!(counts.verified, 2);
        assert_eq!(counts.rejected, 1);
        assert_eq!(counts.total(), 5);
    }

    // ========== Delete Tests ==========

    #[test]
    fn delete_proof() {
        let db = test_db();
        let storage = ExternalProofStorage::new(&db).unwrap();

        let proof = test_attestation(0xAA);
        let proof_id = proof.proof_id().unwrap();
        let intent_id = test_intent_id(0x01);

        storage
            .put_proof_if_absent(&proof, 1_700_000_000_000)
            .unwrap();
        storage
            .bind_proof_to_intent(&proof_id, &intent_id, 1_700_000_001_000)
            .unwrap();

        assert!(storage.proof_exists(&proof_id).unwrap());

        let deleted = storage.delete_proof(&proof_id).unwrap();
        assert!(deleted);
        assert!(!storage.proof_exists(&proof_id).unwrap());

        // Bindings should be cleaned up
        let proofs = storage.list_proofs_for_intent(&intent_id, 10).unwrap();
        assert!(proofs.is_empty());
    }

    #[test]
    fn delete_nonexistent_proof() {
        let db = test_db();
        let storage = ExternalProofStorage::new(&db).unwrap();

        let proof = test_attestation(0xAA);
        let proof_id = proof.proof_id().unwrap();

        let deleted = storage.delete_proof(&proof_id).unwrap();
        assert!(!deleted);
    }

    // ========== Error Cases ==========

    #[test]
    fn bind_nonexistent_proof() {
        let db = test_db();
        let storage = ExternalProofStorage::new(&db).unwrap();

        let proof = test_attestation(0xAA);
        let proof_id = proof.proof_id().unwrap();
        let intent_id = test_intent_id(0x01);

        let result = storage.bind_proof_to_intent(&proof_id, &intent_id, 1_700_000_000_000);
        assert!(matches!(
            result,
            Err(ExternalProofStorageError::NotFound(_))
        ));
    }

    #[test]
    fn set_state_nonexistent_proof() {
        let db = test_db();
        let storage = ExternalProofStorage::new(&db).unwrap();

        let proof = test_attestation(0xAA);
        let proof_id = proof.proof_id().unwrap();

        let result =
            storage.set_proof_state(&proof_id, ExternalProofState::verified(1_700_000_000_000));
        assert!(matches!(
            result,
            Err(ExternalProofStorageError::NotFound(_))
        ));
    }
}
