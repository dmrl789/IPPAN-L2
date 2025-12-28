#![forbid(unsafe_code)]

//! Batch envelope types for L2 batch posting.
//!
//! This module defines canonical BatchPayload and BatchEnvelope structures
//! for deterministic hashing and signing of L2 batches.

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::canonical::{canonical_encode, canonical_hash, CanonicalError, ChainId, Hash32};

/// Domain separator for batch envelope signing (v1).
pub const BATCH_SIGNING_DOMAIN_V1: &[u8] = b"IPPAN-L2:BATCH_ENVELOPE:V1\n";

/// Error types for batch envelope operations.
#[derive(Debug, Error)]
pub enum BatchEnvelopeError {
    #[error("canonical encoding error: {0}")]
    Canonical(#[from] CanonicalError),
    #[error("signing error: {0}")]
    Signing(String),
    #[error("verification error: {0}")]
    Verification(String),
    #[error("invalid payload: {0}")]
    InvalidPayload(String),
}

/// Inner payload of a batch that gets signed.
///
/// This is the canonical structure whose bytes are hashed and signed.
/// All fields are deterministic and no floats are used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchPayload {
    /// L2 chain identifier.
    pub l2_chain_id: ChainId,
    /// Hash of the batch contents (canonical hash of txs).
    pub batch_hash: Hash32,
    /// Hash of the previous batch (zero hash for first batch).
    pub prev_batch_hash: Hash32,
    /// Creation timestamp in milliseconds (service monotonic time).
    pub created_at_ms: u64,
    /// Number of transactions in this batch.
    pub tx_count: u32,
    /// Total size of transaction payload bytes.
    pub tx_bytes: u64,
    /// Merkle root or hash-of-concat of transaction hashes.
    pub tx_root: Hash32,
    /// Raw batch payload bytes (may be compressed).
    #[serde(with = "serde_bytes")]
    pub payload: Vec<u8>,
}

impl BatchPayload {
    /// Create a new batch payload.
    #[allow(clippy::too_many_arguments)]
    #[cfg_attr(feature = "profiling", tracing::instrument(skip(payload), level = "debug"))]
    pub fn new(
        l2_chain_id: ChainId,
        batch_hash: Hash32,
        prev_batch_hash: Hash32,
        created_at_ms: u64,
        tx_count: u32,
        tx_bytes: u64,
        tx_root: Hash32,
        payload: Vec<u8>,
    ) -> Self {
        Self {
            l2_chain_id,
            batch_hash,
            prev_batch_hash,
            created_at_ms,
            tx_count,
            tx_bytes,
            tx_root,
            payload,
        }
    }

    /// Compute the canonical hash of this payload.
    #[cfg_attr(feature = "profiling", tracing::instrument(skip(self), level = "debug"))]
    pub fn hash(&self) -> Result<Hash32, BatchEnvelopeError> {
        canonical_hash(self).map_err(BatchEnvelopeError::from)
    }

    /// Encode this payload to canonical bytes.
    #[cfg_attr(feature = "profiling", tracing::instrument(skip(self), level = "debug"))]
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, BatchEnvelopeError> {
        canonical_encode(self).map_err(BatchEnvelopeError::from)
    }

    /// Zero hash for genesis batch.
    pub fn zero_hash() -> Hash32 {
        Hash32([0u8; 32])
    }
}

/// Signed batch envelope containing the payload and sequencer signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchEnvelope {
    /// Version of the envelope format.
    pub version: String,
    /// The batch payload.
    pub payload: BatchPayload,
    /// Sequencer public key (Ed25519, 32 bytes, hex encoded).
    #[serde(with = "hex_bytes")]
    pub sequencer_pubkey: Vec<u8>,
    /// Sequencer signature (Ed25519, 64 bytes, hex encoded).
    #[serde(with = "hex_bytes")]
    pub sequencer_sig: Vec<u8>,
    /// Hash of the payload (for indexing).
    #[serde(with = "hex_32")]
    pub envelope_hash: [u8; 32],
}

impl BatchEnvelope {
    /// Current envelope version.
    pub const VERSION: &'static str = "v1";

    /// Create an unsigned envelope (for testing or later signing).
    #[cfg_attr(feature = "profiling", tracing::instrument(skip(payload), level = "debug", name = "envelope_build"))]
    pub fn new_unsigned(payload: BatchPayload) -> Result<Self, BatchEnvelopeError> {
        let envelope_hash = payload.hash()?.0;
        Ok(Self {
            version: Self::VERSION.to_string(),
            payload,
            sequencer_pubkey: Vec::new(),
            sequencer_sig: Vec::new(),
            envelope_hash,
        })
    }

    /// Get the canonical bytes to sign.
    ///
    /// Format: BATCH_SIGNING_DOMAIN_V1 || canonical_bytes(payload)
    #[cfg_attr(feature = "profiling", tracing::instrument(skip(self), level = "debug"))]
    pub fn signing_bytes(&self) -> Result<Vec<u8>, BatchEnvelopeError> {
        let payload_bytes = self.payload.to_canonical_bytes()?;
        let mut out = Vec::with_capacity(BATCH_SIGNING_DOMAIN_V1.len() + payload_bytes.len());
        out.extend_from_slice(BATCH_SIGNING_DOMAIN_V1);
        out.extend_from_slice(&payload_bytes);
        Ok(out)
    }

    /// Compute the envelope hash from the payload.
    #[cfg_attr(feature = "profiling", tracing::instrument(skip(self), level = "debug"))]
    pub fn compute_hash(&self) -> Result<Hash32, BatchEnvelopeError> {
        self.payload.hash()
    }

    /// Check if the envelope has a valid signature attached.
    pub fn is_signed(&self) -> bool {
        self.sequencer_pubkey.len() == 32 && self.sequencer_sig.len() == 64
    }
}

/// Sign a batch envelope using Ed25519.
///
/// Requires the `signed-envelopes` feature.
#[cfg(feature = "signed-envelopes")]
pub fn sign_envelope(
    envelope: &mut BatchEnvelope,
    signing_key: &ed25519_dalek::SigningKey,
) -> Result<(), BatchEnvelopeError> {
    use ed25519_dalek::Signer;

    let signing_bytes = envelope.signing_bytes()?;
    let signature = signing_key.sign(&signing_bytes);

    envelope.sequencer_pubkey = signing_key.verifying_key().to_bytes().to_vec();
    envelope.sequencer_sig = signature.to_bytes().to_vec();

    Ok(())
}

/// Verify a batch envelope signature using Ed25519.
///
/// Requires the `signed-envelopes` feature.
#[cfg(feature = "signed-envelopes")]
pub fn verify_envelope(envelope: &BatchEnvelope) -> Result<bool, BatchEnvelopeError> {
    use ed25519_dalek::{Signature, Verifier, VerifyingKey};

    if envelope.sequencer_pubkey.len() != 32 {
        return Err(BatchEnvelopeError::Verification(format!(
            "invalid pubkey length: {}",
            envelope.sequencer_pubkey.len()
        )));
    }
    if envelope.sequencer_sig.len() != 64 {
        return Err(BatchEnvelopeError::Verification(format!(
            "invalid signature length: {}",
            envelope.sequencer_sig.len()
        )));
    }

    let pubkey_bytes: [u8; 32] = envelope.sequencer_pubkey.clone().try_into().map_err(|_| {
        BatchEnvelopeError::Verification("failed to convert pubkey bytes".to_string())
    })?;
    let sig_bytes: [u8; 64] = envelope.sequencer_sig.clone().try_into().map_err(|_| {
        BatchEnvelopeError::Verification("failed to convert signature bytes".to_string())
    })?;

    let verifying_key = VerifyingKey::from_bytes(&pubkey_bytes)
        .map_err(|e| BatchEnvelopeError::Verification(format!("invalid pubkey: {e}")))?;
    let signature = Signature::from_bytes(&sig_bytes);

    let signing_bytes = envelope.signing_bytes()?;

    Ok(verifying_key.verify(&signing_bytes, &signature).is_ok())
}

/// Stub sign function when feature is disabled.
#[cfg(not(feature = "signed-envelopes"))]
pub fn sign_envelope(
    _envelope: &mut BatchEnvelope,
    _signing_key: &[u8; 32],
) -> Result<(), BatchEnvelopeError> {
    Err(BatchEnvelopeError::Signing(
        "signed-envelopes feature not enabled".to_string(),
    ))
}

/// Stub verify function when feature is disabled.
#[cfg(not(feature = "signed-envelopes"))]
pub fn verify_envelope(_envelope: &BatchEnvelope) -> Result<bool, BatchEnvelopeError> {
    Err(BatchEnvelopeError::Verification(
        "signed-envelopes feature not enabled".to_string(),
    ))
}

/// Compute transaction root from a list of transaction hashes.
///
/// For simplicity, uses hash-of-concat: hash(h1 || h2 || ... || hn)
#[cfg_attr(feature = "profiling", tracing::instrument(skip(tx_hashes), level = "debug", fields(tx_count = tx_hashes.len())))]
pub fn compute_tx_root(tx_hashes: &[Hash32]) -> Hash32 {
    if tx_hashes.is_empty() {
        return Hash32([0u8; 32]);
    }
    let mut concat = Vec::with_capacity(tx_hashes.len() * 32);
    for h in tx_hashes {
        concat.extend_from_slice(&h.0);
    }
    Hash32(*blake3::hash(&concat).as_bytes())
}

/// Serde helpers for encoding raw bytes as lowercase hex strings.
mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
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
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}

/// Serde helpers for encoding `[u8; 32]` as lowercase hex string.
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

/// Serde helpers for payload bytes.
mod serde_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
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
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_payload() -> BatchPayload {
        BatchPayload::new(
            ChainId(1337),
            Hash32([0xAA; 32]),
            Hash32([0x00; 32]),
            1_735_000_000_000,
            5,
            1024,
            Hash32([0xBB; 32]),
            vec![1, 2, 3, 4],
        )
    }

    #[test]
    fn batch_payload_hash_is_deterministic() {
        let payload1 = sample_payload();
        let payload2 = sample_payload();
        let hash1 = payload1.hash().unwrap();
        let hash2 = payload2.hash().unwrap();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn batch_payload_canonical_bytes_are_stable() {
        let payload = sample_payload();
        let bytes = payload.to_canonical_bytes().unwrap();
        // Verify it's deterministic
        let bytes2 = payload.to_canonical_bytes().unwrap();
        assert_eq!(bytes, bytes2);
        // Verify non-empty
        assert!(!bytes.is_empty());
    }

    #[test]
    fn envelope_unsigned_creation() {
        let payload = sample_payload();
        let envelope = BatchEnvelope::new_unsigned(payload.clone()).unwrap();
        assert_eq!(envelope.version, "v1");
        assert!(!envelope.is_signed());
        assert_eq!(envelope.envelope_hash, payload.hash().unwrap().0);
    }

    #[test]
    fn compute_tx_root_empty() {
        let root = compute_tx_root(&[]);
        assert_eq!(root, Hash32([0u8; 32]));
    }

    #[test]
    fn compute_tx_root_deterministic() {
        let hashes = vec![Hash32([0x01; 32]), Hash32([0x02; 32]), Hash32([0x03; 32])];
        let root1 = compute_tx_root(&hashes);
        let root2 = compute_tx_root(&hashes);
        assert_eq!(root1, root2);
        // Different order should give different root
        let hashes_rev = vec![Hash32([0x03; 32]), Hash32([0x02; 32]), Hash32([0x01; 32])];
        let root_rev = compute_tx_root(&hashes_rev);
        assert_ne!(root1, root_rev);
    }

    #[test]
    fn batch_payload_golden_hash() {
        // Fixed payload for golden hash test
        let payload = BatchPayload::new(
            ChainId(1),
            Hash32([0x11; 32]),
            Hash32([0x00; 32]),
            1_700_000_000_000,
            10,
            2048,
            Hash32([0x22; 32]),
            vec![0xDE, 0xAD, 0xBE, 0xEF],
        );
        let hash = payload.hash().unwrap();
        // This is the golden hash - must remain stable across versions
        assert_eq!(
            hash.to_hex(),
            "a1e0e845ad9eb790508afe568183cc00ea6c9005296b7b10c43b665df3fdbcff"
        );
    }

    #[test]
    fn envelope_signing_bytes_include_domain() {
        let payload = sample_payload();
        let envelope = BatchEnvelope::new_unsigned(payload).unwrap();
        let signing_bytes = envelope.signing_bytes().unwrap();
        assert!(signing_bytes.starts_with(BATCH_SIGNING_DOMAIN_V1));
    }
}

#[cfg(all(test, feature = "signed-envelopes"))]
mod signing_tests {
    use super::*;

    fn test_signing_key() -> ed25519_dalek::SigningKey {
        // Deterministic test key
        let seed = [0x42u8; 32];
        ed25519_dalek::SigningKey::from_bytes(&seed)
    }

    #[test]
    fn sign_and_verify_envelope() {
        let payload = BatchPayload::new(
            ChainId(1337),
            Hash32([0xAA; 32]),
            Hash32([0x00; 32]),
            1_735_000_000_000,
            5,
            1024,
            Hash32([0xBB; 32]),
            vec![1, 2, 3, 4],
        );
        let mut envelope = BatchEnvelope::new_unsigned(payload).unwrap();
        assert!(!envelope.is_signed());

        let key = test_signing_key();
        sign_envelope(&mut envelope, &key).unwrap();

        assert!(envelope.is_signed());
        assert_eq!(envelope.sequencer_pubkey.len(), 32);
        assert_eq!(envelope.sequencer_sig.len(), 64);

        let valid = verify_envelope(&envelope).unwrap();
        assert!(valid);
    }

    #[test]
    fn verify_fails_with_tampered_payload() {
        let payload = BatchPayload::new(
            ChainId(1337),
            Hash32([0xAA; 32]),
            Hash32([0x00; 32]),
            1_735_000_000_000,
            5,
            1024,
            Hash32([0xBB; 32]),
            vec![1, 2, 3, 4],
        );
        let mut envelope = BatchEnvelope::new_unsigned(payload).unwrap();
        let key = test_signing_key();
        sign_envelope(&mut envelope, &key).unwrap();

        // Tamper with the payload
        envelope.payload.tx_count = 999;

        let valid = verify_envelope(&envelope).unwrap();
        assert!(!valid);
    }

    #[test]
    fn signature_is_deterministic() {
        let payload = BatchPayload::new(
            ChainId(1),
            Hash32([0x11; 32]),
            Hash32([0x00; 32]),
            1_700_000_000_000,
            10,
            2048,
            Hash32([0x22; 32]),
            vec![0xDE, 0xAD, 0xBE, 0xEF],
        );

        let key = test_signing_key();

        let mut envelope1 = BatchEnvelope::new_unsigned(payload.clone()).unwrap();
        sign_envelope(&mut envelope1, &key).unwrap();

        let mut envelope2 = BatchEnvelope::new_unsigned(payload).unwrap();
        sign_envelope(&mut envelope2, &key).unwrap();

        assert_eq!(envelope1.sequencer_sig, envelope2.sequencer_sig);
        assert_eq!(envelope1.sequencer_pubkey, envelope2.sequencer_pubkey);
    }

    #[test]
    fn golden_signature_vector() {
        // Fixed test vector for signature stability
        let payload = BatchPayload::new(
            ChainId(1),
            Hash32([0x11; 32]),
            Hash32([0x00; 32]),
            1_700_000_000_000,
            10,
            2048,
            Hash32([0x22; 32]),
            vec![0xDE, 0xAD, 0xBE, 0xEF],
        );

        let key = test_signing_key();
        let mut envelope = BatchEnvelope::new_unsigned(payload).unwrap();
        sign_envelope(&mut envelope, &key).unwrap();

        // Golden pubkey (deterministic from seed 0x42...)
        assert_eq!(
            hex::encode(&envelope.sequencer_pubkey),
            "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12"
        );

        // The signature should also be deterministic
        let valid = verify_envelope(&envelope).unwrap();
        assert!(valid);
    }
}
