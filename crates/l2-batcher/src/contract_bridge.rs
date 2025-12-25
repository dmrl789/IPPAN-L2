//! Bridge module for converting `BatchEnvelope` to `L2BatchEnvelopeV1`.
//!
//! This module provides the missing wiring between the batcher's internal
//! `BatchEnvelope` format and the versioned contract envelope `L2BatchEnvelopeV1`
//! that is submitted to L1 via `L1Client::submit_batch`.
#![forbid(unsafe_code)]

use l2_core::batch_envelope::{compute_tx_root, BatchEnvelope, BatchEnvelopeError, BatchPayload};
use l2_core::canonical::{canonical_encode, canonical_hash, Batch, Hash32};
use l2_core::l1_contract::{
    Base64Bytes, ContractError, ContractVersion, FixedAmountV1, HubPayloadEnvelopeV1,
    L2BatchEnvelopeV1,
};
use l2_core::L2HubId;
use thiserror::Error;

/// Schema version for batch envelope payloads.
pub const BATCH_ENVELOPE_SCHEMA_VERSION: &str = "batch-envelope-v1";

/// Content type for canonical JSON batch envelope payloads.
pub const BATCH_ENVELOPE_CONTENT_TYPE_JSON: &str = "application/json";

/// Content type for canonical binary batch envelope payloads.
pub const BATCH_ENVELOPE_CONTENT_TYPE_BINARY: &str = "application/octet-stream";

/// Errors that can occur during batch envelope bridging.
#[derive(Debug, Error)]
pub enum BridgeError {
    #[error("batch envelope error: {0}")]
    BatchEnvelope(#[from] BatchEnvelopeError),
    #[error("contract error: {0}")]
    Contract(#[from] ContractError),
    #[error("canonical encoding error: {0}")]
    Canonical(#[from] l2_core::canonical::CanonicalError),
    #[error("serialization error: {0}")]
    Serialization(String),
}

/// Maximum payload size for batch envelopes (1MB default).
pub const MAX_PAYLOAD_SIZE: usize = 1024 * 1024;

/// Configuration for bridge operations.
#[derive(Debug, Clone)]
pub struct BridgeConfig {
    /// L2 hub identifier.
    pub hub: L2HubId,
    /// Content type for payload encoding.
    pub content_type: ContentType,
    /// Protocol fee for batch submission (scaled integer, 0 for MVP).
    pub fee: FixedAmountV1,
    /// Maximum payload size in bytes.
    pub max_payload_size: usize,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            hub: L2HubId::Fin,
            content_type: ContentType::Json,
            fee: FixedAmountV1(0),
            max_payload_size: MAX_PAYLOAD_SIZE,
        }
    }
}

impl BridgeConfig {
    /// Validate configuration. Returns an error if invalid.
    pub fn validate(&self) -> Result<(), BridgeError> {
        // Validate schema version is set (constant, so always valid)
        if BATCH_ENVELOPE_SCHEMA_VERSION.is_empty() {
            return Err(BridgeError::Serialization(
                "schema_version must not be empty".to_string(),
            ));
        }

        // Validate content type produces valid MIME
        let mime = self.content_type.as_mime();
        if mime.is_empty() {
            return Err(BridgeError::Serialization(
                "content_type must produce valid MIME type".to_string(),
            ));
        }

        // Validate max payload size
        if self.max_payload_size == 0 {
            return Err(BridgeError::Serialization(
                "max_payload_size must be > 0".to_string(),
            ));
        }
        if self.max_payload_size > 10 * 1024 * 1024 {
            // 10MB hard limit
            return Err(BridgeError::Serialization(
                "max_payload_size must be <= 10MB".to_string(),
            ));
        }

        Ok(())
    }

    /// Create from environment variables with validation.
    pub fn from_env() -> Result<Self, BridgeError> {
        use l2_core::l1_contract::FixedAmountV1;
        use l2_core::L2HubId;

        let hub = std::env::var("L2_HUB_ID")
            .ok()
            .and_then(|s| match s.to_lowercase().as_str() {
                "fin" => Some(L2HubId::Fin),
                "data" => Some(L2HubId::Data),
                "m2m" => Some(L2HubId::M2m),
                "world" => Some(L2HubId::World),
                "bridge" => Some(L2HubId::Bridge),
                _ => None,
            })
            .unwrap_or(L2HubId::Fin);

        let content_type = std::env::var("L2_CONTENT_TYPE")
            .ok()
            .map(|s| match s.to_lowercase().as_str() {
                "binary" | "octet-stream" => ContentType::Binary,
                _ => ContentType::Json,
            })
            .unwrap_or(ContentType::Json);

        let fee = std::env::var("L2_BATCH_FEE")
            .ok()
            .and_then(|s| s.parse::<i128>().ok())
            .map(FixedAmountV1)
            .unwrap_or(FixedAmountV1(0));

        let max_payload_size = std::env::var("L2_MAX_PAYLOAD_SIZE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(MAX_PAYLOAD_SIZE);

        let config = Self {
            hub,
            content_type,
            fee,
            max_payload_size,
        };

        config.validate()?;
        Ok(config)
    }
}

/// Content type for batch payload encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ContentType {
    /// Canonical JSON encoding.
    #[default]
    Json,
    /// Canonical binary (bincode) encoding.
    Binary,
}

impl ContentType {
    pub fn as_mime(&self) -> &'static str {
        match self {
            ContentType::Json => BATCH_ENVELOPE_CONTENT_TYPE_JSON,
            ContentType::Binary => BATCH_ENVELOPE_CONTENT_TYPE_BINARY,
        }
    }
}

/// Result of building an L1 envelope from a batch.
#[derive(Debug, Clone)]
pub struct BridgeResult {
    /// The L2 batch envelope ready for L1 submission.
    pub l2_envelope: L2BatchEnvelopeV1,
    /// The batch envelope (internal format).
    pub batch_envelope: BatchEnvelope,
    /// The idempotency key (for tracking).
    pub idempotency_key_hex: String,
}

/// Build an `L2BatchEnvelopeV1` from a `Batch` and its computed hash.
///
/// This is the primary bridge function that:
/// 1. Computes tx hashes and tx_root
/// 2. Builds `BatchPayload`
/// 3. Creates unsigned `BatchEnvelope`
/// 4. Wraps in `HubPayloadEnvelopeV1`
/// 5. Constructs `L2BatchEnvelopeV1` with derived idempotency key
///
/// # Arguments
/// * `batch` - The batch to convert
/// * `batch_hash` - Precomputed canonical hash of the batch
/// * `prev_batch_hash` - Hash of the previous batch (zero hash for first)
/// * `config` - Bridge configuration
pub fn batch_to_l1_envelope(
    batch: &Batch,
    batch_hash: &Hash32,
    prev_batch_hash: &Hash32,
    config: &BridgeConfig,
) -> Result<BridgeResult, BridgeError> {
    // Step 1: Compute tx hashes and tx_root
    let tx_hashes: Vec<Hash32> = batch
        .txs
        .iter()
        .map(canonical_hash)
        .collect::<Result<Vec<_>, _>>()?;
    let tx_root = compute_tx_root(&tx_hashes);

    // Step 2: Compute total tx bytes
    let tx_bytes: u64 = batch.txs.iter().map(|tx| tx.payload.len() as u64).sum();

    // Step 3: Encode the batch payload bytes
    let payload_bytes = match config.content_type {
        ContentType::Json => {
            serde_json::to_vec(batch).map_err(|e| BridgeError::Serialization(e.to_string()))?
        }
        ContentType::Binary => canonical_encode(batch)?,
    };

    // Step 4: Build BatchPayload
    let tx_count = u32::try_from(batch.txs.len()).unwrap_or(u32::MAX);
    let batch_payload = BatchPayload::new(
        batch.chain_id,
        *batch_hash,
        *prev_batch_hash,
        batch.created_ms,
        tx_count,
        tx_bytes,
        tx_root,
        payload_bytes.clone(),
    );

    // Step 5: Create unsigned BatchEnvelope
    let batch_envelope = BatchEnvelope::new_unsigned(batch_payload)?;

    // Step 6: Build HubPayloadEnvelopeV1
    // **CANONICAL RULE**: The payload is ALWAYS canonical bytes (bincode), NOT JSON.
    // This ensures deterministic, version-stable byte representation for L1 settlement.
    let envelope_bytes = batch_envelope_payload_bytes(&batch_envelope)?;

    let hub_payload = HubPayloadEnvelopeV1 {
        contract_version: ContractVersion::V1,
        hub: config.hub,
        schema_version: BATCH_ENVELOPE_SCHEMA_VERSION.to_string(),
        // Content type reflects the canonical binary encoding
        content_type: BATCH_ENVELOPE_CONTENT_TYPE_BINARY.to_string(),
        payload: Base64Bytes(envelope_bytes),
    };

    // Validate hub payload
    hub_payload.validate()?;

    // Step 7: Build L2BatchEnvelopeV1
    let l2_envelope = L2BatchEnvelopeV1::new(
        config.hub,
        batch_hash.to_hex(),
        batch.batch_number,
        batch.txs.len() as u64,
        Some(tx_root.to_hex()),
        config.fee,
        hub_payload,
    )?;

    let idempotency_key_hex = hex::encode(l2_envelope.idempotency_key.as_bytes());

    Ok(BridgeResult {
        l2_envelope,
        batch_envelope,
        idempotency_key_hex,
    })
}

/// Build an `L2BatchEnvelopeV1` from a signed `BatchEnvelope`.
///
/// Use this when you already have a signed BatchEnvelope and want to
/// create the L1 submission envelope.
///
/// **CANONICAL RULE**: The payload is ALWAYS canonical bytes (bincode), NOT JSON.
/// This ensures deterministic, version-stable byte representation for L1 settlement.
///
/// # Arguments
/// * `envelope` - The (optionally signed) batch envelope
/// * `batch_number` - Sequence number for the batch
/// * `config` - Bridge configuration
pub fn batch_envelope_to_l1_envelope(
    envelope: &BatchEnvelope,
    batch_number: u64,
    config: &BridgeConfig,
) -> Result<L2BatchEnvelopeV1, BridgeError> {
    // **CANONICAL RULE**: Use canonical bytes (bincode), NOT JSON
    let envelope_bytes = batch_envelope_payload_bytes(envelope)?;

    let hub_payload = HubPayloadEnvelopeV1 {
        contract_version: ContractVersion::V1,
        hub: config.hub,
        schema_version: BATCH_ENVELOPE_SCHEMA_VERSION.to_string(),
        // Content type reflects the canonical binary encoding
        content_type: BATCH_ENVELOPE_CONTENT_TYPE_BINARY.to_string(),
        payload: Base64Bytes(envelope_bytes),
    };

    // Validate hub payload
    hub_payload.validate()?;

    // Use the envelope hash as batch_id
    let batch_id = hex::encode(envelope.envelope_hash);

    // Get tx_count and tx_root from the payload
    let tx_count = u64::from(envelope.payload.tx_count);
    let commitment = Some(envelope.payload.tx_root.to_hex());

    let l2_envelope = L2BatchEnvelopeV1::new(
        config.hub,
        batch_id,
        batch_number,
        tx_count,
        commitment,
        config.fee,
        hub_payload,
    )?;

    Ok(l2_envelope)
}

/// Compute the previous batch hash for linking.
///
/// Returns zero hash if this is the first batch.
pub fn get_prev_batch_hash(last_batch_hash: Option<&Hash32>) -> Hash32 {
    last_batch_hash
        .copied()
        .unwrap_or_else(BatchPayload::zero_hash)
}

/// Helper to get the current timestamp in milliseconds.
pub fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_else(|_| std::time::Duration::from_secs(0))
        .as_millis();
    u64::try_from(millis).unwrap_or(u64::MAX)
}

// ============== Canonical Payload Helpers ==============

/// Extract the canonical payload bytes from a BatchEnvelope.
///
/// **Canonical Rule**: The L1-settled payload is exactly:
/// - `canonical_encode(BatchEnvelope)` bytes (bincode, little-endian, fixed-int)
/// - NOT JSON
///
/// This ensures deterministic, version-stable byte representation.
///
/// # Usage
/// The returned bytes are what gets embedded into `HubPayloadEnvelopeV1.payload`
/// for contract-based settlement.
pub fn batch_envelope_payload_bytes(envelope: &BatchEnvelope) -> Result<Vec<u8>, BridgeError> {
    canonical_encode(envelope).map_err(BridgeError::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use l2_core::canonical::{ChainId, Tx};

    fn test_batch() -> Batch {
        Batch {
            chain_id: ChainId(1337),
            batch_number: 1,
            txs: vec![
                Tx {
                    chain_id: ChainId(1337),
                    nonce: 1,
                    from: "alice".to_string(),
                    payload: vec![1, 2, 3],
                },
                Tx {
                    chain_id: ChainId(1337),
                    nonce: 2,
                    from: "bob".to_string(),
                    payload: vec![4, 5, 6],
                },
            ],
            created_ms: 1_700_000_000_000,
        }
    }

    #[test]
    fn batch_to_l1_envelope_success() {
        let batch = test_batch();
        let batch_hash = canonical_hash(&batch).unwrap();
        let prev_hash = BatchPayload::zero_hash();
        let config = BridgeConfig::default();

        let result = batch_to_l1_envelope(&batch, &batch_hash, &prev_hash, &config).unwrap();

        // Verify envelope structure
        assert_eq!(result.l2_envelope.contract_version, ContractVersion::V1);
        assert_eq!(result.l2_envelope.hub, L2HubId::Fin);
        assert_eq!(result.l2_envelope.batch_id, batch_hash.to_hex());
        assert_eq!(result.l2_envelope.sequence, 1);
        assert_eq!(result.l2_envelope.tx_count, 2);
        assert!(result.l2_envelope.commitment.is_some());

        // Verify idempotency key is non-empty
        assert!(!result.idempotency_key_hex.is_empty());

        // Verify batch envelope
        assert_eq!(result.batch_envelope.version, "v1");
        assert_eq!(result.batch_envelope.payload.tx_count, 2);
    }

    #[test]
    fn batch_to_l1_envelope_deterministic() {
        let batch = test_batch();
        let batch_hash = canonical_hash(&batch).unwrap();
        let prev_hash = BatchPayload::zero_hash();
        let config = BridgeConfig::default();

        let result1 = batch_to_l1_envelope(&batch, &batch_hash, &prev_hash, &config).unwrap();
        let result2 = batch_to_l1_envelope(&batch, &batch_hash, &prev_hash, &config).unwrap();

        // Idempotency keys must match for same input
        assert_eq!(result1.idempotency_key_hex, result2.idempotency_key_hex);
        assert_eq!(
            result1.l2_envelope.idempotency_key,
            result2.l2_envelope.idempotency_key
        );
    }

    #[test]
    fn batch_envelope_to_l1_envelope_success() {
        let batch = test_batch();
        let batch_hash = canonical_hash(&batch).unwrap();
        let prev_hash = BatchPayload::zero_hash();

        // Build batch payload manually
        let tx_hashes: Vec<Hash32> = batch
            .txs
            .iter()
            .map(canonical_hash)
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        let tx_root = compute_tx_root(&tx_hashes);
        let payload_bytes = serde_json::to_vec(&batch).unwrap();

        let batch_payload = BatchPayload::new(
            batch.chain_id,
            batch_hash,
            prev_hash,
            batch.created_ms,
            2,
            6, // 3 + 3 bytes
            tx_root,
            payload_bytes,
        );

        let envelope = BatchEnvelope::new_unsigned(batch_payload).unwrap();
        let config = BridgeConfig::default();

        let l2_envelope = batch_envelope_to_l1_envelope(&envelope, 1, &config).unwrap();

        assert_eq!(l2_envelope.contract_version, ContractVersion::V1);
        assert_eq!(l2_envelope.hub, L2HubId::Fin);
        assert_eq!(l2_envelope.sequence, 1);
        assert_eq!(l2_envelope.tx_count, 2);
    }

    #[test]
    fn golden_idempotency_key() {
        // Fixed test input for golden key verification
        let batch = Batch {
            chain_id: ChainId(1),
            batch_number: 42,
            txs: vec![Tx {
                chain_id: ChainId(1),
                nonce: 1,
                from: "sequencer".to_string(),
                payload: vec![0xDE, 0xAD, 0xBE, 0xEF],
            }],
            created_ms: 1_700_000_000_000,
        };
        let batch_hash = canonical_hash(&batch).unwrap();
        let prev_hash = BatchPayload::zero_hash();
        let config = BridgeConfig {
            hub: L2HubId::Fin,
            content_type: ContentType::Json,
            fee: FixedAmountV1(0),
            max_payload_size: MAX_PAYLOAD_SIZE,
        };

        let result = batch_to_l1_envelope(&batch, &batch_hash, &prev_hash, &config).unwrap();

        // This is the golden idempotency key - must remain stable across versions
        // If this changes, it means the envelope derivation has changed (breaking change)
        //
        // NOTE: This key changed when we switched from JSON to canonical binary encoding
        // (canonical_encode) for the BatchEnvelope payload. This is intentional as
        // canonical binary provides deterministic, version-stable byte representation.
        assert_eq!(
            result.idempotency_key_hex,
            "bc97a01852f899e21e88b66a62acc25241159821132cbad34f0285e368bbc34e"
        );
    }

    #[test]
    fn content_type_mime_strings() {
        assert_eq!(ContentType::Json.as_mime(), "application/json");
        assert_eq!(ContentType::Binary.as_mime(), "application/octet-stream");
    }

    #[test]
    fn prev_batch_hash_zero_for_first() {
        let zero = get_prev_batch_hash(None);
        assert_eq!(zero, BatchPayload::zero_hash());

        let some_hash = Hash32([0xAA; 32]);
        let prev = get_prev_batch_hash(Some(&some_hash));
        assert_eq!(prev, some_hash);
    }

    // ========== Golden Vector Tests for Contract Settlement ===========

    /// Golden vector: Fixed batch produces stable BatchEnvelope bytes.
    ///
    /// This test ensures the canonical encoding of BatchEnvelope is deterministic
    /// and stable across versions. If this test fails, it indicates a breaking
    /// change in the settlement format.
    #[test]
    fn golden_batch_envelope_canonical_bytes() {
        // Fixed test batch
        let batch = Batch {
            chain_id: ChainId(1),
            batch_number: 100,
            txs: vec![
                Tx {
                    chain_id: ChainId(1),
                    nonce: 1,
                    from: "alice".to_string(),
                    payload: vec![0x01, 0x02, 0x03],
                },
                Tx {
                    chain_id: ChainId(1),
                    nonce: 2,
                    from: "bob".to_string(),
                    payload: vec![0x04, 0x05, 0x06],
                },
            ],
            created_ms: 1_700_000_000_000,
        };

        let batch_hash = canonical_hash(&batch).unwrap();
        let prev_hash = BatchPayload::zero_hash();
        let config = BridgeConfig::default();

        let result = batch_to_l1_envelope(&batch, &batch_hash, &prev_hash, &config).unwrap();

        // Extract canonical bytes
        let envelope_bytes = batch_envelope_payload_bytes(&result.batch_envelope).unwrap();

        // Golden hash of the envelope bytes (must remain stable)
        // Uses the same hash function as l2_core::canonical_hash_bytes
        let envelope_bytes_hash = l2_core::canonical_hash_bytes(&envelope_bytes);
        assert_eq!(
            hex::encode(envelope_bytes_hash),
            "e132dcf254f041adf57b73868feee2936088e1da30d9b638cc6e8c4d62f9ac89",
            "BatchEnvelope canonical bytes hash changed - breaking change!"
        );
    }

    /// Golden vector: L2BatchEnvelopeV1 JSON is stable.
    ///
    /// This test ensures the L2BatchEnvelopeV1 JSON structure is deterministic.
    #[test]
    fn golden_l2_envelope_json_stable() {
        let batch = Batch {
            chain_id: ChainId(1),
            batch_number: 50,
            txs: vec![Tx {
                chain_id: ChainId(1),
                nonce: 1,
                from: "test".to_string(),
                payload: vec![0xAB, 0xCD],
            }],
            created_ms: 1_700_000_000_000,
        };

        let batch_hash = canonical_hash(&batch).unwrap();
        let prev_hash = BatchPayload::zero_hash();
        let config = BridgeConfig::default();

        let result = batch_to_l1_envelope(&batch, &batch_hash, &prev_hash, &config).unwrap();

        // Serialize to JSON
        let json = serde_json::to_string(&result.l2_envelope).unwrap();

        // JSON should be deterministic
        let json2 = serde_json::to_string(&result.l2_envelope).unwrap();
        assert_eq!(json, json2);

        // Verify key fields are present (checking actual serde output format)
        assert!(
            json.contains("\"hub\":\"Fin\""),
            "Missing hub field: {}",
            json
        );
        assert!(
            json.contains("\"sequence\":50"),
            "Missing sequence field: {}",
            json
        );
        assert!(
            json.contains("\"tx_count\":1"),
            "Missing tx_count field: {}",
            json
        );
    }

    /// Test that same inputs always produce same idempotency key.
    #[test]
    fn idempotency_key_is_deterministic() {
        let batch = test_batch();
        let batch_hash = canonical_hash(&batch).unwrap();
        let prev_hash = BatchPayload::zero_hash();
        let config = BridgeConfig::default();

        // Build envelope multiple times
        let result1 = batch_to_l1_envelope(&batch, &batch_hash, &prev_hash, &config).unwrap();
        let result2 = batch_to_l1_envelope(&batch, &batch_hash, &prev_hash, &config).unwrap();
        let result3 = batch_to_l1_envelope(&batch, &batch_hash, &prev_hash, &config).unwrap();

        // All idempotency keys must match
        assert_eq!(result1.idempotency_key_hex, result2.idempotency_key_hex);
        assert_eq!(result2.idempotency_key_hex, result3.idempotency_key_hex);

        // Idempotency key must be 64 hex chars (32 bytes)
        assert_eq!(result1.idempotency_key_hex.len(), 64);
    }

    /// Test that different prev_batch_hash produces different idempotency key.
    #[test]
    fn different_prev_hash_different_idempotency_key() {
        let batch = test_batch();
        let batch_hash = canonical_hash(&batch).unwrap();
        let config = BridgeConfig::default();

        let prev_hash_zero = BatchPayload::zero_hash();
        let prev_hash_non_zero = Hash32([0x11; 32]);

        let result1 = batch_to_l1_envelope(&batch, &batch_hash, &prev_hash_zero, &config).unwrap();
        let result2 =
            batch_to_l1_envelope(&batch, &batch_hash, &prev_hash_non_zero, &config).unwrap();

        // Different prev_hash should produce different idempotency keys
        assert_ne!(result1.idempotency_key_hex, result2.idempotency_key_hex);
    }
}
