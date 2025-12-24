//! Bridge module for converting `BatchEnvelope` to `L2BatchEnvelopeV1`.
//!
//! This module provides the missing wiring between the batcher's internal
//! `BatchEnvelope` format and the versioned contract envelope `L2BatchEnvelopeV1`
//! that is submitted to L1 via `L1Client::submit_batch`.
#![forbid(unsafe_code)]

use l2_core::batch_envelope::{BatchEnvelope, BatchEnvelopeError, BatchPayload, compute_tx_root};
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

/// Configuration for bridge operations.
#[derive(Debug, Clone)]
pub struct BridgeConfig {
    /// L2 hub identifier.
    pub hub: L2HubId,
    /// Content type for payload encoding.
    pub content_type: ContentType,
    /// Protocol fee for batch submission (scaled integer, 0 for MVP).
    pub fee: FixedAmountV1,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            hub: L2HubId::Fin,
            content_type: ContentType::Json,
            fee: FixedAmountV1(0),
        }
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
    let tx_bytes: u64 = batch
        .txs
        .iter()
        .map(|tx| tx.payload.len() as u64)
        .sum();

    // Step 3: Encode the batch payload bytes
    let payload_bytes = match config.content_type {
        ContentType::Json => serde_json::to_vec(batch)
            .map_err(|e| BridgeError::Serialization(e.to_string()))?,
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
    // The payload for the hub envelope is the canonical bytes of the BatchEnvelope
    let envelope_bytes = serde_json::to_vec(&batch_envelope)
        .map_err(|e| BridgeError::Serialization(e.to_string()))?;

    let hub_payload = HubPayloadEnvelopeV1 {
        contract_version: ContractVersion::V1,
        hub: config.hub,
        schema_version: BATCH_ENVELOPE_SCHEMA_VERSION.to_string(),
        content_type: config.content_type.as_mime().to_string(),
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
/// # Arguments
/// * `envelope` - The (optionally signed) batch envelope
/// * `batch_number` - Sequence number for the batch
/// * `config` - Bridge configuration
pub fn batch_envelope_to_l1_envelope(
    envelope: &BatchEnvelope,
    batch_number: u64,
    config: &BridgeConfig,
) -> Result<L2BatchEnvelopeV1, BridgeError> {
    // Serialize the batch envelope as the hub payload
    let envelope_bytes = serde_json::to_vec(envelope)
        .map_err(|e| BridgeError::Serialization(e.to_string()))?;

    let hub_payload = HubPayloadEnvelopeV1 {
        contract_version: ContractVersion::V1,
        hub: config.hub,
        schema_version: BATCH_ENVELOPE_SCHEMA_VERSION.to_string(),
        content_type: BATCH_ENVELOPE_CONTENT_TYPE_JSON.to_string(),
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
    last_batch_hash.copied().unwrap_or_else(BatchPayload::zero_hash)
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
        };

        let result = batch_to_l1_envelope(&batch, &batch_hash, &prev_hash, &config).unwrap();

        // This is the golden idempotency key - must remain stable across versions
        // If this changes, it means the envelope derivation has changed (breaking change)
        assert_eq!(
            result.idempotency_key_hex,
            "0f4f0828bc53d38eeaa9e4bebcbea28a5fbd3a9ec7e0f08c7b94bd1077426676"
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
}
