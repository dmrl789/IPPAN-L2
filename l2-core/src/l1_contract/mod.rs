//! L1 ↔ L2 integration contract (versioned, production-grade).
//!
//! This module defines the minimal, versioned "contract" between IPPAN CORE (L1)
//! and IPPAN-L2 (L2). It is **transport-agnostic**: runtime transports (HTTP, etc.)
//! are implemented as adapters that implement [`L1Client`].
//!
//! ## Design constraints
//! - **Contract-first**: stable types and invariants come first.
//! - **No floats**: money/amounts are fixed-point integers.
//! - **No hidden assumptions**: everything L2 needs from L1 must be explicit and validated.
//! - **Deterministic**: canonical encoding + stable hashes for replay safety and fixtures.
//! - **Versioned**: every public wire format is versioned and tested with golden fixtures.
#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]
#![deny(clippy::float_cmp)]
#![deny(clippy::cast_precision_loss)]
#![deny(clippy::cast_possible_truncation)]
#![deny(clippy::cast_possible_wrap)]
#![deny(clippy::cast_sign_loss)]
#![deny(clippy::disallowed_types)]

pub mod mock_client;

#[cfg(feature = "l1-http")]
pub mod http_client;

use crate::L2HubId;
use base64::Engine as _;
use blake3::Hasher;
use serde::{Deserialize, Serialize};

/// Contract version of the wire format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ContractVersion {
    /// v1 of the contract.
    V1,
}

impl ContractVersion {
    pub const fn as_str(self) -> &'static str {
        match self {
            ContractVersion::V1 => "v1",
        }
    }
}

/// Opaque network identifier for L1 (chain/network name or id).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NetworkId(pub String);

/// L1 chain height.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct L1Height(pub u64);

/// L1 time in microseconds (HashTimer™ semantics are L1-defined).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct L1TimeMicros(pub u64);

/// Opaque L1 transaction/commitment identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct L1TxId(pub String);

/// A stable, deterministic idempotency key for submit calls.
///
/// Serialized as base64url (no padding) to keep JSON compact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IdempotencyKey(pub [u8; 32]);

impl IdempotencyKey {
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Serialize for IdempotencyKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&base64url_nopad_encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for IdempotencyKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = base64url_nopad_decode_32(&s).map_err(serde::de::Error::custom)?;
        Ok(Self(bytes))
    }
}

/// Base64url (no padding) bytes wrapper for JSON-friendly payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Base64Bytes(pub Vec<u8>);

impl Serialize for Base64Bytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&base64url_nopad_encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for Base64Bytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(s.as_bytes())
            .map_err(serde::de::Error::custom)?;
        Ok(Self(bytes))
    }
}

/// Fixed-point amount scaled by 1e6 (6 decimals), represented as an integer.
///
/// This is the **wire** amount for contract v1 (do not use floats).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FixedAmountV1(pub i128);

/// L1 chain status returned by L1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct L1ChainStatus {
    pub network_id: NetworkId,
    pub height: L1Height,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finalized_height: Option<L1Height>,
    pub time_micros: L1TimeMicros,
}

/// Result of submitting an L2 batch envelope to L1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct L1SubmitResult {
    /// Whether the submission is accepted by L1.
    pub accepted: bool,
    /// Whether the request was already known (idempotent replay).
    #[serde(default)]
    pub already_known: bool,
    /// Optional L1 tx/commitment id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub l1_tx_id: Option<L1TxId>,
    /// Optional error code (L1-defined).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    /// Optional human-readable message.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

/// Inclusion/finality proof returned by L1 (opaque v1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct L1InclusionProof {
    pub l1_tx_id: L1TxId,
    pub height: L1Height,
    #[serde(default)]
    pub finalized: bool,
    /// Opaque proof bytes (format L1-defined).
    pub proof: Base64Bytes,
}

/// Hub payload envelope (hub -> fin-node) for submission to L1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HubPayloadEnvelopeV1 {
    pub contract_version: ContractVersion,
    pub hub: L2HubId,
    /// Hub payload schema version (hub-defined).
    pub schema_version: String,
    /// MIME-ish content type for payload bytes (e.g. "application/json").
    pub content_type: String,
    /// Payload bytes.
    pub payload: Base64Bytes,
}

/// Batch envelope submitted by fin-node (L2) to L1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct L2BatchEnvelopeV1 {
    pub contract_version: ContractVersion,
    pub hub: L2HubId,
    /// Opaque batch identifier (hub/node-defined).
    pub batch_id: String,
    /// Explicit monotonic sequence number within a hub (0 if unknown).
    pub sequence: u64,
    pub tx_count: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub commitment: Option<String>,
    /// Total protocol fee for the batch (scaled integer).
    pub fee: FixedAmountV1,
    /// Hub payload that produced this batch.
    pub payload: HubPayloadEnvelopeV1,
    /// Deterministic idempotency key derived from v1 invariants.
    pub idempotency_key: IdempotencyKey,
}

impl HubPayloadEnvelopeV1 {
    /// Deterministic canonical JSON bytes for hashing/signing/replay protection.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalizeError> {
        canonical_json_bytes(self)
    }

    pub fn canonical_hash_blake3(&self) -> Result<[u8; 32], CanonicalizeError> {
        let bytes = self.canonical_bytes()?;
        Ok(*blake3::hash(&bytes).as_bytes())
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        if self.schema_version.trim().is_empty() {
            return Err(ContractError::Invalid(
                "schema_version is empty".to_string(),
            ));
        }
        if self.content_type.trim().is_empty() {
            return Err(ContractError::Invalid("content_type is empty".to_string()));
        }
        Ok(())
    }
}

impl L2BatchEnvelopeV1 {
    /// Construct a v1 batch envelope and compute its idempotency key.
    pub fn new(
        hub: L2HubId,
        batch_id: impl Into<String>,
        sequence: u64,
        tx_count: u64,
        commitment: Option<String>,
        fee: FixedAmountV1,
        payload: HubPayloadEnvelopeV1,
    ) -> Result<Self, ContractError> {
        let batch_id = batch_id.into();
        let contract_version = ContractVersion::V1;
        let payload_hash = payload
            .canonical_hash_blake3()
            .map_err(|e| ContractError::Invalid(format!("payload canonicalization failed: {e}")))?;

        let idempotency_key =
            derive_idempotency_key_v1(contract_version, hub, &batch_id, sequence, &payload_hash);

        let env = Self {
            contract_version,
            hub,
            batch_id,
            sequence,
            tx_count,
            commitment,
            fee,
            payload,
            idempotency_key,
        };
        env.validate()?;
        Ok(env)
    }

    /// Deterministic canonical JSON bytes for hashing/signing/replay protection.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CanonicalizeError> {
        canonical_json_bytes(self)
    }

    pub fn canonical_hash_blake3(&self) -> Result<[u8; 32], CanonicalizeError> {
        let bytes = self.canonical_bytes()?;
        Ok(*blake3::hash(&bytes).as_bytes())
    }

    pub fn validate(&self) -> Result<(), ContractError> {
        if self.batch_id.trim().is_empty() {
            return Err(ContractError::Invalid("batch_id is empty".to_string()));
        }
        self.payload.validate()?;

        // Recompute idempotency key and require it matches.
        let payload_hash = self
            .payload
            .canonical_hash_blake3()
            .map_err(|e| ContractError::Invalid(format!("payload canonicalization failed: {e}")))?;
        let expected = derive_idempotency_key_v1(
            self.contract_version,
            self.hub,
            &self.batch_id,
            self.sequence,
            &payload_hash,
        );
        if expected != self.idempotency_key {
            return Err(ContractError::Invalid(
                "idempotency_key does not match v1 derivation rules".to_string(),
            ));
        }
        Ok(())
    }
}

/// Derive a v1 idempotency key:
/// `blake3("ippan-l1l2" || version || hub || batch_id || sequence || payload_hash)`
pub fn derive_idempotency_key_v1(
    version: ContractVersion,
    hub: L2HubId,
    batch_id: &str,
    sequence: u64,
    payload_hash: &[u8; 32],
) -> IdempotencyKey {
    let mut h = Hasher::new();
    h.update(b"ippan-l1l2");
    h.update(version.as_str().as_bytes());
    h.update(format!("{hub:?}").as_bytes());
    h.update(batch_id.as_bytes());
    h.update(sequence.to_be_bytes().as_slice());
    h.update(payload_hash);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    IdempotencyKey(out)
}

/// Required L1 capabilities expressed as a minimal, transport-agnostic client trait.
pub trait L1Client {
    fn chain_status(&self) -> Result<L1ChainStatus, L1ClientError>;
    fn submit_batch(&self, batch: &L2BatchEnvelopeV1) -> Result<L1SubmitResult, L1ClientError>;
    fn get_inclusion(
        &self,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Option<L1InclusionProof>, L1ClientError>;
    fn get_finality(&self, l1_tx_id: &L1TxId) -> Result<Option<L1InclusionProof>, L1ClientError>;
}

#[derive(Debug, thiserror::Error)]
pub enum L1ClientError {
    #[error("configuration error: {0}")]
    Config(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("serialization error: {0}")]
    Serialization(String),
}

#[derive(Debug, thiserror::Error)]
pub enum ContractError {
    #[error("{0}")]
    Invalid(String),
}

#[derive(Debug, thiserror::Error)]
pub enum CanonicalizeError {
    #[error("serde error: {0}")]
    Serde(String),
}

/// Deterministic canonical JSON bytes.
///
/// Implementation strategy:
/// - Convert to `serde_json::Value`
/// - Recursively sort object keys (stable)
/// - Serialize to compact JSON bytes
fn canonical_json_bytes<T: Serialize>(v: &T) -> Result<Vec<u8>, CanonicalizeError> {
    let mut value = serde_json::to_value(v).map_err(|e| CanonicalizeError::Serde(e.to_string()))?;
    canonical_json_sort_in_place(&mut value);
    serde_json::to_vec(&value).map_err(|e| CanonicalizeError::Serde(e.to_string()))
}

fn canonical_json_sort_in_place(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::Object(map) => {
            // Sort keys lexicographically and recurse.
            let mut entries: Vec<(String, serde_json::Value)> =
                std::mem::take(map).into_iter().collect();
            entries.sort_by(|(a, _), (b, _)| a.cmp(b));
            for (_, val) in entries.iter_mut() {
                canonical_json_sort_in_place(val);
            }
            let mut new_map = serde_json::Map::new();
            for (k, val) in entries {
                new_map.insert(k, val);
            }
            *map = new_map;
        }
        serde_json::Value::Array(arr) => {
            for x in arr.iter_mut() {
                canonical_json_sort_in_place(x);
            }
        }
        _ => {}
    }
}

fn base64url_nopad_encode(bytes: &[u8]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn base64url_nopad_decode_32(s: &str) -> Result<[u8; 32], String> {
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .map_err(|e| format!("invalid base64url: {e}"))?;
    if decoded.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", decoded.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(out)
}
