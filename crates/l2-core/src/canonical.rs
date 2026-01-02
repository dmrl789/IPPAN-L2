#![allow(clippy::module_name_repetitions)]

use bincode::Options;
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use thiserror::Error;

/// Current version of the canonical encoding (u16).
pub const CANONICAL_ENCODING_VERSION: u16 = 1;

/// Chain identifier for IPPAN deployments.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChainId(pub u64);

/// 32-byte hash wrapper used across L2 primitives.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Hash32(pub [u8; 32]);

impl Hash32 {
    pub fn to_hex(self) -> String {
        hex::encode(self.0)
    }

    pub fn from_hex(hex_str: &str) -> Result<Self, CanonicalError> {
        let bytes = hex::decode(hex_str).map_err(CanonicalError::from_hex)?;
        let array: [u8; 32] = bytes
            .try_into()
            .map_err(|_| CanonicalError::from_hex("expected 32-byte hash"))?;
        Ok(Self(array))
    }
}

/// Transaction structure for the batching/bridge skeleton.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tx {
    pub chain_id: ChainId,
    pub nonce: u64,
    pub from: String,
    pub payload: Vec<u8>,
}

/// Batch structure containing canonical transactions and metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Batch {
    pub chain_id: ChainId,
    pub batch_number: u64,
    pub txs: Vec<Tx>,
    pub created_ms: u64,
}

/// Receipt emitted for processed transactions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    pub tx_hash: Hash32,
    pub success: bool,
    pub message: Option<String>,
}

/// Canonical serialization/hashing errors.
#[derive(Debug, Error)]
pub enum CanonicalError {
    #[error("serialization error: {0}")]
    Serialization(#[from] bincode::Error),
    #[error("hash decode error: {0}")]
    FromHex(String),
    #[error("encoding version mismatch: expected {1}, got {0}")]
    VersionMismatch(u16, u16),
}

impl CanonicalError {
    fn from_hex(err: impl ToString) -> Self {
        Self::FromHex(err.to_string())
    }
}

/// Canonical encoder options (fixed-int, little-endian, no trailing bytes).
fn encoder() -> impl Options {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .reject_trailing_bytes()
}

/// Serialize using canonical encoding.
/// Serialize using canonical encoding (includes version header).
pub fn canonical_encode<T: Serialize>(value: &T) -> Result<Vec<u8>, CanonicalError> {
    let mut bytes = Vec::new();
    // Prepend version (u16 little-endian)
    bytes.extend_from_slice(&CANONICAL_ENCODING_VERSION.to_le_bytes());
    // Append bincode serialization
    encoder()
        .serialize_into(&mut bytes, value)
        .map_err(CanonicalError::from)?;
    Ok(bytes)
}

/// Decode canonical bytes back into the target structure.
/// Decode canonical bytes back into the target structure (verifies version).
pub fn canonical_decode<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CanonicalError> {
    if bytes.len() < 2 {
        return Err(CanonicalError::Serialization(bincode::ErrorKind::SizeLimit.into()));
    }
    let (ver_bytes, payload) = bytes.split_at(2);
    let ver = u16::from_le_bytes(ver_bytes.try_into().unwrap());
    if ver != CANONICAL_ENCODING_VERSION {
        return Err(CanonicalError::VersionMismatch(ver, CANONICAL_ENCODING_VERSION));
    }
    encoder().deserialize(payload).map_err(CanonicalError::from)
}

/// Hash any serializable value using canonical encoding and BLAKE3.
pub fn canonical_hash<T: Serialize>(value: &T) -> Result<Hash32, CanonicalError> {
    let bytes = canonical_encode(value)?;
    Ok(Hash32(blake3::hash(&bytes).into()))
}

/// Hash raw bytes using BLAKE3.
pub fn canonical_hash_bytes(bytes: &[u8]) -> [u8; 32] {
    blake3::hash(bytes).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_encoding_is_stable() {
        let tx = Tx {
            chain_id: ChainId(1337),
            nonce: 42,
            from: "user-1".to_string(),
            payload: vec![0xAA, 0xBB, 0xCC],
        };
        let encoded = canonical_encode(&tx).expect("encode");
        assert_eq!(
            hex::encode(&encoded),
            "39050000000000002a000000000000000600000000000000757365722d310300000000000000aabbcc"
        );
    }

    #[test]
    fn canonical_hash_vector() {
        let batch = Batch {
            chain_id: ChainId(1337),
            batch_number: 7,
            txs: vec![Tx {
                chain_id: ChainId(1337),
                nonce: 1,
                from: "sequencer".to_string(),
                payload: vec![1, 2, 3, 4],
            }],
            created_ms: 1_735_000_000_000,
        };
        let hash = canonical_hash(&batch).expect("hash");
        assert_eq!(
            hash.to_hex(),
            "cec12e2979f5daef8010bfcec615f02f5158bca069e27f3de6a906d7215972c2"
        );
    }

    #[test]
    fn receipt_roundtrip() {
        let receipt = Receipt {
            tx_hash: Hash32([1u8; 32]),
            success: true,
            message: Some("accepted".to_string()),
        };
        let encoded = canonical_encode(&receipt).expect("encode");
        let decoded: Receipt = encoder().deserialize(&encoded).expect("decode");
        assert_eq!(decoded, receipt);
    }
}
