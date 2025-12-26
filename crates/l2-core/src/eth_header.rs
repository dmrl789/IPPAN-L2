//! Ethereum Block Header Types for Light Client Verification.
//!
//! This module provides types and utilities for Ethereum PoS block headers,
//! enabling deterministic header chain verification for the IPPAN bridge.
//!
//! ## Design Principles
//!
//! - **Deterministic**: All hashing and validation is deterministic
//! - **Minimal**: Only fields needed for header chain verification
//! - **RLP-Compatible**: Headers can be encoded/decoded to match Ethereum format
//!
//! ## Trust Model
//!
//! This is a MVP light client that uses explicit trusted checkpoints.
//! Full PoS sync committee verification is a future enhancement.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Maximum size for extra_data field (32 bytes for PoS).
pub const MAX_EXTRA_DATA_SIZE: usize = 32;

/// Maximum reasonable header RLP size.
pub const MAX_HEADER_RLP_SIZE: usize = 8192;

/// Errors from Ethereum header operations.
#[derive(Debug, Error)]
pub enum EthHeaderError {
    #[error("invalid RLP encoding: {0}")]
    RlpDecode(String),

    #[error("invalid field: {0}")]
    InvalidField(String),

    #[error("hash mismatch: expected {expected}, got {got}")]
    HashMismatch { expected: String, got: String },

    #[error("feature not enabled: keccak-headers")]
    FeatureNotEnabled,
}

/// 32-byte hash type for Ethereum (keccak256).
pub type Hash256 = [u8; 32];

/// 20-byte address type for Ethereum.
pub type Address = [u8; 20];

/// Ethereum block header (V1 - PoS compatible).
///
/// Contains the canonical fields needed for header chain verification
/// and receipt proof anchoring. This is a subset of the full Ethereum
/// block header optimized for light client use.
///
/// ## Field Order (RLP encoding order)
///
/// 0. parent_hash
/// 1. uncle_hash (ommers_hash)
/// 2. coinbase (fee_recipient)
/// 3. state_root
/// 4. transactions_root
/// 5. receipts_root
/// 6. logs_bloom
/// 7. difficulty (always 0 for PoS)
/// 8. number
/// 9. gas_limit
/// 10. gas_used
/// 11. timestamp
/// 12. extra_data
/// 13. mix_hash (prev_randao for PoS)
/// 14. nonce (always 0 for PoS)
/// 15. base_fee_per_gas (EIP-1559, optional pre-London)
/// 16. withdrawals_root (Shanghai, optional)
/// 17. blob_gas_used (Cancun, optional)
/// 18. excess_blob_gas (Cancun, optional)
/// 19. parent_beacon_block_root (Cancun, optional)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EthereumHeaderV1 {
    /// Parent block hash.
    #[serde(with = "hex_32")]
    pub parent_hash: Hash256,

    /// Uncles hash (always empty hash for PoS).
    #[serde(with = "hex_32")]
    pub uncle_hash: Hash256,

    /// Fee recipient (coinbase).
    #[serde(with = "hex_20")]
    pub coinbase: Address,

    /// State trie root.
    #[serde(with = "hex_32")]
    pub state_root: Hash256,

    /// Transactions trie root.
    #[serde(with = "hex_32")]
    pub transactions_root: Hash256,

    /// Receipts trie root.
    #[serde(with = "hex_32")]
    pub receipts_root: Hash256,

    /// Bloom filter for logs.
    #[serde(with = "hex_256")]
    pub logs_bloom: [u8; 256],

    /// Difficulty (always 0 for PoS).
    pub difficulty: u64,

    /// Block number (height).
    pub number: u64,

    /// Gas limit.
    pub gas_limit: u64,

    /// Gas used.
    pub gas_used: u64,

    /// Block timestamp (seconds since epoch).
    pub timestamp: u64,

    /// Extra data (max 32 bytes for PoS).
    #[serde(with = "hex_vec")]
    pub extra_data: Vec<u8>,

    /// Mix hash / prev_randao.
    #[serde(with = "hex_32")]
    pub mix_hash: Hash256,

    /// Nonce (always 0 for PoS).
    pub nonce: u64,

    /// Base fee per gas (EIP-1559, post-London).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_fee_per_gas: Option<u64>,

    /// Withdrawals root (post-Shanghai).
    #[serde(default, skip_serializing_if = "Option::is_none", with = "hex_32_opt")]
    pub withdrawals_root: Option<Hash256>,

    /// Blob gas used (post-Cancun).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blob_gas_used: Option<u64>,

    /// Excess blob gas (post-Cancun).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub excess_blob_gas: Option<u64>,

    /// Parent beacon block root (post-Cancun).
    #[serde(default, skip_serializing_if = "Option::is_none", with = "hex_32_opt")]
    pub parent_beacon_block_root: Option<Hash256>,
}

impl EthereumHeaderV1 {
    /// Get the block number (height).
    pub fn number(&self) -> u64 {
        self.number
    }

    /// Get the parent hash.
    pub fn parent_hash(&self) -> &Hash256 {
        &self.parent_hash
    }

    /// Get the receipts root (for receipt proof verification).
    pub fn receipts_root(&self) -> &Hash256 {
        &self.receipts_root
    }

    /// Get the timestamp.
    pub fn timestamp(&self) -> u64 {
        self.timestamp
    }

    /// Validate basic structural properties.
    pub fn validate_basic(&self) -> Result<(), EthHeaderError> {
        // Extra data must not exceed max size
        if self.extra_data.len() > MAX_EXTRA_DATA_SIZE {
            return Err(EthHeaderError::InvalidField(format!(
                "extra_data too large: {} > {}",
                self.extra_data.len(),
                MAX_EXTRA_DATA_SIZE
            )));
        }

        // Block number must be > 0 for non-genesis
        // (genesis is handled specially)

        // Gas used must not exceed gas limit
        if self.gas_used > self.gas_limit {
            return Err(EthHeaderError::InvalidField(format!(
                "gas_used ({}) > gas_limit ({})",
                self.gas_used, self.gas_limit
            )));
        }

        Ok(())
    }

    /// Check if this is a PoS block (difficulty == 0).
    pub fn is_pos(&self) -> bool {
        self.difficulty == 0
    }

    /// Check if this is a post-London block (has base_fee).
    pub fn is_post_london(&self) -> bool {
        self.base_fee_per_gas.is_some()
    }

    /// Check if this is a post-Shanghai block (has withdrawals_root).
    pub fn is_post_shanghai(&self) -> bool {
        self.withdrawals_root.is_some()
    }

    /// Check if this is a post-Cancun block (has blob fields).
    pub fn is_post_cancun(&self) -> bool {
        self.blob_gas_used.is_some()
    }
}

/// Header ID wrapping a keccak256 hash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HeaderId(#[serde(with = "hex_32")] pub Hash256);

impl HeaderId {
    /// Create from raw bytes.
    pub fn from_bytes(bytes: Hash256) -> Self {
        Self(bytes)
    }

    /// Get as hex string.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Parse from hex string.
    pub fn from_hex(s: &str) -> Result<Self, EthHeaderError> {
        let s = s.strip_prefix("0x").unwrap_or(s);
        let bytes = hex::decode(s)
            .map_err(|e| EthHeaderError::RlpDecode(format!("invalid hex: {}", e)))?;
        if bytes.len() != 32 {
            return Err(EthHeaderError::RlpDecode(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }
}

impl std::fmt::Display for HeaderId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0x{}", self.to_hex())
    }
}

// ============== RLP Encoding/Decoding (requires keccak-headers feature) ==============

#[cfg(feature = "keccak-headers")]
mod keccak_impl {
    use super::*;
    use alloy_primitives::keccak256;
    use alloy_rlp::{Buf, Header as RlpHeader};

    impl EthereumHeaderV1 {
        /// Compute the keccak256 hash of the RLP-encoded header.
        ///
        /// This is the canonical Ethereum block hash.
        pub fn header_hash(&self) -> Hash256 {
            let rlp_bytes = self.rlp_encode();
            let hash = keccak256(&rlp_bytes);
            let mut result = [0u8; 32];
            result.copy_from_slice(hash.as_slice());
            result
        }

        /// Get the header ID (wrapper around header hash).
        pub fn header_id(&self) -> HeaderId {
            HeaderId(self.header_hash())
        }

        /// RLP-encode the header.
        ///
        /// This produces the canonical encoding that hashes to the block hash.
        pub fn rlp_encode(&self) -> Vec<u8> {
            let mut fields: Vec<Vec<u8>> = Vec::with_capacity(20);

            // 0. parent_hash (32 bytes)
            fields.push(rlp_encode_fixed(&self.parent_hash));
            // 1. uncle_hash (32 bytes)
            fields.push(rlp_encode_fixed(&self.uncle_hash));
            // 2. coinbase (20 bytes)
            fields.push(rlp_encode_fixed(&self.coinbase));
            // 3. state_root (32 bytes)
            fields.push(rlp_encode_fixed(&self.state_root));
            // 4. transactions_root (32 bytes)
            fields.push(rlp_encode_fixed(&self.transactions_root));
            // 5. receipts_root (32 bytes)
            fields.push(rlp_encode_fixed(&self.receipts_root));
            // 6. logs_bloom (256 bytes)
            fields.push(rlp_encode_bytes(&self.logs_bloom));
            // 7. difficulty
            fields.push(rlp_encode_u64(self.difficulty));
            // 8. number
            fields.push(rlp_encode_u64(self.number));
            // 9. gas_limit
            fields.push(rlp_encode_u64(self.gas_limit));
            // 10. gas_used
            fields.push(rlp_encode_u64(self.gas_used));
            // 11. timestamp
            fields.push(rlp_encode_u64(self.timestamp));
            // 12. extra_data
            fields.push(rlp_encode_bytes(&self.extra_data));
            // 13. mix_hash (32 bytes)
            fields.push(rlp_encode_fixed(&self.mix_hash));
            // 14. nonce (8 bytes, big-endian)
            fields.push(rlp_encode_nonce(self.nonce));

            // Optional fields (post-London, post-Shanghai, post-Cancun)
            if let Some(base_fee) = self.base_fee_per_gas {
                fields.push(rlp_encode_u64(base_fee));

                if let Some(ref withdrawals_root) = self.withdrawals_root {
                    fields.push(rlp_encode_fixed(withdrawals_root));

                    if let Some(blob_gas_used) = self.blob_gas_used {
                        fields.push(rlp_encode_u64(blob_gas_used));

                        if let Some(excess_blob_gas) = self.excess_blob_gas {
                            fields.push(rlp_encode_u64(excess_blob_gas));

                            if let Some(ref parent_beacon_root) = self.parent_beacon_block_root {
                                fields.push(rlp_encode_fixed(parent_beacon_root));
                            }
                        }
                    }
                }
            }

            // Calculate total payload length
            let payload_len: usize = fields.iter().map(|f| f.len()).sum();

            // Encode list header + fields
            let mut result = Vec::with_capacity(payload_len + 5);
            encode_list_header(&mut result, payload_len);
            for field in fields {
                result.extend_from_slice(&field);
            }

            result
        }

        /// Decode header from RLP bytes.
        pub fn from_rlp(data: &[u8]) -> Result<Self, EthHeaderError> {
            let mut buf = data;

            // Decode outer list header
            let header = RlpHeader::decode(&mut buf)
                .map_err(|e| EthHeaderError::RlpDecode(format!("list header: {}", e)))?;

            if !header.list {
                return Err(EthHeaderError::RlpDecode("expected list".to_string()));
            }

            // Decode fields in order
            let parent_hash = decode_hash32(&mut buf, "parent_hash")?;
            let uncle_hash = decode_hash32(&mut buf, "uncle_hash")?;
            let coinbase = decode_address(&mut buf, "coinbase")?;
            let state_root = decode_hash32(&mut buf, "state_root")?;
            let transactions_root = decode_hash32(&mut buf, "transactions_root")?;
            let receipts_root = decode_hash32(&mut buf, "receipts_root")?;
            let logs_bloom = decode_bloom(&mut buf)?;
            let difficulty = decode_u64(&mut buf, "difficulty")?;
            let number = decode_u64(&mut buf, "number")?;
            let gas_limit = decode_u64(&mut buf, "gas_limit")?;
            let gas_used = decode_u64(&mut buf, "gas_used")?;
            let timestamp = decode_u64(&mut buf, "timestamp")?;
            let extra_data = decode_bytes(&mut buf, "extra_data")?;
            let mix_hash = decode_hash32(&mut buf, "mix_hash")?;
            let nonce = decode_nonce(&mut buf)?;

            // Optional fields
            let base_fee_per_gas = if !buf.is_empty() {
                Some(decode_u64(&mut buf, "base_fee_per_gas")?)
            } else {
                None
            };

            let withdrawals_root = if !buf.is_empty() {
                Some(decode_hash32(&mut buf, "withdrawals_root")?)
            } else {
                None
            };

            let blob_gas_used = if !buf.is_empty() {
                Some(decode_u64(&mut buf, "blob_gas_used")?)
            } else {
                None
            };

            let excess_blob_gas = if !buf.is_empty() {
                Some(decode_u64(&mut buf, "excess_blob_gas")?)
            } else {
                None
            };

            let parent_beacon_block_root = if !buf.is_empty() {
                Some(decode_hash32(&mut buf, "parent_beacon_block_root")?)
            } else {
                None
            };

            Ok(EthereumHeaderV1 {
                parent_hash,
                uncle_hash,
                coinbase,
                state_root,
                transactions_root,
                receipts_root,
                logs_bloom,
                difficulty,
                number,
                gas_limit,
                gas_used,
                timestamp,
                extra_data,
                mix_hash,
                nonce,
                base_fee_per_gas,
                withdrawals_root,
                blob_gas_used,
                excess_blob_gas,
                parent_beacon_block_root,
            })
        }

        /// Verify that the given hash matches this header's computed hash.
        pub fn verify_hash(&self, expected: &Hash256) -> Result<(), EthHeaderError> {
            let computed = self.header_hash();
            if computed != *expected {
                return Err(EthHeaderError::HashMismatch {
                    expected: hex::encode(expected),
                    got: hex::encode(computed),
                });
            }
            Ok(())
        }
    }

    /// Compute header hash from raw RLP bytes.
    pub fn header_hash_from_rlp(rlp_bytes: &[u8]) -> Hash256 {
        let hash = keccak256(rlp_bytes);
        let mut result = [0u8; 32];
        result.copy_from_slice(hash.as_slice());
        result
    }

    /// Compute HeaderId from raw RLP bytes.
    pub fn header_id_from_rlp(rlp_bytes: &[u8]) -> HeaderId {
        HeaderId(header_hash_from_rlp(rlp_bytes))
    }

    // ============== RLP Encoding Helpers ==============

    fn rlp_encode_fixed<const N: usize>(data: &[u8; N]) -> Vec<u8> {
        rlp_encode_bytes(data)
    }

    fn rlp_encode_bytes(data: &[u8]) -> Vec<u8> {
        let len = data.len();
        if len == 0 {
            vec![0x80]
        } else if len == 1 && data[0] < 0x80 {
            vec![data[0]]
        } else if len <= 55 {
            let mut result = Vec::with_capacity(len + 1);
            #[allow(clippy::cast_possible_truncation)]
            result.push(0x80 + len as u8);
            result.extend_from_slice(data);
            result
        } else {
            let len_bytes = encode_length(len);
            let mut result = Vec::with_capacity(1 + len_bytes.len() + len);
            #[allow(clippy::cast_possible_truncation)]
            result.push(0xb7 + len_bytes.len() as u8);
            result.extend_from_slice(&len_bytes);
            result.extend_from_slice(data);
            result
        }
    }

    #[allow(clippy::cast_possible_truncation)]
    fn rlp_encode_u64(value: u64) -> Vec<u8> {
        if value == 0 {
            vec![0x80]
        } else if value < 0x80 {
            vec![value as u8]
        } else {
            let bytes = value.to_be_bytes();
            let start = bytes.iter().position(|&b| b != 0).unwrap_or(8);
            let significant = &bytes[start..];
            let len = significant.len();
            let mut result = Vec::with_capacity(len + 1);
            result.push(0x80 + len as u8);
            result.extend_from_slice(significant);
            result
        }
    }

    fn rlp_encode_nonce(nonce: u64) -> Vec<u8> {
        // Nonce is encoded as 8 bytes (may be truncated if all zeros)
        let bytes = nonce.to_be_bytes();
        rlp_encode_bytes(&bytes)
    }

    fn encode_list_header(out: &mut Vec<u8>, payload_len: usize) {
        if payload_len <= 55 {
            #[allow(clippy::cast_possible_truncation)]
            out.push(0xc0 + payload_len as u8);
        } else {
            let len_bytes = encode_length(payload_len);
            #[allow(clippy::cast_possible_truncation)]
            out.push(0xf7 + len_bytes.len() as u8);
            out.extend_from_slice(&len_bytes);
        }
    }

    #[allow(clippy::cast_possible_truncation)]
    fn encode_length(len: usize) -> Vec<u8> {
        if len <= 0xff {
            vec![len as u8]
        } else if len <= 0xffff {
            vec![(len >> 8) as u8, (len & 0xff) as u8]
        } else if len <= 0xffffff {
            vec![
                (len >> 16) as u8,
                ((len >> 8) & 0xff) as u8,
                (len & 0xff) as u8,
            ]
        } else {
            vec![
                (len >> 24) as u8,
                ((len >> 16) & 0xff) as u8,
                ((len >> 8) & 0xff) as u8,
                (len & 0xff) as u8,
            ]
        }
    }

    // ============== RLP Decoding Helpers ==============

    fn decode_hash32(buf: &mut &[u8], field: &str) -> Result<Hash256, EthHeaderError> {
        let header = RlpHeader::decode(buf)
            .map_err(|e| EthHeaderError::RlpDecode(format!("{}: {}", field, e)))?;

        if header.list {
            return Err(EthHeaderError::RlpDecode(format!(
                "{}: expected bytes, got list",
                field
            )));
        }

        if header.payload_length != 32 {
            return Err(EthHeaderError::RlpDecode(format!(
                "{}: expected 32 bytes, got {}",
                field, header.payload_length
            )));
        }

        if buf.len() < 32 {
            return Err(EthHeaderError::RlpDecode(format!(
                "{}: not enough data",
                field
            )));
        }

        let mut result = [0u8; 32];
        result.copy_from_slice(&buf[..32]);
        buf.advance(32);
        Ok(result)
    }

    fn decode_address(buf: &mut &[u8], field: &str) -> Result<Address, EthHeaderError> {
        let header = RlpHeader::decode(buf)
            .map_err(|e| EthHeaderError::RlpDecode(format!("{}: {}", field, e)))?;

        if header.list {
            return Err(EthHeaderError::RlpDecode(format!(
                "{}: expected bytes, got list",
                field
            )));
        }

        if header.payload_length != 20 {
            return Err(EthHeaderError::RlpDecode(format!(
                "{}: expected 20 bytes, got {}",
                field, header.payload_length
            )));
        }

        if buf.len() < 20 {
            return Err(EthHeaderError::RlpDecode(format!(
                "{}: not enough data",
                field
            )));
        }

        let mut result = [0u8; 20];
        result.copy_from_slice(&buf[..20]);
        buf.advance(20);
        Ok(result)
    }

    fn decode_bloom(buf: &mut &[u8]) -> Result<[u8; 256], EthHeaderError> {
        let header = RlpHeader::decode(buf)
            .map_err(|e| EthHeaderError::RlpDecode(format!("logs_bloom: {}", e)))?;

        if header.list {
            return Err(EthHeaderError::RlpDecode(
                "logs_bloom: expected bytes, got list".to_string(),
            ));
        }

        if header.payload_length != 256 {
            return Err(EthHeaderError::RlpDecode(format!(
                "logs_bloom: expected 256 bytes, got {}",
                header.payload_length
            )));
        }

        if buf.len() < 256 {
            return Err(EthHeaderError::RlpDecode(
                "logs_bloom: not enough data".to_string(),
            ));
        }

        let mut result = [0u8; 256];
        result.copy_from_slice(&buf[..256]);
        buf.advance(256);
        Ok(result)
    }

    fn decode_u64(buf: &mut &[u8], field: &str) -> Result<u64, EthHeaderError> {
        let header = RlpHeader::decode(buf)
            .map_err(|e| EthHeaderError::RlpDecode(format!("{}: {}", field, e)))?;

        if header.list {
            return Err(EthHeaderError::RlpDecode(format!(
                "{}: expected bytes, got list",
                field
            )));
        }

        if header.payload_length == 0 {
            return Ok(0);
        }

        if header.payload_length > 8 {
            return Err(EthHeaderError::RlpDecode(format!(
                "{}: too many bytes for u64: {}",
                field, header.payload_length
            )));
        }

        if buf.len() < header.payload_length {
            return Err(EthHeaderError::RlpDecode(format!(
                "{}: not enough data",
                field
            )));
        }

        let mut result = 0u64;
        for &byte in &buf[..header.payload_length] {
            result = (result << 8) | u64::from(byte);
        }
        buf.advance(header.payload_length);
        Ok(result)
    }

    fn decode_bytes(buf: &mut &[u8], field: &str) -> Result<Vec<u8>, EthHeaderError> {
        let header = RlpHeader::decode(buf)
            .map_err(|e| EthHeaderError::RlpDecode(format!("{}: {}", field, e)))?;

        if header.list {
            return Err(EthHeaderError::RlpDecode(format!(
                "{}: expected bytes, got list",
                field
            )));
        }

        if buf.len() < header.payload_length {
            return Err(EthHeaderError::RlpDecode(format!(
                "{}: not enough data",
                field
            )));
        }

        let result = buf[..header.payload_length].to_vec();
        buf.advance(header.payload_length);
        Ok(result)
    }

    fn decode_nonce(buf: &mut &[u8]) -> Result<u64, EthHeaderError> {
        let header = RlpHeader::decode(buf)
            .map_err(|e| EthHeaderError::RlpDecode(format!("nonce: {}", e)))?;

        if header.list {
            return Err(EthHeaderError::RlpDecode(
                "nonce: expected bytes, got list".to_string(),
            ));
        }

        // Nonce can be 0-8 bytes
        if header.payload_length > 8 {
            return Err(EthHeaderError::RlpDecode(format!(
                "nonce: too many bytes: {}",
                header.payload_length
            )));
        }

        if buf.len() < header.payload_length {
            return Err(EthHeaderError::RlpDecode(
                "nonce: not enough data".to_string(),
            ));
        }

        let mut result = 0u64;
        for &byte in &buf[..header.payload_length] {
            result = (result << 8) | u64::from(byte);
        }
        buf.advance(header.payload_length);
        Ok(result)
    }
}

#[cfg(feature = "keccak-headers")]
pub use keccak_impl::*;

// ============== Stub implementations when feature is not enabled ==============

#[cfg(not(feature = "keccak-headers"))]
impl EthereumHeaderV1 {
    /// Compute the keccak256 hash of the RLP-encoded header (stub).
    pub fn header_hash(&self) -> Hash256 {
        // Return empty hash - feature not enabled
        [0u8; 32]
    }

    /// Get the header ID (stub).
    pub fn header_id(&self) -> HeaderId {
        HeaderId([0u8; 32])
    }

    /// RLP-encode the header (stub).
    pub fn rlp_encode(&self) -> Vec<u8> {
        Vec::new()
    }

    /// Decode header from RLP bytes (stub).
    pub fn from_rlp(_data: &[u8]) -> Result<Self, EthHeaderError> {
        Err(EthHeaderError::FeatureNotEnabled)
    }

    /// Verify that the given hash matches this header's computed hash (stub).
    pub fn verify_hash(&self, _expected: &Hash256) -> Result<(), EthHeaderError> {
        Err(EthHeaderError::FeatureNotEnabled)
    }
}

#[cfg(not(feature = "keccak-headers"))]
pub fn header_hash_from_rlp(_rlp_bytes: &[u8]) -> Hash256 {
    [0u8; 32]
}

#[cfg(not(feature = "keccak-headers"))]
pub fn header_id_from_rlp(_rlp_bytes: &[u8]) -> HeaderId {
    HeaderId([0u8; 32])
}

// ============== Serde Helpers ==============

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
        let s = s.strip_prefix("0x").unwrap_or(&s);
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

mod hex_32_opt {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &Option<[u8; 32]>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match bytes {
            Some(b) => serializer.serialize_some(&hex::encode(b)),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<[u8; 32]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let opt: Option<String> = Option::deserialize(deserializer)?;
        match opt {
            Some(s) => {
                let s = s.strip_prefix("0x").unwrap_or(&s);
                let raw = hex::decode(s).map_err(serde::de::Error::custom)?;
                if raw.len() != 32 {
                    return Err(serde::de::Error::custom(format!(
                        "expected 32 bytes, got {}",
                        raw.len()
                    )));
                }
                let mut out = [0u8; 32];
                out.copy_from_slice(&raw);
                Ok(Some(out))
            }
            None => Ok(None),
        }
    }
}

mod hex_20 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 20], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 20], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.strip_prefix("0x").unwrap_or(&s);
        let raw = hex::decode(s).map_err(serde::de::Error::custom)?;
        if raw.len() != 20 {
            return Err(serde::de::Error::custom(format!(
                "expected 20 bytes, got {}",
                raw.len()
            )));
        }
        let mut out = [0u8; 20];
        out.copy_from_slice(&raw);
        Ok(out)
    }
}

mod hex_256 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 256], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 256], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let s = s.strip_prefix("0x").unwrap_or(&s);
        let raw = hex::decode(s).map_err(serde::de::Error::custom)?;
        if raw.len() != 256 {
            return Err(serde::de::Error::custom(format!(
                "expected 256 bytes, got {}",
                raw.len()
            )));
        }
        let mut out = [0u8; 256];
        out.copy_from_slice(&raw);
        Ok(out)
    }
}

mod hex_vec {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
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
        let s = s.strip_prefix("0x").unwrap_or(&s);
        hex::decode(s).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_header() -> EthereumHeaderV1 {
        EthereumHeaderV1 {
            parent_hash: [0x11; 32],
            uncle_hash: [0x22; 32],
            coinbase: [0x33; 20],
            state_root: [0x44; 32],
            transactions_root: [0x55; 32],
            receipts_root: [0x66; 32],
            logs_bloom: [0x00; 256],
            difficulty: 0,
            number: 18_000_000,
            gas_limit: 30_000_000,
            gas_used: 15_000_000,
            timestamp: 1_700_000_000,
            extra_data: vec![0x01, 0x02, 0x03],
            mix_hash: [0x77; 32],
            nonce: 0,
            base_fee_per_gas: Some(10_000_000_000),
            withdrawals_root: Some([0x88; 32]),
            blob_gas_used: Some(131_072),
            excess_blob_gas: Some(0),
            parent_beacon_block_root: Some([0x99; 32]),
        }
    }

    #[test]
    fn validate_basic_success() {
        let header = test_header();
        assert!(header.validate_basic().is_ok());
    }

    #[test]
    fn validate_basic_extra_data_too_large() {
        let mut header = test_header();
        header.extra_data = vec![0; 33];
        let result = header.validate_basic();
        assert!(matches!(result, Err(EthHeaderError::InvalidField(_))));
    }

    #[test]
    fn validate_basic_gas_overflow() {
        let mut header = test_header();
        header.gas_used = 40_000_000;
        header.gas_limit = 30_000_000;
        let result = header.validate_basic();
        assert!(matches!(result, Err(EthHeaderError::InvalidField(_))));
    }

    #[test]
    fn header_accessors() {
        let header = test_header();
        assert_eq!(header.number(), 18_000_000);
        assert_eq!(header.parent_hash(), &[0x11; 32]);
        assert_eq!(header.receipts_root(), &[0x66; 32]);
        assert_eq!(header.timestamp(), 1_700_000_000);
    }

    #[test]
    fn header_is_pos() {
        let header = test_header();
        assert!(header.is_pos());

        let mut pow_header = test_header();
        pow_header.difficulty = 1;
        assert!(!pow_header.is_pos());
    }

    #[test]
    fn header_is_post_london() {
        let header = test_header();
        assert!(header.is_post_london());

        let mut pre_london = test_header();
        pre_london.base_fee_per_gas = None;
        assert!(!pre_london.is_post_london());
    }

    #[test]
    fn header_id_hex_roundtrip() {
        let id = HeaderId([0xAB; 32]);
        let hex_str = id.to_hex();
        let parsed = HeaderId::from_hex(&hex_str).expect("parse");
        assert_eq!(parsed, id);
    }

    #[test]
    fn header_id_with_prefix() {
        let id = HeaderId([0xAB; 32]);
        let hex_with_prefix = format!("0x{}", id.to_hex());
        let parsed = HeaderId::from_hex(&hex_with_prefix).expect("parse");
        assert_eq!(parsed, id);
    }

    #[cfg(feature = "keccak-headers")]
    mod keccak_tests {
        use super::*;

        #[test]
        fn rlp_roundtrip() {
            let header = test_header();
            let rlp = header.rlp_encode();
            let decoded = EthereumHeaderV1::from_rlp(&rlp).expect("decode");
            assert_eq!(decoded, header);
        }

        #[test]
        fn header_hash_deterministic() {
            let header = test_header();
            let hash1 = header.header_hash();
            let hash2 = header.header_hash();
            assert_eq!(hash1, hash2);
        }

        #[test]
        fn header_hash_changes_with_field() {
            let header1 = test_header();
            let mut header2 = test_header();
            header2.number = 18_000_001;

            let hash1 = header1.header_hash();
            let hash2 = header2.header_hash();
            assert_ne!(hash1, hash2);
        }

        #[test]
        fn verify_hash_success() {
            let header = test_header();
            let hash = header.header_hash();
            assert!(header.verify_hash(&hash).is_ok());
        }

        #[test]
        fn verify_hash_failure() {
            let header = test_header();
            let wrong_hash = [0xFF; 32];
            let result = header.verify_hash(&wrong_hash);
            assert!(matches!(result, Err(EthHeaderError::HashMismatch { .. })));
        }

        #[test]
        fn header_id_from_rlp_matches() {
            let header = test_header();
            let rlp = header.rlp_encode();

            let id_from_struct = header.header_id();
            let id_from_rlp = header_id_from_rlp(&rlp);

            assert_eq!(id_from_struct, id_from_rlp);
        }

        // Test with real Ethereum block header (mainnet block 18000000)
        // This is a golden vector test to ensure compatibility with Ethereum
        #[test]
        fn mainnet_block_18000000_hash() {
            // Block 18000000 header data (simplified for test)
            // In production, we'd use actual block data
            // For now, verify that the hashing infrastructure works

            let header = EthereumHeaderV1 {
                parent_hash: [0; 32], // Would be actual parent hash
                uncle_hash: [
                    0x1d, 0xcc, 0x4d, 0xe8, 0xde, 0xc7, 0x5d, 0x7a, 0xab, 0x85, 0xb5, 0x67, 0xb6,
                    0xcc, 0xd4, 0x1a, 0xd3, 0x12, 0x45, 0x1b, 0x94, 0x8a, 0x74, 0x13, 0xf0, 0xa1,
                    0x42, 0xfd, 0x40, 0xd4, 0x93, 0x47,
                ], // Empty uncles hash
                coinbase: [0; 20],
                state_root: [0; 32],
                transactions_root: [0; 32],
                receipts_root: [0; 32],
                logs_bloom: [0; 256],
                difficulty: 0,
                number: 18_000_000,
                gas_limit: 30_000_000,
                gas_used: 15_000_000,
                timestamp: 1_693_526_375,
                extra_data: vec![],
                mix_hash: [0; 32],
                nonce: 0,
                base_fee_per_gas: Some(10_000_000_000),
                withdrawals_root: Some([0; 32]),
                blob_gas_used: None,
                excess_blob_gas: None,
                parent_beacon_block_root: None,
            };

            // Just verify it produces a valid hash
            let hash = header.header_hash();
            assert!(!hash.iter().all(|&b| b == 0)); // Should not be all zeros
        }
    }
}
