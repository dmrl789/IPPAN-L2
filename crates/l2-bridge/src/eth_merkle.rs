//! Ethereum Receipt Merkle Patricia Trie Proof Verification.
//!
//! This module provides deterministic verification of Ethereum receipt inclusion proofs
//! using Merkle Patricia Trie (MPT) proofs.
//!
//! ## Verification Steps
//!
//! 1. Verify block header hash matches `block_hash` (keccak256 of header RLP)
//! 2. Extract `receipts_root` from the block header
//! 3. Verify receipt RLP is included at key `rlp_encode(tx_index)` using MPT proof
//! 4. Decode receipt and extract the log at `log_index`
//! 5. Verify log matches expected filters (contract, topic0, data_hash)
//!
//! ## Trust Model
//!
//! This proof eliminates trust in attestors but still requires policy decisions about
//! block finality. The verifier accepts a block header as-is; confirming that header
//! is valid/final is a policy decision (confirmations count, light client, etc.).
//!
//! ## Dependencies
//!
//! Requires the `merkle-proofs` feature to be enabled.

#[cfg(feature = "merkle-proofs")]
mod implementation {
    use alloy_primitives::keccak256;
    use alloy_rlp::{Buf, Header as RlpHeader};
    use l2_core::EthReceiptMerkleProofV1;
    use thiserror::Error;

    /// Errors from Ethereum Merkle proof verification.
    #[derive(Debug, Error)]
    pub enum EthMerkleVerifyError {
        #[error("block hash mismatch: expected {expected}, got {got}")]
        BlockHashMismatch { expected: String, got: String },

        #[error("failed to decode block header: {0}")]
        HeaderDecodeFailed(String),

        #[error("receipts root not found in header")]
        ReceiptsRootNotFound,

        #[error("MPT proof verification failed: {0}")]
        MptProofFailed(String),

        #[error("failed to decode receipt: {0}")]
        ReceiptDecodeFailed(String),

        #[error("log index {index} out of bounds (receipt has {count} logs)")]
        LogIndexOutOfBounds { index: u32, count: usize },

        #[error("contract address mismatch: expected {expected}, got {got}")]
        ContractMismatch { expected: String, got: String },

        #[error("topic0 mismatch: expected {expected}, got {got}")]
        Topic0Mismatch { expected: String, got: String },

        #[error("data hash mismatch: expected {expected}, got {got}")]
        DataHashMismatch { expected: String, got: String },

        #[error("RLP decode error: {0}")]
        RlpDecode(String),

        #[error("empty proof nodes")]
        EmptyProofNodes,
    }

    /// Result of successful Merkle proof verification.
    #[derive(Debug, Clone)]
    pub struct MerkleVerifiedEvent {
        /// Block hash where the event was included.
        pub block_hash: [u8; 32],
        /// Block number.
        pub block_number: u64,
        /// Transaction hash.
        pub tx_hash: [u8; 32],
        /// Transaction index in block.
        pub tx_index: u32,
        /// Log index in receipt.
        pub log_index: u32,
        /// Contract address that emitted the event.
        pub contract: [u8; 20],
        /// Event signature (topic0).
        pub topic0: [u8; 32],
        /// Blake3 hash of event data.
        pub data_hash: [u8; 32],
    }

    /// Ethereum block header (minimal fields needed for verification).
    #[derive(Debug)]
    pub(crate) struct BlockHeader {
        pub(crate) receipts_root: [u8; 32],
    }

    impl BlockHeader {
        /// Decode a block header from RLP.
        /// We only need the receipts_root (field index 5 in the header).
        pub(crate) fn from_rlp(data: &[u8]) -> Result<Self, EthMerkleVerifyError> {
            let mut buf = data;

            // Decode the outer list header
            let header = RlpHeader::decode(&mut buf)
                .map_err(|e| EthMerkleVerifyError::HeaderDecodeFailed(e.to_string()))?;

            if !header.list {
                return Err(EthMerkleVerifyError::HeaderDecodeFailed(
                    "expected list".to_string(),
                ));
            }

            // Block header fields (in order):
            // 0: parentHash, 1: uncleHash, 2: coinbase, 3: stateRoot,
            // 4: transactionsRoot, 5: receiptsRoot, 6: logsBloom, 7: difficulty, ...
            // We need to skip to field 5 (receiptsRoot)

            for i in 0..6 {
                let field_header = RlpHeader::decode(&mut buf).map_err(|e| {
                    EthMerkleVerifyError::HeaderDecodeFailed(format!(
                        "failed to decode field {}: {}",
                        i, e
                    ))
                })?;

                if i == 5 {
                    // This is receiptsRoot
                    if field_header.list {
                        return Err(EthMerkleVerifyError::HeaderDecodeFailed(
                            "receiptsRoot should not be a list".to_string(),
                        ));
                    }
                    let payload_len = field_header.payload_length;
                    if payload_len != 32 {
                        return Err(EthMerkleVerifyError::HeaderDecodeFailed(format!(
                            "receiptsRoot should be 32 bytes, got {}",
                            payload_len
                        )));
                    }
                    if buf.len() < 32 {
                        return Err(EthMerkleVerifyError::HeaderDecodeFailed(
                            "not enough data for receiptsRoot".to_string(),
                        ));
                    }
                    let mut receipts_root = [0u8; 32];
                    receipts_root.copy_from_slice(&buf[..32]);
                    return Ok(BlockHeader { receipts_root });
                } else {
                    // Skip this field
                    if field_header.list {
                        // For lists, we need to skip payload_length bytes
                        buf.advance(field_header.payload_length);
                    } else {
                        // For strings, we need to skip payload_length bytes
                        buf.advance(field_header.payload_length);
                    }
                }
            }

            Err(EthMerkleVerifyError::ReceiptsRootNotFound)
        }
    }

    /// Ethereum log entry.
    #[derive(Debug)]
    struct Log {
        address: [u8; 20],
        topics: Vec<[u8; 32]>,
        data: Vec<u8>,
    }

    /// Ethereum receipt (minimal fields needed for verification).
    #[derive(Debug)]
    struct Receipt {
        logs: Vec<Log>,
    }

    impl Receipt {
        /// Decode a receipt from RLP.
        /// Handles both legacy and EIP-2718 typed receipts.
        fn from_rlp(data: &[u8]) -> Result<Self, EthMerkleVerifyError> {
            let mut buf = data;

            // EIP-2718: typed transactions have a type prefix byte (0x01, 0x02, 0x03)
            // If the first byte is < 0x80, it's a type prefix
            if !buf.is_empty() && buf[0] < 0x80 {
                // Skip the type byte
                buf = &buf[1..];
            }

            // Now decode the receipt list: [status, cumulativeGasUsed, logsBloom, logs]
            let header = RlpHeader::decode(&mut buf)
                .map_err(|e| EthMerkleVerifyError::ReceiptDecodeFailed(e.to_string()))?;

            if !header.list {
                return Err(EthMerkleVerifyError::ReceiptDecodeFailed(
                    "expected list".to_string(),
                ));
            }

            // Skip status (field 0)
            let field0 = RlpHeader::decode(&mut buf).map_err(|e| {
                EthMerkleVerifyError::ReceiptDecodeFailed(format!("failed to decode status: {}", e))
            })?;
            buf.advance(field0.payload_length);

            // Skip cumulativeGasUsed (field 1)
            let field1 = RlpHeader::decode(&mut buf).map_err(|e| {
                EthMerkleVerifyError::ReceiptDecodeFailed(format!(
                    "failed to decode cumulativeGasUsed: {}",
                    e
                ))
            })?;
            buf.advance(field1.payload_length);

            // Skip logsBloom (field 2)
            let field2 = RlpHeader::decode(&mut buf).map_err(|e| {
                EthMerkleVerifyError::ReceiptDecodeFailed(format!(
                    "failed to decode logsBloom: {}",
                    e
                ))
            })?;
            buf.advance(field2.payload_length);

            // Decode logs (field 3)
            let logs_header = RlpHeader::decode(&mut buf).map_err(|e| {
                EthMerkleVerifyError::ReceiptDecodeFailed(format!(
                    "failed to decode logs list: {}",
                    e
                ))
            })?;

            if !logs_header.list {
                return Err(EthMerkleVerifyError::ReceiptDecodeFailed(
                    "logs should be a list".to_string(),
                ));
            }

            let logs_end = buf.len() - logs_header.payload_length;
            let mut logs = Vec::new();

            while buf.len() > logs_end {
                let log = Self::decode_log(&mut buf)?;
                logs.push(log);
            }

            Ok(Receipt { logs })
        }

        fn decode_log(buf: &mut &[u8]) -> Result<Log, EthMerkleVerifyError> {
            // Log: [address, topics, data]
            let header = RlpHeader::decode(buf).map_err(|e| {
                EthMerkleVerifyError::ReceiptDecodeFailed(format!(
                    "failed to decode log list: {}",
                    e
                ))
            })?;

            if !header.list {
                return Err(EthMerkleVerifyError::ReceiptDecodeFailed(
                    "log should be a list".to_string(),
                ));
            }

            // Decode address (field 0)
            let addr_header = RlpHeader::decode(buf).map_err(|e| {
                EthMerkleVerifyError::ReceiptDecodeFailed(format!(
                    "failed to decode address: {}",
                    e
                ))
            })?;

            if addr_header.payload_length != 20 {
                return Err(EthMerkleVerifyError::ReceiptDecodeFailed(format!(
                    "address should be 20 bytes, got {}",
                    addr_header.payload_length
                )));
            }

            let mut address = [0u8; 20];
            address.copy_from_slice(&buf[..20]);
            buf.advance(20);

            // Decode topics (field 1)
            let topics_header = RlpHeader::decode(buf).map_err(|e| {
                EthMerkleVerifyError::ReceiptDecodeFailed(format!(
                    "failed to decode topics list: {}",
                    e
                ))
            })?;

            if !topics_header.list {
                return Err(EthMerkleVerifyError::ReceiptDecodeFailed(
                    "topics should be a list".to_string(),
                ));
            }

            let mut topics = Vec::new();
            let topics_end = buf.len() - topics_header.payload_length;
            while buf.len() > topics_end {
                let topic_header = RlpHeader::decode(buf).map_err(|e| {
                    EthMerkleVerifyError::ReceiptDecodeFailed(format!(
                        "failed to decode topic: {}",
                        e
                    ))
                })?;

                if topic_header.payload_length != 32 {
                    return Err(EthMerkleVerifyError::ReceiptDecodeFailed(format!(
                        "topic should be 32 bytes, got {}",
                        topic_header.payload_length
                    )));
                }

                let mut topic = [0u8; 32];
                topic.copy_from_slice(&buf[..32]);
                buf.advance(32);
                topics.push(topic);
            }

            // Decode data (field 2)
            let data_header = RlpHeader::decode(buf).map_err(|e| {
                EthMerkleVerifyError::ReceiptDecodeFailed(format!("failed to decode data: {}", e))
            })?;

            let data = buf[..data_header.payload_length].to_vec();
            buf.advance(data_header.payload_length);

            Ok(Log {
                address,
                topics,
                data,
            })
        }
    }

    /// RLP-encode a transaction index as the MPT key.
    #[allow(clippy::cast_possible_truncation)]
    pub(crate) fn rlp_encode_tx_index(index: u32) -> Vec<u8> {
        if index == 0 {
            // RLP for 0 is 0x80
            vec![0x80]
        } else if index < 0x80 {
            // Single byte - safe: index < 128 fits in u8
            vec![index as u8]
        } else if index < 0x100 {
            // 1 byte + length prefix - safe: index < 256 fits in u8
            vec![0x81, index as u8]
        } else if index < 0x10000 {
            // 2 bytes + length prefix - safe: masked to u8 range
            vec![0x82, (index >> 8) as u8, (index & 0xff) as u8]
        } else if index < 0x1000000 {
            // 3 bytes + length prefix - safe: masked to u8 range
            vec![
                0x83,
                (index >> 16) as u8,
                (index >> 8) as u8,
                (index & 0xff) as u8,
            ]
        } else {
            // 4 bytes + length prefix - safe: masked to u8 range
            vec![
                0x84,
                (index >> 24) as u8,
                (index >> 16) as u8,
                (index >> 8) as u8,
                (index & 0xff) as u8,
            ]
        }
    }

    /// Convert key bytes to nibbles for MPT traversal.
    pub(crate) fn bytes_to_nibbles(bytes: &[u8]) -> Vec<u8> {
        let mut nibbles = Vec::with_capacity(bytes.len() * 2);
        for b in bytes {
            nibbles.push(b >> 4);
            nibbles.push(b & 0x0f);
        }
        nibbles
    }

    /// Verify a Merkle Patricia Trie proof.
    ///
    /// This verifies that `value` is stored at `key` in a trie with `root`.
    fn verify_mpt_proof(
        root: &[u8; 32],
        key: &[u8],
        value: &[u8],
        proof: &[Vec<u8>],
    ) -> Result<(), EthMerkleVerifyError> {
        if proof.is_empty() {
            return Err(EthMerkleVerifyError::EmptyProofNodes);
        }

        let key_nibbles = bytes_to_nibbles(key);
        let mut key_idx = 0;
        let mut expected_hash = *root;

        for (node_idx, node) in proof.iter().enumerate() {
            // Verify node hash matches expected
            let node_hash = keccak256(node);
            if node_hash.as_slice() != expected_hash {
                return Err(EthMerkleVerifyError::MptProofFailed(format!(
                    "node {} hash mismatch: expected {}, got {}",
                    node_idx,
                    hex::encode(expected_hash),
                    hex::encode(node_hash)
                )));
            }

            // Decode the node
            let mut buf = node.as_slice();
            let header = RlpHeader::decode(&mut buf).map_err(|e| {
                EthMerkleVerifyError::MptProofFailed(format!(
                    "failed to decode node {}: {}",
                    node_idx, e
                ))
            })?;

            if !header.list {
                return Err(EthMerkleVerifyError::MptProofFailed(format!(
                    "node {} is not a list",
                    node_idx
                )));
            }

            // Count elements to determine node type
            let mut temp_buf = buf;
            let mut element_count = 0;
            let end_pos = buf.len() - header.payload_length;
            while temp_buf.len() > end_pos {
                let elem_header = RlpHeader::decode(&mut temp_buf).map_err(|e| {
                    EthMerkleVerifyError::MptProofFailed(format!(
                        "failed to count elements in node {}: {}",
                        node_idx, e
                    ))
                })?;
                temp_buf.advance(elem_header.payload_length);
                element_count += 1;
            }

            if element_count == 17 {
                // Branch node: 16 children + value
                let mut children = Vec::new();
                let mut value_field = Vec::new();

                for i in 0..17 {
                    let child_header = RlpHeader::decode(&mut buf).map_err(|e| {
                        EthMerkleVerifyError::MptProofFailed(format!(
                            "failed to decode branch child {}: {}",
                            i, e
                        ))
                    })?;

                    let child_data = &buf[..child_header.payload_length];
                    if i < 16 {
                        children.push(child_data.to_vec());
                    } else {
                        value_field = child_data.to_vec();
                    }
                    buf.advance(child_header.payload_length);
                }

                // Check if we're at the end of the key
                if key_idx >= key_nibbles.len() {
                    // Value should be in this node
                    if value_field == value {
                        return Ok(());
                    } else {
                        return Err(EthMerkleVerifyError::MptProofFailed(
                            "value mismatch at branch node".to_string(),
                        ));
                    }
                }

                // Follow the child at key_nibbles[key_idx]
                let nibble = key_nibbles[key_idx] as usize;
                key_idx += 1;

                let child = &children[nibble];
                if child.is_empty() {
                    return Err(EthMerkleVerifyError::MptProofFailed(
                        "empty child in branch node".to_string(),
                    ));
                }

                // If child is 32 bytes, it's a hash; otherwise it's an embedded node
                if child.len() == 32 {
                    expected_hash.copy_from_slice(child);
                } else {
                    // Embedded node - verify inline
                    // This is complex; for now just compute hash
                    let h = keccak256(child);
                    expected_hash.copy_from_slice(h.as_slice());
                }
            } else if element_count == 2 {
                // Extension or leaf node
                let path_header = RlpHeader::decode(&mut buf).map_err(|e| {
                    EthMerkleVerifyError::MptProofFailed(format!("failed to decode path: {}", e))
                })?;

                let path_bytes = &buf[..path_header.payload_length];
                buf.advance(path_header.payload_length);

                let value_header = RlpHeader::decode(&mut buf).map_err(|e| {
                    EthMerkleVerifyError::MptProofFailed(format!("failed to decode value: {}", e))
                })?;

                let value_data = &buf[..value_header.payload_length];
                buf.advance(value_header.payload_length);

                // Decode HP-encoded path
                let (path_nibbles, is_leaf) = hp_decode(path_bytes)?;

                // Verify path matches remaining key
                let remaining_key = &key_nibbles[key_idx..];
                if is_leaf {
                    // Leaf node - path should match remaining key exactly
                    if path_nibbles != remaining_key {
                        return Err(EthMerkleVerifyError::MptProofFailed(format!(
                            "leaf path mismatch: expected {:?}, got {:?}",
                            remaining_key, path_nibbles
                        )));
                    }

                    // Value should match
                    if value_data == value {
                        return Ok(());
                    } else {
                        return Err(EthMerkleVerifyError::MptProofFailed(
                            "value mismatch at leaf node".to_string(),
                        ));
                    }
                } else {
                    // Extension node - path is a prefix of remaining key
                    if remaining_key.len() < path_nibbles.len() {
                        return Err(EthMerkleVerifyError::MptProofFailed(
                            "extension path longer than remaining key".to_string(),
                        ));
                    }

                    if &remaining_key[..path_nibbles.len()] != path_nibbles.as_slice() {
                        return Err(EthMerkleVerifyError::MptProofFailed(format!(
                            "extension path mismatch: expected prefix {:?}, got {:?}",
                            &remaining_key[..path_nibbles.len()],
                            path_nibbles
                        )));
                    }

                    key_idx += path_nibbles.len();

                    // Follow to next node
                    if value_data.len() == 32 {
                        expected_hash.copy_from_slice(value_data);
                    } else {
                        let h = keccak256(value_data);
                        expected_hash.copy_from_slice(h.as_slice());
                    }
                }
            } else {
                return Err(EthMerkleVerifyError::MptProofFailed(format!(
                    "invalid node element count: {}",
                    element_count
                )));
            }
        }

        Err(EthMerkleVerifyError::MptProofFailed(
            "proof ended before reaching value".to_string(),
        ))
    }

    /// Decode hex-prefix encoded path.
    /// Returns (nibbles, is_leaf)
    pub(crate) fn hp_decode(encoded: &[u8]) -> Result<(Vec<u8>, bool), EthMerkleVerifyError> {
        if encoded.is_empty() {
            return Ok((vec![], false));
        }

        let first_nibble = encoded[0] >> 4;
        let is_odd = (first_nibble & 0x01) != 0;
        let is_leaf = (first_nibble & 0x02) != 0;

        let mut nibbles = Vec::new();

        if is_odd {
            // Odd length - first byte contains one nibble
            nibbles.push(encoded[0] & 0x0f);
        }

        for &b in &encoded[1..] {
            nibbles.push(b >> 4);
            nibbles.push(b & 0x0f);
        }

        Ok((nibbles, is_leaf))
    }

    /// Verify an Ethereum receipt Merkle proof.
    ///
    /// This is the main entry point for verifying `EthReceiptMerkleProofV1` proofs.
    pub fn verify_eth_receipt_merkle_proof(
        proof: &EthReceiptMerkleProofV1,
    ) -> Result<MerkleVerifiedEvent, EthMerkleVerifyError> {
        // Step 1: Verify block hash matches keccak256(header_rlp)
        let computed_hash = keccak256(&proof.header_rlp);
        if computed_hash.as_slice() != proof.block_hash {
            return Err(EthMerkleVerifyError::BlockHashMismatch {
                expected: hex::encode(proof.block_hash),
                got: hex::encode(computed_hash),
            });
        }

        // Step 2: Decode block header and extract receipts_root
        let header = BlockHeader::from_rlp(&proof.header_rlp)?;

        // Step 3: Verify receipt inclusion using MPT proof
        let key = rlp_encode_tx_index(proof.tx_index);
        verify_mpt_proof(
            &header.receipts_root,
            &key,
            &proof.receipt_rlp,
            &proof.proof_nodes,
        )?;

        // Step 4: Decode receipt and get the log
        let receipt = Receipt::from_rlp(&proof.receipt_rlp)?;

        let log_idx = proof.log_index as usize;
        if log_idx >= receipt.logs.len() {
            return Err(EthMerkleVerifyError::LogIndexOutOfBounds {
                index: proof.log_index,
                count: receipt.logs.len(),
            });
        }

        let log = &receipt.logs[log_idx];

        // Step 5: Verify event filters
        if log.address != proof.contract {
            return Err(EthMerkleVerifyError::ContractMismatch {
                expected: hex::encode(proof.contract),
                got: hex::encode(log.address),
            });
        }

        if log.topics.is_empty() || log.topics[0] != proof.topic0 {
            let got = if log.topics.is_empty() {
                "none".to_string()
            } else {
                hex::encode(log.topics[0])
            };
            return Err(EthMerkleVerifyError::Topic0Mismatch {
                expected: hex::encode(proof.topic0),
                got,
            });
        }

        // Verify data hash (using blake3 as specified)
        let computed_data_hash = blake3::hash(&log.data);
        if computed_data_hash.as_bytes() != &proof.data_hash {
            return Err(EthMerkleVerifyError::DataHashMismatch {
                expected: hex::encode(proof.data_hash),
                got: hex::encode(computed_data_hash.as_bytes()),
            });
        }

        Ok(MerkleVerifiedEvent {
            block_hash: proof.block_hash,
            block_number: proof.block_number,
            tx_hash: proof.tx_hash,
            tx_index: proof.tx_index,
            log_index: proof.log_index,
            contract: proof.contract,
            topic0: proof.topic0,
            data_hash: proof.data_hash,
        })
    }
}

#[cfg(feature = "merkle-proofs")]
pub use implementation::*;

/// Header-aware Merkle proof verification (requires `eth-headers` feature).
///
/// This module extends the basic Merkle proof verification with header chain awareness,
/// requiring that proofs reference blocks that are:
/// 1. Known in the header store
/// 2. On a verified chain (descend from checkpoints)
/// 3. Have sufficient confirmations
#[cfg(all(feature = "merkle-proofs", feature = "eth-headers"))]
mod header_aware {
    use super::implementation::*;
    use crate::eth_headers_verify::{HeaderVerifier, HeaderVerifyError};
    use l2_core::EthReceiptMerkleProofV1;
    use l2_storage::eth_headers::EthHeaderStorage;
    use thiserror::Error;

    /// Errors from header-aware Merkle proof verification.
    #[derive(Debug, Error)]
    pub enum HeaderAwareMerkleError {
        #[error("merkle proof error: {0}")]
        Merkle(#[from] EthMerkleVerifyError),

        #[error("header verification error: {0}")]
        Header(#[from] HeaderVerifyError),

        #[error("block not found in header store: {0}")]
        BlockNotFound(String),

        #[error("block not on verified chain: {0}")]
        BlockNotVerified(String),

        #[error("receipts root mismatch: proof has {proof}, header has {stored}")]
        ReceiptsRootMismatch { proof: String, stored: String },

        #[error("insufficient confirmations: got {got}, need {need}")]
        InsufficientConfirmations { got: u64, need: u64 },
    }

    /// Result of header-aware Merkle proof verification.
    #[derive(Debug, Clone)]
    pub struct HeaderAwareVerifiedEvent {
        /// The verified event from Merkle proof.
        pub event: MerkleVerifiedEvent,

        /// Number of confirmations for this block.
        pub confirmations: u64,

        /// Whether the block is on the best verified chain.
        pub on_verified_chain: bool,
    }

    /// Verify a Merkle receipt proof with header chain awareness.
    ///
    /// This function:
    /// 1. Checks that the block exists in the header store
    /// 2. Verifies the block is on a verified chain (descends from checkpoint)
    /// 3. Uses the stored header's receipts_root (not from proof) as source of truth
    /// 4. Verifies sufficient confirmations
    /// 5. Performs the MPT proof verification
    pub fn verify_merkle_proof_with_headers(
        proof: &EthReceiptMerkleProofV1,
        storage: &EthHeaderStorage,
        verifier: &HeaderVerifier,
    ) -> Result<HeaderAwareVerifiedEvent, HeaderAwareMerkleError> {
        // Step 1: Check confirmations (also verifies block is known and verified)
        let confirmations = verifier.check_confirmations(storage, &proof.block_hash)?;

        // Step 2: Get the stored header's receipts root
        let stored_receipts_root = verifier.get_verified_receipts_root(storage, &proof.block_hash)?;

        // Step 3: Verify the proof's header RLP produces the expected block hash
        // (This is already done in the basic verify function, but we do it explicitly here
        // to be extra safe before we use the receipts_root)
        use alloy_primitives::keccak256;
        let computed_hash = keccak256(&proof.header_rlp);
        if computed_hash.as_slice() != proof.block_hash {
            return Err(HeaderAwareMerkleError::Merkle(EthMerkleVerifyError::BlockHashMismatch {
                expected: hex::encode(proof.block_hash),
                got: hex::encode(computed_hash),
            }));
        }

        // Step 4: Extract receipts_root from the proof's header and compare with stored
        // (We could skip this if we fully trust our stored headers, but this is a sanity check)
        let header_from_proof = super::implementation::BlockHeader::from_rlp(&proof.header_rlp)?;
        if header_from_proof.receipts_root != stored_receipts_root {
            return Err(HeaderAwareMerkleError::ReceiptsRootMismatch {
                proof: hex::encode(header_from_proof.receipts_root),
                stored: hex::encode(stored_receipts_root),
            });
        }

        // Step 5: Perform the full Merkle proof verification
        let event = verify_eth_receipt_merkle_proof(proof)?;

        Ok(HeaderAwareVerifiedEvent {
            event,
            confirmations,
            on_verified_chain: true,
        })
    }

    /// Check if a proof can be verified (block is known with sufficient confirmations).
    ///
    /// This is useful for the reconciler to determine if a proof is ready for verification
    /// or should remain pending waiting for headers.
    pub fn can_verify_proof(
        proof: &EthReceiptMerkleProofV1,
        storage: &EthHeaderStorage,
        verifier: &HeaderVerifier,
    ) -> ProofReadiness {
        use l2_core::eth_header::HeaderId;

        // Check if header exists
        let header_id = HeaderId(proof.block_hash);
        match storage.get_header(&header_id) {
            Ok(Some(stored)) => {
                if !stored.state.is_verified() {
                    return ProofReadiness::BlockNotVerified;
                }

                // Check confirmations
                match storage.confirmations(&proof.block_hash) {
                    Ok(Some(confs)) => {
                        let min_required = verifier.config().min_confirmations(storage.chain_id());
                        if confs >= min_required {
                            ProofReadiness::Ready { confirmations: confs }
                        } else {
                            ProofReadiness::InsufficientConfirmations {
                                got: confs,
                                need: min_required,
                            }
                        }
                    }
                    Ok(None) => ProofReadiness::BlockNotOnBestChain,
                    Err(_) => ProofReadiness::StorageError,
                }
            }
            Ok(None) => ProofReadiness::BlockNotFound,
            Err(_) => ProofReadiness::StorageError,
        }
    }

    /// Proof readiness status.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub enum ProofReadiness {
        /// Proof is ready for verification.
        Ready { confirmations: u64 },
        /// Block not found in header store.
        BlockNotFound,
        /// Block exists but is not on a verified chain.
        BlockNotVerified,
        /// Block is verified but not on best chain (may be a fork).
        BlockNotOnBestChain,
        /// Insufficient confirmations.
        InsufficientConfirmations { got: u64, need: u64 },
        /// Storage error.
        StorageError,
    }

    impl ProofReadiness {
        /// Check if the proof is ready.
        pub fn is_ready(&self) -> bool {
            matches!(self, Self::Ready { .. })
        }

        /// Check if the proof is pending (might become ready later).
        pub fn is_pending(&self) -> bool {
            matches!(
                self,
                Self::BlockNotFound
                    | Self::BlockNotVerified
                    | Self::BlockNotOnBestChain
                    | Self::InsufficientConfirmations { .. }
            )
        }

        /// Get a human-readable reason for not being ready.
        pub fn reason(&self) -> Option<String> {
            match self {
                Self::Ready { .. } => None,
                Self::BlockNotFound => Some("block not found in header store".to_string()),
                Self::BlockNotVerified => Some("block not on verified chain".to_string()),
                Self::BlockNotOnBestChain => Some("block not on best chain".to_string()),
                Self::InsufficientConfirmations { got, need } => {
                    Some(format!("insufficient confirmations: {} < {}", got, need))
                }
                Self::StorageError => Some("storage error".to_string()),
            }
        }
    }
}

#[cfg(all(feature = "merkle-proofs", feature = "eth-headers"))]
pub use header_aware::*;

// Stub exports when feature is not enabled
#[cfg(not(feature = "merkle-proofs"))]
pub mod stub {
    use l2_core::EthReceiptMerkleProofV1;
    use thiserror::Error;

    #[derive(Debug, Error)]
    pub enum EthMerkleVerifyError {
        #[error("merkle-proofs feature not enabled")]
        FeatureNotEnabled,
    }

    #[derive(Debug, Clone)]
    pub struct MerkleVerifiedEvent {
        pub block_hash: [u8; 32],
        pub block_number: u64,
        pub tx_hash: [u8; 32],
        pub tx_index: u32,
        pub log_index: u32,
        pub contract: [u8; 20],
        pub topic0: [u8; 32],
        pub data_hash: [u8; 32],
    }

    pub fn verify_eth_receipt_merkle_proof(
        _proof: &EthReceiptMerkleProofV1,
    ) -> Result<MerkleVerifiedEvent, EthMerkleVerifyError> {
        Err(EthMerkleVerifyError::FeatureNotEnabled)
    }
}

#[cfg(not(feature = "merkle-proofs"))]
pub use stub::*;

#[cfg(test)]
#[cfg(feature = "merkle-proofs")]
mod tests {
    use super::*;

    #[test]
    fn test_rlp_encode_tx_index() {
        use implementation::rlp_encode_tx_index;

        // Test zero
        assert_eq!(rlp_encode_tx_index(0), vec![0x80]);

        // Test small values
        assert_eq!(rlp_encode_tx_index(1), vec![0x01]);
        assert_eq!(rlp_encode_tx_index(127), vec![0x7f]);

        // Test medium values
        assert_eq!(rlp_encode_tx_index(128), vec![0x81, 0x80]);
        assert_eq!(rlp_encode_tx_index(255), vec![0x81, 0xff]);

        // Test larger values
        assert_eq!(rlp_encode_tx_index(256), vec![0x82, 0x01, 0x00]);
    }

    #[test]
    fn test_bytes_to_nibbles() {
        use implementation::bytes_to_nibbles;

        assert_eq!(
            bytes_to_nibbles(&[0xab, 0xcd]),
            vec![0x0a, 0x0b, 0x0c, 0x0d]
        );
        assert_eq!(bytes_to_nibbles(&[0x00]), vec![0x00, 0x00]);
        assert_eq!(bytes_to_nibbles(&[0xff]), vec![0x0f, 0x0f]);
    }

    #[test]
    fn test_hp_decode() {
        use implementation::hp_decode;

        // Even extension (prefix 0x00)
        let (nibbles, is_leaf) = hp_decode(&[0x00, 0xab, 0xcd]).unwrap();
        assert_eq!(nibbles, vec![0x0a, 0x0b, 0x0c, 0x0d]);
        assert!(!is_leaf);

        // Odd extension (prefix 0x1X)
        let (nibbles, is_leaf) = hp_decode(&[0x1a, 0xbc]).unwrap();
        assert_eq!(nibbles, vec![0x0a, 0x0b, 0x0c]);
        assert!(!is_leaf);

        // Even leaf (prefix 0x20)
        let (nibbles, is_leaf) = hp_decode(&[0x20, 0xab]).unwrap();
        assert_eq!(nibbles, vec![0x0a, 0x0b]);
        assert!(is_leaf);

        // Odd leaf (prefix 0x3X)
        let (nibbles, is_leaf) = hp_decode(&[0x3a]).unwrap();
        assert_eq!(nibbles, vec![0x0a]);
        assert!(is_leaf);
    }
}
