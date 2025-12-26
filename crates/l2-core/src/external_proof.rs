//! External Chain Proof Types (Generic, Versioned).
//!
//! This module defines types for verifiable statements about events on external chains
//! (Ethereum, etc.). IPPAN does not "trust" external chains; it records verifiable
//! statements with explicit attestor identity.
//!
//! ## Design Principles
//!
//! 1. **Non-authoritative**: External proofs are statements with proofs, not "truth"
//! 2. **Deterministic**: All validation and hashing is deterministic
//! 3. **Versioned**: Types are versioned for upgrade paths
//! 4. **Generic**: Support for multiple chains without code changes
//!
//! ## Proof Types
//!
//! MVP: `EthReceiptAttestationV1` - signed attestation from a trusted attestor
//! Future: `EthReceiptMerkleProofV1` - cryptographic proof against block header

use crate::{canonical_encode, canonical_hash, CanonicalError, Hash32};
use serde::{Deserialize, Serialize};
use std::fmt;
use thiserror::Error;

/// Domain separator for external proof attestation signing (v1).
///
/// Used to prevent cross-protocol replay attacks.
pub const EXTERNAL_PROOF_SIGNING_DOMAIN_V1: &[u8] = b"IPPAN-L2:EXTERNAL_PROOF_ATTESTATION:V1\n";

/// Maximum size for receipt RLP bytes.
pub const MAX_RECEIPT_RLP_SIZE: usize = 65536; // 64 KB

/// Maximum size for a single proof node.
pub const MAX_PROOF_NODE_SIZE: usize = 4096; // 4 KB

/// Maximum number of proof nodes in a Merkle proof.
pub const MAX_PROOF_NODES: usize = 128;

/// Maximum size for block header RLP bytes.
pub const MAX_HEADER_RLP_SIZE: usize = 8192; // 8 KB

/// Verification mode for external chain proofs.
///
/// This enum represents the trust model used to verify an external event:
///
/// - `Attestation`: Fastest but requires trust in allowlisted attestors
/// - `EthMerkleReceiptProof`: Stronger cryptographic verification using MPT proofs
/// - Future: `LightClient` for fully trust-minimised verification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum VerificationMode {
    /// Verification via signed attestation from a trusted attestor.
    ///
    /// Trust assumption: The attestor is honest and correctly observed the event.
    Attestation,

    /// Verification via Ethereum Merkle Patricia Trie receipt inclusion proof.
    ///
    /// Trust assumption: The block header is valid (confirmations policy or light client).
    EthMerkleReceiptProof,
}

impl VerificationMode {
    /// Get a human-readable name for the mode.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Attestation => "attestation",
            Self::EthMerkleReceiptProof => "eth_merkle_receipt_proof",
        }
    }
}

impl fmt::Display for VerificationMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.name())
    }
}

/// Identifier for an external chain.
///
/// Uses explicit enum variants for well-known chains to avoid arbitrary string
/// injection, while supporting `Other` for testnet/custom chains.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ExternalChainId {
    /// Ethereum Mainnet (chain ID 1).
    EthereumMainnet,
    /// Ethereum Sepolia testnet (chain ID 11155111).
    EthereumSepolia,
    /// Ethereum Holesky testnet (chain ID 17000).
    EthereumHolesky,
    /// Other chain with explicit chain ID and name.
    ///
    /// The name should be a short, lowercase identifier (e.g., "arbitrum", "polygon").
    Other { chain_id: u64, name: String },
}

impl ExternalChainId {
    /// Get the numeric chain ID.
    pub fn chain_id(&self) -> u64 {
        match self {
            ExternalChainId::EthereumMainnet => 1,
            ExternalChainId::EthereumSepolia => 11_155_111,
            ExternalChainId::EthereumHolesky => 17_000,
            ExternalChainId::Other { chain_id, .. } => *chain_id,
        }
    }

    /// Get a short name for logging/display.
    pub fn name(&self) -> &str {
        match self {
            ExternalChainId::EthereumMainnet => "ethereum",
            ExternalChainId::EthereumSepolia => "sepolia",
            ExternalChainId::EthereumHolesky => "holesky",
            ExternalChainId::Other { name, .. } => name,
        }
    }

    /// Create from numeric chain ID (well-known chains only).
    pub fn from_chain_id(chain_id: u64) -> Option<Self> {
        match chain_id {
            1 => Some(ExternalChainId::EthereumMainnet),
            11_155_111 => Some(ExternalChainId::EthereumSepolia),
            17_000 => Some(ExternalChainId::EthereumHolesky),
            _ => None,
        }
    }

    /// Check if this is an Ethereum-based chain.
    pub fn is_ethereum(&self) -> bool {
        matches!(
            self,
            ExternalChainId::EthereumMainnet
                | ExternalChainId::EthereumSepolia
                | ExternalChainId::EthereumHolesky
        )
    }

    /// Check if this is a mainnet chain (vs testnet).
    ///
    /// Returns true for Ethereum Mainnet and any Other chain with chain_id 1.
    /// Used to determine confirmation thresholds.
    pub fn is_mainnet(&self) -> bool {
        matches!(self, ExternalChainId::EthereumMainnet)
            || matches!(self, ExternalChainId::Other { chain_id, .. } if *chain_id == 1)
    }
}

impl fmt::Display for ExternalChainId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.name(), self.chain_id())
    }
}

/// Identifier for an external proof.
///
/// This is a blake3 hash of the canonical proof bytes, used for deduplication
/// and reference.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ExternalProofId(pub Hash32);

impl ExternalProofId {
    /// Create from raw bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Hash32(bytes))
    }

    /// Get the hex representation.
    pub fn to_hex(&self) -> String {
        self.0.to_hex()
    }

    /// Parse from hex string.
    pub fn from_hex(hex_str: &str) -> Result<Self, CanonicalError> {
        Hash32::from_hex(hex_str).map(ExternalProofId)
    }
}

impl fmt::Display for ExternalProofId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// External event proof (versioned enum).
///
/// Each variant represents a different proof mechanism with different
/// trust assumptions and verification costs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExternalEventProofV1 {
    /// Ethereum receipt attestation from a trusted attestor.
    ///
    /// MVP proof type: an attestor signs a statement about an event.
    /// Trust assumption: the attestor is honest and correctly observed the event.
    EthReceiptAttestationV1(EthReceiptAttestationV1),

    /// Ethereum receipt Merkle proof (stub for future implementation).
    ///
    /// Cryptographic proof against a block header's receipts root.
    /// Trust assumption: the block header is valid (light client or finality).
    EthReceiptMerkleProofV1(EthReceiptMerkleProofV1),
}

impl ExternalEventProofV1 {
    /// Compute the canonical proof ID (blake3 hash of canonical bytes).
    pub fn proof_id(&self) -> Result<ExternalProofId, CanonicalError> {
        let hash = canonical_hash(self)?;
        Ok(ExternalProofId(hash))
    }

    /// Encode to canonical bytes.
    pub fn to_canonical_bytes(&self) -> Result<Vec<u8>, CanonicalError> {
        canonical_encode(self)
    }

    /// Get the external chain this proof is for.
    pub fn chain(&self) -> &ExternalChainId {
        match self {
            ExternalEventProofV1::EthReceiptAttestationV1(p) => &p.chain,
            ExternalEventProofV1::EthReceiptMerkleProofV1(p) => &p.chain,
        }
    }

    /// Get the transaction hash this proof refers to.
    pub fn tx_hash(&self) -> &[u8; 32] {
        match self {
            ExternalEventProofV1::EthReceiptAttestationV1(p) => &p.tx_hash,
            ExternalEventProofV1::EthReceiptMerkleProofV1(p) => &p.tx_hash,
        }
    }

    /// Get the block number this proof refers to.
    pub fn block_number(&self) -> u64 {
        match self {
            ExternalEventProofV1::EthReceiptAttestationV1(p) => p.block_number,
            ExternalEventProofV1::EthReceiptMerkleProofV1(p) => p.block_number,
        }
    }

    /// Validate basic formatting and structure.
    ///
    /// This does NOT verify cryptographic signatures or Merkle proofs.
    pub fn validate_basic(&self) -> Result<(), ExternalProofValidationError> {
        match self {
            ExternalEventProofV1::EthReceiptAttestationV1(p) => p.validate_basic(),
            ExternalEventProofV1::EthReceiptMerkleProofV1(p) => p.validate_basic(),
        }
    }

    /// Get a human-readable proof type name.
    pub fn proof_type(&self) -> &'static str {
        match self {
            ExternalEventProofV1::EthReceiptAttestationV1(_) => "eth_receipt_attestation_v1",
            ExternalEventProofV1::EthReceiptMerkleProofV1(_) => "eth_receipt_merkle_v1",
        }
    }

    /// Get the verification mode for this proof.
    pub fn verification_mode(&self) -> VerificationMode {
        match self {
            ExternalEventProofV1::EthReceiptAttestationV1(p) => p.verification_mode(),
            ExternalEventProofV1::EthReceiptMerkleProofV1(p) => p.verification_mode(),
        }
    }

    /// Get the log index this proof refers to.
    pub fn log_index(&self) -> u32 {
        match self {
            ExternalEventProofV1::EthReceiptAttestationV1(p) => p.log_index,
            ExternalEventProofV1::EthReceiptMerkleProofV1(p) => p.log_index,
        }
    }

    /// Get the contract address this proof refers to.
    pub fn contract(&self) -> &[u8; 20] {
        match self {
            ExternalEventProofV1::EthReceiptAttestationV1(p) => &p.contract,
            ExternalEventProofV1::EthReceiptMerkleProofV1(p) => &p.contract,
        }
    }

    /// Get the topic0 (event signature) this proof refers to.
    pub fn topic0(&self) -> &[u8; 32] {
        match self {
            ExternalEventProofV1::EthReceiptAttestationV1(p) => &p.topic0,
            ExternalEventProofV1::EthReceiptMerkleProofV1(p) => &p.topic0,
        }
    }

    /// Get the data hash this proof refers to.
    pub fn data_hash(&self) -> &[u8; 32] {
        match self {
            ExternalEventProofV1::EthReceiptAttestationV1(p) => &p.data_hash,
            ExternalEventProofV1::EthReceiptMerkleProofV1(p) => &p.data_hash,
        }
    }

    /// Get the block hash this proof refers to.
    pub fn block_hash(&self) -> &[u8; 32] {
        match self {
            ExternalEventProofV1::EthReceiptAttestationV1(p) => &p.block_hash,
            ExternalEventProofV1::EthReceiptMerkleProofV1(p) => &p.block_hash,
        }
    }

    /// Get the confirmations (if available).
    pub fn confirmations(&self) -> Option<u32> {
        match self {
            ExternalEventProofV1::EthReceiptAttestationV1(p) => Some(p.confirmations),
            ExternalEventProofV1::EthReceiptMerkleProofV1(p) => p.confirmations,
        }
    }
}

/// Ethereum receipt attestation (signed statement from trusted attestor).
///
/// An attestor observes an Ethereum transaction and signs a statement
/// about the event it emitted. The attestor's identity is explicit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EthReceiptAttestationV1 {
    /// The external chain this event occurred on.
    pub chain: ExternalChainId,

    /// Ethereum transaction hash (32 bytes).
    #[serde(with = "hex_32")]
    pub tx_hash: [u8; 32],

    /// Log index within the transaction receipt.
    pub log_index: u32,

    /// Contract address that emitted the event (20 bytes).
    #[serde(with = "hex_20")]
    pub contract: [u8; 20],

    /// First topic (event signature, 32 bytes).
    #[serde(with = "hex_32")]
    pub topic0: [u8; 32],

    /// Blake3 hash of the event data for binding verification.
    ///
    /// This allows verifying the event matches expected parameters
    /// without including all event data in the attestation.
    #[serde(with = "hex_32")]
    pub data_hash: [u8; 32],

    /// Block number where the transaction was included.
    pub block_number: u64,

    /// Block hash where the transaction was included (32 bytes).
    #[serde(with = "hex_32")]
    pub block_hash: [u8; 32],

    /// Number of confirmations at the time of attestation.
    ///
    /// This is informational - the verifier should check against
    /// a minimum confirmation threshold.
    pub confirmations: u32,

    /// Attestor's Ed25519 public key (32 bytes).
    #[serde(with = "hex_32")]
    pub attestor_pubkey: [u8; 32],

    /// Ed25519 signature over the canonical attestation bytes (64 bytes).
    ///
    /// Signed message: EXTERNAL_PROOF_SIGNING_DOMAIN_V1 || canonical_bytes(attestation_data)
    #[serde(with = "hex_64")]
    pub signature: [u8; 64],
}

impl EthReceiptAttestationV1 {
    /// Validate basic formatting and structure.
    pub fn validate_basic(&self) -> Result<(), ExternalProofValidationError> {
        // Block number must be > 0 (genesis is block 0, rarely has user txs)
        if self.block_number == 0 {
            return Err(ExternalProofValidationError::InvalidBlockNumber(0));
        }

        // Confirmations must be > 0
        if self.confirmations == 0 {
            return Err(ExternalProofValidationError::ZeroConfirmations);
        }

        // Contract address must not be zero
        if self.contract == [0u8; 20] {
            return Err(ExternalProofValidationError::ZeroContractAddress);
        }

        // Topic0 must not be zero (event signature)
        if self.topic0 == [0u8; 32] {
            return Err(ExternalProofValidationError::ZeroTopic);
        }

        // Tx hash must not be zero
        if self.tx_hash == [0u8; 32] {
            return Err(ExternalProofValidationError::ZeroTxHash);
        }

        // Block hash must not be zero
        if self.block_hash == [0u8; 32] {
            return Err(ExternalProofValidationError::ZeroBlockHash);
        }

        // Attestor pubkey must not be zero
        if self.attestor_pubkey == [0u8; 32] {
            return Err(ExternalProofValidationError::ZeroAttestorKey);
        }

        Ok(())
    }

    /// Get the canonical attestation data bytes for signature verification.
    ///
    /// This excludes the signature field itself.
    pub fn attestation_data(&self) -> AttestationData {
        AttestationData {
            chain: self.chain.clone(),
            tx_hash: self.tx_hash,
            log_index: self.log_index,
            contract: self.contract,
            topic0: self.topic0,
            data_hash: self.data_hash,
            block_number: self.block_number,
            block_hash: self.block_hash,
            confirmations: self.confirmations,
            attestor_pubkey: self.attestor_pubkey,
        }
    }

    /// Build the signing message bytes.
    pub fn signing_message(&self) -> Result<Vec<u8>, CanonicalError> {
        let data = self.attestation_data();
        let canonical_bytes = canonical_encode(&data)?;
        let mut message =
            Vec::with_capacity(EXTERNAL_PROOF_SIGNING_DOMAIN_V1.len() + canonical_bytes.len());
        message.extend_from_slice(EXTERNAL_PROOF_SIGNING_DOMAIN_V1);
        message.extend_from_slice(&canonical_bytes);
        Ok(message)
    }

    /// Get the verification mode for this proof type.
    pub fn verification_mode(&self) -> VerificationMode {
        VerificationMode::Attestation
    }
}

/// Attestation data (everything except the signature).
///
/// Used for signature verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationData {
    pub chain: ExternalChainId,
    #[serde(with = "hex_32")]
    pub tx_hash: [u8; 32],
    pub log_index: u32,
    #[serde(with = "hex_20")]
    pub contract: [u8; 20],
    #[serde(with = "hex_32")]
    pub topic0: [u8; 32],
    #[serde(with = "hex_32")]
    pub data_hash: [u8; 32],
    pub block_number: u64,
    #[serde(with = "hex_32")]
    pub block_hash: [u8; 32],
    pub confirmations: u32,
    #[serde(with = "hex_32")]
    pub attestor_pubkey: [u8; 32],
}

/// Ethereum receipt Merkle/Patricia proof (V1).
///
/// This provides cryptographic proof of receipt inclusion in a block's receipts trie.
/// Verification steps:
/// 1. Verify block header hash matches `block_hash`
/// 2. Verify receipt RLP is included in the receipts trie at `tx_index` using MPT proof
/// 3. Decode receipt and verify the log at `log_index` matches expected event filters
///
/// ## Trust Model
///
/// This proof eliminates trust in attestors but still requires policy decisions about
/// block finality (confirmation count, light client, etc.).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EthReceiptMerkleProofV1 {
    /// The external chain this event occurred on.
    pub chain: ExternalChainId,

    /// Ethereum transaction hash (32 bytes).
    #[serde(with = "hex_32")]
    pub tx_hash: [u8; 32],

    /// Block number where the transaction was included.
    pub block_number: u64,

    /// Block hash where the transaction was included (32 bytes).
    /// This must match keccak256(header_rlp).
    #[serde(with = "hex_32")]
    pub block_hash: [u8; 32],

    /// RLP-encoded block header.
    /// Used to verify block_hash and extract receipts_root.
    #[serde(with = "hex_vec")]
    pub header_rlp: Vec<u8>,

    /// RLP-encoded transaction receipt.
    /// May be prefixed with transaction type byte for EIP-2718 typed receipts.
    #[serde(with = "hex_vec")]
    pub receipt_rlp: Vec<u8>,

    /// Merkle Patricia Trie proof nodes.
    /// Each node is RLP-encoded. The proof demonstrates inclusion of `receipt_rlp`
    /// at key `rlp_encode(tx_index)` in the trie with root `receipts_root`.
    #[serde(with = "hex_vec_vec")]
    pub proof_nodes: Vec<Vec<u8>>,

    /// Transaction index in the block (receipt position).
    pub tx_index: u32,

    /// Log index within the transaction receipt.
    pub log_index: u32,

    /// Expected contract address that emitted the event (20 bytes).
    #[serde(with = "hex_20")]
    pub contract: [u8; 20],

    /// Expected first topic / event signature (32 bytes).
    #[serde(with = "hex_32")]
    pub topic0: [u8; 32],

    /// Blake3 hash of the expected event data.
    /// Verifier computes blake3(log.data) and compares.
    #[serde(with = "hex_32")]
    pub data_hash: [u8; 32],

    /// Optional: Number of confirmations at proof creation time.
    /// This is informational and may be verified against RPC tip or light client.
    #[serde(default)]
    pub confirmations: Option<u32>,

    /// Optional: Tip block number at proof creation time.
    /// Used for RPC-assisted confirmation checking.
    #[serde(default)]
    pub tip_block_number: Option<u64>,
}

impl EthReceiptMerkleProofV1 {
    /// Validate basic formatting and structure.
    pub fn validate_basic(&self) -> Result<(), ExternalProofValidationError> {
        // Block number must be > 0
        if self.block_number == 0 {
            return Err(ExternalProofValidationError::InvalidBlockNumber(0));
        }

        // Contract address must not be zero
        if self.contract == [0u8; 20] {
            return Err(ExternalProofValidationError::ZeroContractAddress);
        }

        // Topic0 must not be zero (event signature)
        if self.topic0 == [0u8; 32] {
            return Err(ExternalProofValidationError::ZeroTopic);
        }

        // Tx hash must not be zero
        if self.tx_hash == [0u8; 32] {
            return Err(ExternalProofValidationError::ZeroTxHash);
        }

        // Block hash must not be zero
        if self.block_hash == [0u8; 32] {
            return Err(ExternalProofValidationError::ZeroBlockHash);
        }

        // Header RLP must not be empty and within bounds
        if self.header_rlp.is_empty() {
            return Err(ExternalProofValidationError::EmptyHeaderRlp);
        }
        if self.header_rlp.len() > MAX_HEADER_RLP_SIZE {
            return Err(ExternalProofValidationError::HeaderRlpTooLarge {
                size: self.header_rlp.len(),
                max: MAX_HEADER_RLP_SIZE,
            });
        }

        // Receipt RLP must not be empty and within bounds
        if self.receipt_rlp.is_empty() {
            return Err(ExternalProofValidationError::EmptyReceiptRlp);
        }
        if self.receipt_rlp.len() > MAX_RECEIPT_RLP_SIZE {
            return Err(ExternalProofValidationError::ReceiptRlpTooLarge {
                size: self.receipt_rlp.len(),
                max: MAX_RECEIPT_RLP_SIZE,
            });
        }

        // Proof nodes must not be empty
        if self.proof_nodes.is_empty() {
            return Err(ExternalProofValidationError::EmptyProofNodes);
        }

        // Proof node count within bounds
        if self.proof_nodes.len() > MAX_PROOF_NODES {
            return Err(ExternalProofValidationError::TooManyProofNodes {
                count: self.proof_nodes.len(),
                max: MAX_PROOF_NODES,
            });
        }

        // Each proof node within bounds
        for (i, node) in self.proof_nodes.iter().enumerate() {
            if node.len() > MAX_PROOF_NODE_SIZE {
                return Err(ExternalProofValidationError::ProofNodeTooLarge {
                    index: i,
                    size: node.len(),
                    max: MAX_PROOF_NODE_SIZE,
                });
            }
        }

        Ok(())
    }

    /// Get the verification mode for this proof type.
    pub fn verification_mode(&self) -> VerificationMode {
        VerificationMode::EthMerkleReceiptProof
    }
}

/// Validation errors for external proofs.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ExternalProofValidationError {
    #[error("invalid block number: {0}")]
    InvalidBlockNumber(u64),

    #[error("zero confirmations not allowed")]
    ZeroConfirmations,

    #[error("zero contract address not allowed")]
    ZeroContractAddress,

    #[error("zero topic0 (event signature) not allowed")]
    ZeroTopic,

    #[error("zero tx hash not allowed")]
    ZeroTxHash,

    #[error("zero block hash not allowed")]
    ZeroBlockHash,

    #[error("zero attestor public key not allowed")]
    ZeroAttestorKey,

    #[error("empty header RLP not allowed")]
    EmptyHeaderRlp,

    #[error("header RLP too large: {size} bytes > max {max}")]
    HeaderRlpTooLarge { size: usize, max: usize },

    #[error("empty receipt RLP not allowed")]
    EmptyReceiptRlp,

    #[error("receipt RLP too large: {size} bytes > max {max}")]
    ReceiptRlpTooLarge { size: usize, max: usize },

    #[error("empty proof nodes not allowed")]
    EmptyProofNodes,

    #[error("too many proof nodes: {count} > max {max}")]
    TooManyProofNodes { count: usize, max: usize },

    #[error("proof node {index} too large: {size} bytes > max {max}")]
    ProofNodeTooLarge {
        index: usize,
        size: usize,
        max: usize,
    },
}

/// Verification state for an external proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ExternalProofState {
    /// Proof has been submitted but not yet verified.
    Unverified,

    /// Proof has been cryptographically verified.
    Verified {
        /// Timestamp when verification completed (ms since epoch).
        verified_at_ms: u64,
    },

    /// Proof was rejected during verification.
    Rejected {
        /// Reason for rejection.
        reason: String,
        /// Timestamp when rejection occurred (ms since epoch).
        rejected_at_ms: u64,
    },
}

impl ExternalProofState {
    /// Create a new Verified state.
    pub fn verified(verified_at_ms: u64) -> Self {
        Self::Verified { verified_at_ms }
    }

    /// Create a new Rejected state.
    pub fn rejected(reason: String, rejected_at_ms: u64) -> Self {
        Self::Rejected {
            reason,
            rejected_at_ms,
        }
    }

    /// Check if this proof is verified.
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }

    /// Check if this proof is unverified.
    pub fn is_unverified(&self) -> bool {
        matches!(self, Self::Unverified)
    }

    /// Check if this proof was rejected.
    pub fn is_rejected(&self) -> bool {
        matches!(self, Self::Rejected { .. })
    }

    /// Get the state name for logging/display.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Unverified => "unverified",
            Self::Verified { .. } => "verified",
            Self::Rejected { .. } => "rejected",
        }
    }
}

impl fmt::Display for ExternalProofState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unverified => write!(f, "Unverified"),
            Self::Verified { verified_at_ms } => write!(f, "Verified(at={})", verified_at_ms),
            Self::Rejected {
                reason,
                rejected_at_ms,
            } => write!(f, "Rejected(at={}, reason={})", rejected_at_ms, reason),
        }
    }
}

/// Serde helper for encoding `[u8; 32]` as lowercase hex string.
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

/// Serde helper for encoding `[u8; 20]` as lowercase hex string.
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

/// Serde helper for encoding `[u8; 64]` as lowercase hex string.
mod hex_64 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let raw = hex::decode(s).map_err(serde::de::Error::custom)?;
        if raw.len() != 64 {
            return Err(serde::de::Error::custom(format!(
                "expected 64 bytes, got {}",
                raw.len()
            )));
        }
        let mut out = [0u8; 64];
        out.copy_from_slice(&raw);
        Ok(out)
    }
}

/// Serde helper for encoding `Vec<u8>` as lowercase hex string.
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

/// Serde helper for encoding `Vec<Vec<u8>>` as array of lowercase hex strings.
mod hex_vec_vec {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(bytes_vec: &[Vec<u8>], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_strings: Vec<String> = bytes_vec.iter().map(hex::encode).collect();
        hex_strings.serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<Vec<u8>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let strings: Vec<String> = Vec::deserialize(deserializer)?;
        strings
            .into_iter()
            .map(|s| {
                let s = s.strip_prefix("0x").unwrap_or(&s);
                hex::decode(s).map_err(serde::de::Error::custom)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    // ========== ExternalChainId Tests ==========

    #[test]
    fn chain_id_known_chains() {
        assert_eq!(ExternalChainId::EthereumMainnet.chain_id(), 1);
        assert_eq!(ExternalChainId::EthereumSepolia.chain_id(), 11_155_111);
        assert_eq!(ExternalChainId::EthereumHolesky.chain_id(), 17_000);
    }

    #[test]
    fn chain_id_from_chain_id() {
        assert_eq!(
            ExternalChainId::from_chain_id(1),
            Some(ExternalChainId::EthereumMainnet)
        );
        assert_eq!(
            ExternalChainId::from_chain_id(11_155_111),
            Some(ExternalChainId::EthereumSepolia)
        );
        assert_eq!(ExternalChainId::from_chain_id(999), None);
    }

    #[test]
    fn chain_id_other() {
        let other = ExternalChainId::Other {
            chain_id: 42161,
            name: "arbitrum".to_string(),
        };
        assert_eq!(other.chain_id(), 42161);
        assert_eq!(other.name(), "arbitrum");
    }

    #[test]
    fn chain_id_is_ethereum() {
        assert!(ExternalChainId::EthereumMainnet.is_ethereum());
        assert!(ExternalChainId::EthereumSepolia.is_ethereum());
        assert!(!ExternalChainId::Other {
            chain_id: 42161,
            name: "arbitrum".to_string()
        }
        .is_ethereum());
    }

    #[test]
    fn chain_id_display() {
        assert_eq!(
            format!("{}", ExternalChainId::EthereumMainnet),
            "ethereum:1"
        );
        assert_eq!(
            format!("{}", ExternalChainId::EthereumSepolia),
            "sepolia:11155111"
        );
    }

    // ========== ExternalProofId Tests ==========

    #[test]
    fn proof_id_hex_roundtrip() {
        let id = ExternalProofId(Hash32([0x12; 32]));
        let hex_str = id.to_hex();
        let parsed = ExternalProofId::from_hex(&hex_str).expect("parse");
        assert_eq!(parsed, id);
    }

    #[test]
    fn proof_id_display() {
        let id = ExternalProofId(Hash32([0xAB; 32]));
        let display = format!("{}", id);
        assert_eq!(display, id.to_hex());
    }

    // ========== EthReceiptAttestationV1 Tests ==========

    #[test]
    fn attestation_validate_basic_success() {
        let attestation = test_attestation();
        assert!(attestation.validate_basic().is_ok());
    }

    #[test]
    fn attestation_validate_zero_block_number() {
        let mut attestation = test_attestation();
        attestation.block_number = 0;
        assert!(matches!(
            attestation.validate_basic(),
            Err(ExternalProofValidationError::InvalidBlockNumber(0))
        ));
    }

    #[test]
    fn attestation_validate_zero_confirmations() {
        let mut attestation = test_attestation();
        attestation.confirmations = 0;
        assert!(matches!(
            attestation.validate_basic(),
            Err(ExternalProofValidationError::ZeroConfirmations)
        ));
    }

    #[test]
    fn attestation_validate_zero_contract() {
        let mut attestation = test_attestation();
        attestation.contract = [0u8; 20];
        assert!(matches!(
            attestation.validate_basic(),
            Err(ExternalProofValidationError::ZeroContractAddress)
        ));
    }

    #[test]
    fn attestation_validate_zero_topic0() {
        let mut attestation = test_attestation();
        attestation.topic0 = [0u8; 32];
        assert!(matches!(
            attestation.validate_basic(),
            Err(ExternalProofValidationError::ZeroTopic)
        ));
    }

    #[test]
    fn attestation_validate_zero_tx_hash() {
        let mut attestation = test_attestation();
        attestation.tx_hash = [0u8; 32];
        assert!(matches!(
            attestation.validate_basic(),
            Err(ExternalProofValidationError::ZeroTxHash)
        ));
    }

    #[test]
    fn attestation_validate_zero_block_hash() {
        let mut attestation = test_attestation();
        attestation.block_hash = [0u8; 32];
        assert!(matches!(
            attestation.validate_basic(),
            Err(ExternalProofValidationError::ZeroBlockHash)
        ));
    }

    #[test]
    fn attestation_validate_zero_attestor_key() {
        let mut attestation = test_attestation();
        attestation.attestor_pubkey = [0u8; 32];
        assert!(matches!(
            attestation.validate_basic(),
            Err(ExternalProofValidationError::ZeroAttestorKey)
        ));
    }

    // ========== ExternalEventProofV1 Tests ==========

    #[test]
    fn proof_id_is_deterministic() {
        let attestation = test_attestation();
        let proof = ExternalEventProofV1::EthReceiptAttestationV1(attestation);

        let id1 = proof.proof_id().expect("proof_id");
        let id2 = proof.proof_id().expect("proof_id");

        assert_eq!(id1, id2);
    }

    #[test]
    fn proof_id_changes_with_any_field() {
        let base = test_attestation();
        let base_proof = ExternalEventProofV1::EthReceiptAttestationV1(base.clone());
        let base_id = base_proof.proof_id().expect("proof_id");

        // Different tx_hash
        let mut changed = base.clone();
        changed.tx_hash = [0xFF; 32];
        let changed_proof = ExternalEventProofV1::EthReceiptAttestationV1(changed);
        assert_ne!(changed_proof.proof_id().expect("proof_id"), base_id);

        // Different block_number
        let mut changed = base.clone();
        changed.block_number = 18_000_001;
        let changed_proof = ExternalEventProofV1::EthReceiptAttestationV1(changed);
        assert_ne!(changed_proof.proof_id().expect("proof_id"), base_id);

        // Different chain
        let mut changed = base.clone();
        changed.chain = ExternalChainId::EthereumSepolia;
        let changed_proof = ExternalEventProofV1::EthReceiptAttestationV1(changed);
        assert_ne!(changed_proof.proof_id().expect("proof_id"), base_id);
    }

    #[test]
    fn proof_id_golden_vector() {
        // Fixed attestation for golden test
        let attestation = EthReceiptAttestationV1 {
            chain: ExternalChainId::EthereumMainnet,
            tx_hash: [0x01; 32],
            log_index: 0,
            contract: [0x02; 20],
            topic0: [0x03; 32],
            data_hash: [0x04; 32],
            block_number: 18_000_000,
            block_hash: [0x05; 32],
            confirmations: 12,
            attestor_pubkey: [0x06; 32],
            signature: [0x07; 64],
        };

        let proof = ExternalEventProofV1::EthReceiptAttestationV1(attestation);
        let id = proof.proof_id().expect("proof_id");

        // This hash should remain stable across versions
        assert_eq!(
            id.to_hex(),
            "7c43c787dc2c6c39366b9394ddba1d8b3ea3b927c1f53f294afcb2119cbc7fe2"
        );
    }

    #[test]
    fn proof_accessors() {
        let attestation = test_attestation();
        let proof = ExternalEventProofV1::EthReceiptAttestationV1(attestation.clone());

        assert_eq!(proof.chain(), &attestation.chain);
        assert_eq!(proof.tx_hash(), &attestation.tx_hash);
        assert_eq!(proof.block_number(), attestation.block_number);
        assert_eq!(proof.proof_type(), "eth_receipt_attestation_v1");
    }

    // ========== ExternalProofState Tests ==========

    #[test]
    fn proof_state_constructors() {
        let unverified = ExternalProofState::Unverified;
        assert!(unverified.is_unverified());
        assert!(!unverified.is_verified());
        assert!(!unverified.is_rejected());
        assert_eq!(unverified.name(), "unverified");

        let verified = ExternalProofState::verified(1_700_000_000_000);
        assert!(!verified.is_unverified());
        assert!(verified.is_verified());
        assert!(!verified.is_rejected());
        assert_eq!(verified.name(), "verified");

        let rejected =
            ExternalProofState::rejected("invalid signature".to_string(), 1_700_000_000_000);
        assert!(!rejected.is_unverified());
        assert!(!rejected.is_verified());
        assert!(rejected.is_rejected());
        assert_eq!(rejected.name(), "rejected");
    }

    #[test]
    fn proof_state_display() {
        assert_eq!(format!("{}", ExternalProofState::Unverified), "Unverified");
        assert_eq!(
            format!("{}", ExternalProofState::verified(1234)),
            "Verified(at=1234)"
        );
        assert_eq!(
            format!(
                "{}",
                ExternalProofState::rejected("bad sig".to_string(), 5678)
            ),
            "Rejected(at=5678, reason=bad sig)"
        );
    }

    // ========== Signing Message Tests ==========

    #[test]
    fn signing_message_includes_domain_separator() {
        let attestation = test_attestation();
        let message = attestation.signing_message().expect("signing_message");

        // Should start with domain separator
        assert!(message.starts_with(EXTERNAL_PROOF_SIGNING_DOMAIN_V1));
    }

    #[test]
    fn signing_message_is_deterministic() {
        let attestation = test_attestation();
        let msg1 = attestation.signing_message().expect("signing_message");
        let msg2 = attestation.signing_message().expect("signing_message");
        assert_eq!(msg1, msg2);
    }

    // ========== Merkle Proof Tests ==========

    fn test_merkle_proof() -> EthReceiptMerkleProofV1 {
        EthReceiptMerkleProofV1 {
            chain: ExternalChainId::EthereumMainnet,
            tx_hash: [0xAA; 32],
            block_number: 18_000_000,
            block_hash: [0xEE; 32],
            header_rlp: vec![0x01, 0x02, 0x03],
            receipt_rlp: vec![0x04, 0x05, 0x06],
            proof_nodes: vec![vec![0x07, 0x08]],
            tx_index: 0,
            log_index: 0,
            contract: [0xBB; 20],
            topic0: [0xCC; 32],
            data_hash: [0xDD; 32],
            confirmations: Some(15),
            tip_block_number: Some(18_000_015),
        }
    }

    #[test]
    fn merkle_proof_validate_basic() {
        let proof = test_merkle_proof();
        assert!(proof.validate_basic().is_ok());
    }

    #[test]
    fn merkle_proof_validate_empty_header_rlp() {
        let mut proof = test_merkle_proof();
        proof.header_rlp = vec![];

        assert!(matches!(
            proof.validate_basic(),
            Err(ExternalProofValidationError::EmptyHeaderRlp)
        ));
    }

    #[test]
    fn merkle_proof_validate_header_rlp_too_large() {
        let mut proof = test_merkle_proof();
        proof.header_rlp = vec![0u8; MAX_HEADER_RLP_SIZE + 1];

        assert!(matches!(
            proof.validate_basic(),
            Err(ExternalProofValidationError::HeaderRlpTooLarge { .. })
        ));
    }

    #[test]
    fn merkle_proof_validate_empty_rlp() {
        let mut proof = test_merkle_proof();
        proof.receipt_rlp = vec![];

        assert!(matches!(
            proof.validate_basic(),
            Err(ExternalProofValidationError::EmptyReceiptRlp)
        ));
    }

    #[test]
    fn merkle_proof_validate_receipt_rlp_too_large() {
        let mut proof = test_merkle_proof();
        proof.receipt_rlp = vec![0u8; MAX_RECEIPT_RLP_SIZE + 1];

        assert!(matches!(
            proof.validate_basic(),
            Err(ExternalProofValidationError::ReceiptRlpTooLarge { .. })
        ));
    }

    #[test]
    fn merkle_proof_validate_empty_nodes() {
        let mut proof = test_merkle_proof();
        proof.proof_nodes = vec![];

        assert!(matches!(
            proof.validate_basic(),
            Err(ExternalProofValidationError::EmptyProofNodes)
        ));
    }

    #[test]
    fn merkle_proof_validate_too_many_nodes() {
        let mut proof = test_merkle_proof();
        proof.proof_nodes = (0..MAX_PROOF_NODES + 1).map(|_| vec![0x01]).collect();

        assert!(matches!(
            proof.validate_basic(),
            Err(ExternalProofValidationError::TooManyProofNodes { .. })
        ));
    }

    #[test]
    fn merkle_proof_validate_node_too_large() {
        let mut proof = test_merkle_proof();
        proof.proof_nodes = vec![vec![0u8; MAX_PROOF_NODE_SIZE + 1]];

        assert!(matches!(
            proof.validate_basic(),
            Err(ExternalProofValidationError::ProofNodeTooLarge { .. })
        ));
    }

    #[test]
    fn merkle_proof_validate_zero_topic() {
        let mut proof = test_merkle_proof();
        proof.topic0 = [0u8; 32];

        assert!(matches!(
            proof.validate_basic(),
            Err(ExternalProofValidationError::ZeroTopic)
        ));
    }

    #[test]
    fn merkle_proof_validate_zero_block_hash() {
        let mut proof = test_merkle_proof();
        proof.block_hash = [0u8; 32];

        assert!(matches!(
            proof.validate_basic(),
            Err(ExternalProofValidationError::ZeroBlockHash)
        ));
    }

    // ========== VerificationMode Tests ==========

    #[test]
    fn verification_mode_attestation() {
        let mode = VerificationMode::Attestation;
        assert_eq!(mode.name(), "attestation");
        assert_eq!(format!("{}", mode), "attestation");
    }

    #[test]
    fn verification_mode_merkle_proof() {
        let mode = VerificationMode::EthMerkleReceiptProof;
        assert_eq!(mode.name(), "eth_merkle_receipt_proof");
        assert_eq!(format!("{}", mode), "eth_merkle_receipt_proof");
    }

    #[test]
    fn attestation_verification_mode() {
        let attestation = test_attestation();
        assert_eq!(
            attestation.verification_mode(),
            VerificationMode::Attestation
        );
    }

    #[test]
    fn merkle_proof_verification_mode() {
        let proof = test_merkle_proof();
        assert_eq!(
            proof.verification_mode(),
            VerificationMode::EthMerkleReceiptProof
        );
    }

    #[test]
    fn proof_verification_mode_accessor() {
        let attestation = test_attestation();
        let proof = ExternalEventProofV1::EthReceiptAttestationV1(attestation);
        assert_eq!(proof.verification_mode(), VerificationMode::Attestation);

        let merkle_proof = test_merkle_proof();
        let proof = ExternalEventProofV1::EthReceiptMerkleProofV1(merkle_proof);
        assert_eq!(
            proof.verification_mode(),
            VerificationMode::EthMerkleReceiptProof
        );
    }

    // ========== Additional Accessor Tests ==========

    #[test]
    fn proof_accessors_merkle() {
        let merkle_proof = test_merkle_proof();
        let proof = ExternalEventProofV1::EthReceiptMerkleProofV1(merkle_proof.clone());

        assert_eq!(proof.chain(), &merkle_proof.chain);
        assert_eq!(proof.tx_hash(), &merkle_proof.tx_hash);
        assert_eq!(proof.block_number(), merkle_proof.block_number);
        assert_eq!(proof.log_index(), merkle_proof.log_index);
        assert_eq!(proof.contract(), &merkle_proof.contract);
        assert_eq!(proof.topic0(), &merkle_proof.topic0);
        assert_eq!(proof.data_hash(), &merkle_proof.data_hash);
        assert_eq!(proof.block_hash(), &merkle_proof.block_hash);
        assert_eq!(proof.confirmations(), merkle_proof.confirmations);
        assert_eq!(proof.proof_type(), "eth_receipt_merkle_v1");
    }

    #[test]
    fn proof_confirmations_optional() {
        let mut merkle_proof = test_merkle_proof();
        merkle_proof.confirmations = None;
        let proof = ExternalEventProofV1::EthReceiptMerkleProofV1(merkle_proof);
        assert_eq!(proof.confirmations(), None);
    }
}
