#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SubjectScore {
    pub subject_id: [u8; 32],
    pub score: u64,
    /// Human-readable identifier, e.g. "@alice.ipn" or validator public key hex.
    pub label: String,
    /// Optional Ethereum address associated with this subject (if known).
    ///
    /// Reserved for future integration with a handle registry / ENS / IPPAN-exposed ETH identities.
    pub eth_address: Option<String>,
}

/// Local mapping cache value for subject_id -> subject metadata.
///
/// Note: this is currently used by the daemon to preserve a local mapping even though only scores
/// are pushed on-chain. `eth_address` is reserved for future integration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SubjectMeta {
    pub score: u64,
    pub label: String,
    pub eth_address: Option<String>,
}
