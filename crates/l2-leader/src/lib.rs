#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]
#![deny(clippy::float_cmp)]
#![deny(clippy::cast_precision_loss)]
#![deny(clippy::cast_possible_truncation)]
#![deny(clippy::cast_possible_wrap)]
#![deny(clippy::cast_sign_loss)]
#![deny(clippy::disallowed_types)]

//! IPPAN L2 Leader Rotation Module
//!
//! Provides deterministic leader election based on:
//! - A fixed ordered set of leader public keys (ed25519, hex-encoded)
//! - Epoch-based rotation with configurable epoch duration
//! - Deterministic selection: `leader_for_epoch(epoch_idx, leader_set)`

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// 32-byte ed25519 public key (hex-encoded for config/display).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PubKey(pub [u8; 32]);

impl PubKey {
    /// Create a PubKey from a 32-byte array.
    pub const fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Parse a hex-encoded public key.
    pub fn from_hex(s: &str) -> Result<Self, LeaderError> {
        let bytes =
            hex::decode(s).map_err(|e| LeaderError::InvalidPubKey(format!("invalid hex: {e}")))?;
        if bytes.len() != 32 {
            return Err(LeaderError::InvalidPubKey(format!(
                "expected 32 bytes, got {}",
                bytes.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(Self(arr))
    }

    /// Return the hex representation of this public key.
    pub fn to_hex(&self) -> String {
        hex::encode(self.0)
    }

    /// Return the raw bytes.
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Serialize for PubKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for PubKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Self::from_hex(&s).map_err(serde::de::Error::custom)
    }
}

impl std::fmt::Display for PubKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// Ordered set of leader public keys.
///
/// The order matters for deterministic leader selection.
/// Parse from comma-separated hex-encoded pubkeys.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaderSet {
    leaders: Vec<PubKey>,
}

impl LeaderSet {
    /// Create an empty leader set.
    pub const fn empty() -> Self {
        Self { leaders: vec![] }
    }

    /// Create a leader set from a list of pubkeys.
    pub fn new(leaders: Vec<PubKey>) -> Self {
        Self { leaders }
    }

    /// Parse from comma-separated hex-encoded pubkeys.
    ///
    /// Example: `"aabbcc...,ddeeff...,112233..."`
    pub fn from_csv(s: &str) -> Result<Self, LeaderError> {
        if s.trim().is_empty() {
            return Ok(Self::empty());
        }
        let leaders: Result<Vec<PubKey>, _> = s
            .split(',')
            .map(|part| PubKey::from_hex(part.trim()))
            .collect();
        Ok(Self { leaders: leaders? })
    }

    /// Number of leaders in the set.
    pub fn len(&self) -> usize {
        self.leaders.len()
    }

    /// Check if the set is empty.
    pub fn is_empty(&self) -> bool {
        self.leaders.is_empty()
    }

    /// Get the leader at a given index.
    pub fn get(&self, idx: usize) -> Option<&PubKey> {
        self.leaders.get(idx)
    }

    /// Return slice of all leaders.
    pub fn as_slice(&self) -> &[PubKey] {
        &self.leaders
    }

    /// Check if a pubkey is in the leader set.
    pub fn contains(&self, pubkey: &PubKey) -> bool {
        self.leaders.contains(pubkey)
    }

    /// Find the index of a pubkey in the leader set.
    pub fn index_of(&self, pubkey: &PubKey) -> Option<usize> {
        self.leaders.iter().position(|p| p == pubkey)
    }
}

/// Configuration for leader rotation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaderConfig {
    /// Ordered set of leader public keys.
    pub leader_set: LeaderSet,
    /// Epoch duration in milliseconds.
    pub epoch_ms: u64,
    /// Genesis timestamp (milliseconds since UNIX epoch).
    /// All nodes must agree on this value.
    pub genesis_ms: u64,
    /// This node's public key.
    pub node_pubkey: PubKey,
}

impl Default for LeaderConfig {
    fn default() -> Self {
        Self {
            leader_set: LeaderSet::empty(),
            epoch_ms: 10_000, // 10 seconds
            genesis_ms: 0,
            node_pubkey: PubKey([0u8; 32]),
        }
    }
}

impl LeaderConfig {
    /// Create a new config from environment variables.
    ///
    /// Environment variables:
    /// - `L2_LEADER_SET`: comma-separated hex-encoded pubkeys
    /// - `L2_EPOCH_MS`: epoch duration in milliseconds (default 10000)
    /// - `L2_GENESIS_MS`: genesis timestamp in milliseconds
    /// - `L2_NODE_PUBKEY`: this node's public key (hex)
    pub fn from_env() -> Result<Self, LeaderError> {
        let leader_set_str = std::env::var("L2_LEADER_SET").unwrap_or_default();
        let leader_set = LeaderSet::from_csv(&leader_set_str)?;

        let epoch_ms: u64 = std::env::var("L2_EPOCH_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(10_000);

        let genesis_ms: u64 = std::env::var("L2_GENESIS_MS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        let node_pubkey = if let Ok(s) = std::env::var("L2_NODE_PUBKEY") {
            PubKey::from_hex(&s)?
        } else {
            PubKey([0u8; 32])
        };

        Ok(Self {
            leader_set,
            epoch_ms,
            genesis_ms,
            node_pubkey,
        })
    }

    /// Calculate the current epoch index from a given timestamp.
    ///
    /// `epoch_idx = floor((current_ms - genesis_ms) / epoch_ms)`
    pub fn epoch_at(&self, current_ms: u64) -> u64 {
        if current_ms <= self.genesis_ms || self.epoch_ms == 0 {
            return 0;
        }
        current_ms.saturating_sub(self.genesis_ms) / self.epoch_ms
    }

    /// Calculate the start time of a given epoch.
    pub fn epoch_start_ms(&self, epoch_idx: u64) -> u64 {
        self.genesis_ms
            .saturating_add(epoch_idx.saturating_mul(self.epoch_ms))
    }

    /// Calculate the end time of a given epoch.
    pub fn epoch_end_ms(&self, epoch_idx: u64) -> u64 {
        self.epoch_start_ms(epoch_idx).saturating_add(self.epoch_ms)
    }

    /// Get the elected leader for a given epoch.
    ///
    /// Returns `None` if the leader set is empty.
    pub fn leader_for_epoch(&self, epoch_idx: u64) -> Option<&PubKey> {
        leader_for_epoch(epoch_idx, &self.leader_set)
    }

    /// Check if this node is the elected leader for a given epoch.
    pub fn is_leader_at_epoch(&self, epoch_idx: u64) -> bool {
        match self.leader_for_epoch(epoch_idx) {
            Some(elected) => *elected == self.node_pubkey,
            None => false,
        }
    }

    /// Check if this node is currently the leader (using current timestamp).
    pub fn is_current_leader(&self, current_ms: u64) -> bool {
        let epoch = self.epoch_at(current_ms);
        self.is_leader_at_epoch(epoch)
    }
}

/// Errors that can occur in leader rotation logic.
#[derive(Debug, Error)]
pub enum LeaderError {
    #[error("invalid public key: {0}")]
    InvalidPubKey(String),
    #[error("no leaders configured")]
    NoLeaders,
    #[error("configuration error: {0}")]
    Config(String),
}

/// Deterministic leader selection for a given epoch.
///
/// The selection is deterministic across all nodes:
/// 1. Compute a hash of the epoch index
/// 2. Use the hash to select a leader from the set
///
/// This ensures all nodes with the same leader set and epoch
/// will elect the same leader.
///
/// Returns `None` if the leader set is empty.
pub fn leader_for_epoch(epoch_idx: u64, leader_set: &LeaderSet) -> Option<&PubKey> {
    if leader_set.is_empty() {
        return None;
    }

    // Simple deterministic selection: hash the epoch index and use modulo
    // This provides uniform distribution across leaders over time
    let mut hasher = Sha256::new();
    hasher.update(b"L2_LEADER_ELECTION_V1:");
    hasher.update(epoch_idx.to_le_bytes());
    let hash = hasher.finalize();

    // Use first 8 bytes of hash as u64 for index calculation
    let hash_bytes: [u8; 8] = hash[0..8].try_into().expect("slice has 8 bytes");
    let hash_value = u64::from_le_bytes(hash_bytes);

    // Modulo by leader count to get index
    let leader_count = leader_set.len();
    // Safe: we already checked leader_set is not empty
    let idx = usize::try_from(hash_value % (leader_count as u64)).unwrap_or(0);

    leader_set.get(idx)
}

/// Runtime state for leader rotation.
///
/// This can be used by the node to track current epoch and leader state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LeaderState {
    /// Current epoch index.
    pub epoch_idx: u64,
    /// Elected leader for current epoch.
    pub elected_leader: Option<PubKey>,
    /// Whether this node is the current leader.
    pub is_leader: bool,
    /// Epoch start timestamp (ms).
    pub epoch_start_ms: u64,
    /// Epoch end timestamp (ms).
    pub epoch_end_ms: u64,
}

impl LeaderState {
    /// Create a new leader state from config and current time.
    pub fn from_config(config: &LeaderConfig, current_ms: u64) -> Self {
        let epoch_idx = config.epoch_at(current_ms);
        let elected_leader = config.leader_for_epoch(epoch_idx).copied();
        let is_leader = config.is_leader_at_epoch(epoch_idx);
        let epoch_start_ms = config.epoch_start_ms(epoch_idx);
        let epoch_end_ms = config.epoch_end_ms(epoch_idx);

        Self {
            epoch_idx,
            elected_leader,
            is_leader,
            epoch_start_ms,
            epoch_end_ms,
        }
    }

    /// Update state for a new timestamp.
    pub fn update(&mut self, config: &LeaderConfig, current_ms: u64) {
        let new_epoch = config.epoch_at(current_ms);
        if new_epoch != self.epoch_idx {
            *self = Self::from_config(config, current_ms);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_pubkey(val: u8) -> PubKey {
        PubKey([val; 32])
    }

    #[test]
    fn pubkey_hex_roundtrip() {
        let pk = test_pubkey(0xAB);
        let hex = pk.to_hex();
        let parsed = PubKey::from_hex(&hex).unwrap();
        assert_eq!(pk, parsed);
    }

    #[test]
    fn pubkey_from_hex_invalid_length() {
        let result = PubKey::from_hex("aabbcc");
        assert!(result.is_err());
    }

    #[test]
    fn pubkey_from_hex_invalid_chars() {
        let result = PubKey::from_hex("gg");
        assert!(result.is_err());
    }

    #[test]
    fn leader_set_from_csv() {
        let pk1 = test_pubkey(0x01);
        let pk2 = test_pubkey(0x02);
        let csv = format!("{},{}", pk1.to_hex(), pk2.to_hex());
        let set = LeaderSet::from_csv(&csv).unwrap();
        assert_eq!(set.len(), 2);
        assert_eq!(set.get(0), Some(&pk1));
        assert_eq!(set.get(1), Some(&pk2));
    }

    #[test]
    fn leader_set_from_csv_empty() {
        let set = LeaderSet::from_csv("").unwrap();
        assert!(set.is_empty());
    }

    #[test]
    fn leader_set_contains() {
        let pk1 = test_pubkey(0x01);
        let pk2 = test_pubkey(0x02);
        let pk3 = test_pubkey(0x03);
        let set = LeaderSet::new(vec![pk1, pk2]);
        assert!(set.contains(&pk1));
        assert!(set.contains(&pk2));
        assert!(!set.contains(&pk3));
    }

    #[test]
    fn epoch_calculation() {
        let config = LeaderConfig {
            leader_set: LeaderSet::empty(),
            epoch_ms: 10_000,
            genesis_ms: 1_000_000,
            node_pubkey: test_pubkey(0x01),
        };

        // Before genesis
        assert_eq!(config.epoch_at(500_000), 0);

        // At genesis
        assert_eq!(config.epoch_at(1_000_000), 0);

        // First epoch
        assert_eq!(config.epoch_at(1_005_000), 0);

        // Second epoch
        assert_eq!(config.epoch_at(1_010_000), 1);
        assert_eq!(config.epoch_at(1_015_000), 1);

        // Later epochs
        assert_eq!(config.epoch_at(1_050_000), 5);
    }

    #[test]
    fn leader_for_epoch_deterministic() {
        let pk1 = test_pubkey(0x01);
        let pk2 = test_pubkey(0x02);
        let pk3 = test_pubkey(0x03);
        let set = LeaderSet::new(vec![pk1, pk2, pk3]);

        // Same epoch always returns same leader
        let leader_e0 = leader_for_epoch(0, &set);
        let leader_e0_again = leader_for_epoch(0, &set);
        assert_eq!(leader_e0, leader_e0_again);

        // Different epochs may return different leaders
        // (not testing specific values, just that function works)
        let _leader_e1 = leader_for_epoch(1, &set);
        let _leader_e100 = leader_for_epoch(100, &set);
    }

    #[test]
    fn leader_for_epoch_empty_set() {
        let set = LeaderSet::empty();
        assert!(leader_for_epoch(0, &set).is_none());
        assert!(leader_for_epoch(100, &set).is_none());
    }

    #[test]
    fn leader_for_epoch_single_leader() {
        let pk = test_pubkey(0x99);
        let set = LeaderSet::new(vec![pk]);

        // Single leader is always elected
        for epoch in 0..100 {
            assert_eq!(leader_for_epoch(epoch, &set), Some(&pk));
        }
    }

    #[test]
    fn leader_for_epoch_distribution() {
        // Test that leader selection distributes across leaders
        let leaders: Vec<PubKey> = (0..5).map(|i| test_pubkey(i)).collect();
        let set = LeaderSet::new(leaders.clone());

        let mut counts = vec![0usize; 5];
        for epoch in 0..1000 {
            if let Some(leader) = leader_for_epoch(epoch, &set) {
                if let Some(idx) = set.index_of(leader) {
                    counts[idx] += 1;
                }
            }
        }

        // Each leader should be selected at least some times
        for (i, count) in counts.iter().enumerate() {
            assert!(
                *count > 100,
                "leader {i} was selected only {count} times in 1000 epochs"
            );
        }
    }

    #[test]
    fn is_leader_at_epoch() {
        let pk1 = test_pubkey(0x01);
        let pk2 = test_pubkey(0x02);
        let set = LeaderSet::new(vec![pk1, pk2]);

        // Node is pk1
        let config1 = LeaderConfig {
            leader_set: set.clone(),
            epoch_ms: 10_000,
            genesis_ms: 0,
            node_pubkey: pk1,
        };

        // Node is pk2
        let config2 = LeaderConfig {
            leader_set: set,
            epoch_ms: 10_000,
            genesis_ms: 0,
            node_pubkey: pk2,
        };

        // For each epoch, exactly one of the two nodes should be leader
        for epoch in 0..100 {
            let is_leader_1 = config1.is_leader_at_epoch(epoch);
            let is_leader_2 = config2.is_leader_at_epoch(epoch);

            // Exactly one should be leader
            assert!(
                is_leader_1 ^ is_leader_2,
                "epoch {epoch}: both leaders or neither"
            );
        }
    }

    #[test]
    fn leader_state_creation() {
        let pk1 = test_pubkey(0x01);
        let pk2 = test_pubkey(0x02);
        let set = LeaderSet::new(vec![pk1, pk2]);

        let config = LeaderConfig {
            leader_set: set,
            epoch_ms: 10_000,
            genesis_ms: 0,
            node_pubkey: pk1,
        };

        let state = LeaderState::from_config(&config, 15_000);
        assert_eq!(state.epoch_idx, 1);
        assert!(state.elected_leader.is_some());
        assert_eq!(state.epoch_start_ms, 10_000);
        assert_eq!(state.epoch_end_ms, 20_000);
    }

    #[test]
    fn leader_state_update() {
        let pk1 = test_pubkey(0x01);
        let set = LeaderSet::new(vec![pk1]);

        let config = LeaderConfig {
            leader_set: set,
            epoch_ms: 10_000,
            genesis_ms: 0,
            node_pubkey: pk1,
        };

        let mut state = LeaderState::from_config(&config, 5_000);
        assert_eq!(state.epoch_idx, 0);

        // Update within same epoch - no change
        state.update(&config, 8_000);
        assert_eq!(state.epoch_idx, 0);

        // Update to new epoch - state changes
        state.update(&config, 15_000);
        assert_eq!(state.epoch_idx, 1);
    }

    #[test]
    fn pubkey_serde_roundtrip() {
        let pk = test_pubkey(0x42);
        let json = serde_json::to_string(&pk).unwrap();
        let parsed: PubKey = serde_json::from_str(&json).unwrap();
        assert_eq!(pk, parsed);
    }

    #[test]
    fn leader_set_index_of() {
        let pk1 = test_pubkey(0x01);
        let pk2 = test_pubkey(0x02);
        let pk3 = test_pubkey(0x03);
        let set = LeaderSet::new(vec![pk1, pk2]);
        assert_eq!(set.index_of(&pk1), Some(0));
        assert_eq!(set.index_of(&pk2), Some(1));
        assert_eq!(set.index_of(&pk3), None);
    }

    #[test]
    fn determinism_across_nodes() {
        // Simulate 3 nodes with the same leader set
        let pk1 = test_pubkey(0x11);
        let pk2 = test_pubkey(0x22);
        let pk3 = test_pubkey(0x33);
        let set = LeaderSet::new(vec![pk1, pk2, pk3]);

        // Create configs for each "node"
        let config_node1 = LeaderConfig {
            leader_set: set.clone(),
            epoch_ms: 10_000,
            genesis_ms: 1_000_000,
            node_pubkey: pk1,
        };
        let config_node2 = LeaderConfig {
            leader_set: set.clone(),
            epoch_ms: 10_000,
            genesis_ms: 1_000_000,
            node_pubkey: pk2,
        };
        let config_node3 = LeaderConfig {
            leader_set: set,
            epoch_ms: 10_000,
            genesis_ms: 1_000_000,
            node_pubkey: pk3,
        };

        // All nodes should agree on the leader for each epoch
        for epoch in 0..500 {
            let leader1 = config_node1.leader_for_epoch(epoch);
            let leader2 = config_node2.leader_for_epoch(epoch);
            let leader3 = config_node3.leader_for_epoch(epoch);

            assert_eq!(
                leader1, leader2,
                "nodes 1 and 2 disagree on leader for epoch {epoch}"
            );
            assert_eq!(
                leader2, leader3,
                "nodes 2 and 3 disagree on leader for epoch {epoch}"
            );
        }
    }

    #[test]
    fn epoch_boundary_consistency() {
        let pk = test_pubkey(0xAA);
        let set = LeaderSet::new(vec![pk]);

        let config = LeaderConfig {
            leader_set: set,
            epoch_ms: 10_000,
            genesis_ms: 0,
            node_pubkey: pk,
        };

        // Test exact epoch boundaries
        assert_eq!(config.epoch_at(0), 0);
        assert_eq!(config.epoch_at(9_999), 0);
        assert_eq!(config.epoch_at(10_000), 1);
        assert_eq!(config.epoch_at(10_001), 1);
        assert_eq!(config.epoch_at(19_999), 1);
        assert_eq!(config.epoch_at(20_000), 2);

        // Verify epoch start/end match
        assert_eq!(config.epoch_start_ms(0), 0);
        assert_eq!(config.epoch_end_ms(0), 10_000);
        assert_eq!(config.epoch_start_ms(1), 10_000);
        assert_eq!(config.epoch_end_ms(1), 20_000);
    }

    #[test]
    fn leader_config_from_csv_with_whitespace() {
        let pk1 = test_pubkey(0x01);
        let pk2 = test_pubkey(0x02);
        // Include whitespace around pubkeys
        let csv = format!(" {} , {} ", pk1.to_hex(), pk2.to_hex());
        let set = LeaderSet::from_csv(&csv).unwrap();
        assert_eq!(set.len(), 2);
        assert!(set.contains(&pk1));
        assert!(set.contains(&pk2));
    }
}
