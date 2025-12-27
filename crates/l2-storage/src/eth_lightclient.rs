//! Ethereum Light Client State Storage.
//!
//! This module provides persistent storage for Ethereum PoS light client state,
//! including sync committee tracking and finalized header management.
//!
//! ## Features
//!
//! - Persist light client store (finalized header, sync committees)
//! - Track finalized execution headers
//! - Idempotent update application (via update_id tracking)
//! - Query finalization status for execution blocks
//!
//! ## Trust Model
//!
//! This storage module does not perform cryptographic verification.
//! It assumes all data written has been verified by the light client verifier.

use l2_core::eth_lightclient::{
    BeaconBlockHeaderV1, ExecutionPayloadHeaderV1, LightClientBootstrapV1, LightClientStatusV1,
    LightClientStoreV1, LightClientUpdateV1, Root, SyncCommitteeV1,
};
use sled::Tree;
use thiserror::Error;
use tracing::{debug, info};

/// JSON encode for storage.
fn json_encode<T: serde::Serialize>(value: &T) -> Result<Vec<u8>, EthLightClientStorageError> {
    serde_json::to_vec(value)
        .map_err(|e| EthLightClientStorageError::Encoding(format!("json encode: {}", e)))
}

/// JSON decode from storage.
fn json_decode<T: serde::de::DeserializeOwned>(
    bytes: &[u8],
) -> Result<T, EthLightClientStorageError> {
    serde_json::from_slice(bytes)
        .map_err(|e| EthLightClientStorageError::Encoding(format!("json decode: {}", e)))
}

/// Errors from Ethereum light client storage operations.
#[derive(Debug, Error)]
pub enum EthLightClientStorageError {
    #[error("storage error: {0}")]
    Sled(#[from] sled::Error),

    #[error("encoding error: {0}")]
    Encoding(String),

    #[error("not bootstrapped")]
    NotBootstrapped,

    #[error("already bootstrapped")]
    AlreadyBootstrapped,

    #[error("update already applied: {0}")]
    UpdateAlreadyApplied(String),

    #[error("invalid state: {0}")]
    InvalidState(String),
}

/// Key constants for storage.
const KEY_LC_STORE: &[u8] = b"lc_store";
const KEY_BOOTSTRAP_ID: &[u8] = b"bootstrap_id";
const KEY_UPDATES_APPLIED: &[u8] = b"updates_applied";
const KEY_LAST_UPDATE_MS: &[u8] = b"last_update_ms";

/// Ethereum Light Client Storage.
///
/// Provides persistent storage for light client state.
pub struct EthLightClientStorage {
    /// Main light client state.
    lc_state: Tree,

    /// Applied update IDs for idempotency.
    applied_updates: Tree,

    /// Finalized execution headers by block hash.
    finalized_exec_headers: Tree,

    /// Finalized execution headers by block number (for range queries).
    finalized_exec_by_number: Tree,

    /// Chain ID for this storage.
    chain_id: u64,
}

impl EthLightClientStorage {
    /// Create a new light client storage from a sled database.
    pub fn new(db: &sled::Db, chain_id: u64) -> Result<Self, EthLightClientStorageError> {
        let prefix = format!("eth_lc_{}", chain_id);
        Ok(Self {
            lc_state: db.open_tree(format!("{}_state", prefix))?,
            applied_updates: db.open_tree(format!("{}_updates", prefix))?,
            finalized_exec_headers: db.open_tree(format!("{}_exec_headers", prefix))?,
            finalized_exec_by_number: db.open_tree(format!("{}_exec_by_num", prefix))?,
            chain_id,
        })
    }

    /// Get the chain ID.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Check if the light client has been bootstrapped.
    pub fn is_bootstrapped(&self) -> Result<bool, EthLightClientStorageError> {
        Ok(self.lc_state.contains_key(KEY_LC_STORE)?)
    }

    /// Get the current light client store state.
    pub fn get_lc_state(&self) -> Result<Option<LightClientStoreV1>, EthLightClientStorageError> {
        match self.lc_state.get(KEY_LC_STORE)? {
            Some(bytes) => {
                let store: LightClientStoreV1 = json_decode(&bytes)?;
                Ok(Some(store))
            }
            None => Ok(None),
        }
    }

    /// Get the light client status summary.
    pub fn get_status(&self) -> Result<LightClientStatusV1, EthLightClientStorageError> {
        let store = self.get_lc_state()?;
        let updates_applied = self.get_updates_applied_count()?;
        let last_update_ms = self.get_last_update_ms()?;

        match store {
            Some(s) => Ok(LightClientStatusV1 {
                bootstrapped: true,
                current_period: s.current_period(),
                finalized_slot: s.finalized_slot(),
                finalized_execution_number: s.finalized_execution_block_number(),
                finalized_execution_hash: s.finalized_execution_block_hash().copied(),
                has_next_sync_committee: s.next_sync_committee.is_some(),
                updates_applied,
                last_update_ms,
            }),
            None => Ok(LightClientStatusV1 {
                bootstrapped: false,
                current_period: 0,
                finalized_slot: 0,
                finalized_execution_number: None,
                finalized_execution_hash: None,
                has_next_sync_committee: false,
                updates_applied: 0,
                last_update_ms: None,
            }),
        }
    }

    /// Apply bootstrap data to initialize the light client.
    ///
    /// This can only be called once unless `allow_reset` is true.
    pub fn apply_bootstrap(
        &self,
        bootstrap: &LightClientBootstrapV1,
        execution_header: Option<&ExecutionPayloadHeaderV1>,
        now_ms: u64,
        allow_reset: bool,
    ) -> Result<(), EthLightClientStorageError> {
        // Check if already bootstrapped
        if self.is_bootstrapped()? && !allow_reset {
            return Err(EthLightClientStorageError::AlreadyBootstrapped);
        }

        // Create initial store
        let store = LightClientStoreV1 {
            finalized_header: bootstrap.header.clone(),
            current_sync_committee: bootstrap.current_sync_committee.clone(),
            next_sync_committee: None,
            optimistic_header: None,
            finalized_execution_header: execution_header.cloned(),
            updated_at_ms: now_ms,
        };

        // Store the state
        let bytes = json_encode(&store)?;
        self.lc_state.insert(KEY_LC_STORE, bytes)?;

        // Store bootstrap ID
        let bootstrap_id = bootstrap.bootstrap_id();
        self.lc_state.insert(KEY_BOOTSTRAP_ID, &bootstrap_id)?;

        // Reset counters
        self.lc_state
            .insert(KEY_UPDATES_APPLIED, &0u64.to_le_bytes())?;
        self.lc_state
            .insert(KEY_LAST_UPDATE_MS, &now_ms.to_le_bytes())?;

        // Store execution header if provided
        if let Some(exec_header) = execution_header {
            self.store_finalized_execution_header(exec_header)?;
        }

        info!(
            chain_id = self.chain_id,
            slot = bootstrap.header.slot,
            period = bootstrap.sync_committee_period(),
            "light client bootstrapped"
        );

        Ok(())
    }

    /// Apply an update to advance the light client state.
    ///
    /// This is idempotent - applying the same update twice is a no-op.
    pub fn apply_update(
        &self,
        update: &LightClientUpdateV1,
        execution_header: Option<&ExecutionPayloadHeaderV1>,
        now_ms: u64,
    ) -> Result<bool, EthLightClientStorageError> {
        // Must be bootstrapped
        let mut store = self
            .get_lc_state()?
            .ok_or(EthLightClientStorageError::NotBootstrapped)?;

        // Check idempotency
        let update_id = update.update_id();
        let update_key = hex::encode(update_id);
        if self.applied_updates.contains_key(update_key.as_bytes())? {
            debug!(
                chain_id = self.chain_id,
                update_id = %update_key,
                "update already applied"
            );
            return Ok(false);
        }

        // Update finalized header
        store.finalized_header = update.finalized_header.clone();

        // Update sync committee if present
        if let Some(ref next_committee) = update.next_sync_committee {
            // Rotate: next becomes current
            if let Some(ref current_next) = store.next_sync_committee {
                store.current_sync_committee = current_next.clone();
            }
            store.next_sync_committee = Some(next_committee.clone());
        }

        // Update optimistic header
        store.optimistic_header = Some(update.attested_header.clone());

        // Update execution header if provided
        if let Some(exec_header) = execution_header {
            store.finalized_execution_header = Some(exec_header.clone());
            self.store_finalized_execution_header(exec_header)?;
        }

        store.updated_at_ms = now_ms;

        // Persist state
        let bytes = json_encode(&store)?;
        self.lc_state.insert(KEY_LC_STORE, bytes)?;

        // Mark update as applied
        self.applied_updates
            .insert(update_key.as_bytes(), &now_ms.to_le_bytes())?;

        // Update counters
        let count = self.get_updates_applied_count()?.saturating_add(1);
        self.lc_state
            .insert(KEY_UPDATES_APPLIED, &count.to_le_bytes())?;
        self.lc_state
            .insert(KEY_LAST_UPDATE_MS, &now_ms.to_le_bytes())?;

        debug!(
            chain_id = self.chain_id,
            finalized_slot = update.finalized_header.slot,
            update_id = %update_key,
            "applied light client update"
        );

        Ok(true)
    }

    /// Store a finalized execution header.
    fn store_finalized_execution_header(
        &self,
        header: &ExecutionPayloadHeaderV1,
    ) -> Result<(), EthLightClientStorageError> {
        let bytes = json_encode(header)?;

        // Store by block hash
        let hash_key = hex::encode(header.block_hash);
        self.finalized_exec_headers
            .insert(hash_key.as_bytes(), bytes.as_slice())?;

        // Store by block number (for range queries)
        let num_key = header.block_number.to_be_bytes();
        self.finalized_exec_by_number
            .insert(num_key, &header.block_hash[..])?;

        Ok(())
    }

    /// Check if an execution block hash is finalized.
    pub fn is_execution_header_finalized(
        &self,
        block_hash: &Root,
    ) -> Result<bool, EthLightClientStorageError> {
        let key = hex::encode(block_hash);
        Ok(self.finalized_exec_headers.contains_key(key.as_bytes())?)
    }

    /// Get a finalized execution header by block hash.
    pub fn get_finalized_execution_header(
        &self,
        block_hash: &Root,
    ) -> Result<Option<ExecutionPayloadHeaderV1>, EthLightClientStorageError> {
        let key = hex::encode(block_hash);
        match self.finalized_exec_headers.get(key.as_bytes())? {
            Some(bytes) => {
                let header: ExecutionPayloadHeaderV1 = json_decode(&bytes)?;
                Ok(Some(header))
            }
            None => Ok(None),
        }
    }

    /// Get the finalized execution tip (highest finalized block number).
    pub fn finalized_execution_tip_number(
        &self,
    ) -> Result<Option<u64>, EthLightClientStorageError> {
        // Get the last (highest) entry in the by-number index
        match self.finalized_exec_by_number.last()? {
            Some((key, _)) => {
                if key.len() != 8 {
                    return Err(EthLightClientStorageError::InvalidState(
                        "invalid block number key".to_string(),
                    ));
                }
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&key);
                Ok(Some(u64::from_be_bytes(bytes)))
            }
            None => Ok(None),
        }
    }

    /// Get the finalized execution tip block hash.
    pub fn finalized_execution_tip(
        &self,
    ) -> Result<Option<(u64, Root)>, EthLightClientStorageError> {
        match self.finalized_exec_by_number.last()? {
            Some((key, value)) => {
                if key.len() != 8 || value.len() != 32 {
                    return Err(EthLightClientStorageError::InvalidState(
                        "invalid block index entry".to_string(),
                    ));
                }
                let mut num_bytes = [0u8; 8];
                num_bytes.copy_from_slice(&key);
                let mut hash_bytes = [0u8; 32];
                hash_bytes.copy_from_slice(&value);
                Ok(Some((u64::from_be_bytes(num_bytes), hash_bytes)))
            }
            None => Ok(None),
        }
    }

    /// Compute confirmations for an execution block.
    ///
    /// Returns the number of finalized blocks since this block.
    /// Returns `None` if the block is not finalized.
    pub fn execution_confirmations(
        &self,
        block_hash: &Root,
    ) -> Result<Option<u64>, EthLightClientStorageError> {
        // Get the header to find its block number
        let header = match self.get_finalized_execution_header(block_hash)? {
            Some(h) => h,
            None => return Ok(None),
        };

        // Get the tip number
        let tip_number = match self.finalized_execution_tip_number()? {
            Some(n) => n,
            None => return Ok(None),
        };

        // Compute confirmations: tip - block + 1
        if tip_number >= header.block_number {
            Ok(Some(tip_number - header.block_number + 1))
        } else {
            Ok(None)
        }
    }

    /// Get the current sync committee.
    pub fn get_current_sync_committee(
        &self,
    ) -> Result<Option<SyncCommitteeV1>, EthLightClientStorageError> {
        self.get_lc_state()
            .map(|opt| opt.map(|s| s.current_sync_committee))
    }

    /// Get the next sync committee (if known).
    pub fn get_next_sync_committee(
        &self,
    ) -> Result<Option<SyncCommitteeV1>, EthLightClientStorageError> {
        self.get_lc_state()
            .map(|opt| opt.and_then(|s| s.next_sync_committee))
    }

    /// Get the finalized beacon header.
    pub fn get_finalized_beacon_header(
        &self,
    ) -> Result<Option<BeaconBlockHeaderV1>, EthLightClientStorageError> {
        self.get_lc_state()
            .map(|opt| opt.map(|s| s.finalized_header))
    }

    /// Get the bootstrap ID.
    pub fn get_bootstrap_id(&self) -> Result<Option<Root>, EthLightClientStorageError> {
        match self.lc_state.get(KEY_BOOTSTRAP_ID)? {
            Some(bytes) => {
                if bytes.len() != 32 {
                    return Err(EthLightClientStorageError::InvalidState(
                        "invalid bootstrap_id length".to_string(),
                    ));
                }
                let mut id = [0u8; 32];
                id.copy_from_slice(&bytes);
                Ok(Some(id))
            }
            None => Ok(None),
        }
    }

    /// Get the count of applied updates.
    pub fn get_updates_applied_count(&self) -> Result<u64, EthLightClientStorageError> {
        match self.lc_state.get(KEY_UPDATES_APPLIED)? {
            Some(bytes) => {
                if bytes.len() != 8 {
                    return Err(EthLightClientStorageError::InvalidState(
                        "invalid updates_applied length".to_string(),
                    ));
                }
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&bytes);
                Ok(u64::from_le_bytes(arr))
            }
            None => Ok(0),
        }
    }

    /// Get the timestamp of the last update.
    pub fn get_last_update_ms(&self) -> Result<Option<u64>, EthLightClientStorageError> {
        match self.lc_state.get(KEY_LAST_UPDATE_MS)? {
            Some(bytes) => {
                if bytes.len() != 8 {
                    return Err(EthLightClientStorageError::InvalidState(
                        "invalid last_update_ms length".to_string(),
                    ));
                }
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&bytes);
                Ok(Some(u64::from_le_bytes(arr)))
            }
            None => Ok(None),
        }
    }

    /// Check if an update has been applied.
    pub fn is_update_applied(&self, update_id: &Root) -> Result<bool, EthLightClientStorageError> {
        let key = hex::encode(update_id);
        Ok(self.applied_updates.contains_key(key.as_bytes())?)
    }

    /// List applied update IDs (up to limit).
    pub fn list_applied_updates(
        &self,
        limit: usize,
    ) -> Result<Vec<(Root, u64)>, EthLightClientStorageError> {
        let mut results = Vec::new();
        for result in self.applied_updates.iter() {
            if results.len() >= limit {
                break;
            }
            let (key, value) = result?;
            let key_str = String::from_utf8_lossy(&key);
            let key_hex = key_str.strip_prefix("0x").unwrap_or(&key_str);
            if let Ok(bytes) = hex::decode(key_hex) {
                if bytes.len() == 32 && value.len() == 8 {
                    let mut id = [0u8; 32];
                    id.copy_from_slice(&bytes);
                    let mut ts_bytes = [0u8; 8];
                    ts_bytes.copy_from_slice(&value);
                    let timestamp = u64::from_le_bytes(ts_bytes);
                    results.push((id, timestamp));
                }
            }
        }
        Ok(results)
    }

    /// Count finalized execution headers.
    pub fn count_finalized_headers(&self) -> Result<u64, EthLightClientStorageError> {
        let count = self.finalized_exec_headers.len();
        Ok(u64::try_from(count).unwrap_or(u64::MAX))
    }

    /// Reset the light client state (for testing/devnet).
    pub fn reset(&self) -> Result<(), EthLightClientStorageError> {
        self.lc_state.clear()?;
        self.applied_updates.clear()?;
        self.finalized_exec_headers.clear()?;
        self.finalized_exec_by_number.clear()?;
        info!(chain_id = self.chain_id, "light client state reset");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use l2_core::eth_lightclient::{SyncCommitteeV1, SYNC_COMMITTEE_SIZE};
    use tempfile::tempdir;

    fn test_db() -> sled::Db {
        let dir = tempdir().expect("tmpdir");
        sled::open(dir.path()).expect("open")
    }

    fn test_beacon_header(slot: u64) -> BeaconBlockHeaderV1 {
        BeaconBlockHeaderV1 {
            slot,
            proposer_index: 12345,
            parent_root: [0x11; 32],
            state_root: [0x22; 32],
            body_root: [0x33; 32],
        }
    }

    fn test_execution_header(block_number: u64) -> ExecutionPayloadHeaderV1 {
        ExecutionPayloadHeaderV1 {
            parent_hash: [0x11; 32],
            fee_recipient: [0x22; 20],
            state_root: [0x33; 32],
            receipts_root: [0x44; 32],
            logs_bloom: [0x00; 256],
            prev_randao: [0x55; 32],
            block_number,
            gas_limit: 30_000_000,
            gas_used: 15_000_000,
            timestamp: 1_700_000_000 + block_number,
            extra_data: vec![],
            base_fee_per_gas: 10_000_000_000,
            block_hash: {
                // Make hash unique based on block number
                let mut hash = [0x66; 32];
                hash[0..8].copy_from_slice(&block_number.to_le_bytes());
                hash
            },
            transactions_root: [0x77; 32],
            withdrawals_root: [0x88; 32],
            blob_gas_used: 0,
            excess_blob_gas: 0,
        }
    }

    fn test_sync_committee() -> SyncCommitteeV1 {
        SyncCommitteeV1 {
            pubkeys: vec![[0xAA; 48]; SYNC_COMMITTEE_SIZE],
            aggregate_pubkey: [0xBB; 48],
        }
    }

    fn test_bootstrap() -> LightClientBootstrapV1 {
        LightClientBootstrapV1 {
            header: test_beacon_header(8_000_000),
            current_sync_committee: test_sync_committee(),
            current_sync_committee_branch: vec![[0xCC; 32]; 5],
        }
    }

    #[test]
    fn storage_new() {
        let db = test_db();
        let storage = EthLightClientStorage::new(&db, 1).expect("create");
        assert_eq!(storage.chain_id(), 1);
        assert!(!storage.is_bootstrapped().unwrap());
    }

    #[test]
    fn apply_bootstrap() {
        let db = test_db();
        let storage = EthLightClientStorage::new(&db, 1).expect("create");

        let bootstrap = test_bootstrap();
        let exec_header = test_execution_header(18_000_000);

        storage
            .apply_bootstrap(&bootstrap, Some(&exec_header), 1_700_000_000_000, false)
            .expect("bootstrap");

        assert!(storage.is_bootstrapped().unwrap());

        let state = storage.get_lc_state().unwrap().unwrap();
        assert_eq!(state.finalized_header.slot, 8_000_000);
        assert!(state.finalized_execution_header.is_some());
    }

    #[test]
    fn apply_bootstrap_twice_fails() {
        let db = test_db();
        let storage = EthLightClientStorage::new(&db, 1).expect("create");

        let bootstrap = test_bootstrap();

        storage
            .apply_bootstrap(&bootstrap, None, 1_700_000_000_000, false)
            .expect("bootstrap");

        let result = storage.apply_bootstrap(&bootstrap, None, 1_700_000_001_000, false);
        assert!(matches!(
            result,
            Err(EthLightClientStorageError::AlreadyBootstrapped)
        ));
    }

    #[test]
    fn apply_bootstrap_with_reset() {
        let db = test_db();
        let storage = EthLightClientStorage::new(&db, 1).expect("create");

        let bootstrap = test_bootstrap();

        storage
            .apply_bootstrap(&bootstrap, None, 1_700_000_000_000, false)
            .expect("bootstrap");

        // With allow_reset = true, should succeed
        let result = storage.apply_bootstrap(&bootstrap, None, 1_700_000_001_000, true);
        assert!(result.is_ok());
    }

    #[test]
    fn apply_update() {
        let db = test_db();
        let storage = EthLightClientStorage::new(&db, 1).expect("create");

        // Bootstrap first
        let bootstrap = test_bootstrap();
        storage
            .apply_bootstrap(&bootstrap, None, 1_700_000_000_000, false)
            .expect("bootstrap");

        // Apply update
        let update = LightClientUpdateV1 {
            attested_header: test_beacon_header(8_001_000),
            next_sync_committee: None,
            next_sync_committee_branch: None,
            finalized_header: test_beacon_header(8_000_900),
            finality_branch: vec![[0xDD; 32]; 6],
            sync_aggregate: l2_core::eth_lightclient::SyncAggregateV1 {
                sync_committee_bits: vec![0xFF; 64],
                sync_committee_signature: [0xEE; 96],
            },
            signature_slot: 8_001_001,
        };

        let exec_header = test_execution_header(18_000_100);

        let was_new = storage
            .apply_update(&update, Some(&exec_header), 1_700_000_001_000)
            .expect("apply");
        assert!(was_new);

        // Check state was updated
        let state = storage.get_lc_state().unwrap().unwrap();
        assert_eq!(state.finalized_header.slot, 8_000_900);

        // Check update count
        assert_eq!(storage.get_updates_applied_count().unwrap(), 1);
    }

    #[test]
    fn apply_update_idempotent() {
        let db = test_db();
        let storage = EthLightClientStorage::new(&db, 1).expect("create");

        let bootstrap = test_bootstrap();
        storage
            .apply_bootstrap(&bootstrap, None, 1_700_000_000_000, false)
            .expect("bootstrap");

        let update = LightClientUpdateV1 {
            attested_header: test_beacon_header(8_001_000),
            next_sync_committee: None,
            next_sync_committee_branch: None,
            finalized_header: test_beacon_header(8_000_900),
            finality_branch: vec![[0xDD; 32]; 6],
            sync_aggregate: l2_core::eth_lightclient::SyncAggregateV1 {
                sync_committee_bits: vec![0xFF; 64],
                sync_committee_signature: [0xEE; 96],
            },
            signature_slot: 8_001_001,
        };

        // Apply twice
        let was_new1 = storage
            .apply_update(&update, None, 1_700_000_001_000)
            .expect("apply1");
        let was_new2 = storage
            .apply_update(&update, None, 1_700_000_002_000)
            .expect("apply2");

        assert!(was_new1);
        assert!(!was_new2);

        // Count should be 1 (not 2)
        assert_eq!(storage.get_updates_applied_count().unwrap(), 1);
    }

    #[test]
    fn execution_header_finalization() {
        let db = test_db();
        let storage = EthLightClientStorage::new(&db, 1).expect("create");

        let bootstrap = test_bootstrap();
        let exec1 = test_execution_header(18_000_000);

        storage
            .apply_bootstrap(&bootstrap, Some(&exec1), 1_700_000_000_000, false)
            .expect("bootstrap");

        // Check it's finalized
        assert!(storage
            .is_execution_header_finalized(&exec1.block_hash)
            .unwrap());

        // Check tip
        let (tip_num, tip_hash) = storage.finalized_execution_tip().unwrap().unwrap();
        assert_eq!(tip_num, 18_000_000);
        assert_eq!(tip_hash, exec1.block_hash);

        // Check confirmations (only one block)
        let confs = storage
            .execution_confirmations(&exec1.block_hash)
            .unwrap()
            .unwrap();
        assert_eq!(confs, 1);
    }

    #[test]
    fn execution_confirmations_multiple_blocks() {
        let db = test_db();
        let storage = EthLightClientStorage::new(&db, 1).expect("create");

        let bootstrap = test_bootstrap();
        let exec1 = test_execution_header(18_000_000);
        storage
            .apply_bootstrap(&bootstrap, Some(&exec1), 1_700_000_000_000, false)
            .expect("bootstrap");

        // Add more blocks via updates
        for i in 1..=5 {
            let update = LightClientUpdateV1 {
                attested_header: test_beacon_header(8_000_000 + i * 1000),
                next_sync_committee: None,
                next_sync_committee_branch: None,
                finalized_header: test_beacon_header(8_000_000 + i * 900),
                finality_branch: vec![[0xDD; 32]; 6],
                sync_aggregate: l2_core::eth_lightclient::SyncAggregateV1 {
                    sync_committee_bits: vec![0xFF; 64],
                    sync_committee_signature: [0xEE; 96],
                },
                signature_slot: 8_000_000 + i * 1000 + 1,
            };
            let exec = test_execution_header(18_000_000 + i);
            storage
                .apply_update(&update, Some(&exec), 1_700_000_000_000 + i * 1000)
                .expect("update");
        }

        // Check tip is block 18_000_005
        let tip_num = storage.finalized_execution_tip_number().unwrap().unwrap();
        assert_eq!(tip_num, 18_000_005);

        // Check confirmations for first block
        let confs = storage
            .execution_confirmations(&exec1.block_hash)
            .unwrap()
            .unwrap();
        assert_eq!(confs, 6); // 18_000_005 - 18_000_000 + 1
    }

    #[test]
    fn get_status_not_bootstrapped() {
        let db = test_db();
        let storage = EthLightClientStorage::new(&db, 1).expect("create");

        let status = storage.get_status().unwrap();
        assert!(!status.bootstrapped);
        assert_eq!(status.current_period, 0);
        assert_eq!(status.finalized_slot, 0);
    }

    #[test]
    fn get_status_bootstrapped() {
        let db = test_db();
        let storage = EthLightClientStorage::new(&db, 1).expect("create");

        let bootstrap = test_bootstrap();
        let exec = test_execution_header(18_000_000);
        storage
            .apply_bootstrap(&bootstrap, Some(&exec), 1_700_000_000_000, false)
            .expect("bootstrap");

        let status = storage.get_status().unwrap();
        assert!(status.bootstrapped);
        assert_eq!(status.finalized_slot, 8_000_000);
        assert_eq!(status.finalized_execution_number, Some(18_000_000));
        assert!(!status.has_next_sync_committee);
    }

    #[test]
    fn reset_clears_state() {
        let db = test_db();
        let storage = EthLightClientStorage::new(&db, 1).expect("create");

        let bootstrap = test_bootstrap();
        storage
            .apply_bootstrap(&bootstrap, None, 1_700_000_000_000, false)
            .expect("bootstrap");
        assert!(storage.is_bootstrapped().unwrap());

        storage.reset().expect("reset");
        assert!(!storage.is_bootstrapped().unwrap());
    }
}
