#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]
#![deny(clippy::float_cmp)]

//! IPPAN DATA – Data & Content Hub
//!
//! Handles content attestations for videos, articles, posts, datasets, and
//! other digital artefacts. Does NOT store content, only hashes + metadata.

use l2_core::{
    AccountId, FixedAmount, L1SettlementClient, L2Batch, L2BatchId, L2HubId, SettlementError,
    SettlementRequest, SettlementResult,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Logical identifier for the DATA Hub.
pub const HUB_ID: L2HubId = L2HubId::Data;

/// Hash of the content (e.g., BLAKE3 or SHA256 in hex).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, PartialOrd, Ord)]
pub struct ContentHash(pub String);

/// A single content attestation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Attestation {
    /// Hash of the content being attested.
    pub content_hash: ContentHash,
    /// IPPAN account (handle key) that issues the attestation.
    pub issuer: AccountId,
    /// Type of claim (authorship, publication, verification, ownership, etc.).
    pub claim_type: String,
    /// Optional URL where the content is accessible (social network, website, etc.).
    pub url: Option<String>,
    /// Optional platform identifier (e.g. "YouTube", "TikTok", "NewspaperSite").
    pub platform: Option<String>,
}

/// A DATA Hub transaction wraps an attestation with a local tx_id.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataTransaction {
    pub tx_id: String,
    pub attestation: Attestation,
}

/// In-memory registry of attestations keyed by content hash.
#[derive(Debug, Default, Clone)]
pub struct DataState {
    /// All attestations for a given content hash.
    pub by_hash: BTreeMap<ContentHash, Vec<Attestation>>,
}

#[derive(Debug, thiserror::Error)]
pub enum DataStateError {
    #[error("storage error: {0}")]
    Storage(String),
}

/// Abstract storage interface for DATA state.
pub trait DataStateStore {
    fn load_state(&self) -> DataState;
    fn save_state(&self, state: &DataState) -> Result<(), DataStateError>;
}

/// Simple in-memory implementation of the DATA store.
#[derive(Debug, Default)]
pub struct InMemoryDataStateStore {
    state: std::sync::Mutex<DataState>,
}

impl InMemoryDataStateStore {
    pub fn new() -> Self {
        Self {
            state: std::sync::Mutex::new(DataState::default()),
        }
    }
}

impl DataStateStore for InMemoryDataStateStore {
    fn load_state(&self) -> DataState {
        self.state.lock().expect("poisoned mutex").clone()
    }

    fn save_state(&self, state: &DataState) -> Result<(), DataStateError> {
        let mut guard = self
            .state
            .lock()
            .map_err(|e| DataStateError::Storage(format!("mutex poisoned: {e}")))?;
        *guard = state.clone();
        Ok(())
    }
}

impl DataState {
    /// Apply an attestation to the state, appending it to the list for the given hash.
    pub fn apply_attestation(&mut self, att: Attestation) -> Result<(), DataStateError> {
        self.by_hash
            .entry(att.content_hash.clone())
            .or_default()
            .push(att);
        Ok(())
    }
}

/// DATA Hub engine: applies attestations, persists state, and submits batches to CORE.
pub struct DataHubEngine<C: L1SettlementClient, S: DataStateStore> {
    client: C,
    store: S,
}

impl<C: L1SettlementClient, S: DataStateStore> DataHubEngine<C, S> {
    pub fn new(client: C, store: S) -> Self {
        Self { client, store }
    }

    pub fn submit_attestations(
        &self,
        batch_id: L2BatchId,
        txs: &[DataTransaction],
        fee: FixedAmount,
    ) -> Result<SettlementResult, SettlementError> {
        // Load state
        let mut state = self.store.load_state();

        // Apply all attestations
        for tx in txs {
            state
                .apply_attestation(tx.attestation.clone())
                .map_err(|e| SettlementError::Internal(format!("state error: {e}")))?;
        }

        // Save state
        self.store
            .save_state(&state)
            .map_err(|e| SettlementError::Internal(format!("save error: {e}")))?;

        // Build batch and submit to CORE
        let batch = L2Batch::new(HUB_ID, batch_id, txs.len() as u64);
        let request = SettlementRequest {
            hub: HUB_ID,
            batch,
            fee,
        };

        self.client.submit_settlement(request)
    }

    /// Read-only snapshot for inspection (e.g., for APIs or tests).
    pub fn snapshot_state(&self) -> DataState {
        self.store.load_state()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use l2_core::{L2BatchId, SettlementError};

    struct DummyClient;

    impl L1SettlementClient for DummyClient {
        fn submit_settlement(
            &self,
            request: SettlementRequest,
        ) -> Result<SettlementResult, SettlementError> {
            Ok(SettlementResult {
                hub: request.hub,
                batch_id: request.batch.batch_id,
                l1_reference: "dummy".to_string(),
                finalised: true,
            })
        }
    }

    #[test]
    fn data_hub_engine_records_attestations() {
        let client = DummyClient;
        let store = InMemoryDataStateStore::new();
        let engine = DataHubEngine::new(client, store);

        let hash = ContentHash("hash-123".to_string());
        let issuer = AccountId::new("acc-alice");

        let txs = vec![DataTransaction {
            tx_id: "tx-1".to_string(),
            attestation: Attestation {
                content_hash: hash.clone(),
                issuer: issuer.clone(),
                claim_type: "authorship".to_string(),
                url: Some("https://example.com/article".to_string()),
                platform: Some("ExampleNews".to_string()),
            },
        }];

        let batch_id = L2BatchId("batch-001".to_string());
        let fee = FixedAmount::from_units(1, 6);

        let result = engine
            .submit_attestations(batch_id.clone(), &txs, fee)
            .unwrap();
        assert_eq!(result.hub, HUB_ID);
        assert_eq!(result.batch_id.0, batch_id.0);

        let snapshot = engine.snapshot_state();
        let list = snapshot.by_hash.get(&hash).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].issuer.0, issuer.0);
    }
}
