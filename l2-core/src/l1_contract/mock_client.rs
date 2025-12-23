//! Deterministic in-memory mock L1 client for tests and offline smoke paths.
#![forbid(unsafe_code)]

use super::{
    Base64Bytes, ContractError, IdempotencyKey, L1ChainStatus, L1Client, L1ClientError, L1Height,
    L1InclusionProof, L1SubmitResult, L1TimeMicros, L1TxId, L2BatchEnvelopeV1, NetworkId,
};
use base64::Engine as _;
use std::collections::HashMap;
use std::sync::Mutex;

#[derive(Debug)]
pub struct MockL1Client {
    network_id: NetworkId,
    height: Mutex<u64>,
    finalized_height: Mutex<u64>,
    time_micros: Mutex<u64>,
    submitted: Mutex<HashMap<IdempotencyKey, StoredSubmission>>,
}

#[derive(Debug, Clone)]
struct StoredSubmission {
    l1_tx_id: L1TxId,
    envelope_hash: [u8; 32],
}

impl MockL1Client {
    pub fn new(network_id: impl Into<String>) -> Self {
        Self {
            network_id: NetworkId(network_id.into()),
            height: Mutex::new(1),
            finalized_height: Mutex::new(0),
            time_micros: Mutex::new(1_700_000_000_000_000), // deterministic default
            submitted: Mutex::new(HashMap::new()),
        }
    }

    fn next_height(&self) -> u64 {
        let mut h = self.height.lock().expect("mutex poisoned");
        *h = h.saturating_add(1);
        *h
    }

    fn advance_time(&self, delta: u64) -> u64 {
        let mut t = self.time_micros.lock().expect("mutex poisoned");
        *t = t.saturating_add(delta);
        *t
    }

    fn maybe_finalize(&self, height: u64) {
        let mut f = self.finalized_height.lock().expect("mutex poisoned");
        // Finalize everything up to current height-1 to keep deterministic lag.
        let target = height.saturating_sub(1);
        if target > *f {
            *f = target;
        }
    }

    fn make_tx_id(key: &IdempotencyKey) -> L1TxId {
        let s = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(key.as_bytes());
        L1TxId(format!("mock:{s}"))
    }

    fn make_proof(key: &IdempotencyKey, envelope_hash: &[u8; 32]) -> Vec<u8> {
        // Deterministic but opaque: blake3(key || envelope_hash).
        let mut h = blake3::Hasher::new();
        h.update(key.as_bytes());
        h.update(envelope_hash);
        h.finalize().as_bytes().to_vec()
    }
}

impl Default for MockL1Client {
    fn default() -> Self {
        Self::new("mocknet")
    }
}

impl L1Client for MockL1Client {
    fn chain_status(&self) -> Result<L1ChainStatus, L1ClientError> {
        let height = *self.height.lock().expect("mutex poisoned");
        let finalized = *self.finalized_height.lock().expect("mutex poisoned");
        let time = *self.time_micros.lock().expect("mutex poisoned");
        Ok(L1ChainStatus {
            network_id: self.network_id.clone(),
            height: L1Height(height),
            finalized_height: Some(L1Height(finalized)),
            time_micros: L1TimeMicros(time),
        })
    }

    fn submit_batch(&self, batch: &L2BatchEnvelopeV1) -> Result<L1SubmitResult, L1ClientError> {
        batch.validate().map_err(|ContractError::Invalid(s)| L1ClientError::Protocol(s))?;

        let envelope_hash = batch
            .canonical_hash_blake3()
            .map_err(|e| L1ClientError::Serialization(e.to_string()))?;

        let mut submitted = self.submitted.lock().expect("mutex poisoned");

        if let Some(existing) = submitted.get(&batch.idempotency_key) {
            return Ok(L1SubmitResult {
                accepted: true,
                already_known: true,
                l1_tx_id: Some(existing.l1_tx_id.clone()),
                error_code: None,
                message: Some("already known".to_string()),
            });
        }

        let new_height = self.next_height();
        self.advance_time(10);
        self.maybe_finalize(new_height);

        let l1_tx_id = Self::make_tx_id(&batch.idempotency_key);
        submitted.insert(
            batch.idempotency_key,
            StoredSubmission {
                l1_tx_id: l1_tx_id.clone(),
                envelope_hash,
            },
        );

        Ok(L1SubmitResult {
            accepted: true,
            already_known: false,
            l1_tx_id: Some(l1_tx_id),
            error_code: None,
            message: None,
        })
    }

    fn get_inclusion(
        &self,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Option<L1InclusionProof>, L1ClientError> {
        let submitted = self.submitted.lock().expect("mutex poisoned");
        let stored = match submitted.get(idempotency_key) {
            Some(s) => s.clone(),
            None => return Ok(None),
        };

        let height = *self.height.lock().expect("mutex poisoned");
        Ok(Some(L1InclusionProof {
            l1_tx_id: stored.l1_tx_id,
            height: L1Height(height),
            finalized: false,
            proof: Base64Bytes(Self::make_proof(idempotency_key, &stored.envelope_hash)),
        }))
    }

    fn get_finality(&self, l1_tx_id: &L1TxId) -> Result<Option<L1InclusionProof>, L1ClientError> {
        let submitted = self.submitted.lock().expect("mutex poisoned");
        let mut found: Option<(IdempotencyKey, StoredSubmission)> = None;
        for (k, v) in submitted.iter() {
            if &v.l1_tx_id == l1_tx_id {
                found = Some((*k, v.clone()));
                break;
            }
        }
        let (key, stored) = match found {
            Some(x) => x,
            None => return Ok(None),
        };

        let finalized = *self.finalized_height.lock().expect("mutex poisoned");
        Ok(Some(L1InclusionProof {
            l1_tx_id: stored.l1_tx_id,
            height: L1Height(finalized),
            finalized: true,
            proof: Base64Bytes(Self::make_proof(&key, &stored.envelope_hash)),
        }))
    }
}

