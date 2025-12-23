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
    staged: Mutex<HashMap<IdempotencyKey, StagedDelays>>,
}

#[derive(Debug, Clone)]
struct StoredSubmission {
    l1_tx_id: L1TxId,
    envelope_hash: [u8; 32],
    inclusion_none_before_some: u32,
    finality_none_before_some: u32,
    inclusion_checks: u32,
    finality_checks: u32,
}

#[derive(Debug, Clone, Copy)]
struct StagedDelays {
    inclusion_none_before_some: u32,
    finality_none_before_some: u32,
}

impl MockL1Client {
    pub fn new(network_id: impl Into<String>) -> Self {
        Self {
            network_id: NetworkId(network_id.into()),
            height: Mutex::new(1),
            finalized_height: Mutex::new(0),
            time_micros: Mutex::new(1_700_000_000_000_000), // deterministic default
            submitted: Mutex::new(HashMap::new()),
            staged: Mutex::new(HashMap::new()),
        }
    }

    /// Configure staged inclusion/finality responses for a given idempotency key.
    ///
    /// - `inclusion_none_before_some = N`: the first N inclusion checks return None, then Some.
    /// - `finality_none_before_some = N`: the first N finality checks return None, then Some.
    pub fn set_staged_delays(
        &self,
        idempotency_key: &IdempotencyKey,
        inclusion_none_before_some: u32,
        finality_none_before_some: u32,
    ) {
        let mut staged = self.staged.lock().expect("mutex poisoned");
        staged.insert(
            *idempotency_key,
            StagedDelays {
                inclusion_none_before_some,
                finality_none_before_some,
            },
        );

        // If already submitted, update the stored thresholds too (so tests can configure after submit).
        let mut submitted = self.submitted.lock().expect("mutex poisoned");
        if let Some(s) = submitted.get_mut(idempotency_key) {
            s.inclusion_none_before_some = inclusion_none_before_some;
            s.finality_none_before_some = finality_none_before_some;
        }
    }

    /// Convenience helper to configure staged responses using base64url key string.
    pub fn set_staged_delays_b64(
        &self,
        idempotency_key_b64: &str,
        inclusion_none_before_some: u32,
        finality_none_before_some: u32,
    ) -> Result<(), String> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(idempotency_key_b64.as_bytes())
            .map_err(|e| format!("invalid base64url idempotency_key: {e}"))?;
        if bytes.len() != 32 {
            return Err(format!("expected 32 bytes, got {}", bytes.len()));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        let key = IdempotencyKey(out);
        self.set_staged_delays(&key, inclusion_none_before_some, finality_none_before_some);
        Ok(())
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
        batch
            .validate()
            .map_err(|ContractError::Invalid(s)| L1ClientError::DecodeError(s))?;

        let envelope_hash = batch
            .canonical_hash_blake3()
            .map_err(|e| L1ClientError::DecodeError(e.to_string()))?;

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
        let staged = self.staged.lock().expect("mutex poisoned");
        let delays = staged
            .get(&batch.idempotency_key)
            .copied()
            .unwrap_or(StagedDelays {
                inclusion_none_before_some: 0,
                finality_none_before_some: 0,
            });
        submitted.insert(
            batch.idempotency_key,
            StoredSubmission {
                l1_tx_id: l1_tx_id.clone(),
                envelope_hash,
                inclusion_none_before_some: delays.inclusion_none_before_some,
                finality_none_before_some: delays.finality_none_before_some,
                inclusion_checks: 0,
                finality_checks: 0,
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
        let mut submitted = self.submitted.lock().expect("mutex poisoned");
        let stored = match submitted.get_mut(idempotency_key) {
            Some(s) => s,
            None => return Ok(None),
        };

        stored.inclusion_checks = stored.inclusion_checks.saturating_add(1);
        if stored.inclusion_checks <= stored.inclusion_none_before_some {
            return Ok(None);
        }

        let height = *self.height.lock().expect("mutex poisoned");
        Ok(Some(L1InclusionProof {
            l1_tx_id: stored.l1_tx_id.clone(),
            height: L1Height(height),
            finalized: false,
            proof: Base64Bytes(Self::make_proof(idempotency_key, &stored.envelope_hash)),
        }))
    }

    fn get_finality(&self, l1_tx_id: &L1TxId) -> Result<Option<L1InclusionProof>, L1ClientError> {
        let mut submitted = self.submitted.lock().expect("mutex poisoned");
        // O(n) lookup is fine for test mock.
        let mut found: Option<(IdempotencyKey, &mut StoredSubmission)> = None;
        for (k, v) in submitted.iter_mut() {
            if &v.l1_tx_id == l1_tx_id {
                found = Some((*k, v));
                break;
            }
        }
        let (key, stored) = match found {
            Some(x) => x,
            None => return Ok(None),
        };

        stored.finality_checks = stored.finality_checks.saturating_add(1);
        if stored.finality_checks <= stored.finality_none_before_some {
            return Ok(None);
        }

        let finalized = *self.finalized_height.lock().expect("mutex poisoned");
        Ok(Some(L1InclusionProof {
            l1_tx_id: stored.l1_tx_id.clone(),
            height: L1Height(finalized),
            finalized: true,
            proof: Base64Bytes(Self::make_proof(&key, &stored.envelope_hash)),
        }))
    }
}
