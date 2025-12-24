#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]
#![deny(clippy::float_cmp)]
#![deny(clippy::cast_precision_loss)]
#![deny(clippy::cast_possible_truncation)]
#![deny(clippy::cast_possible_wrap)]
#![deny(clippy::cast_sign_loss)]
#![deny(clippy::disallowed_types)]

use std::path::Path;

use l2_core::forced_inclusion::{ForcedInclusionStatus, InclusionTicket};
use l2_core::{canonical_decode, canonical_encode, canonical_hash, Batch, Hash32, Receipt, Tx};
use serde::{Deserialize, Serialize};
use sled::Tree;
use thiserror::Error;
use tracing::info;

pub const SCHEMA_VERSION: &str = "2";
const META_SCHEMA_KEY: &[u8] = b"schema_version";

#[derive(Debug, Error)]
pub enum StorageError {
    #[error("storage error: {0}")]
    Sled(#[from] sled::Error),
    #[error("canonical encoding error: {0}")]
    Canonical(#[from] l2_core::CanonicalError),
    #[error("schema mismatch: expected {expected}, found {found:?}")]
    SchemaMismatch {
        expected: String,
        found: Option<String>,
    },
}

/// State of a batch posting to L1 (IPPAN CORE).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PostingState {
    /// Batch is ready to be posted but not yet sent.
    Pending {
        /// Timestamp when batch was created (ms since epoch).
        created_at_ms: u64,
    },
    /// Batch has been posted to L1, awaiting confirmation.
    Posted {
        /// L1 transaction hash/id.
        l1_tx: String,
        /// Timestamp when the batch was posted (ms since epoch).
        posted_at_ms: u64,
    },
    /// Batch posting has been confirmed on L1.
    Confirmed {
        /// L1 transaction hash/id.
        l1_tx: String,
        /// Timestamp when confirmation was received (ms since epoch).
        confirmed_at_ms: u64,
    },
    /// Batch posting failed.
    Failed {
        /// Reason for failure.
        reason: String,
        /// Timestamp when the failure occurred (ms since epoch).
        failed_at_ms: u64,
        /// Number of retry attempts made.
        retry_count: u32,
    },
}

impl PostingState {
    /// Create a new Pending state.
    pub fn pending(created_at_ms: u64) -> Self {
        Self::Pending { created_at_ms }
    }

    /// Create a new Posted state.
    pub fn posted(l1_tx: String, posted_at_ms: u64) -> Self {
        Self::Posted {
            l1_tx,
            posted_at_ms,
        }
    }

    /// Create a new Confirmed state.
    pub fn confirmed(l1_tx: String, confirmed_at_ms: u64) -> Self {
        Self::Confirmed {
            l1_tx,
            confirmed_at_ms,
        }
    }

    /// Create a new Failed state.
    pub fn failed(reason: String, failed_at_ms: u64, retry_count: u32) -> Self {
        Self::Failed {
            reason,
            failed_at_ms,
            retry_count,
        }
    }

    /// Check if this is a terminal state (Confirmed or Failed).
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Confirmed { .. } | Self::Failed { .. })
    }

    /// Check if this batch needs posting (Pending).
    pub fn is_pending(&self) -> bool {
        matches!(self, Self::Pending { .. })
    }

    /// Check if this batch is awaiting confirmation (Posted).
    pub fn is_posted(&self) -> bool {
        matches!(self, Self::Posted { .. })
    }

    /// Get the L1 tx hash if available.
    pub fn l1_tx(&self) -> Option<&str> {
        match self {
            Self::Posted { l1_tx, .. } | Self::Confirmed { l1_tx, .. } => Some(l1_tx),
            _ => None,
        }
    }
}

/// Entry in the posting state index for listing.
#[derive(Debug, Clone)]
pub struct PostingStateEntry {
    pub batch_hash: Hash32,
    pub state: PostingState,
}

/// Counts of batches in each posting state.
#[derive(Debug, Clone, Default)]
pub struct PostingStateCounts {
    pub pending: u64,
    pub posted: u64,
    pub confirmed: u64,
    pub failed: u64,
}

impl PostingStateCounts {
    /// Total number of batches tracked.
    pub fn total(&self) -> u64 {
        self.pending
            .saturating_add(self.posted)
            .saturating_add(self.confirmed)
            .saturating_add(self.failed)
    }
}

/// Counts of forced inclusion tickets by status.
#[derive(Debug, Clone, Default)]
pub struct ForcedQueueCounts {
    pub queued: u64,
    pub included: u64,
    pub rejected: u64,
    pub expired: u64,
}

impl ForcedQueueCounts {
    /// Total number of tickets tracked.
    pub fn total(&self) -> u64 {
        self.queued
            .saturating_add(self.included)
            .saturating_add(self.rejected)
            .saturating_add(self.expired)
    }
}

pub struct Storage {
    #[allow(dead_code)]
    db: sled::Db,
    tx_pool: Tree,
    batches: Tree,
    receipts: Tree,
    meta: Tree,
    posting_state: Tree,
    /// Forced inclusion queue (tx_hash -> InclusionTicket).
    forced_queue: Tree,
    /// Bridge deposits (deposit_id -> DepositEvent).
    bridge_deposits: Tree,
    /// Bridge withdrawals (withdraw_id -> WithdrawRequest).
    bridge_withdrawals: Tree,
}

impl Storage {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let db = sled::open(path)?;
        let tx_pool = db.open_tree("tx_pool")?;
        let batches = db.open_tree("batches")?;
        let receipts = db.open_tree("receipts")?;
        let meta = db.open_tree("meta")?;
        let posting_state = db.open_tree("posting_state")?;
        let forced_queue = db.open_tree("forced_queue")?;
        let bridge_deposits = db.open_tree("bridge_deposits")?;
        let bridge_withdrawals = db.open_tree("bridge_withdrawals")?;
        let storage = Self {
            db,
            tx_pool,
            batches,
            receipts,
            meta,
            posting_state,
            forced_queue,
            bridge_deposits,
            bridge_withdrawals,
        };
        storage.init_schema()?;
        Ok(storage)
    }

    pub fn put_tx(&self, tx: &Tx) -> Result<Hash32, StorageError> {
        let hash = canonical_hash(tx)?;
        let bytes = canonical_encode(tx)?;
        self.tx_pool.insert(hash.0, bytes)?;
        Ok(hash)
    }

    pub fn get_tx(&self, hash: &Hash32) -> Result<Option<Tx>, StorageError> {
        self.tx_pool
            .get(hash.0)
            .map(|opt| opt.map(|ivec| canonical_decode(&ivec)))?
            .transpose()
            .map_err(Into::into)
    }

    pub fn put_batch(&self, batch: &Batch) -> Result<Hash32, StorageError> {
        let hash = canonical_hash(batch)?;
        let bytes = canonical_encode(batch)?;
        self.batches.insert(hash.0, bytes)?;
        Ok(hash)
    }

    pub fn get_batch(&self, hash: &Hash32) -> Result<Option<Batch>, StorageError> {
        self.batches
            .get(hash.0)
            .map(|opt| opt.map(|ivec| canonical_decode(&ivec)))?
            .transpose()
            .map_err(Into::into)
    }

    pub fn put_receipt(&self, receipt: &Receipt) -> Result<(), StorageError> {
        let bytes = canonical_encode(receipt)?;
        self.receipts.insert(receipt.tx_hash.0, bytes)?;
        Ok(())
    }

    pub fn get_receipt(&self, hash: &Hash32) -> Result<Option<Receipt>, StorageError> {
        self.receipts
            .get(hash.0)
            .map(|opt| opt.map(|ivec| canonical_decode(&ivec)))?
            .transpose()
            .map_err(Into::into)
    }

    pub fn set_meta(&self, key: &str, value: &[u8]) -> Result<(), StorageError> {
        self.meta.insert(key.as_bytes(), value)?;
        Ok(())
    }

    pub fn get_meta(&self, key: &str) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self.meta.get(key.as_bytes())?.map(|ivec| ivec.to_vec()))
    }

    // ========== Posting State APIs ==========

    /// Set the posting state for a batch.
    pub fn set_posting_state(
        &self,
        batch_hash: &Hash32,
        state: &PostingState,
    ) -> Result<(), StorageError> {
        let bytes = canonical_encode(state)?;
        self.posting_state.insert(batch_hash.0, bytes)?;
        Ok(())
    }

    /// Get the posting state for a batch.
    pub fn get_posting_state(
        &self,
        batch_hash: &Hash32,
    ) -> Result<Option<PostingState>, StorageError> {
        self.posting_state
            .get(batch_hash.0)
            .map(|opt| opt.map(|ivec| canonical_decode(&ivec)))?
            .transpose()
            .map_err(Into::into)
    }

    /// List batches in pending state (ready to be posted).
    ///
    /// Returns up to `limit` entries, ordered by batch hash.
    pub fn list_pending(&self, limit: usize) -> Result<Vec<PostingStateEntry>, StorageError> {
        let mut entries = Vec::new();
        for result in self.posting_state.iter() {
            if entries.len() >= limit {
                break;
            }
            let (key, value) = result?;
            let batch_hash = Hash32(key.as_ref().try_into().map_err(|_| {
                StorageError::Canonical(l2_core::CanonicalError::FromHex(
                    "invalid batch hash length".to_string(),
                ))
            })?);
            let state: PostingState = canonical_decode(&value)?;
            if state.is_pending() {
                entries.push(PostingStateEntry { batch_hash, state });
            }
        }
        Ok(entries)
    }

    /// List batches in posted state (awaiting confirmation).
    ///
    /// Returns up to `limit` entries, ordered by batch hash.
    pub fn list_posted(&self, limit: usize) -> Result<Vec<PostingStateEntry>, StorageError> {
        let mut entries = Vec::new();
        for result in self.posting_state.iter() {
            if entries.len() >= limit {
                break;
            }
            let (key, value) = result?;
            let batch_hash = Hash32(key.as_ref().try_into().map_err(|_| {
                StorageError::Canonical(l2_core::CanonicalError::FromHex(
                    "invalid batch hash length".to_string(),
                ))
            })?);
            let state: PostingState = canonical_decode(&value)?;
            if state.is_posted() {
                entries.push(PostingStateEntry { batch_hash, state });
            }
        }
        Ok(entries)
    }

    /// Delete posting state for a batch (used in cleanup).
    pub fn delete_posting_state(&self, batch_hash: &Hash32) -> Result<bool, StorageError> {
        let existed = self.posting_state.remove(batch_hash.0)?.is_some();
        Ok(existed)
    }

    /// Count batches by posting state.
    pub fn count_posting_states(&self) -> Result<PostingStateCounts, StorageError> {
        let mut counts = PostingStateCounts::default();
        for result in self.posting_state.iter() {
            let (_key, value) = result?;
            let state: PostingState = canonical_decode(&value)?;
            match state {
                PostingState::Pending { .. } => counts.pending += 1,
                PostingState::Posted { .. } => counts.posted += 1,
                PostingState::Confirmed { .. } => counts.confirmed += 1,
                PostingState::Failed { .. } => counts.failed += 1,
            }
        }
        Ok(counts)
    }

    // ========== Forced Queue APIs ==========

    /// Store a forced inclusion ticket.
    pub fn put_forced_ticket(&self, ticket: &InclusionTicket) -> Result<(), StorageError> {
        let bytes = canonical_encode(ticket)?;
        self.forced_queue.insert(ticket.tx_hash.0, bytes)?;
        Ok(())
    }

    /// Get a forced inclusion ticket by tx hash.
    pub fn get_forced_ticket(&self, tx_hash: &Hash32) -> Result<Option<InclusionTicket>, StorageError> {
        self.forced_queue
            .get(tx_hash.0)
            .map(|opt| opt.map(|ivec| canonical_decode(&ivec)))?
            .transpose()
            .map_err(Into::into)
    }

    /// Update a forced inclusion ticket.
    pub fn update_forced_ticket(&self, ticket: &InclusionTicket) -> Result<(), StorageError> {
        self.put_forced_ticket(ticket)
    }

    /// Delete a forced inclusion ticket.
    pub fn delete_forced_ticket(&self, tx_hash: &Hash32) -> Result<bool, StorageError> {
        let existed = self.forced_queue.remove(tx_hash.0)?.is_some();
        Ok(existed)
    }

    /// List all queued forced tickets (status == Queued).
    ///
    /// Returns up to `limit` entries.
    pub fn list_queued_forced(&self, limit: usize) -> Result<Vec<InclusionTicket>, StorageError> {
        let mut tickets = Vec::new();
        for result in self.forced_queue.iter() {
            if tickets.len() >= limit {
                break;
            }
            let (_key, value) = result?;
            let ticket: InclusionTicket = canonical_decode(&value)?;
            if ticket.status == ForcedInclusionStatus::Queued {
                tickets.push(ticket);
            }
        }
        Ok(tickets)
    }

    /// List forced tickets that must be included by a given epoch.
    ///
    /// Returns tickets where `created_epoch + max_epochs <= epoch`.
    pub fn list_due_forced(&self, current_epoch: u64, limit: usize) -> Result<Vec<InclusionTicket>, StorageError> {
        let mut tickets = Vec::new();
        for result in self.forced_queue.iter() {
            if tickets.len() >= limit {
                break;
            }
            let (_key, value) = result?;
            let ticket: InclusionTicket = canonical_decode(&value)?;
            if ticket.status == ForcedInclusionStatus::Queued
                && ticket.must_include_by_epoch() <= current_epoch
            {
                tickets.push(ticket);
            }
        }
        Ok(tickets)
    }

    /// Count forced tickets by status.
    pub fn count_forced_queue(&self) -> Result<ForcedQueueCounts, StorageError> {
        let mut counts = ForcedQueueCounts::default();
        for result in self.forced_queue.iter() {
            let (_key, value) = result?;
            let ticket: InclusionTicket = canonical_decode(&value)?;
            match ticket.status {
                ForcedInclusionStatus::Queued => counts.queued += 1,
                ForcedInclusionStatus::Included => counts.included += 1,
                ForcedInclusionStatus::Rejected => counts.rejected += 1,
                ForcedInclusionStatus::Expired => counts.expired += 1,
            }
        }
        Ok(counts)
    }

    /// Check if an account has exceeded forced tx limit for an epoch.
    pub fn count_forced_for_account_epoch(
        &self,
        account: &str,
        epoch: u64,
    ) -> Result<u64, StorageError> {
        let mut count = 0u64;
        for result in self.forced_queue.iter() {
            let (_key, value) = result?;
            let ticket: InclusionTicket = canonical_decode(&value)?;
            if ticket.requester == account && ticket.created_epoch == epoch {
                count = count.saturating_add(1);
            }
        }
        Ok(count)
    }

    // ========== Bridge Deposit APIs ==========

    /// Store a deposit event.
    pub fn put_deposit(&self, deposit_id: &str, data: &[u8]) -> Result<(), StorageError> {
        self.bridge_deposits.insert(deposit_id.as_bytes(), data)?;
        Ok(())
    }

    /// Get a deposit event by ID.
    pub fn get_deposit(&self, deposit_id: &str) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self
            .bridge_deposits
            .get(deposit_id.as_bytes())?
            .map(|ivec| ivec.to_vec()))
    }

    /// Check if a deposit exists.
    pub fn deposit_exists(&self, deposit_id: &str) -> Result<bool, StorageError> {
        Ok(self.bridge_deposits.contains_key(deposit_id.as_bytes())?)
    }

    /// Count deposits.
    pub fn count_deposits(&self) -> Result<u64, StorageError> {
        let count = self.bridge_deposits.len();
        Ok(u64::try_from(count).unwrap_or(u64::MAX))
    }

    // ========== Bridge Withdrawal APIs ==========

    /// Store a withdrawal request.
    pub fn put_withdrawal(&self, withdraw_id: &str, data: &[u8]) -> Result<(), StorageError> {
        self.bridge_withdrawals.insert(withdraw_id.as_bytes(), data)?;
        Ok(())
    }

    /// Get a withdrawal request by ID.
    pub fn get_withdrawal(&self, withdraw_id: &str) -> Result<Option<Vec<u8>>, StorageError> {
        Ok(self
            .bridge_withdrawals
            .get(withdraw_id.as_bytes())?
            .map(|ivec| ivec.to_vec()))
    }

    /// Check if a withdrawal exists.
    pub fn withdrawal_exists(&self, withdraw_id: &str) -> Result<bool, StorageError> {
        Ok(self
            .bridge_withdrawals
            .contains_key(withdraw_id.as_bytes())?)
    }

    /// Count withdrawals.
    pub fn count_withdrawals(&self) -> Result<u64, StorageError> {
        let count = self.bridge_withdrawals.len();
        Ok(u64::try_from(count).unwrap_or(u64::MAX))
    }

    /// List withdrawal IDs (up to limit).
    pub fn list_withdrawal_ids(&self, limit: usize) -> Result<Vec<String>, StorageError> {
        let mut ids = Vec::new();
        for result in self.bridge_withdrawals.iter() {
            if ids.len() >= limit {
                break;
            }
            let (key, _value) = result?;
            if let Ok(id) = String::from_utf8(key.to_vec()) {
                ids.push(id);
            }
        }
        Ok(ids)
    }

    fn init_schema(&self) -> Result<(), StorageError> {
        let existing = self.meta.get(META_SCHEMA_KEY)?;
        match existing {
            Some(val) => {
                let current = String::from_utf8_lossy(&val).to_string();
                if current != SCHEMA_VERSION {
                    return Err(StorageError::SchemaMismatch {
                        expected: SCHEMA_VERSION.to_string(),
                        found: Some(current),
                    });
                }
            }
            None => {
                self.meta
                    .insert(META_SCHEMA_KEY, SCHEMA_VERSION.as_bytes())?;
                info!(schema = SCHEMA_VERSION, "initialized schema version");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use l2_core::ChainId;
    use tempfile::tempdir;

    #[test]
    fn store_and_load_tx() {
        let dir = tempdir().expect("tmpdir");
        let storage = Storage::open(dir.path()).expect("open");
        let tx = Tx {
            chain_id: ChainId(1),
            nonce: 1,
            from: "alice".to_string(),
            payload: vec![1, 2, 3],
        };
        let hash = storage.put_tx(&tx).expect("put");
        let loaded = storage.get_tx(&hash).expect("get").expect("present");
        assert_eq!(loaded, tx);
    }

    #[test]
    fn schema_version_is_enforced() {
        let dir = tempdir().expect("tmpdir");
        {
            let storage = Storage::open(dir.path()).expect("open");
            storage
                .meta
                .insert(META_SCHEMA_KEY, b"999")
                .expect("overwrite");
            storage.meta.flush().expect("flush");
        }
        // Drop storage to ensure write is persisted
        let reopened = Storage::open(dir.path());
        assert!(matches!(reopened, Err(StorageError::SchemaMismatch { .. })));
    }

    #[test]
    fn posting_state_roundtrip() {
        let dir = tempdir().expect("tmpdir");
        let storage = Storage::open(dir.path()).expect("open");

        let batch_hash = Hash32([0xAA; 32]);
        let state = PostingState::pending(1_700_000_000_000);

        storage.set_posting_state(&batch_hash, &state).expect("set");
        let loaded = storage
            .get_posting_state(&batch_hash)
            .expect("get")
            .expect("present");

        assert_eq!(loaded, state);
    }

    #[test]
    fn posting_state_transition() {
        let dir = tempdir().expect("tmpdir");
        let storage = Storage::open(dir.path()).expect("open");

        let batch_hash = Hash32([0xBB; 32]);

        // Start as pending
        let pending = PostingState::pending(1_700_000_000_000);
        storage
            .set_posting_state(&batch_hash, &pending)
            .expect("set pending");
        assert!(storage
            .get_posting_state(&batch_hash)
            .unwrap()
            .unwrap()
            .is_pending());

        // Transition to posted
        let posted = PostingState::posted("l1tx123".to_string(), 1_700_000_001_000);
        storage
            .set_posting_state(&batch_hash, &posted)
            .expect("set posted");
        let loaded = storage.get_posting_state(&batch_hash).unwrap().unwrap();
        assert!(loaded.is_posted());
        assert_eq!(loaded.l1_tx(), Some("l1tx123"));

        // Transition to confirmed
        let confirmed = PostingState::confirmed("l1tx123".to_string(), 1_700_000_002_000);
        storage
            .set_posting_state(&batch_hash, &confirmed)
            .expect("set confirmed");
        let loaded = storage.get_posting_state(&batch_hash).unwrap().unwrap();
        assert!(loaded.is_terminal());
        assert_eq!(loaded.l1_tx(), Some("l1tx123"));
    }

    #[test]
    fn list_pending_batches() {
        let dir = tempdir().expect("tmpdir");
        let storage = Storage::open(dir.path()).expect("open");

        // Add some batches in different states
        let hash1 = Hash32([0x01; 32]);
        let hash2 = Hash32([0x02; 32]);
        let hash3 = Hash32([0x03; 32]);

        storage
            .set_posting_state(&hash1, &PostingState::pending(1000))
            .unwrap();
        storage
            .set_posting_state(&hash2, &PostingState::posted("tx".to_string(), 2000))
            .unwrap();
        storage
            .set_posting_state(&hash3, &PostingState::pending(3000))
            .unwrap();

        let pending = storage.list_pending(10).unwrap();
        assert_eq!(pending.len(), 2);

        // Verify they're both pending
        for entry in &pending {
            assert!(entry.state.is_pending());
        }
    }

    #[test]
    fn list_posted_batches() {
        let dir = tempdir().expect("tmpdir");
        let storage = Storage::open(dir.path()).expect("open");

        let hash1 = Hash32([0x11; 32]);
        let hash2 = Hash32([0x12; 32]);
        let hash3 = Hash32([0x13; 32]);

        storage
            .set_posting_state(&hash1, &PostingState::pending(1000))
            .unwrap();
        storage
            .set_posting_state(&hash2, &PostingState::posted("tx2".to_string(), 2000))
            .unwrap();
        storage
            .set_posting_state(&hash3, &PostingState::confirmed("tx3".to_string(), 3000))
            .unwrap();

        let posted = storage.list_posted(10).unwrap();
        assert_eq!(posted.len(), 1);
        assert!(posted[0].state.is_posted());
        assert_eq!(posted[0].state.l1_tx(), Some("tx2"));
    }

    #[test]
    fn count_posting_states() {
        let dir = tempdir().expect("tmpdir");
        let storage = Storage::open(dir.path()).expect("open");

        storage
            .set_posting_state(&Hash32([0x01; 32]), &PostingState::pending(1000))
            .unwrap();
        storage
            .set_posting_state(&Hash32([0x02; 32]), &PostingState::pending(1000))
            .unwrap();
        storage
            .set_posting_state(
                &Hash32([0x03; 32]),
                &PostingState::posted("tx".to_string(), 2000),
            )
            .unwrap();
        storage
            .set_posting_state(
                &Hash32([0x04; 32]),
                &PostingState::confirmed("tx".to_string(), 3000),
            )
            .unwrap();
        storage
            .set_posting_state(
                &Hash32([0x05; 32]),
                &PostingState::failed("err".to_string(), 4000, 3),
            )
            .unwrap();

        let counts = storage.count_posting_states().unwrap();
        assert_eq!(counts.pending, 2);
        assert_eq!(counts.posted, 1);
        assert_eq!(counts.confirmed, 1);
        assert_eq!(counts.failed, 1);
        assert_eq!(counts.total(), 5);
    }

    #[test]
    fn delete_posting_state() {
        let dir = tempdir().expect("tmpdir");
        let storage = Storage::open(dir.path()).expect("open");

        let hash = Hash32([0xFF; 32]);
        storage
            .set_posting_state(&hash, &PostingState::pending(1000))
            .unwrap();

        assert!(storage.get_posting_state(&hash).unwrap().is_some());
        let deleted = storage.delete_posting_state(&hash).unwrap();
        assert!(deleted);
        assert!(storage.get_posting_state(&hash).unwrap().is_none());

        // Deleting again returns false
        let deleted_again = storage.delete_posting_state(&hash).unwrap();
        assert!(!deleted_again);
    }

    #[test]
    fn posting_state_failed() {
        let dir = tempdir().expect("tmpdir");
        let storage = Storage::open(dir.path()).expect("open");

        let hash = Hash32([0xEE; 32]);
        let failed = PostingState::failed("network timeout".to_string(), 5000, 3);

        storage.set_posting_state(&hash, &failed).unwrap();
        let loaded = storage.get_posting_state(&hash).unwrap().unwrap();

        assert!(loaded.is_terminal());
        assert!(!loaded.is_pending());
        assert!(!loaded.is_posted());
        assert_eq!(loaded.l1_tx(), None);

        if let PostingState::Failed {
            reason,
            retry_count,
            ..
        } = loaded
        {
            assert_eq!(reason, "network timeout");
            assert_eq!(retry_count, 3);
        } else {
            panic!("expected Failed state");
        }
    }
}
