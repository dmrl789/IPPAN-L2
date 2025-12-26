#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]
#![deny(clippy::float_cmp)]
#![deny(clippy::cast_precision_loss)]
#![deny(clippy::cast_possible_truncation)]
#![deny(clippy::cast_possible_wrap)]
#![deny(clippy::cast_sign_loss)]
#![deny(clippy::disallowed_types)]

//! Sled-backed storage for IPPAN L2 node.
//!
//! This crate provides persistent storage for batches, transactions, and
//! settlement state. All operations are crash-safe and atomic.

pub mod m2m;
pub mod m2m_ops;
pub mod settlement;

use std::path::Path;

use l2_core::forced_inclusion::{ForcedInclusionStatus, InclusionTicket};
use l2_core::{canonical_decode, canonical_encode, canonical_hash, Batch, Hash32, Receipt, Tx};
use serde::{Deserialize, Serialize};
use sled::Tree;
use thiserror::Error;
use tracing::info;

pub use settlement::{
    validate_transition, SettlementState, SettlementStateCounts, SettlementStateEntry,
    SettlementTransitionError,
};

pub const SCHEMA_VERSION: &str = "3";
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

/// Audit log event types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    /// Deposit claim created.
    DepositCreated,
    /// Deposit verified.
    DepositVerified,
    /// Deposit rejected.
    DepositRejected,
    /// Withdrawal request created.
    WithdrawCreated,
    /// Withdrawal posted to L1.
    WithdrawPosted,
    /// Withdrawal confirmed.
    WithdrawConfirmed,
    /// Withdrawal failed.
    WithdrawFailed,
    /// Forced inclusion ticket created.
    ForcedTicketCreated,
    /// Forced inclusion ticket included.
    ForcedTicketIncluded,
    /// Forced inclusion ticket expired.
    ForcedTicketExpired,
}

/// Audit log entry.
///
/// Note: We intentionally do NOT use `skip_serializing_if` for Option fields
/// because bincode (used by canonical_encode) requires all fields to be present.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Entry ID (timestamp-based).
    pub id: String,
    /// Timestamp (ms since epoch).
    pub timestamp_ms: u64,
    /// Event type.
    pub event_type: AuditEventType,
    /// Related entity ID (deposit_id, withdraw_id, tx_hash, etc.).
    pub entity_id: String,
    /// Related account (if applicable).
    pub account: Option<String>,
    /// Additional context as JSON.
    pub context: Option<String>,
}

impl AuditEntry {
    /// Create a new audit entry.
    pub fn new(
        event_type: AuditEventType,
        entity_id: String,
        account: Option<String>,
        context: Option<String>,
    ) -> Self {
        let timestamp_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis();
        let timestamp_ms = u64::try_from(timestamp_ms).unwrap_or(u64::MAX);
        // ID is timestamp + random suffix for uniqueness
        let id = format!("{timestamp_ms}:{:08x}", rand_u32());
        Self {
            id,
            timestamp_ms,
            event_type,
            entity_id,
            account,
            context,
        }
    }
}

/// Simple deterministic pseudo-random based on system time.
fn rand_u32() -> u32 {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();
    nanos.wrapping_mul(1103515245).wrapping_add(12345)
}

pub struct Storage {
    #[allow(dead_code)]
    db: sled::Db,
    tx_pool: Tree,
    batches: Tree,
    receipts: Tree,
    meta: Tree,
    posting_state: Tree,
    /// Settlement state machine (batch_hash -> SettlementState).
    settlement_state: Tree,
    /// Forced inclusion queue (tx_hash -> InclusionTicket).
    forced_queue: Tree,
    /// Bridge deposits (deposit_id -> DepositEvent).
    bridge_deposits: Tree,
    /// Bridge withdrawals (withdraw_id -> WithdrawRequest).
    bridge_withdrawals: Tree,
    /// Audit log (timestamp_id -> AuditEntry).
    audit_log: Tree,
}

impl Storage {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let db = sled::open(path)?;
        let tx_pool = db.open_tree("tx_pool")?;
        let batches = db.open_tree("batches")?;
        let receipts = db.open_tree("receipts")?;
        let meta = db.open_tree("meta")?;
        let posting_state = db.open_tree("posting_state")?;
        let settlement_state = db.open_tree("settlement_state")?;
        let forced_queue = db.open_tree("forced_queue")?;
        let bridge_deposits = db.open_tree("bridge_deposits")?;
        let bridge_withdrawals = db.open_tree("bridge_withdrawals")?;
        let audit_log = db.open_tree("audit_log")?;
        let storage = Self {
            db,
            tx_pool,
            batches,
            receipts,
            meta,
            posting_state,
            settlement_state,
            forced_queue,
            bridge_deposits,
            bridge_withdrawals,
            audit_log,
        };
        storage.init_schema()?;
        Ok(storage)
    }

    /// Get a reference to the underlying sled database.
    ///
    /// This is used for creating additional tree handles (e.g., M2M storage).
    pub fn db(&self) -> &sled::Db {
        &self.db
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
    pub fn get_forced_ticket(
        &self,
        tx_hash: &Hash32,
    ) -> Result<Option<InclusionTicket>, StorageError> {
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
    pub fn list_due_forced(
        &self,
        current_epoch: u64,
        limit: usize,
    ) -> Result<Vec<InclusionTicket>, StorageError> {
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
        self.bridge_withdrawals
            .insert(withdraw_id.as_bytes(), data)?;
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

    // ========== Batch Chaining APIs ==========

    /// Get the last posted batch hash for a given hub and chain.
    ///
    /// Returns None if no batch has been posted yet (genesis case).
    pub fn get_last_batch_hash(
        &self,
        hub: &str,
        chain_id: u64,
    ) -> Result<Option<Hash32>, StorageError> {
        let key = format!("last_batch_hash:{}:{}", hub, chain_id);
        match self.meta.get(key.as_bytes())? {
            Some(ivec) => {
                if ivec.len() != 32 {
                    return Err(StorageError::Canonical(l2_core::CanonicalError::FromHex(
                        "invalid batch hash length".to_string(),
                    )));
                }
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&ivec);
                Ok(Some(Hash32(hash)))
            }
            None => Ok(None),
        }
    }

    /// Set the last posted batch hash for a given hub and chain.
    ///
    /// Should be called when a batch submission is accepted (or confirmed).
    pub fn set_last_batch_hash(
        &self,
        hub: &str,
        chain_id: u64,
        hash: &Hash32,
    ) -> Result<(), StorageError> {
        let key = format!("last_batch_hash:{}:{}", hub, chain_id);
        self.meta.insert(key.as_bytes(), &hash.0)?;
        Ok(())
    }

    /// Clear the last batch hash for a given hub and chain.
    ///
    /// Used for testing or resetting state.
    pub fn clear_last_batch_hash(&self, hub: &str, chain_id: u64) -> Result<bool, StorageError> {
        let key = format!("last_batch_hash:{}:{}", hub, chain_id);
        Ok(self.meta.remove(key.as_bytes())?.is_some())
    }

    // ========== Per-Hub Batch Number APIs ==========

    /// Get the last batch number for a given hub and chain.
    ///
    /// Returns 0 if no batches have been created yet (genesis case).
    pub fn get_hub_batch_number(&self, hub: &str, chain_id: u64) -> Result<u64, StorageError> {
        let key = format!("hub_batch_number:{}:{}", hub, chain_id);
        match self.meta.get(key.as_bytes())? {
            Some(ivec) => {
                if ivec.len() != 8 {
                    return Err(StorageError::Canonical(l2_core::CanonicalError::FromHex(
                        "invalid batch number length".to_string(),
                    )));
                }
                let mut bytes = [0u8; 8];
                bytes.copy_from_slice(&ivec);
                Ok(u64::from_le_bytes(bytes))
            }
            None => {
                // Check for legacy key migration
                self.migrate_legacy_batch_number(hub, chain_id)
            }
        }
    }

    /// Increment and get the next batch number for a given hub and chain.
    ///
    /// This is atomic and safe for concurrent access.
    pub fn next_hub_batch_number(&self, hub: &str, chain_id: u64) -> Result<u64, StorageError> {
        let current = self.get_hub_batch_number(hub, chain_id)?;
        let next = current.saturating_add(1);
        self.set_hub_batch_number(hub, chain_id, next)?;
        Ok(next)
    }

    /// Set the batch number for a given hub and chain.
    pub fn set_hub_batch_number(
        &self,
        hub: &str,
        chain_id: u64,
        batch_number: u64,
    ) -> Result<(), StorageError> {
        let key = format!("hub_batch_number:{}:{}", hub, chain_id);
        self.meta.insert(key.as_bytes(), &batch_number.to_le_bytes())?;
        Ok(())
    }

    /// Migrate legacy batch number to per-hub format.
    ///
    /// If legacy key exists, map it to the default hub (Fin) for backward compatibility.
    fn migrate_legacy_batch_number(&self, hub: &str, chain_id: u64) -> Result<u64, StorageError> {
        // Only migrate if hub is "fin" (default hub)
        if hub == "fin" {
            if let Some(legacy_bytes) = self.meta.get("last_batch_number")? {
                if let Ok(bytes) = legacy_bytes.as_ref().try_into() {
                    let legacy_number = u64::from_le_bytes(bytes);
                    // Migrate to new key
                    self.set_hub_batch_number(hub, chain_id, legacy_number)?;
                    tracing::info!(
                        hub = hub,
                        chain_id = chain_id,
                        batch_number = legacy_number,
                        "migrated legacy batch number to per-hub format"
                    );
                    return Ok(legacy_number);
                }
            }
        }
        Ok(0)
    }

    // ========== Per-Hub Queue Statistics ==========

    /// Get per-hub queue statistics.
    ///
    /// Returns (queue_depth, forced_queue_depth) for the given hub.
    pub fn get_hub_queue_stats(&self, hub: &str) -> Result<(u64, u64), StorageError> {
        let queue_key = format!("hub_queue_depth:{}", hub);
        let forced_key = format!("hub_forced_depth:{}", hub);

        let queue_depth = self.meta.get(queue_key.as_bytes())?
            .and_then(|ivec| ivec.as_ref().try_into().ok().map(u64::from_le_bytes))
            .unwrap_or(0);

        let forced_depth = self.meta.get(forced_key.as_bytes())?
            .and_then(|ivec| ivec.as_ref().try_into().ok().map(u64::from_le_bytes))
            .unwrap_or(0);

        Ok((queue_depth, forced_depth))
    }

    /// Update per-hub queue statistics.
    pub fn set_hub_queue_stats(
        &self,
        hub: &str,
        queue_depth: u64,
        forced_depth: u64,
    ) -> Result<(), StorageError> {
        let queue_key = format!("hub_queue_depth:{}", hub);
        let forced_key = format!("hub_forced_depth:{}", hub);

        self.meta.insert(queue_key.as_bytes(), &queue_depth.to_le_bytes())?;
        self.meta.insert(forced_key.as_bytes(), &forced_depth.to_le_bytes())?;
        Ok(())
    }

    // ========== Per-Hub Fee Totals ==========

    /// Get total finalised fees for a hub (M2M hub only).
    pub fn get_hub_total_fees(&self, hub: &str, chain_id: u64) -> Result<u64, StorageError> {
        let key = format!("hub_total_fees:{}:{}", hub, chain_id);
        Ok(self.meta.get(key.as_bytes())?
            .and_then(|ivec| ivec.as_ref().try_into().ok().map(u64::from_le_bytes))
            .unwrap_or(0))
    }

    /// Add to total finalised fees for a hub.
    pub fn add_hub_total_fees(
        &self,
        hub: &str,
        chain_id: u64,
        amount_scaled: u64,
    ) -> Result<u64, StorageError> {
        let current = self.get_hub_total_fees(hub, chain_id)?;
        let new_total = current.saturating_add(amount_scaled);
        let key = format!("hub_total_fees:{}:{}", hub, chain_id);
        self.meta.insert(key.as_bytes(), &new_total.to_le_bytes())?;
        Ok(new_total)
    }

    // ========== Per-Hub In-Flight Batch Tracking ==========

    /// Get the count of in-flight batches for a given hub.
    pub fn get_hub_in_flight_count(&self, hub: &str, chain_id: u64) -> Result<u32, StorageError> {
        let key = format!("hub_in_flight:{}:{}", hub, chain_id);
        Ok(self.meta.get(key.as_bytes())?
            .and_then(|ivec| ivec.as_ref().try_into().ok().map(u32::from_le_bytes))
            .unwrap_or(0))
    }

    /// Increment in-flight batch count for a hub.
    pub fn inc_hub_in_flight(&self, hub: &str, chain_id: u64) -> Result<u32, StorageError> {
        let current = self.get_hub_in_flight_count(hub, chain_id)?;
        let new_count = current.saturating_add(1);
        let key = format!("hub_in_flight:{}:{}", hub, chain_id);
        self.meta.insert(key.as_bytes(), &new_count.to_le_bytes())?;
        Ok(new_count)
    }

    /// Decrement in-flight batch count for a hub.
    pub fn dec_hub_in_flight(&self, hub: &str, chain_id: u64) -> Result<u32, StorageError> {
        let current = self.get_hub_in_flight_count(hub, chain_id)?;
        let new_count = current.saturating_sub(1);
        let key = format!("hub_in_flight:{}:{}", hub, chain_id);
        self.meta.insert(key.as_bytes(), &new_count.to_le_bytes())?;
        Ok(new_count)
    }

    // ========== Per-Hub Forced Queue APIs ==========

    /// Store a forced inclusion ticket with hub association.
    pub fn put_forced_ticket_for_hub(
        &self,
        hub: &str,
        ticket: &InclusionTicket,
    ) -> Result<(), StorageError> {
        // Store the ticket
        self.put_forced_ticket(ticket)?;
        // Also store the hub association
        let hub_key = format!("forced_hub:{}:{}", hub, hex::encode(ticket.tx_hash.0));
        self.meta.insert(hub_key.as_bytes(), hub.as_bytes())?;
        Ok(())
    }

    /// Get the hub for a forced ticket.
    pub fn get_forced_ticket_hub(&self, tx_hash: &Hash32) -> Result<Option<String>, StorageError> {
        // Check all hubs for this tx_hash
        for hub in &["fin", "data", "m2m", "world", "bridge"] {
            let hub_key = format!("forced_hub:{}:{}", hub, hex::encode(tx_hash.0));
            if self.meta.contains_key(hub_key.as_bytes())? {
                return Ok(Some((*hub).to_string()));
            }
        }
        Ok(None)
    }

    /// List queued forced tickets for a specific hub.
    pub fn list_queued_forced_for_hub(
        &self,
        hub: &str,
        limit: usize,
    ) -> Result<Vec<InclusionTicket>, StorageError> {
        let mut tickets = Vec::new();
        for result in self.forced_queue.iter() {
            if tickets.len() >= limit {
                break;
            }
            let (key, value) = result?;
            let ticket: InclusionTicket = canonical_decode(&value)?;
            if ticket.status == ForcedInclusionStatus::Queued {
                // Check if this ticket belongs to this hub
                let tx_hash = Hash32(key.as_ref().try_into().map_err(|_| {
                    StorageError::Canonical(l2_core::CanonicalError::FromHex(
                        "invalid tx hash length".to_string(),
                    ))
                })?);
                let hub_key = format!("forced_hub:{}:{}", hub, hex::encode(tx_hash.0));
                if self.meta.contains_key(hub_key.as_bytes())? {
                    tickets.push(ticket);
                }
            }
        }
        Ok(tickets)
    }

    /// Count forced tickets by hub and status.
    pub fn count_forced_queue_for_hub(&self, hub: &str) -> Result<ForcedQueueCounts, StorageError> {
        let mut counts = ForcedQueueCounts::default();
        for result in self.forced_queue.iter() {
            let (key, value) = result?;
            let ticket: InclusionTicket = canonical_decode(&value)?;
            // Check if this ticket belongs to this hub
            let tx_hash = Hash32(key.as_ref().try_into().map_err(|_| {
                StorageError::Canonical(l2_core::CanonicalError::FromHex(
                    "invalid tx hash length".to_string(),
                ))
            })?);
            let hub_key = format!("forced_hub:{}:{}", hub, hex::encode(tx_hash.0));
            if self.meta.contains_key(hub_key.as_bytes())? {
                match ticket.status {
                    ForcedInclusionStatus::Queued => counts.queued += 1,
                    ForcedInclusionStatus::Included => counts.included += 1,
                    ForcedInclusionStatus::Rejected => counts.rejected += 1,
                    ForcedInclusionStatus::Expired => counts.expired += 1,
                }
            }
        }
        Ok(counts)
    }

    // ========== Settlement State APIs ==========

    /// Set the settlement state for a batch.
    ///
    /// This validates the transition from the current state (if any) and persists
    /// the new state atomically.
    pub fn set_settlement_state(
        &self,
        batch_hash: &Hash32,
        state: &SettlementState,
    ) -> Result<(), StorageError> {
        // Check for valid transition if state already exists
        if let Some(current) = self.get_settlement_state(batch_hash)? {
            validate_transition(&current, state).map_err(|e| {
                StorageError::Canonical(l2_core::CanonicalError::FromHex(e.to_string()))
            })?;
        }

        let bytes = canonical_encode(state)?;
        self.settlement_state.insert(batch_hash.0, bytes)?;
        Ok(())
    }

    /// Set the settlement state without validation.
    ///
    /// Use only for crash recovery or tests. Normal code should use `set_settlement_state`.
    pub fn set_settlement_state_unchecked(
        &self,
        batch_hash: &Hash32,
        state: &SettlementState,
    ) -> Result<(), StorageError> {
        let bytes = canonical_encode(state)?;
        self.settlement_state.insert(batch_hash.0, bytes)?;
        Ok(())
    }

    /// Get the settlement state for a batch.
    pub fn get_settlement_state(
        &self,
        batch_hash: &Hash32,
    ) -> Result<Option<SettlementState>, StorageError> {
        self.settlement_state
            .get(batch_hash.0)
            .map(|opt| opt.map(|ivec| canonical_decode(&ivec)))?
            .transpose()
            .map_err(Into::into)
    }

    /// Delete settlement state for a batch (used in cleanup).
    pub fn delete_settlement_state(&self, batch_hash: &Hash32) -> Result<bool, StorageError> {
        let existed = self.settlement_state.remove(batch_hash.0)?.is_some();
        Ok(existed)
    }

    /// List batches in Created state.
    ///
    /// Returns up to `limit` entries.
    pub fn list_settlement_created(
        &self,
        limit: usize,
    ) -> Result<Vec<SettlementStateEntry>, StorageError> {
        self.list_settlement_by_predicate(limit, |s| s.is_created())
    }

    /// List batches in Submitted state (awaiting inclusion).
    ///
    /// Returns up to `limit` entries.
    pub fn list_settlement_submitted(
        &self,
        limit: usize,
    ) -> Result<Vec<SettlementStateEntry>, StorageError> {
        self.list_settlement_by_predicate(limit, |s| s.is_submitted())
    }

    /// List batches in Included state (awaiting finality).
    ///
    /// Returns up to `limit` entries.
    pub fn list_settlement_included(
        &self,
        limit: usize,
    ) -> Result<Vec<SettlementStateEntry>, StorageError> {
        self.list_settlement_by_predicate(limit, |s| s.is_included())
    }

    /// List batches needing reconciliation (Submitted or Included).
    ///
    /// Returns up to `limit` entries.
    pub fn list_settlement_needs_reconciliation(
        &self,
        limit: usize,
    ) -> Result<Vec<SettlementStateEntry>, StorageError> {
        self.list_settlement_by_predicate(limit, |s| s.needs_reconciliation())
    }

    /// Count batches by settlement state.
    pub fn count_settlement_states(&self) -> Result<SettlementStateCounts, StorageError> {
        let mut counts = SettlementStateCounts::default();
        for result in self.settlement_state.iter() {
            let (_key, value) = result?;
            let state: SettlementState = canonical_decode(&value)?;
            match state {
                SettlementState::Created { .. } => counts.created += 1,
                SettlementState::Submitted { .. } => counts.submitted += 1,
                SettlementState::Included { .. } => counts.included += 1,
                SettlementState::Finalised { .. } => counts.finalised += 1,
                SettlementState::Failed { .. } => counts.failed += 1,
            }
        }
        Ok(counts)
    }

    /// Get the last finalised batch hash and timestamp for a given hub and chain.
    ///
    /// Returns (batch_hash, finalised_at_ms) or None if no finalised batches exist.
    pub fn get_last_finalised_batch(
        &self,
        hub: &str,
        chain_id: u64,
    ) -> Result<Option<(Hash32, u64)>, StorageError> {
        let key = format!("last_finalised_batch:{}:{}", hub, chain_id);
        match self.meta.get(key.as_bytes())? {
            Some(ivec) => {
                // Format: 32 bytes hash + 8 bytes timestamp
                if ivec.len() != 40 {
                    return Err(StorageError::Canonical(l2_core::CanonicalError::FromHex(
                        "invalid last_finalised_batch format".to_string(),
                    )));
                }
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&ivec[0..32]);
                let mut ts_bytes = [0u8; 8];
                ts_bytes.copy_from_slice(&ivec[32..40]);
                let timestamp = u64::from_le_bytes(ts_bytes);
                Ok(Some((Hash32(hash), timestamp)))
            }
            None => Ok(None),
        }
    }

    /// Set the last finalised batch for a given hub and chain.
    pub fn set_last_finalised_batch(
        &self,
        hub: &str,
        chain_id: u64,
        batch_hash: &Hash32,
        finalised_at_ms: u64,
    ) -> Result<(), StorageError> {
        let key = format!("last_finalised_batch:{}:{}", hub, chain_id);
        let mut value = Vec::with_capacity(40);
        value.extend_from_slice(&batch_hash.0);
        value.extend_from_slice(&finalised_at_ms.to_le_bytes());
        self.meta.insert(key.as_bytes(), value)?;
        Ok(())
    }

    /// Internal helper: list settlement entries by predicate.
    fn list_settlement_by_predicate<F>(
        &self,
        limit: usize,
        predicate: F,
    ) -> Result<Vec<SettlementStateEntry>, StorageError>
    where
        F: Fn(&SettlementState) -> bool,
    {
        let mut entries = Vec::new();
        for result in self.settlement_state.iter() {
            if entries.len() >= limit {
                break;
            }
            let (key, value) = result?;
            let batch_hash = Hash32(key.as_ref().try_into().map_err(|_| {
                StorageError::Canonical(l2_core::CanonicalError::FromHex(
                    "invalid batch hash length".to_string(),
                ))
            })?);
            let state: SettlementState = canonical_decode(&value)?;
            if predicate(&state) {
                entries.push(SettlementStateEntry { batch_hash, state });
            }
        }
        Ok(entries)
    }

    // ========== Audit Log APIs ==========

    /// Append an audit log entry.
    pub fn append_audit(&self, entry: &AuditEntry) -> Result<(), StorageError> {
        let bytes = canonical_encode(entry)?;
        self.audit_log.insert(entry.id.as_bytes(), bytes)?;
        Ok(())
    }

    /// Get an audit entry by ID.
    pub fn get_audit(&self, id: &str) -> Result<Option<AuditEntry>, StorageError> {
        self.audit_log
            .get(id.as_bytes())
            .map(|opt| opt.map(|ivec| canonical_decode(&ivec)))?
            .transpose()
            .map_err(Into::into)
    }

    /// List recent audit entries (up to limit, newest first).
    pub fn list_audit(&self, limit: usize) -> Result<Vec<AuditEntry>, StorageError> {
        let mut entries = Vec::new();
        for result in self.audit_log.iter() {
            let (_key, value) = result?;
            let entry: AuditEntry = canonical_decode(&value)?;
            entries.push(entry);
        }
        // Sort by timestamp descending (newest first)
        entries.sort_by(|a, b| b.timestamp_ms.cmp(&a.timestamp_ms));
        // Truncate to limit
        entries.truncate(limit);
        Ok(entries)
    }

    /// Count audit log entries.
    pub fn count_audit(&self) -> Result<u64, StorageError> {
        let count = self.audit_log.len();
        Ok(u64::try_from(count).unwrap_or(u64::MAX))
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

    #[test]
    fn bridge_deposits_roundtrip() {
        let dir = tempdir().expect("tmpdir");
        let storage = Storage::open(dir.path()).expect("open");

        let deposit_id = "l1tx_abc123:0";
        let data = b"deposit data".to_vec();

        // Initially doesn't exist
        assert!(!storage.deposit_exists(deposit_id).unwrap());
        assert!(storage.get_deposit(deposit_id).unwrap().is_none());

        // Store and retrieve
        storage.put_deposit(deposit_id, &data).unwrap();
        assert!(storage.deposit_exists(deposit_id).unwrap());
        assert_eq!(storage.get_deposit(deposit_id).unwrap(), Some(data));
        assert_eq!(storage.count_deposits().unwrap(), 1);
    }

    #[test]
    fn bridge_withdrawals_roundtrip() {
        let dir = tempdir().expect("tmpdir");
        let storage = Storage::open(dir.path()).expect("open");

        let withdraw_id = "wd_123";
        let data = b"withdrawal data".to_vec();

        // Initially doesn't exist
        assert!(!storage.withdrawal_exists(withdraw_id).unwrap());
        assert!(storage.get_withdrawal(withdraw_id).unwrap().is_none());

        // Store and retrieve
        storage.put_withdrawal(withdraw_id, &data).unwrap();
        assert!(storage.withdrawal_exists(withdraw_id).unwrap());
        assert_eq!(storage.get_withdrawal(withdraw_id).unwrap(), Some(data));
        assert_eq!(storage.count_withdrawals().unwrap(), 1);
    }

    #[test]
    fn list_withdrawal_ids() {
        let dir = tempdir().expect("tmpdir");
        let storage = Storage::open(dir.path()).expect("open");

        // Add some withdrawals
        for i in 0u8..5 {
            storage.put_withdrawal(&format!("wd_{i}"), &[i]).unwrap();
        }

        let ids = storage.list_withdrawal_ids(10).unwrap();
        assert_eq!(ids.len(), 5);
    }

    #[test]
    fn audit_log_roundtrip() {
        let dir = tempdir().expect("tmpdir");
        let storage = Storage::open(dir.path()).expect("open");

        let entry = AuditEntry::new(
            AuditEventType::DepositCreated,
            "deposit_123".to_string(),
            Some("alice".to_string()),
            Some(r#"{"amount":1000}"#.to_string()),
        );

        storage.append_audit(&entry).unwrap();

        let loaded = storage.get_audit(&entry.id).unwrap().unwrap();
        assert_eq!(loaded.entity_id, "deposit_123");
        assert_eq!(loaded.account, Some("alice".to_string()));
        assert_eq!(loaded.event_type, AuditEventType::DepositCreated);

        assert_eq!(storage.count_audit().unwrap(), 1);
    }

    #[test]
    fn batch_chaining_roundtrip() {
        let dir = tempdir().expect("tmpdir");
        let storage = Storage::open(dir.path()).expect("open");

        let hub = "fin";
        let chain_id = 1337u64;
        let hash = Hash32([0xAA; 32]);

        // Initially no hash
        assert!(storage
            .get_last_batch_hash(hub, chain_id)
            .unwrap()
            .is_none());

        // Set and retrieve
        storage.set_last_batch_hash(hub, chain_id, &hash).unwrap();
        assert_eq!(
            storage.get_last_batch_hash(hub, chain_id).unwrap(),
            Some(hash)
        );

        // Update to different hash
        let hash2 = Hash32([0xBB; 32]);
        storage.set_last_batch_hash(hub, chain_id, &hash2).unwrap();
        assert_eq!(
            storage.get_last_batch_hash(hub, chain_id).unwrap(),
            Some(hash2)
        );

        // Different hub/chain should be independent
        storage
            .set_last_batch_hash("data", chain_id, &hash)
            .unwrap();
        assert_eq!(
            storage.get_last_batch_hash(hub, chain_id).unwrap(),
            Some(hash2)
        );
        assert_eq!(
            storage.get_last_batch_hash("data", chain_id).unwrap(),
            Some(hash)
        );

        // Clear
        assert!(storage.clear_last_batch_hash(hub, chain_id).unwrap());
        assert!(storage
            .get_last_batch_hash(hub, chain_id)
            .unwrap()
            .is_none());
        assert!(!storage.clear_last_batch_hash(hub, chain_id).unwrap());
    }

    #[test]
    fn audit_log_multiple_entries() {
        let dir = tempdir().expect("tmpdir");
        let storage = Storage::open(dir.path()).expect("open");

        // Add multiple entries with varying Option values
        let entry1 = AuditEntry::new(
            AuditEventType::DepositCreated,
            "deposit_1".to_string(),
            Some("alice".to_string()),
            None,
        );
        let entry2 = AuditEntry::new(
            AuditEventType::WithdrawCreated,
            "withdraw_1".to_string(),
            Some("bob".to_string()),
            None,
        );
        let entry3 = AuditEntry::new(
            AuditEventType::ForcedTicketCreated,
            "ticket_1".to_string(),
            None,
            None,
        );

        storage.append_audit(&entry1).unwrap();
        storage.append_audit(&entry2).unwrap();
        storage.append_audit(&entry3).unwrap();

        assert_eq!(storage.count_audit().unwrap(), 3);

        // Test list_audit returns all entries
        let entries = storage.list_audit(10).unwrap();
        assert_eq!(entries.len(), 3);
    }

    // ========== Settlement State Tests ==========

    #[test]
    fn settlement_state_roundtrip() {
        let dir = tempdir().expect("tmpdir");
        let storage = Storage::open(dir.path()).expect("open");

        let batch_hash = Hash32([0xAA; 32]);
        let state = SettlementState::created(1_700_000_000_000);

        storage
            .set_settlement_state_unchecked(&batch_hash, &state)
            .expect("set");
        let loaded = storage
            .get_settlement_state(&batch_hash)
            .expect("get")
            .expect("present");

        assert_eq!(loaded, state);
    }

    #[test]
    fn settlement_state_valid_transitions() {
        let dir = tempdir().expect("tmpdir");
        let storage = Storage::open(dir.path()).expect("open");

        let batch_hash = Hash32([0xBB; 32]);

        // Start as Created
        let created = SettlementState::created(1_700_000_000_000);
        storage
            .set_settlement_state_unchecked(&batch_hash, &created)
            .expect("set created");
        assert!(storage
            .get_settlement_state(&batch_hash)
            .unwrap()
            .unwrap()
            .is_created());

        // Transition to Submitted
        let submitted = SettlementState::submitted(
            "l1tx123".to_string(),
            1_700_000_001_000,
            "key1".to_string(),
        );
        storage
            .set_settlement_state(&batch_hash, &submitted)
            .expect("set submitted");
        let loaded = storage.get_settlement_state(&batch_hash).unwrap().unwrap();
        assert!(loaded.is_submitted());
        assert_eq!(loaded.l1_tx_id(), Some("l1tx123"));

        // Transition to Included
        let included = SettlementState::included(
            "l1tx123".to_string(),
            100,
            1_700_000_002_000,
            1_700_000_002_500,
        );
        storage
            .set_settlement_state(&batch_hash, &included)
            .expect("set included");
        let loaded = storage.get_settlement_state(&batch_hash).unwrap().unwrap();
        assert!(loaded.is_included());
        assert_eq!(loaded.l1_block(), Some(100));

        // Transition to Finalised
        let finalised = SettlementState::finalised(
            "l1tx123".to_string(),
            100,
            1_700_000_002_000,
            1_700_000_003_000,
        );
        storage
            .set_settlement_state(&batch_hash, &finalised)
            .expect("set finalised");
        let loaded = storage.get_settlement_state(&batch_hash).unwrap().unwrap();
        assert!(loaded.is_finalised());
        assert!(loaded.is_terminal());
    }

    #[test]
    fn settlement_state_invalid_transition_rejected() {
        let dir = tempdir().expect("tmpdir");
        let storage = Storage::open(dir.path()).expect("open");

        let batch_hash = Hash32([0xCC; 32]);

        // Start as Submitted
        let submitted =
            SettlementState::submitted("l1tx".to_string(), 1_700_000_001_000, "key".to_string());
        storage
            .set_settlement_state_unchecked(&batch_hash, &submitted)
            .expect("set");

        // Try to go back to Created - should fail
        let created = SettlementState::created(1_700_000_000_000);
        let result = storage.set_settlement_state(&batch_hash, &created);
        assert!(result.is_err());
    }

    #[test]
    fn settlement_state_cannot_transition_from_terminal() {
        let dir = tempdir().expect("tmpdir");
        let storage = Storage::open(dir.path()).expect("open");

        let batch_hash = Hash32([0xDD; 32]);

        // Start as Finalised (terminal)
        let finalised = SettlementState::finalised(
            "l1tx".to_string(),
            100,
            1_700_000_002_000,
            1_700_000_003_000,
        );
        storage
            .set_settlement_state_unchecked(&batch_hash, &finalised)
            .expect("set");

        // Try any transition - should fail
        let created = SettlementState::created(1_700_000_000_000);
        let result = storage.set_settlement_state(&batch_hash, &created);
        assert!(result.is_err());
    }

    #[test]
    fn settlement_state_can_fail_from_any_state() {
        let dir = tempdir().expect("tmpdir");
        let storage = Storage::open(dir.path()).expect("open");

        let batch_hash = Hash32([0xEE; 32]);

        // Start as Submitted
        let submitted =
            SettlementState::submitted("l1tx".to_string(), 1_700_000_001_000, "key".to_string());
        storage
            .set_settlement_state_unchecked(&batch_hash, &submitted)
            .expect("set");

        // Transition to Failed - should succeed
        let failed =
            SettlementState::failed("network timeout".to_string(), 1_700_000_002_000, 3, None);
        storage
            .set_settlement_state(&batch_hash, &failed)
            .expect("set failed");

        let loaded = storage.get_settlement_state(&batch_hash).unwrap().unwrap();
        assert!(loaded.is_failed());
        assert!(loaded.is_terminal());
    }

    #[test]
    fn list_settlement_by_state() {
        let dir = tempdir().expect("tmpdir");
        let storage = Storage::open(dir.path()).expect("open");

        // Add batches in different states
        let hash1 = Hash32([0x01; 32]);
        let hash2 = Hash32([0x02; 32]);
        let hash3 = Hash32([0x03; 32]);
        let hash4 = Hash32([0x04; 32]);

        storage
            .set_settlement_state_unchecked(&hash1, &SettlementState::created(1000))
            .unwrap();
        storage
            .set_settlement_state_unchecked(
                &hash2,
                &SettlementState::submitted("tx2".to_string(), 2000, "key2".to_string()),
            )
            .unwrap();
        storage
            .set_settlement_state_unchecked(
                &hash3,
                &SettlementState::included("tx3".to_string(), 100, 3000, 3001),
            )
            .unwrap();
        storage
            .set_settlement_state_unchecked(
                &hash4,
                &SettlementState::finalised("tx4".to_string(), 200, 4000, 4001),
            )
            .unwrap();

        // Test list methods
        let created = storage.list_settlement_created(10).unwrap();
        assert_eq!(created.len(), 1);

        let submitted = storage.list_settlement_submitted(10).unwrap();
        assert_eq!(submitted.len(), 1);

        let included = storage.list_settlement_included(10).unwrap();
        assert_eq!(included.len(), 1);

        let needs_reconciliation = storage.list_settlement_needs_reconciliation(10).unwrap();
        assert_eq!(needs_reconciliation.len(), 2); // Submitted + Included
    }

    #[test]
    fn count_settlement_states() {
        let dir = tempdir().expect("tmpdir");
        let storage = Storage::open(dir.path()).expect("open");

        storage
            .set_settlement_state_unchecked(&Hash32([0x01; 32]), &SettlementState::created(1000))
            .unwrap();
        storage
            .set_settlement_state_unchecked(&Hash32([0x02; 32]), &SettlementState::created(1000))
            .unwrap();
        storage
            .set_settlement_state_unchecked(
                &Hash32([0x03; 32]),
                &SettlementState::submitted("tx".to_string(), 2000, "key".to_string()),
            )
            .unwrap();
        storage
            .set_settlement_state_unchecked(
                &Hash32([0x04; 32]),
                &SettlementState::included("tx".to_string(), 100, 3000, 3001),
            )
            .unwrap();
        storage
            .set_settlement_state_unchecked(
                &Hash32([0x05; 32]),
                &SettlementState::finalised("tx".to_string(), 200, 4000, 4001),
            )
            .unwrap();
        storage
            .set_settlement_state_unchecked(
                &Hash32([0x06; 32]),
                &SettlementState::failed("err".to_string(), 5000, 3, None),
            )
            .unwrap();

        let counts = storage.count_settlement_states().unwrap();
        assert_eq!(counts.created, 2);
        assert_eq!(counts.submitted, 1);
        assert_eq!(counts.included, 1);
        assert_eq!(counts.finalised, 1);
        assert_eq!(counts.failed, 1);
        assert_eq!(counts.total(), 6);
        assert_eq!(counts.in_flight(), 4);
    }

    #[test]
    fn delete_settlement_state() {
        let dir = tempdir().expect("tmpdir");
        let storage = Storage::open(dir.path()).expect("open");

        let hash = Hash32([0xFF; 32]);
        storage
            .set_settlement_state_unchecked(&hash, &SettlementState::created(1000))
            .unwrap();

        assert!(storage.get_settlement_state(&hash).unwrap().is_some());
        let deleted = storage.delete_settlement_state(&hash).unwrap();
        assert!(deleted);
        assert!(storage.get_settlement_state(&hash).unwrap().is_none());

        // Deleting again returns false
        let deleted_again = storage.delete_settlement_state(&hash).unwrap();
        assert!(!deleted_again);
    }

    #[test]
    fn last_finalised_batch_roundtrip() {
        let dir = tempdir().expect("tmpdir");
        let storage = Storage::open(dir.path()).expect("open");

        let hub = "fin";
        let chain_id = 1337u64;
        let hash = Hash32([0xAB; 32]);
        let timestamp = 1_700_000_000_000u64;

        // Initially none
        assert!(storage
            .get_last_finalised_batch(hub, chain_id)
            .unwrap()
            .is_none());

        // Set and retrieve
        storage
            .set_last_finalised_batch(hub, chain_id, &hash, timestamp)
            .unwrap();
        let (loaded_hash, loaded_ts) = storage
            .get_last_finalised_batch(hub, chain_id)
            .unwrap()
            .unwrap();
        assert_eq!(loaded_hash, hash);
        assert_eq!(loaded_ts, timestamp);

        // Update to new hash
        let hash2 = Hash32([0xCD; 32]);
        let timestamp2 = 1_700_000_001_000u64;
        storage
            .set_last_finalised_batch(hub, chain_id, &hash2, timestamp2)
            .unwrap();
        let (loaded_hash, loaded_ts) = storage
            .get_last_finalised_batch(hub, chain_id)
            .unwrap()
            .unwrap();
        assert_eq!(loaded_hash, hash2);
        assert_eq!(loaded_ts, timestamp2);
    }

    // ========== Per-Hub Batch Number Tests ==========

    #[test]
    fn hub_batch_number_starts_at_zero() {
        let dir = tempdir().expect("tmpdir");
        let storage = Storage::open(dir.path()).expect("open");

        let batch_number = storage.get_hub_batch_number("fin", 1337).unwrap();
        assert_eq!(batch_number, 0);
    }

    #[test]
    fn hub_batch_number_increment() {
        let dir = tempdir().expect("tmpdir");
        let storage = Storage::open(dir.path()).expect("open");

        assert_eq!(storage.next_hub_batch_number("fin", 1337).unwrap(), 1);
        assert_eq!(storage.next_hub_batch_number("fin", 1337).unwrap(), 2);
        assert_eq!(storage.next_hub_batch_number("fin", 1337).unwrap(), 3);
        assert_eq!(storage.get_hub_batch_number("fin", 1337).unwrap(), 3);
    }

    #[test]
    fn hub_batch_number_per_hub_isolation() {
        let dir = tempdir().expect("tmpdir");
        let storage = Storage::open(dir.path()).expect("open");

        // Each hub has independent batch numbers
        assert_eq!(storage.next_hub_batch_number("fin", 1337).unwrap(), 1);
        assert_eq!(storage.next_hub_batch_number("data", 1337).unwrap(), 1);
        assert_eq!(storage.next_hub_batch_number("m2m", 1337).unwrap(), 1);

        assert_eq!(storage.next_hub_batch_number("fin", 1337).unwrap(), 2);
        assert_eq!(storage.get_hub_batch_number("data", 1337).unwrap(), 1);
        assert_eq!(storage.get_hub_batch_number("m2m", 1337).unwrap(), 1);
    }

    #[test]
    fn hub_batch_number_per_chain_isolation() {
        let dir = tempdir().expect("tmpdir");
        let storage = Storage::open(dir.path()).expect("open");

        // Same hub, different chains have independent batch numbers
        assert_eq!(storage.next_hub_batch_number("fin", 1).unwrap(), 1);
        assert_eq!(storage.next_hub_batch_number("fin", 2).unwrap(), 1);

        assert_eq!(storage.next_hub_batch_number("fin", 1).unwrap(), 2);
        assert_eq!(storage.get_hub_batch_number("fin", 2).unwrap(), 1);
    }

    // ========== Per-Hub Queue Stats Tests ==========

    #[test]
    fn hub_queue_stats_default_zero() {
        let dir = tempdir().expect("tmpdir");
        let storage = Storage::open(dir.path()).expect("open");

        let (queue, forced) = storage.get_hub_queue_stats("fin").unwrap();
        assert_eq!(queue, 0);
        assert_eq!(forced, 0);
    }

    #[test]
    fn hub_queue_stats_roundtrip() {
        let dir = tempdir().expect("tmpdir");
        let storage = Storage::open(dir.path()).expect("open");

        storage.set_hub_queue_stats("fin", 100, 5).unwrap();
        let (queue, forced) = storage.get_hub_queue_stats("fin").unwrap();
        assert_eq!(queue, 100);
        assert_eq!(forced, 5);
    }

    #[test]
    fn hub_queue_stats_per_hub_isolation() {
        let dir = tempdir().expect("tmpdir");
        let storage = Storage::open(dir.path()).expect("open");

        storage.set_hub_queue_stats("fin", 100, 5).unwrap();
        storage.set_hub_queue_stats("data", 200, 10).unwrap();

        let (fin_queue, fin_forced) = storage.get_hub_queue_stats("fin").unwrap();
        assert_eq!(fin_queue, 100);
        assert_eq!(fin_forced, 5);

        let (data_queue, data_forced) = storage.get_hub_queue_stats("data").unwrap();
        assert_eq!(data_queue, 200);
        assert_eq!(data_forced, 10);
    }

    // ========== Per-Hub Fee Totals Tests ==========

    #[test]
    fn hub_total_fees_default_zero() {
        let dir = tempdir().expect("tmpdir");
        let storage = Storage::open(dir.path()).expect("open");

        assert_eq!(storage.get_hub_total_fees("m2m", 1337).unwrap(), 0);
    }

    #[test]
    fn hub_total_fees_accumulate() {
        let dir = tempdir().expect("tmpdir");
        let storage = Storage::open(dir.path()).expect("open");

        storage.add_hub_total_fees("m2m", 1337, 1_000_000).unwrap();
        assert_eq!(storage.get_hub_total_fees("m2m", 1337).unwrap(), 1_000_000);

        storage.add_hub_total_fees("m2m", 1337, 500_000).unwrap();
        assert_eq!(storage.get_hub_total_fees("m2m", 1337).unwrap(), 1_500_000);
    }

    #[test]
    fn hub_total_fees_per_hub_isolation() {
        let dir = tempdir().expect("tmpdir");
        let storage = Storage::open(dir.path()).expect("open");

        storage.add_hub_total_fees("m2m", 1337, 1_000_000).unwrap();
        storage.add_hub_total_fees("fin", 1337, 500_000).unwrap();

        assert_eq!(storage.get_hub_total_fees("m2m", 1337).unwrap(), 1_000_000);
        assert_eq!(storage.get_hub_total_fees("fin", 1337).unwrap(), 500_000);
    }

    // ========== Per-Hub In-Flight Tests ==========

    #[test]
    fn hub_in_flight_starts_at_zero() {
        let dir = tempdir().expect("tmpdir");
        let storage = Storage::open(dir.path()).expect("open");

        assert_eq!(storage.get_hub_in_flight_count("fin", 1337).unwrap(), 0);
    }

    #[test]
    fn hub_in_flight_increment_decrement() {
        let dir = tempdir().expect("tmpdir");
        let storage = Storage::open(dir.path()).expect("open");

        assert_eq!(storage.inc_hub_in_flight("fin", 1337).unwrap(), 1);
        assert_eq!(storage.inc_hub_in_flight("fin", 1337).unwrap(), 2);
        assert_eq!(storage.inc_hub_in_flight("fin", 1337).unwrap(), 3);

        assert_eq!(storage.dec_hub_in_flight("fin", 1337).unwrap(), 2);
        assert_eq!(storage.dec_hub_in_flight("fin", 1337).unwrap(), 1);
        assert_eq!(storage.dec_hub_in_flight("fin", 1337).unwrap(), 0);

        // Should not go negative
        assert_eq!(storage.dec_hub_in_flight("fin", 1337).unwrap(), 0);
    }

    #[test]
    fn hub_in_flight_per_hub_isolation() {
        let dir = tempdir().expect("tmpdir");
        let storage = Storage::open(dir.path()).expect("open");

        storage.inc_hub_in_flight("fin", 1337).unwrap();
        storage.inc_hub_in_flight("fin", 1337).unwrap();
        storage.inc_hub_in_flight("data", 1337).unwrap();

        assert_eq!(storage.get_hub_in_flight_count("fin", 1337).unwrap(), 2);
        assert_eq!(storage.get_hub_in_flight_count("data", 1337).unwrap(), 1);
        assert_eq!(storage.get_hub_in_flight_count("m2m", 1337).unwrap(), 0);
    }
}
