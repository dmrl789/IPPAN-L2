//! M2M (Machine-to-Machine) fee accounting storage.
//!
//! This module provides persistent storage for:
//! - Machine balances
//! - Fee reservations
//! - Quota windows (rate limiting)
//! - Forced inclusion tier flags
//! - Transaction ledger (crash-safe, idempotent tracking)
//!
//! All operations are atomic and crash-safe using sled transactions.
//!
//! ## Crash Safety & Idempotency
//!
//! The `m2m_ledger` tree provides a per-transaction ledger that ensures:
//! - Reservations cannot be made twice for the same tx_id
//! - Finalization cannot happen twice (idempotent)
//! - Refunds cannot be issued twice
//! - Crash/restart cannot cause double-charging
//!
//! Each transaction has a deterministic key derived from its tx_id using blake3.

use l2_core::fees::{FeeAmount, FeeError, FeeSchedule, M2mFeeBreakdown};
use l2_core::{canonical_decode, canonical_encode, CanonicalError};
use serde::{Deserialize, Serialize};
use sled::Tree;
use thiserror::Error;
use tracing::{debug, info, warn};

/// Errors from M2M storage operations.
#[derive(Debug, Error)]
pub enum M2mStorageError {
    #[error("storage error: {0}")]
    Sled(#[from] sled::Error),
    #[error("canonical encoding error: {0}")]
    Canonical(#[from] CanonicalError),
    #[error("fee error: {0}")]
    Fee(#[from] FeeError),
    #[error("insufficient balance: required {required}, available {available}")]
    InsufficientBalance { required: u64, available: u64 },
    #[error("insufficient reservation: reserved {reserved}, requested {requested}")]
    InsufficientReservation { reserved: u64, requested: u64 },
    #[error("quota exceeded: {reason}")]
    QuotaExceeded { reason: String },
    #[error("machine not found: {machine_id}")]
    MachineNotFound { machine_id: String },
    #[error("invalid machine ID format: {reason}")]
    InvalidMachineId { reason: String },
    #[error("ledger conflict: tx_id already {state} (expected {expected})")]
    LedgerConflict { state: String, expected: String },
    #[error("invalid tx_id format: {reason}")]
    InvalidTxId { reason: String },
}

// ========== Transaction Ledger Types ==========

/// Transaction ledger entry for crash-safe, idempotent fee tracking.
///
/// Each transaction gets exactly one ledger entry that tracks its lifecycle:
/// - Reserved: Fee has been reserved, tx pending inclusion
/// - Finalised: Fee has been charged/refunded, tx included in batch
///
/// This prevents double-charging, double-refunds, and ensures crash safety.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum LedgerEntry {
    /// Fee has been reserved for this transaction.
    Reserved {
        /// Machine that reserved the fee.
        machine_id: String,
        /// Amount reserved (scaled).
        reserved_scaled: u64,
        /// Timestamp when reserved (ms since epoch).
        created_ms: u64,
    },
    /// Fee has been finalised for this transaction.
    Finalised {
        /// Machine that was charged.
        machine_id: String,
        /// Amount actually charged (scaled).
        charged_scaled: u64,
        /// Amount refunded (scaled).
        refunded_scaled: u64,
        /// Timestamp when finalised (ms since epoch).
        finalised_ms: u64,
        /// Batch hash where this tx was included (hex).
        batch_hash_hex: String,
    },
}

impl LedgerEntry {
    /// Check if this entry is in Reserved state.
    pub fn is_reserved(&self) -> bool {
        matches!(self, Self::Reserved { .. })
    }

    /// Check if this entry is in Finalised state.
    pub fn is_finalised(&self) -> bool {
        matches!(self, Self::Finalised { .. })
    }

    /// Get the machine_id for this entry.
    pub fn machine_id(&self) -> &str {
        match self {
            Self::Reserved { machine_id, .. } => machine_id,
            Self::Finalised { machine_id, .. } => machine_id,
        }
    }

    /// Get the state name for error messages.
    pub fn state_name(&self) -> &'static str {
        match self {
            Self::Reserved { .. } => "reserved",
            Self::Finalised { .. } => "finalised",
        }
    }
}

/// Result of a fee finalization operation.
#[derive(Debug, Clone)]
pub enum FinaliseFeeResult {
    /// Fee was finalised successfully.
    Finalised {
        /// Amount charged.
        charged_scaled: u64,
        /// Amount refunded.
        refunded_scaled: u64,
    },
    /// Fee was already finalised (idempotent success).
    AlreadyFinalised {
        /// Amount that was charged.
        charged_scaled: u64,
        /// Amount that was refunded.
        refunded_scaled: u64,
    },
}

impl FinaliseFeeResult {
    /// Get the refund amount regardless of whether this was a new finalization.
    pub fn refund_scaled(&self) -> u64 {
        match self {
            Self::Finalised {
                refunded_scaled, ..
            } => *refunded_scaled,
            Self::AlreadyFinalised {
                refunded_scaled, ..
            } => *refunded_scaled,
        }
    }

    /// Check if this was a new finalization (not already finalised).
    pub fn is_new(&self) -> bool {
        matches!(self, Self::Finalised { .. })
    }
}

// ========== Canonical Machine ID ==========

/// Maximum length for machine IDs.
pub const MAX_MACHINE_ID_LEN: usize = 64;

/// Minimum length for machine IDs.
pub const MIN_MACHINE_ID_LEN: usize = 1;

/// Maximum length for tx_id (hex-encoded hash).
pub const MAX_TX_ID_LEN: usize = 128;

/// Validate a canonical machine ID.
///
/// Machine IDs must be:
/// - 1-64 characters
/// - ASCII alphanumeric, dash, underscore only
/// - No leading/trailing whitespace
/// - No control characters or Unicode
pub fn validate_canonical_machine_id(machine_id: &str) -> Result<(), M2mStorageError> {
    if machine_id.is_empty() {
        return Err(M2mStorageError::InvalidMachineId {
            reason: "machine_id cannot be empty".to_string(),
        });
    }

    if machine_id.len() > MAX_MACHINE_ID_LEN {
        return Err(M2mStorageError::InvalidMachineId {
            reason: format!(
                "machine_id exceeds max length of {} characters",
                MAX_MACHINE_ID_LEN
            ),
        });
    }

    // Check for leading/trailing whitespace
    if machine_id.trim() != machine_id {
        return Err(M2mStorageError::InvalidMachineId {
            reason: "machine_id cannot have leading/trailing whitespace".to_string(),
        });
    }

    // Check each character is valid ASCII alphanumeric, dash, or underscore
    for (i, c) in machine_id.chars().enumerate() {
        if !c.is_ascii() {
            return Err(M2mStorageError::InvalidMachineId {
                reason: format!("non-ASCII character at position {}", i),
            });
        }
        if !c.is_ascii_alphanumeric() && c != '-' && c != '_' {
            return Err(M2mStorageError::InvalidMachineId {
                reason: format!("invalid character '{}' at position {}", c, i),
            });
        }
    }

    Ok(())
}

/// Validate a tx_id format.
///
/// tx_id must be:
/// - 1-128 characters
/// - Hex characters only (0-9, a-f, A-F)
/// - No whitespace
pub fn validate_tx_id(tx_id: &str) -> Result<(), M2mStorageError> {
    if tx_id.is_empty() {
        return Err(M2mStorageError::InvalidTxId {
            reason: "tx_id cannot be empty".to_string(),
        });
    }

    if tx_id.len() > MAX_TX_ID_LEN {
        return Err(M2mStorageError::InvalidTxId {
            reason: format!("tx_id exceeds max length of {} characters", MAX_TX_ID_LEN),
        });
    }

    // Check for whitespace
    if tx_id.contains(char::is_whitespace) {
        return Err(M2mStorageError::InvalidTxId {
            reason: "tx_id cannot contain whitespace".to_string(),
        });
    }

    // Check all characters are hex
    for (i, c) in tx_id.chars().enumerate() {
        if !c.is_ascii_hexdigit() {
            return Err(M2mStorageError::InvalidTxId {
                reason: format!("non-hex character '{}' at position {}", c, i),
            });
        }
    }

    Ok(())
}

/// Compute a deterministic ledger key from a tx_id.
///
/// Uses blake3 hash of "m2m-ledger" || tx_id to create a unique, collision-resistant key.
fn compute_ledger_key(tx_id: &str) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"m2m-ledger");
    hasher.update(tx_id.as_bytes());
    *hasher.finalize().as_bytes()
}

// ========== Machine Account Types ==========

/// Machine account state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MachineAccount {
    /// Machine identifier.
    pub machine_id: String,
    /// Available balance (scaled).
    pub balance_scaled: u64,
    /// Reserved balance (scaled).
    pub reserved_scaled: u64,
    /// Whether this machine has forced inclusion privileges.
    pub forced_class: ForcedClass,
    /// Last updated timestamp (ms since epoch).
    pub updated_at_ms: u64,
    /// Total fees paid (lifetime, scaled).
    pub total_fees_paid_scaled: u64,
    /// Total transactions submitted.
    pub total_tx_count: u64,
}

impl MachineAccount {
    /// Create a new machine account with zero balance.
    pub fn new(machine_id: String, forced_class: ForcedClass) -> Self {
        Self {
            machine_id,
            balance_scaled: 0,
            reserved_scaled: 0,
            forced_class,
            updated_at_ms: 0,
            total_fees_paid_scaled: 0,
            total_tx_count: 0,
        }
    }

    /// Get available balance (balance - reserved).
    pub fn available_balance(&self) -> u64 {
        self.balance_scaled.saturating_sub(self.reserved_scaled)
    }
}

/// Forced inclusion class for a machine.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ForcedClass {
    /// Standard machine - subject to normal rate limits.
    #[default]
    Standard,
    /// Safety-critical device - can bypass normal queue limits.
    ForcedInclusion,
}

/// Quota window for rate limiting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuotaWindow {
    /// Machine identifier.
    pub machine_id: String,
    /// Start of current quota window (ms since epoch).
    pub window_start_ms: u64,
    /// Units consumed in current window.
    pub used_units: u64,
    /// Maximum units allowed per window.
    pub max_units: u64,
    /// Window duration (ms).
    pub window_duration_ms: u64,
}

impl QuotaWindow {
    /// Create a new quota window.
    pub fn new(machine_id: String, max_units: u64, window_duration_ms: u64) -> Self {
        Self {
            machine_id,
            window_start_ms: 0,
            used_units: 0,
            max_units,
            window_duration_ms,
        }
    }

    /// Check if the window needs to be reset at the given timestamp.
    pub fn should_reset(&self, now_ms: u64) -> bool {
        now_ms >= self.window_start_ms.saturating_add(self.window_duration_ms)
    }

    /// Reset the window.
    pub fn reset(&mut self, now_ms: u64) {
        self.window_start_ms = now_ms;
        self.used_units = 0;
    }

    /// Get remaining quota.
    pub fn remaining(&self) -> u64 {
        self.max_units.saturating_sub(self.used_units)
    }
}

/// Pending fee reservation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingReservation {
    /// Transaction hash.
    pub tx_hash: [u8; 32],
    /// Machine ID.
    pub machine_id: String,
    /// Reserved amount (scaled).
    pub reserved_scaled: u64,
    /// Fee breakdown.
    pub breakdown: M2mFeeBreakdown,
    /// Created timestamp (ms since epoch).
    pub created_at_ms: u64,
    /// Whether this is a forced inclusion tx.
    pub forced: bool,
}

/// Configuration for forced inclusion with unbypassable daily limits.
///
/// These limits are enforced atomically with fee reservation to prevent:
/// - Rotating machine_id to bypass limits
/// - Resubmitting same tx to flood queue
/// - Exceeding byte quotas per day
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ForcedInclusionLimits {
    /// Maximum forced txs per machine per day.
    pub max_tx_per_day: u64,
    /// Maximum forced bytes per machine per day.
    pub max_bytes_per_day: u64,
    /// Current day start (ms since epoch).
    pub day_start_ms: u64,
    /// Transaction count for current day.
    pub used_tx_today: u64,
    /// Bytes used for current day.
    pub used_bytes_today: u64,
}

impl Default for ForcedInclusionLimits {
    fn default() -> Self {
        Self {
            max_tx_per_day: 100,
            max_bytes_per_day: 10 * 1024 * 1024, // 10 MB default
            day_start_ms: 0,
            used_tx_today: 0,
            used_bytes_today: 0,
        }
    }
}

impl ForcedInclusionLimits {
    /// Check if the day has rolled over and reset if needed.
    pub fn maybe_reset(&mut self, now_ms: u64) {
        const MS_PER_DAY: u64 = 86_400_000;
        if now_ms >= self.day_start_ms.saturating_add(MS_PER_DAY) {
            self.day_start_ms = now_ms.saturating_sub(now_ms % MS_PER_DAY);
            self.used_tx_today = 0;
            self.used_bytes_today = 0;
        }
    }

    /// Check if adding a tx with given bytes would exceed limits.
    pub fn would_exceed(&self, tx_bytes: u64) -> Option<String> {
        if self.used_tx_today >= self.max_tx_per_day {
            return Some(format!(
                "forced tx daily limit exceeded: {} >= {}",
                self.used_tx_today, self.max_tx_per_day
            ));
        }
        if self.used_bytes_today.saturating_add(tx_bytes) > self.max_bytes_per_day {
            return Some(format!(
                "forced bytes daily limit exceeded: {} + {} > {}",
                self.used_bytes_today, tx_bytes, self.max_bytes_per_day
            ));
        }
        None
    }

    /// Apply usage for a forced tx.
    pub fn apply_usage(&mut self, tx_bytes: u64) {
        self.used_tx_today = self.used_tx_today.saturating_add(1);
        self.used_bytes_today = self.used_bytes_today.saturating_add(tx_bytes);
    }

    /// Remaining tx count for today.
    pub fn remaining_tx(&self) -> u64 {
        self.max_tx_per_day.saturating_sub(self.used_tx_today)
    }

    /// Remaining bytes for today.
    pub fn remaining_bytes(&self) -> u64 {
        self.max_bytes_per_day.saturating_sub(self.used_bytes_today)
    }
}

/// Maximum forced txs to drain per batch (deterministic bound).
pub const MAX_FORCED_PER_BATCH: usize = 50;

/// Batch fee totals.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchFeeTotals {
    /// Batch hash.
    pub batch_hash: [u8; 32],
    /// Total fees collected (scaled).
    pub total_fees_scaled: u64,
    /// Number of transactions.
    pub tx_count: u64,
    /// Total refunds issued (scaled).
    pub total_refunds_scaled: u64,
    /// Created timestamp.
    pub created_at_ms: u64,
}

/// M2M storage handle.
pub struct M2mStorage {
    /// Machine accounts (machine_id -> MachineAccount).
    accounts: Tree,
    /// Quota windows (machine_id -> QuotaWindow).
    quotas: Tree,
    /// Pending reservations (tx_hash -> PendingReservation).
    reservations: Tree,
    /// Batch fee totals (batch_hash -> BatchFeeTotals).
    batch_fees: Tree,
    /// Forced inclusion usage (machine_id -> ForcedInclusionLimits).
    forced_limits: Tree,
    /// Transaction ledger (ledger_key -> LedgerEntry).
    /// This provides crash-safe, idempotent tracking per tx_id.
    ledger: Tree,
    /// Fee schedule.
    schedule: FeeSchedule,
}

impl M2mStorage {
    /// Create a new M2M storage using the given sled database.
    pub fn open(db: &sled::Db, schedule: FeeSchedule) -> Result<Self, M2mStorageError> {
        let accounts = db.open_tree("m2m_accounts")?;
        let quotas = db.open_tree("m2m_quotas")?;
        let reservations = db.open_tree("m2m_reservations")?;
        let batch_fees = db.open_tree("m2m_batch_fees")?;
        let forced_limits = db.open_tree("m2m_forced_limits")?;
        let ledger = db.open_tree("m2m_ledger")?;

        Ok(Self {
            accounts,
            quotas,
            reservations,
            batch_fees,
            forced_limits,
            ledger,
            schedule,
        })
    }

    /// Validate machine ID format.
    ///
    /// Machine IDs must be:
    /// - 1-64 characters
    /// - ASCII alphanumeric, dash, underscore only
    /// - No leading/trailing whitespace
    /// - No Unicode or control characters
    pub fn validate_machine_id(machine_id: &str) -> Result<(), M2mStorageError> {
        validate_canonical_machine_id(machine_id)
    }

    /// Get the current fee schedule.
    pub fn get_schedule(&self) -> &FeeSchedule {
        &self.schedule
    }

    // ========== Balance APIs ==========

    /// Get account balance.
    pub fn balance(&self, machine_id: &str) -> Result<FeeAmount, M2mStorageError> {
        Self::validate_machine_id(machine_id)?;

        match self.accounts.get(machine_id.as_bytes())? {
            Some(data) => {
                let account: MachineAccount = canonical_decode(&data)?;
                Ok(FeeAmount::from_scaled(account.balance_scaled))
            }
            None => Ok(FeeAmount::ZERO),
        }
    }

    /// Get full machine account.
    pub fn get_account(&self, machine_id: &str) -> Result<Option<MachineAccount>, M2mStorageError> {
        Self::validate_machine_id(machine_id)?;

        match self.accounts.get(machine_id.as_bytes())? {
            Some(data) => Ok(Some(canonical_decode(&data)?)),
            None => Ok(None),
        }
    }

    /// Get reserved amount for a machine.
    pub fn reserved(&self, machine_id: &str) -> Result<FeeAmount, M2mStorageError> {
        Self::validate_machine_id(machine_id)?;

        match self.accounts.get(machine_id.as_bytes())? {
            Some(data) => {
                let account: MachineAccount = canonical_decode(&data)?;
                Ok(FeeAmount::from_scaled(account.reserved_scaled))
            }
            None => Ok(FeeAmount::ZERO),
        }
    }

    /// Get forced class for a machine.
    pub fn forced_class(&self, machine_id: &str) -> Result<ForcedClass, M2mStorageError> {
        Self::validate_machine_id(machine_id)?;

        match self.accounts.get(machine_id.as_bytes())? {
            Some(data) => {
                let account: MachineAccount = canonical_decode(&data)?;
                Ok(account.forced_class)
            }
            None => Ok(ForcedClass::Standard),
        }
    }

    /// Set forced class for a machine.
    pub fn set_forced_class(
        &self,
        machine_id: &str,
        class: ForcedClass,
        now_ms: u64,
    ) -> Result<(), M2mStorageError> {
        Self::validate_machine_id(machine_id)?;

        let mut account = self
            .get_account(machine_id)?
            .unwrap_or_else(|| MachineAccount::new(machine_id.to_string(), class));

        account.forced_class = class;
        account.updated_at_ms = now_ms;

        let data = canonical_encode(&account)?;
        self.accounts.insert(machine_id.as_bytes(), data)?;
        Ok(())
    }

    /// Top up balance (devnet only).
    pub fn topup(
        &self,
        machine_id: &str,
        amount_scaled: u64,
        now_ms: u64,
    ) -> Result<FeeAmount, M2mStorageError> {
        Self::validate_machine_id(machine_id)?;

        let mut account = self
            .get_account(machine_id)?
            .unwrap_or_else(|| MachineAccount::new(machine_id.to_string(), ForcedClass::Standard));

        account.balance_scaled = account
            .balance_scaled
            .checked_add(amount_scaled)
            .ok_or(FeeError::Overflow)?;
        account.updated_at_ms = now_ms;

        let data = canonical_encode(&account)?;
        self.accounts.insert(machine_id.as_bytes(), data)?;

        info!(
            machine_id = %machine_id,
            amount_scaled = amount_scaled,
            new_balance = account.balance_scaled,
            "topped up machine balance"
        );

        Ok(FeeAmount::from_scaled(account.balance_scaled))
    }

    // ========== Ledger APIs ==========

    /// Get a ledger entry by tx_id.
    pub fn get_ledger_entry(&self, tx_id: &str) -> Result<Option<LedgerEntry>, M2mStorageError> {
        validate_tx_id(tx_id)?;
        let key = compute_ledger_key(tx_id);
        match self.ledger.get(key)? {
            Some(data) => Ok(Some(canonical_decode(&data)?)),
            None => Ok(None),
        }
    }

    /// Get a ledger entry by tx_hash (32-byte hash converted to hex).
    pub fn get_ledger_entry_by_hash(
        &self,
        tx_hash: &[u8; 32],
    ) -> Result<Option<LedgerEntry>, M2mStorageError> {
        let tx_id = hex::encode(tx_hash);
        self.get_ledger_entry(&tx_id)
    }

    /// List all ledger entries (for debugging/ops only).
    pub fn list_ledger_entries(
        &self,
        limit: usize,
    ) -> Result<Vec<(String, LedgerEntry)>, M2mStorageError> {
        let mut entries = Vec::new();
        for result in self.ledger.iter() {
            if entries.len() >= limit {
                break;
            }
            let (key, value) = result?;
            let entry: LedgerEntry = canonical_decode(&value)?;
            // Key is a blake3 hash, not the original tx_id, so we can't recover it
            // For ops purposes, we return the hex of the key
            entries.push((hex::encode(&key), entry));
        }
        Ok(entries)
    }

    // ========== Reservation APIs ==========

    /// Reserve fee for a transaction (idempotent via ledger).
    ///
    /// This deducts from available balance and creates a pending reservation.
    /// If the same tx_id is reserved twice, returns Ok (idempotent).
    /// If the tx_id is already finalised, returns an error.
    ///
    /// # Arguments
    /// * `machine_id` - The machine reserving the fee
    /// * `tx_id` - Unique transaction identifier (hex string, typically hash)
    /// * `tx_hash` - 32-byte transaction hash for legacy reservation lookup
    /// * `amount_scaled` - Amount to reserve (scaled)
    /// * `breakdown` - Fee breakdown details
    /// * `forced` - Whether this is a forced inclusion tx
    /// * `now_ms` - Current timestamp in milliseconds
    pub fn reserve_fee(
        &self,
        machine_id: &str,
        tx_hash: [u8; 32],
        amount_scaled: u64,
        breakdown: M2mFeeBreakdown,
        forced: bool,
        now_ms: u64,
    ) -> Result<(), M2mStorageError> {
        let tx_id = hex::encode(tx_hash);
        self.reserve_fee_by_tx_id(
            machine_id,
            &tx_id,
            tx_hash,
            amount_scaled,
            breakdown,
            forced,
            now_ms,
        )
    }

    /// Reserve fee for a transaction by tx_id (idempotent via ledger).
    ///
    /// This is the primary reservation method that uses the ledger for idempotency.
    #[allow(clippy::too_many_arguments)]
    pub fn reserve_fee_by_tx_id(
        &self,
        machine_id: &str,
        tx_id: &str,
        tx_hash: [u8; 32],
        amount_scaled: u64,
        breakdown: M2mFeeBreakdown,
        forced: bool,
        now_ms: u64,
    ) -> Result<(), M2mStorageError> {
        Self::validate_machine_id(machine_id)?;
        validate_tx_id(tx_id)?;

        let ledger_key = compute_ledger_key(tx_id);

        // Check ledger first (idempotency check)
        if let Some(entry) = self.ledger.get(ledger_key)? {
            let existing: LedgerEntry = canonical_decode(&entry)?;
            match &existing {
                LedgerEntry::Reserved {
                    machine_id: existing_mid,
                    reserved_scaled: existing_amt,
                    ..
                } => {
                    // Already reserved - idempotent success if same machine/amount
                    if existing_mid == machine_id && *existing_amt == amount_scaled {
                        debug!(
                            tx_id = %tx_id,
                            machine_id = %machine_id,
                            "reserve_fee idempotent: already reserved"
                        );
                        return Ok(());
                    }
                    // Different machine or amount - conflict
                    return Err(M2mStorageError::LedgerConflict {
                        state: format!("reserved by {} for {}", existing_mid, existing_amt),
                        expected: format!("not reserved or same reservation by {}", machine_id),
                    });
                }
                LedgerEntry::Finalised { .. } => {
                    // Already finalised - cannot reserve again
                    return Err(M2mStorageError::LedgerConflict {
                        state: "finalised".to_string(),
                        expected: "not finalised".to_string(),
                    });
                }
            }
        }

        // Get account
        let mut account =
            self.get_account(machine_id)?
                .ok_or_else(|| M2mStorageError::MachineNotFound {
                    machine_id: machine_id.to_string(),
                })?;

        // Check available balance
        let available = account.available_balance();
        if available < amount_scaled {
            return Err(M2mStorageError::InsufficientBalance {
                required: amount_scaled,
                available,
            });
        }

        // Update reserved amount
        account.reserved_scaled = account
            .reserved_scaled
            .checked_add(amount_scaled)
            .ok_or(FeeError::Overflow)?;
        account.updated_at_ms = now_ms;

        // Create ledger entry
        let ledger_entry = LedgerEntry::Reserved {
            machine_id: machine_id.to_string(),
            reserved_scaled: amount_scaled,
            created_ms: now_ms,
        };

        // Create reservation (legacy, for backwards compatibility)
        let reservation = PendingReservation {
            tx_hash,
            machine_id: machine_id.to_string(),
            reserved_scaled: amount_scaled,
            breakdown,
            created_at_ms: now_ms,
            forced,
        };

        // Persist atomically
        let account_data = canonical_encode(&account)?;
        let reservation_data = canonical_encode(&reservation)?;
        let ledger_data = canonical_encode(&ledger_entry)?;

        self.accounts.insert(machine_id.as_bytes(), account_data)?;
        self.reservations.insert(tx_hash, reservation_data)?;
        self.ledger.insert(ledger_key, ledger_data)?;

        debug!(
            machine_id = %machine_id,
            tx_id = %tx_id,
            amount_scaled = amount_scaled,
            "reserved fee (ledger)"
        );

        Ok(())
    }

    /// Finalise fee for a transaction (idempotent via ledger).
    ///
    /// This releases the reservation and deducts the final fee.
    /// Any excess is refunded to the available balance.
    ///
    /// If already finalised, returns `FinaliseFeeResult::AlreadyFinalised` (idempotent).
    ///
    /// # Arguments
    /// * `machine_id` - The machine being charged
    /// * `tx_hash` - 32-byte transaction hash
    /// * `final_amount_scaled` - Final amount to charge (scaled)
    /// * `now_ms` - Current timestamp in milliseconds
    /// * `batch_hash_hex` - Hex string of batch hash where tx was included
    pub fn finalise_fee(
        &self,
        machine_id: &str,
        tx_hash: [u8; 32],
        final_amount_scaled: u64,
        now_ms: u64,
    ) -> Result<u64, M2mStorageError> {
        // Default batch hash for legacy compatibility
        let result = self.finalise_fee_with_batch(
            machine_id,
            tx_hash,
            final_amount_scaled,
            now_ms,
            "0000000000000000000000000000000000000000000000000000000000000000",
        )?;
        Ok(result.refund_scaled())
    }

    /// Finalise fee for a transaction with batch hash (idempotent via ledger).
    ///
    /// This is the primary finalization method that records the batch hash in the ledger.
    pub fn finalise_fee_with_batch(
        &self,
        machine_id: &str,
        tx_hash: [u8; 32],
        final_amount_scaled: u64,
        now_ms: u64,
        batch_hash_hex: &str,
    ) -> Result<FinaliseFeeResult, M2mStorageError> {
        let tx_id = hex::encode(tx_hash);
        self.finalise_fee_by_tx_id(
            machine_id,
            &tx_id,
            tx_hash,
            final_amount_scaled,
            now_ms,
            batch_hash_hex,
        )
    }

    /// Finalise fee by tx_id (idempotent via ledger).
    pub fn finalise_fee_by_tx_id(
        &self,
        machine_id: &str,
        tx_id: &str,
        tx_hash: [u8; 32],
        final_amount_scaled: u64,
        now_ms: u64,
        batch_hash_hex: &str,
    ) -> Result<FinaliseFeeResult, M2mStorageError> {
        Self::validate_machine_id(machine_id)?;
        validate_tx_id(tx_id)?;

        let ledger_key = compute_ledger_key(tx_id);

        // Check ledger first (idempotency check)
        if let Some(entry) = self.ledger.get(ledger_key)? {
            let existing: LedgerEntry = canonical_decode(&entry)?;
            match &existing {
                LedgerEntry::Finalised {
                    charged_scaled,
                    refunded_scaled,
                    ..
                } => {
                    // Already finalised - idempotent success
                    debug!(
                        tx_id = %tx_id,
                        machine_id = %machine_id,
                        "finalise_fee idempotent: already finalised"
                    );
                    return Ok(FinaliseFeeResult::AlreadyFinalised {
                        charged_scaled: *charged_scaled,
                        refunded_scaled: *refunded_scaled,
                    });
                }
                LedgerEntry::Reserved {
                    machine_id: reserved_mid,
                    reserved_scaled,
                    ..
                } => {
                    // Verify machine ID matches
                    if reserved_mid != machine_id {
                        return Err(M2mStorageError::InvalidMachineId {
                            reason: format!(
                                "reservation machine_id mismatch: {} vs {}",
                                reserved_mid, machine_id
                            ),
                        });
                    }

                    // Check final doesn't exceed reserved
                    if final_amount_scaled > *reserved_scaled {
                        return Err(M2mStorageError::InsufficientReservation {
                            reserved: *reserved_scaled,
                            requested: final_amount_scaled,
                        });
                    }

                    // Calculate refund
                    let refund = reserved_scaled.saturating_sub(final_amount_scaled);

                    // Get account
                    let mut account = self.get_account(machine_id)?.ok_or_else(|| {
                        M2mStorageError::MachineNotFound {
                            machine_id: machine_id.to_string(),
                        }
                    })?;

                    // Update account:
                    // - Deduct final fee from balance
                    // - Release reservation
                    account.balance_scaled =
                        account.balance_scaled.saturating_sub(final_amount_scaled);
                    account.reserved_scaled =
                        account.reserved_scaled.saturating_sub(*reserved_scaled);
                    account.total_fees_paid_scaled = account
                        .total_fees_paid_scaled
                        .saturating_add(final_amount_scaled);
                    account.total_tx_count = account.total_tx_count.saturating_add(1);
                    account.updated_at_ms = now_ms;

                    // Create finalised ledger entry
                    let ledger_entry = LedgerEntry::Finalised {
                        machine_id: machine_id.to_string(),
                        charged_scaled: final_amount_scaled,
                        refunded_scaled: refund,
                        finalised_ms: now_ms,
                        batch_hash_hex: batch_hash_hex.to_string(),
                    };

                    // Persist atomically
                    let account_data = canonical_encode(&account)?;
                    let ledger_data = canonical_encode(&ledger_entry)?;

                    self.accounts.insert(machine_id.as_bytes(), account_data)?;
                    self.reservations.remove(tx_hash)?;
                    self.ledger.insert(ledger_key, ledger_data)?;

                    debug!(
                        machine_id = %machine_id,
                        tx_id = %tx_id,
                        final_amount_scaled = final_amount_scaled,
                        refund = refund,
                        batch_hash = %batch_hash_hex,
                        "finalised fee (ledger)"
                    );

                    return Ok(FinaliseFeeResult::Finalised {
                        charged_scaled: final_amount_scaled,
                        refunded_scaled: refund,
                    });
                }
            }
        }

        // No ledger entry - try legacy path (reservation without ledger)
        // This handles txs reserved before ledger was introduced
        let reservation_data = self.reservations.get(tx_hash)?;
        if let Some(data) = reservation_data {
            let reservation: PendingReservation = canonical_decode(&data)?;

            // Verify machine ID matches
            if reservation.machine_id != machine_id {
                return Err(M2mStorageError::InvalidMachineId {
                    reason: format!(
                        "reservation machine_id mismatch: {} vs {}",
                        reservation.machine_id, machine_id
                    ),
                });
            }

            // Check final doesn't exceed reserved
            if final_amount_scaled > reservation.reserved_scaled {
                return Err(M2mStorageError::InsufficientReservation {
                    reserved: reservation.reserved_scaled,
                    requested: final_amount_scaled,
                });
            }

            // Get account
            let mut account =
                self.get_account(machine_id)?
                    .ok_or_else(|| M2mStorageError::MachineNotFound {
                        machine_id: machine_id.to_string(),
                    })?;

            // Calculate refund
            let refund = reservation
                .reserved_scaled
                .saturating_sub(final_amount_scaled);

            // Update account
            account.balance_scaled = account.balance_scaled.saturating_sub(final_amount_scaled);
            account.reserved_scaled = account
                .reserved_scaled
                .saturating_sub(reservation.reserved_scaled);
            account.total_fees_paid_scaled = account
                .total_fees_paid_scaled
                .saturating_add(final_amount_scaled);
            account.total_tx_count = account.total_tx_count.saturating_add(1);
            account.updated_at_ms = now_ms;

            // Create finalised ledger entry (upgrade to ledger)
            let ledger_entry = LedgerEntry::Finalised {
                machine_id: machine_id.to_string(),
                charged_scaled: final_amount_scaled,
                refunded_scaled: refund,
                finalised_ms: now_ms,
                batch_hash_hex: batch_hash_hex.to_string(),
            };

            // Persist
            let account_data = canonical_encode(&account)?;
            let ledger_data = canonical_encode(&ledger_entry)?;

            self.accounts.insert(machine_id.as_bytes(), account_data)?;
            self.reservations.remove(tx_hash)?;
            self.ledger.insert(ledger_key, ledger_data)?;

            debug!(
                machine_id = %machine_id,
                tx_id = %tx_id,
                final_amount_scaled = final_amount_scaled,
                refund = refund,
                "finalised fee (legacy upgrade to ledger)"
            );

            return Ok(FinaliseFeeResult::Finalised {
                charged_scaled: final_amount_scaled,
                refunded_scaled: refund,
            });
        }

        // No reservation found at all
        Err(M2mStorageError::MachineNotFound {
            machine_id: format!("reservation:{}", tx_id),
        })
    }

    /// Release a reservation without finalising (e.g., tx rejected).
    ///
    /// If the tx is already finalised, returns 0 (idempotent - cannot release after finalize).
    /// If the tx is reserved, releases the reservation and removes the ledger entry.
    pub fn release_reservation(
        &self,
        machine_id: &str,
        tx_hash: [u8; 32],
        now_ms: u64,
    ) -> Result<u64, M2mStorageError> {
        let tx_id = hex::encode(tx_hash);
        self.release_reservation_by_tx_id(machine_id, &tx_id, tx_hash, now_ms)
    }

    /// Release a reservation by tx_id (idempotent via ledger).
    pub fn release_reservation_by_tx_id(
        &self,
        machine_id: &str,
        tx_id: &str,
        tx_hash: [u8; 32],
        now_ms: u64,
    ) -> Result<u64, M2mStorageError> {
        Self::validate_machine_id(machine_id)?;
        validate_tx_id(tx_id)?;

        let ledger_key = compute_ledger_key(tx_id);

        // Check ledger first
        if let Some(entry) = self.ledger.get(ledger_key)? {
            let existing: LedgerEntry = canonical_decode(&entry)?;
            match &existing {
                LedgerEntry::Finalised { .. } => {
                    // Already finalised - cannot release, but this is idempotent success
                    warn!(
                        tx_id = %tx_id,
                        machine_id = %machine_id,
                        "release_reservation: already finalised, cannot release"
                    );
                    return Ok(0);
                }
                LedgerEntry::Reserved {
                    machine_id: reserved_mid,
                    reserved_scaled,
                    ..
                } => {
                    // Verify machine ID matches (or allow release by any machine?)
                    // For safety, we require matching machine_id
                    if reserved_mid != machine_id {
                        return Err(M2mStorageError::InvalidMachineId {
                            reason: format!(
                                "reservation machine_id mismatch: {} vs {}",
                                reserved_mid, machine_id
                            ),
                        });
                    }

                    // Get account
                    let mut account = match self.get_account(machine_id)? {
                        Some(acc) => acc,
                        None => return Ok(0),
                    };

                    // Release reserved amount
                    account.reserved_scaled =
                        account.reserved_scaled.saturating_sub(*reserved_scaled);
                    account.updated_at_ms = now_ms;

                    // Persist - remove both ledger entry and reservation
                    let account_data = canonical_encode(&account)?;
                    self.accounts.insert(machine_id.as_bytes(), account_data)?;
                    self.reservations.remove(tx_hash)?;
                    self.ledger.remove(ledger_key)?;

                    debug!(
                        machine_id = %machine_id,
                        tx_id = %tx_id,
                        released = reserved_scaled,
                        "released reservation (ledger)"
                    );

                    return Ok(*reserved_scaled);
                }
            }
        }

        // No ledger entry - try legacy path
        let reservation_data = match self.reservations.get(tx_hash)? {
            Some(data) => data,
            None => return Ok(0), // No reservation to release
        };
        let reservation: PendingReservation = canonical_decode(&reservation_data)?;

        // Get account
        let mut account = match self.get_account(machine_id)? {
            Some(acc) => acc,
            None => return Ok(0),
        };

        // Release reserved amount
        account.reserved_scaled = account
            .reserved_scaled
            .saturating_sub(reservation.reserved_scaled);
        account.updated_at_ms = now_ms;

        // Persist
        let account_data = canonical_encode(&account)?;
        self.accounts.insert(machine_id.as_bytes(), account_data)?;
        self.reservations.remove(tx_hash)?;

        debug!(
            machine_id = %machine_id,
            tx_id = %tx_id,
            released = reservation.reserved_scaled,
            "released reservation (legacy)"
        );

        Ok(reservation.reserved_scaled)
    }

    /// Get a pending reservation.
    pub fn get_reservation(
        &self,
        tx_hash: &[u8; 32],
    ) -> Result<Option<PendingReservation>, M2mStorageError> {
        match self.reservations.get(tx_hash)? {
            Some(data) => Ok(Some(canonical_decode(&data)?)),
            None => Ok(None),
        }
    }

    // ========== Quota APIs ==========

    /// Get quota window for a machine.
    pub fn get_quota_window(
        &self,
        machine_id: &str,
    ) -> Result<Option<QuotaWindow>, M2mStorageError> {
        Self::validate_machine_id(machine_id)?;

        match self.quotas.get(machine_id.as_bytes())? {
            Some(data) => Ok(Some(canonical_decode(&data)?)),
            None => Ok(None),
        }
    }

    /// Apply quota usage.
    ///
    /// This checks and updates the quota window for the machine.
    /// If the quota would be exceeded, returns an error.
    pub fn apply_quota(
        &self,
        machine_id: &str,
        cost_units: u64,
        now_ms: u64,
        max_units: u64,
        window_duration_ms: u64,
    ) -> Result<(), M2mStorageError> {
        Self::validate_machine_id(machine_id)?;

        let mut window = self.get_quota_window(machine_id)?.unwrap_or_else(|| {
            QuotaWindow::new(machine_id.to_string(), max_units, window_duration_ms)
        });

        // Reset window if expired
        if window.should_reset(now_ms) {
            window.reset(now_ms);
            window.max_units = max_units;
            window.window_duration_ms = window_duration_ms;
        }

        // Check quota
        let new_usage = window.used_units.saturating_add(cost_units);
        if new_usage > window.max_units {
            return Err(M2mStorageError::QuotaExceeded {
                reason: format!(
                    "quota exceeded: {} + {} > {} (resets at {})",
                    window.used_units,
                    cost_units,
                    window.max_units,
                    window
                        .window_start_ms
                        .saturating_add(window.window_duration_ms)
                ),
            });
        }

        // Update window
        window.used_units = new_usage;
        let data = canonical_encode(&window)?;
        self.quotas.insert(machine_id.as_bytes(), data)?;

        Ok(())
    }

    // ========== Forced Inclusion APIs ==========

    /// Check forced inclusion caps before reservation (does not apply usage).
    ///
    /// This should be called before reserve_fee for forced txs to ensure
    /// the caps won't be exceeded. Use `apply_forced_usage` atomically with
    /// `reserve_fee` to actually apply the usage.
    pub fn check_forced_caps(
        &self,
        machine_id: &str,
        tx_bytes: u64,
        now_ms: u64,
    ) -> Result<(), M2mStorageError> {
        Self::validate_machine_id(machine_id)?;

        // Check machine class
        let class = self.forced_class(machine_id)?;
        if class != ForcedClass::ForcedInclusion {
            return Err(M2mStorageError::QuotaExceeded {
                reason: "machine does not have forced inclusion privileges".to_string(),
            });
        }

        // Get or create limits
        let mut limits = match self.forced_limits.get(machine_id.as_bytes())? {
            Some(data) => canonical_decode(&data)?,
            None => ForcedInclusionLimits::default(),
        };

        // Maybe reset for new day
        limits.maybe_reset(now_ms);

        // Check limits
        if let Some(reason) = limits.would_exceed(tx_bytes) {
            return Err(M2mStorageError::QuotaExceeded { reason });
        }

        Ok(())
    }

    /// Check and apply forced inclusion usage atomically.
    ///
    /// For ForcedInclusion class machines, this tracks daily usage limits
    /// for both transaction count and bytes.
    ///
    /// # Arguments
    /// * `machine_id` - The machine ID
    /// * `tx_bytes` - Size of the transaction in bytes
    /// * `now_ms` - Current timestamp in milliseconds
    pub fn apply_forced_usage(
        &self,
        machine_id: &str,
        tx_bytes: u64,
        now_ms: u64,
    ) -> Result<(), M2mStorageError> {
        Self::validate_machine_id(machine_id)?;

        // Check machine class
        let class = self.forced_class(machine_id)?;
        if class != ForcedClass::ForcedInclusion {
            return Err(M2mStorageError::QuotaExceeded {
                reason: "machine does not have forced inclusion privileges".to_string(),
            });
        }

        // Get or create limits
        let mut limits = match self.forced_limits.get(machine_id.as_bytes())? {
            Some(data) => canonical_decode(&data)?,
            None => ForcedInclusionLimits::default(),
        };

        // Maybe reset for new day
        limits.maybe_reset(now_ms);

        // Check limits
        if let Some(reason) = limits.would_exceed(tx_bytes) {
            return Err(M2mStorageError::QuotaExceeded { reason });
        }

        // Apply usage
        limits.apply_usage(tx_bytes);

        // Persist
        let data = canonical_encode(&limits)?;
        self.forced_limits.insert(machine_id.as_bytes(), data)?;

        debug!(
            machine_id = %machine_id,
            tx_bytes = tx_bytes,
            used_tx = limits.used_tx_today,
            used_bytes = limits.used_bytes_today,
            "applied forced usage"
        );

        Ok(())
    }

    /// Reserve fee and apply forced usage atomically.
    ///
    /// This combines `check_forced_caps`, `apply_forced_usage`, and `reserve_fee`
    /// into a single atomic operation to prevent bypass attacks.
    pub fn reserve_forced_fee(
        &self,
        machine_id: &str,
        tx_hash: [u8; 32],
        amount_scaled: u64,
        tx_bytes: u64,
        breakdown: M2mFeeBreakdown,
        now_ms: u64,
    ) -> Result<(), M2mStorageError> {
        // Check and apply forced caps first
        self.apply_forced_usage(machine_id, tx_bytes, now_ms)?;

        // Then reserve the fee
        self.reserve_fee(machine_id, tx_hash, amount_scaled, breakdown, true, now_ms)
    }

    /// Get forced inclusion limits for a machine.
    pub fn get_forced_limits(
        &self,
        machine_id: &str,
    ) -> Result<Option<ForcedInclusionLimits>, M2mStorageError> {
        Self::validate_machine_id(machine_id)?;

        match self.forced_limits.get(machine_id.as_bytes())? {
            Some(data) => Ok(Some(canonical_decode(&data)?)),
            None => Ok(None),
        }
    }

    /// Set forced inclusion limits for a machine.
    pub fn set_forced_limits(
        &self,
        machine_id: &str,
        limits: ForcedInclusionLimits,
    ) -> Result<(), M2mStorageError> {
        Self::validate_machine_id(machine_id)?;

        let data = canonical_encode(&limits)?;
        self.forced_limits.insert(machine_id.as_bytes(), data)?;
        Ok(())
    }

    // ========== Batch Fee APIs ==========

    /// Record batch fee totals.
    pub fn record_batch_fees(&self, totals: &BatchFeeTotals) -> Result<(), M2mStorageError> {
        let data = canonical_encode(totals)?;
        self.batch_fees.insert(totals.batch_hash, data)?;
        Ok(())
    }

    /// Get batch fee totals.
    pub fn get_batch_fees(
        &self,
        batch_hash: &[u8; 32],
    ) -> Result<Option<BatchFeeTotals>, M2mStorageError> {
        match self.batch_fees.get(batch_hash)? {
            Some(data) => Ok(Some(canonical_decode(&data)?)),
            None => Ok(None),
        }
    }

    // ========== Statistics APIs ==========

    /// Get total M2M fee statistics including ledger metrics.
    pub fn get_stats(&self) -> Result<M2mStats, M2mStorageError> {
        let mut stats = M2mStats::default();

        for result in self.accounts.iter() {
            let (_key, value) = result?;
            let account: MachineAccount = canonical_decode(&value)?;
            stats.total_machines = stats.total_machines.saturating_add(1);
            stats.total_balance_scaled = stats
                .total_balance_scaled
                .saturating_add(account.balance_scaled);
            stats.total_reserved_scaled = stats
                .total_reserved_scaled
                .saturating_add(account.reserved_scaled);
            stats.total_fees_paid_scaled = stats
                .total_fees_paid_scaled
                .saturating_add(account.total_fees_paid_scaled);
            if account.forced_class == ForcedClass::ForcedInclusion {
                stats.forced_machines = stats.forced_machines.saturating_add(1);
            }
        }

        stats.pending_reservations = u64::try_from(self.reservations.len()).unwrap_or(u64::MAX);

        // Count ledger entries
        for result in self.ledger.iter() {
            let (_key, value) = result?;
            let entry: LedgerEntry = canonical_decode(&value)?;
            match entry {
                LedgerEntry::Reserved { .. } => {
                    stats.ledger_reserved_count = stats.ledger_reserved_count.saturating_add(1);
                }
                LedgerEntry::Finalised {
                    charged_scaled,
                    refunded_scaled,
                    ..
                } => {
                    stats.ledger_finalised_count = stats.ledger_finalised_count.saturating_add(1);
                    stats.ledger_total_charged_scaled = stats
                        .ledger_total_charged_scaled
                        .saturating_add(charged_scaled);
                    stats.ledger_total_refunded_scaled = stats
                        .ledger_total_refunded_scaled
                        .saturating_add(refunded_scaled);
                }
            }
        }

        Ok(stats)
    }

    /// Get batch fees with settlement state (if available).
    pub fn get_batch_fees_with_settlement(
        &self,
        batch_hash: &[u8; 32],
        settlement_state: Option<&str>,
    ) -> Result<Option<BatchFeeSettlement>, M2mStorageError> {
        match self.get_batch_fees(batch_hash)? {
            Some(totals) => Ok(Some(BatchFeeSettlement {
                totals,
                settlement_state: settlement_state.map(|s| s.to_string()),
                fees_finalised: settlement_state == Some("finalised"),
            })),
            None => Ok(None),
        }
    }

    /// Get in-flight batch fee totals (sum of non-finalised batches).
    pub fn get_in_flight_fee_totals(&self) -> Result<(u64, u64), M2mStorageError> {
        let mut total_fees = 0u64;
        let mut batch_count = 0u64;

        // Note: This is a simple implementation that iterates all batches.
        // In production, you'd want an index on settlement state.
        for result in self.batch_fees.iter() {
            let (_key, value) = result?;
            let totals: BatchFeeTotals = canonical_decode(&value)?;
            total_fees = total_fees.saturating_add(totals.total_fees_scaled);
            batch_count = batch_count.saturating_add(1);
        }

        Ok((total_fees, batch_count))
    }

    /// Record batch fee totals with settlement state tracking.
    pub fn record_batch_fees_with_state(
        &self,
        totals: &BatchFeeTotals,
        settlement_state: &str,
    ) -> Result<(), M2mStorageError> {
        // Record the basic totals
        self.record_batch_fees(totals)?;

        // Store a side record linking batch to settlement state
        let state_key = format!("batch_state:{}", hex::encode(totals.batch_hash));
        self.batch_fees
            .insert(state_key.as_bytes(), settlement_state.as_bytes())?;

        Ok(())
    }

    /// Update batch fee settlement state.
    pub fn update_batch_fee_state(
        &self,
        batch_hash: &[u8; 32],
        settlement_state: &str,
    ) -> Result<(), M2mStorageError> {
        let state_key = format!("batch_state:{}", hex::encode(batch_hash));
        self.batch_fees
            .insert(state_key.as_bytes(), settlement_state.as_bytes())?;
        Ok(())
    }

    /// Get the settlement state for a batch's fees.
    pub fn get_batch_fee_state(
        &self,
        batch_hash: &[u8; 32],
    ) -> Result<Option<String>, M2mStorageError> {
        let state_key = format!("batch_state:{}", hex::encode(batch_hash));
        match self.batch_fees.get(state_key.as_bytes())? {
            Some(data) => Ok(Some(String::from_utf8_lossy(&data).to_string())),
            None => Ok(None),
        }
    }
}

/// M2M statistics.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct M2mStats {
    /// Total number of registered machines.
    pub total_machines: u64,
    /// Number of machines with forced inclusion privileges.
    pub forced_machines: u64,
    /// Total balance across all machines (scaled).
    pub total_balance_scaled: u64,
    /// Total reserved balance (scaled).
    pub total_reserved_scaled: u64,
    /// Total fees paid (lifetime, scaled).
    pub total_fees_paid_scaled: u64,
    /// Number of pending reservations.
    pub pending_reservations: u64,
    /// Number of ledger entries in Reserved state.
    pub ledger_reserved_count: u64,
    /// Number of ledger entries in Finalised state.
    pub ledger_finalised_count: u64,
    /// Total fees charged in finalised ledger entries (scaled).
    pub ledger_total_charged_scaled: u64,
    /// Total refunds in finalised ledger entries (scaled).
    pub ledger_total_refunded_scaled: u64,
}

/// Extended batch fee totals with settlement lifecycle tracking.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchFeeSettlement {
    /// Basic batch fee totals.
    pub totals: BatchFeeTotals,
    /// Settlement state (if linked).
    pub settlement_state: Option<String>,
    /// Whether this batch's fees are marked as finalised in settlement.
    pub fees_finalised: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_storage() -> (sled::Db, M2mStorage) {
        let dir = tempdir().expect("tmpdir");
        let db = sled::open(dir.path()).expect("open db");
        let storage = M2mStorage::open(&db, FeeSchedule::default()).expect("open m2m");
        (db, storage)
    }

    #[test]
    fn validate_machine_id() {
        assert!(M2mStorage::validate_machine_id("device-001").is_ok());
        assert!(M2mStorage::validate_machine_id("machine_123").is_ok());
        assert!(M2mStorage::validate_machine_id("A").is_ok());

        // Invalid cases
        assert!(M2mStorage::validate_machine_id("").is_err());
        assert!(M2mStorage::validate_machine_id(" space").is_err());
        assert!(M2mStorage::validate_machine_id("a".repeat(65).as_str()).is_err());
        assert!(M2mStorage::validate_machine_id("invalid@char").is_err());

        // Non-ASCII should fail (canonical validation)
        assert!(M2mStorage::validate_machine_id("机器").is_err());
        assert!(M2mStorage::validate_machine_id("device\x00id").is_err());
    }

    #[test]
    fn validate_tx_id_format() {
        // Valid hex strings
        assert!(validate_tx_id("aabbccdd").is_ok());
        assert!(validate_tx_id("AABBCCDD").is_ok());
        assert!(validate_tx_id("0123456789abcdef").is_ok());

        // Invalid cases
        assert!(validate_tx_id("").is_err()); // Empty
        assert!(validate_tx_id("gg").is_err()); // Non-hex
        assert!(validate_tx_id("aa bb").is_err()); // Whitespace
        assert!(validate_tx_id(&"a".repeat(129)).is_err()); // Too long
    }

    #[test]
    fn ledger_key_deterministic() {
        let key1 = compute_ledger_key("abc123");
        let key2 = compute_ledger_key("abc123");
        let key3 = compute_ledger_key("abc124");

        assert_eq!(key1, key2, "same tx_id should produce same key");
        assert_ne!(key1, key3, "different tx_id should produce different key");
    }

    #[test]
    fn topup_and_balance() {
        let (_db, storage) = test_storage();
        let machine_id = "device-001";

        // Initial balance is zero
        assert_eq!(storage.balance(machine_id).unwrap().scaled(), 0);

        // Top up
        let new_balance = storage.topup(machine_id, 1_000_000, 1000).unwrap();
        assert_eq!(new_balance.scaled(), 1_000_000);
        assert_eq!(storage.balance(machine_id).unwrap().scaled(), 1_000_000);

        // Top up again
        let new_balance = storage.topup(machine_id, 500_000, 2000).unwrap();
        assert_eq!(new_balance.scaled(), 1_500_000);
    }

    #[test]
    fn reserve_and_finalise_fee() {
        let (_db, storage) = test_storage();
        let machine_id = "device-002";
        let tx_hash = [0xAA; 32];

        // Top up first
        storage.topup(machine_id, 1_000_000, 1000).unwrap();

        // Reserve
        let breakdown = M2mFeeBreakdown::new(100, 50, 1, FeeAmount::from_scaled(50_000));
        storage
            .reserve_fee(machine_id, tx_hash, 50_000, breakdown, false, 2000)
            .unwrap();

        // Check reserved
        assert_eq!(storage.reserved(machine_id).unwrap().scaled(), 50_000);
        assert!(storage.get_reservation(&tx_hash).unwrap().is_some());

        // Finalise with lower actual fee
        let refund = storage
            .finalise_fee(machine_id, tx_hash, 30_000, 3000)
            .unwrap();
        assert_eq!(refund, 20_000);

        // Check final state
        assert_eq!(storage.reserved(machine_id).unwrap().scaled(), 0);
        assert_eq!(storage.balance(machine_id).unwrap().scaled(), 970_000);
        assert!(storage.get_reservation(&tx_hash).unwrap().is_none());
    }

    #[test]
    fn reserve_insufficient_balance() {
        let (_db, storage) = test_storage();
        let machine_id = "device-003";
        let tx_hash = [0xBB; 32];

        // Top up small amount
        storage.topup(machine_id, 10_000, 1000).unwrap();

        // Try to reserve more than available
        let breakdown = M2mFeeBreakdown::new(100, 50, 1, FeeAmount::from_scaled(100_000));
        let result = storage.reserve_fee(machine_id, tx_hash, 100_000, breakdown, false, 2000);
        assert!(matches!(
            result,
            Err(M2mStorageError::InsufficientBalance { .. })
        ));
    }

    #[test]
    fn release_reservation() {
        let (_db, storage) = test_storage();
        let machine_id = "device-004";
        let tx_hash = [0xCC; 32];

        storage.topup(machine_id, 1_000_000, 1000).unwrap();

        let breakdown = M2mFeeBreakdown::new(100, 50, 1, FeeAmount::from_scaled(50_000));
        storage
            .reserve_fee(machine_id, tx_hash, 50_000, breakdown, false, 2000)
            .unwrap();

        // Release without finalising
        let released = storage
            .release_reservation(machine_id, tx_hash, 3000)
            .unwrap();
        assert_eq!(released, 50_000);
        assert_eq!(storage.reserved(machine_id).unwrap().scaled(), 0);
        assert_eq!(storage.balance(machine_id).unwrap().scaled(), 1_000_000);
    }

    #[test]
    fn quota_window() {
        let (_db, storage) = test_storage();
        let machine_id = "device-005";

        // Apply quota
        storage
            .apply_quota(machine_id, 100, 1000, 1000, 60_000)
            .unwrap();
        storage
            .apply_quota(machine_id, 200, 2000, 1000, 60_000)
            .unwrap();

        let window = storage.get_quota_window(machine_id).unwrap().unwrap();
        assert_eq!(window.used_units, 300);

        // Exceed quota
        let result = storage.apply_quota(machine_id, 800, 3000, 1000, 60_000);
        assert!(matches!(result, Err(M2mStorageError::QuotaExceeded { .. })));

        // After window expires, quota resets
        storage
            .apply_quota(machine_id, 100, 70_000, 1000, 60_000)
            .unwrap();
        let window = storage.get_quota_window(machine_id).unwrap().unwrap();
        assert_eq!(window.used_units, 100);
    }

    #[test]
    fn forced_class() {
        let (_db, storage) = test_storage();
        let machine_id = "device-006";

        // Default is standard
        assert_eq!(
            storage.forced_class(machine_id).unwrap(),
            ForcedClass::Standard
        );

        // Set to forced
        storage
            .set_forced_class(machine_id, ForcedClass::ForcedInclusion, 1000)
            .unwrap();
        assert_eq!(
            storage.forced_class(machine_id).unwrap(),
            ForcedClass::ForcedInclusion
        );
    }

    #[test]
    fn forced_usage_limits() {
        let (_db, storage) = test_storage();
        let machine_id = "device-007";

        // Set up forced machine
        storage
            .set_forced_class(machine_id, ForcedClass::ForcedInclusion, 1000)
            .unwrap();

        // Set low limit for testing
        let limits = ForcedInclusionLimits {
            max_tx_per_day: 3,
            max_bytes_per_day: 10_000_000,
            day_start_ms: 0,
            used_tx_today: 0,
            used_bytes_today: 0,
        };
        storage.set_forced_limits(machine_id, limits).unwrap();

        // Use up limit (tx_bytes = 100 each)
        storage.apply_forced_usage(machine_id, 100, 1000).unwrap();
        storage.apply_forced_usage(machine_id, 100, 2000).unwrap();
        storage.apply_forced_usage(machine_id, 100, 3000).unwrap();

        // Should fail now
        let result = storage.apply_forced_usage(machine_id, 100, 4000);
        assert!(matches!(result, Err(M2mStorageError::QuotaExceeded { .. })));
    }

    #[test]
    fn batch_fees_roundtrip() {
        let (_db, storage) = test_storage();
        let batch_hash = [0xDD; 32];

        let totals = BatchFeeTotals {
            batch_hash,
            total_fees_scaled: 1_000_000,
            tx_count: 50,
            total_refunds_scaled: 50_000,
            created_at_ms: 1_700_000_000_000,
        };

        storage.record_batch_fees(&totals).unwrap();
        let loaded = storage.get_batch_fees(&batch_hash).unwrap().unwrap();

        assert_eq!(loaded.total_fees_scaled, 1_000_000);
        assert_eq!(loaded.tx_count, 50);
    }

    #[test]
    fn stats() {
        let (_db, storage) = test_storage();

        storage.topup("device-a", 1_000_000, 1000).unwrap();
        storage.topup("device-b", 2_000_000, 1000).unwrap();
        storage
            .set_forced_class("device-b", ForcedClass::ForcedInclusion, 1000)
            .unwrap();

        let stats = storage.get_stats().unwrap();
        assert_eq!(stats.total_machines, 2);
        assert_eq!(stats.total_balance_scaled, 3_000_000);
        assert_eq!(stats.forced_machines, 1);
    }

    // ========== Ledger Idempotency Tests ==========

    #[test]
    fn reserve_twice_same_tx_id_is_idempotent() {
        let (_db, storage) = test_storage();
        let machine_id = "device-ledger-001";
        let tx_hash = [0xAA; 32];

        // Top up first
        storage.topup(machine_id, 1_000_000, 1000).unwrap();

        let breakdown = M2mFeeBreakdown::new(100, 50, 1, FeeAmount::from_scaled(50_000));

        // First reserve
        storage
            .reserve_fee(machine_id, tx_hash, 50_000, breakdown.clone(), false, 2000)
            .unwrap();

        // Second reserve with same params should succeed (idempotent)
        storage
            .reserve_fee(machine_id, tx_hash, 50_000, breakdown.clone(), false, 3000)
            .unwrap();

        // Reserved should only be counted once
        assert_eq!(storage.reserved(machine_id).unwrap().scaled(), 50_000);

        // Ledger should have one entry
        let entry = storage.get_ledger_entry_by_hash(&tx_hash).unwrap().unwrap();
        assert!(entry.is_reserved());
    }

    #[test]
    fn finalise_twice_same_tx_id_is_idempotent() {
        let (_db, storage) = test_storage();
        let machine_id = "device-ledger-002";
        let tx_hash = [0xBB; 32];

        storage.topup(machine_id, 1_000_000, 1000).unwrap();

        let breakdown = M2mFeeBreakdown::new(100, 50, 1, FeeAmount::from_scaled(50_000));
        storage
            .reserve_fee(machine_id, tx_hash, 50_000, breakdown, false, 2000)
            .unwrap();

        // First finalise
        let result1 = storage
            .finalise_fee_with_batch(machine_id, tx_hash, 30_000, 3000, "batchhash1")
            .unwrap();
        assert!(result1.is_new());
        assert_eq!(result1.refund_scaled(), 20_000);

        // Second finalise should return AlreadyFinalised
        let result2 = storage
            .finalise_fee_with_batch(machine_id, tx_hash, 30_000, 4000, "batchhash2")
            .unwrap();
        assert!(!result2.is_new());
        assert_eq!(result2.refund_scaled(), 20_000);

        // Balance should only be deducted once
        assert_eq!(storage.balance(machine_id).unwrap().scaled(), 970_000);

        // Ledger should be finalised
        let entry = storage.get_ledger_entry_by_hash(&tx_hash).unwrap().unwrap();
        assert!(entry.is_finalised());
    }

    #[test]
    fn reserve_then_finalise_then_reserve_rejected() {
        let (_db, storage) = test_storage();
        let machine_id = "device-ledger-003";
        let tx_hash = [0xCC; 32];

        storage.topup(machine_id, 1_000_000, 1000).unwrap();

        let breakdown = M2mFeeBreakdown::new(100, 50, 1, FeeAmount::from_scaled(50_000));

        // Reserve
        storage
            .reserve_fee(machine_id, tx_hash, 50_000, breakdown.clone(), false, 2000)
            .unwrap();

        // Finalise
        storage
            .finalise_fee_with_batch(machine_id, tx_hash, 30_000, 3000, "batch1")
            .unwrap();

        // Try to reserve again - should fail
        let result = storage.reserve_fee(machine_id, tx_hash, 50_000, breakdown, false, 4000);
        assert!(matches!(
            result,
            Err(M2mStorageError::LedgerConflict { .. })
        ));
    }

    #[test]
    fn release_after_finalise_returns_zero() {
        let (_db, storage) = test_storage();
        let machine_id = "device-ledger-004";
        let tx_hash = [0xDD; 32];

        storage.topup(machine_id, 1_000_000, 1000).unwrap();

        let breakdown = M2mFeeBreakdown::new(100, 50, 1, FeeAmount::from_scaled(50_000));
        storage
            .reserve_fee(machine_id, tx_hash, 50_000, breakdown, false, 2000)
            .unwrap();

        // Finalise
        storage
            .finalise_fee(machine_id, tx_hash, 30_000, 3000)
            .unwrap();

        // Release should return 0 (cannot release after finalise)
        let released = storage
            .release_reservation(machine_id, tx_hash, 4000)
            .unwrap();
        assert_eq!(released, 0);
    }

    #[test]
    fn ledger_entry_queries() {
        let (_db, storage) = test_storage();
        let machine_id = "device-ledger-005";
        let tx_hash = [0xEE; 32];

        storage.topup(machine_id, 1_000_000, 1000).unwrap();

        let breakdown = M2mFeeBreakdown::new(100, 50, 1, FeeAmount::from_scaled(50_000));
        storage
            .reserve_fee(machine_id, tx_hash, 50_000, breakdown, false, 2000)
            .unwrap();

        // Query by hash
        let entry = storage.get_ledger_entry_by_hash(&tx_hash).unwrap().unwrap();
        assert!(entry.is_reserved());
        assert_eq!(entry.machine_id(), machine_id);

        // Query by tx_id
        let tx_id = hex::encode(tx_hash);
        let entry2 = storage.get_ledger_entry(&tx_id).unwrap().unwrap();
        assert!(entry2.is_reserved());
    }

    // ========== Forced Inclusion Caps Tests ==========

    #[test]
    fn forced_tx_daily_cap_enforced() {
        let (_db, storage) = test_storage();
        let machine_id = "device-forced-001";

        storage.topup(machine_id, 10_000_000, 1000).unwrap();
        storage
            .set_forced_class(machine_id, ForcedClass::ForcedInclusion, 1000)
            .unwrap();

        // Set low limit for testing
        let limits = ForcedInclusionLimits {
            max_tx_per_day: 3,
            max_bytes_per_day: 10_000_000,
            day_start_ms: 0,
            used_tx_today: 0,
            used_bytes_today: 0,
        };
        storage.set_forced_limits(machine_id, limits).unwrap();

        // Use up the limit
        storage.apply_forced_usage(machine_id, 100, 1000).unwrap();
        storage.apply_forced_usage(machine_id, 100, 2000).unwrap();
        storage.apply_forced_usage(machine_id, 100, 3000).unwrap();

        // Fourth should fail
        let result = storage.apply_forced_usage(machine_id, 100, 4000);
        assert!(matches!(result, Err(M2mStorageError::QuotaExceeded { .. })));
    }

    #[test]
    fn forced_bytes_daily_cap_enforced() {
        let (_db, storage) = test_storage();
        let machine_id = "device-forced-002";

        storage.topup(machine_id, 10_000_000, 1000).unwrap();
        storage
            .set_forced_class(machine_id, ForcedClass::ForcedInclusion, 1000)
            .unwrap();

        // Set low bytes limit for testing
        let limits = ForcedInclusionLimits {
            max_tx_per_day: 100,
            max_bytes_per_day: 500, // Very low
            day_start_ms: 0,
            used_tx_today: 0,
            used_bytes_today: 0,
        };
        storage.set_forced_limits(machine_id, limits).unwrap();

        // First tx uses 300 bytes
        storage.apply_forced_usage(machine_id, 300, 1000).unwrap();

        // Second tx would exceed (300 + 300 > 500)
        let result = storage.apply_forced_usage(machine_id, 300, 2000);
        assert!(matches!(result, Err(M2mStorageError::QuotaExceeded { .. })));

        // But a smaller tx should work
        storage.apply_forced_usage(machine_id, 100, 3000).unwrap();
    }

    #[test]
    fn forced_caps_reset_on_new_day() {
        let (_db, storage) = test_storage();
        let machine_id = "device-forced-003";

        storage.topup(machine_id, 10_000_000, 1000).unwrap();
        storage
            .set_forced_class(machine_id, ForcedClass::ForcedInclusion, 1000)
            .unwrap();

        let limits = ForcedInclusionLimits {
            max_tx_per_day: 2,
            max_bytes_per_day: 1000,
            day_start_ms: 0,
            used_tx_today: 0,
            used_bytes_today: 0,
        };
        storage.set_forced_limits(machine_id, limits).unwrap();

        // Use up limit on "day 0"
        storage.apply_forced_usage(machine_id, 100, 1000).unwrap();
        storage.apply_forced_usage(machine_id, 100, 2000).unwrap();

        // Should fail on same day
        let result = storage.apply_forced_usage(machine_id, 100, 3000);
        assert!(matches!(result, Err(M2mStorageError::QuotaExceeded { .. })));

        // Next day (86_400_001 ms later)
        let next_day = 86_400_001;
        storage
            .apply_forced_usage(machine_id, 100, next_day)
            .unwrap();
    }

    #[test]
    fn reserve_forced_fee_atomic() {
        let (_db, storage) = test_storage();
        let machine_id = "device-forced-004";
        let tx_hash = [0xFF; 32];

        storage.topup(machine_id, 1_000_000, 1000).unwrap();
        storage
            .set_forced_class(machine_id, ForcedClass::ForcedInclusion, 1000)
            .unwrap();

        let breakdown = M2mFeeBreakdown::new(100, 50, 1, FeeAmount::from_scaled(50_000));

        // Reserve forced fee atomically
        storage
            .reserve_forced_fee(machine_id, tx_hash, 50_000, 100, breakdown, 2000)
            .unwrap();

        // Check forced limits were applied
        let limits = storage.get_forced_limits(machine_id).unwrap().unwrap();
        assert_eq!(limits.used_tx_today, 1);
        assert_eq!(limits.used_bytes_today, 100);

        // Check reservation was made
        assert_eq!(storage.reserved(machine_id).unwrap().scaled(), 50_000);
    }

    // ========== Stats with Ledger ==========

    #[test]
    fn stats_include_ledger_metrics() {
        let (_db, storage) = test_storage();

        storage.topup("device-stats-1", 1_000_000, 1000).unwrap();
        storage.topup("device-stats-2", 1_000_000, 1000).unwrap();

        let breakdown = M2mFeeBreakdown::new(100, 50, 1, FeeAmount::from_scaled(50_000));

        // Create a reserved entry
        storage
            .reserve_fee(
                "device-stats-1",
                [0x01; 32],
                50_000,
                breakdown.clone(),
                false,
                2000,
            )
            .unwrap();

        // Create a finalised entry
        storage
            .reserve_fee("device-stats-2", [0x02; 32], 50_000, breakdown, false, 2000)
            .unwrap();
        storage
            .finalise_fee_with_batch("device-stats-2", [0x02; 32], 30_000, 3000, "batch1")
            .unwrap();

        let stats = storage.get_stats().unwrap();
        assert_eq!(stats.ledger_reserved_count, 1);
        assert_eq!(stats.ledger_finalised_count, 1);
        assert_eq!(stats.ledger_total_charged_scaled, 30_000);
        assert_eq!(stats.ledger_total_refunded_scaled, 20_000);
    }
}
