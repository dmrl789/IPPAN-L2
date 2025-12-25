//! M2M Ops/Audit APIs for operational visibility.
//!
//! These APIs are intended for **devnet-only** use during rollout and debugging.
//! They provide visibility into M2M fee accounting internals.
//!
//! **WARNING**: These endpoints expose internal state and should be guarded
//! in production environments.

use crate::m2m::{
    BatchFeeTotals, ForcedInclusionLimits, LedgerEntry, M2mStats, M2mStorage, M2mStorageError,
    MachineAccount,
};
use serde::{Deserialize, Serialize};

/// Response for GET /m2m/stats endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct M2mStatsResponse {
    /// Schema version for API compatibility.
    pub schema_version: u32,
    /// M2M statistics.
    pub stats: M2mStats,
}

/// Response for GET /m2m/ledger/:tx_id endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEntryResponse {
    /// Schema version for API compatibility.
    pub schema_version: u32,
    /// Transaction ID queried.
    pub tx_id: String,
    /// Ledger entry if found.
    pub entry: Option<LedgerEntryView>,
}

/// View of a ledger entry for API response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEntryView {
    /// State of the entry.
    pub state: String,
    /// Machine ID.
    pub machine_id: String,
    /// Details based on state.
    pub details: serde_json::Value,
}

impl From<LedgerEntry> for LedgerEntryView {
    fn from(entry: LedgerEntry) -> Self {
        match entry {
            LedgerEntry::Reserved {
                machine_id,
                reserved_scaled,
                created_ms,
            } => LedgerEntryView {
                state: "reserved".to_string(),
                machine_id,
                details: serde_json::json!({
                    "reserved_scaled": reserved_scaled,
                    "created_ms": created_ms,
                }),
            },
            LedgerEntry::Finalised {
                machine_id,
                charged_scaled,
                refunded_scaled,
                finalised_ms,
                batch_hash_hex,
            } => LedgerEntryView {
                state: "finalised".to_string(),
                machine_id,
                details: serde_json::json!({
                    "charged_scaled": charged_scaled,
                    "refunded_scaled": refunded_scaled,
                    "finalised_ms": finalised_ms,
                    "batch_hash_hex": batch_hash_hex,
                }),
            },
        }
    }
}

/// Response for GET /m2m/batch/:batch_hash/fees endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BatchFeesResponse {
    /// Schema version for API compatibility.
    pub schema_version: u32,
    /// Batch hash queried.
    pub batch_hash_hex: String,
    /// Batch fee totals if found.
    pub fees: Option<BatchFeeTotals>,
    /// Settlement state if tracked.
    pub settlement_state: Option<String>,
}

/// Response for GET /m2m/accounts/:machine_id endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountResponse {
    /// Schema version for API compatibility.
    pub schema_version: u32,
    /// Machine ID queried.
    pub machine_id: String,
    /// Account if found.
    pub account: Option<MachineAccount>,
    /// Forced inclusion limits if applicable.
    pub forced_limits: Option<ForcedInclusionLimits>,
}

/// M2M Ops API providing devnet-only audit endpoints.
pub struct M2mOpsApi<'a> {
    storage: &'a M2mStorage,
}

impl<'a> M2mOpsApi<'a> {
    /// Create a new M2M Ops API.
    pub fn new(storage: &'a M2mStorage) -> Self {
        Self { storage }
    }

    /// Get M2M statistics.
    pub fn get_stats(&self) -> Result<M2mStatsResponse, M2mStorageError> {
        let stats = self.storage.get_stats()?;
        Ok(M2mStatsResponse {
            schema_version: 1,
            stats,
        })
    }

    /// Get a ledger entry by tx_id.
    pub fn get_ledger_entry(&self, tx_id: &str) -> Result<LedgerEntryResponse, M2mStorageError> {
        let entry = self.storage.get_ledger_entry(tx_id)?;
        Ok(LedgerEntryResponse {
            schema_version: 1,
            tx_id: tx_id.to_string(),
            entry: entry.map(LedgerEntryView::from),
        })
    }

    /// Get batch fees by batch hash (hex string).
    pub fn get_batch_fees(&self, batch_hash_hex: &str) -> Result<BatchFeesResponse, M2mStorageError> {
        let batch_hash = hex::decode(batch_hash_hex)
            .map_err(|e| M2mStorageError::InvalidTxId {
                reason: format!("invalid hex: {}", e),
            })?;

        if batch_hash.len() != 32 {
            return Err(M2mStorageError::InvalidTxId {
                reason: "batch_hash must be 32 bytes".to_string(),
            });
        }

        let mut hash_arr = [0u8; 32];
        hash_arr.copy_from_slice(&batch_hash);

        let fees = self.storage.get_batch_fees(&hash_arr)?;
        let settlement_state = self.storage.get_batch_fee_state(&hash_arr)?;

        Ok(BatchFeesResponse {
            schema_version: 1,
            batch_hash_hex: batch_hash_hex.to_string(),
            fees,
            settlement_state,
        })
    }

    /// Get account and forced limits by machine_id.
    pub fn get_account(&self, machine_id: &str) -> Result<AccountResponse, M2mStorageError> {
        let account = self.storage.get_account(machine_id)?;
        let forced_limits = self.storage.get_forced_limits(machine_id)?;

        Ok(AccountResponse {
            schema_version: 1,
            machine_id: machine_id.to_string(),
            account,
            forced_limits,
        })
    }

    /// List ledger entries (for debugging, limited).
    pub fn list_ledger_entries(
        &self,
        limit: usize,
    ) -> Result<Vec<(String, LedgerEntryView)>, M2mStorageError> {
        let entries = self.storage.list_ledger_entries(limit)?;
        Ok(entries
            .into_iter()
            .map(|(key, entry)| (key, LedgerEntryView::from(entry)))
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::m2m::{ForcedClass, M2mStorage};
    use l2_core::fees::{FeeAmount, FeeSchedule, M2mFeeBreakdown};
    use tempfile::tempdir;

    #[test]
    fn ops_api_stats() {
        let dir = tempdir().expect("tmpdir");
        let db = sled::open(dir.path()).expect("open db");
        let storage = M2mStorage::open(&db, FeeSchedule::default()).expect("open m2m");

        storage.topup("device-001", 1_000_000, 1000).unwrap();

        let api = M2mOpsApi::new(&storage);
        let resp = api.get_stats().unwrap();

        assert_eq!(resp.schema_version, 1);
        assert_eq!(resp.stats.total_machines, 1);
        assert_eq!(resp.stats.total_balance_scaled, 1_000_000);
    }

    #[test]
    fn ops_api_ledger_entry() {
        let dir = tempdir().expect("tmpdir");
        let db = sled::open(dir.path()).expect("open db");
        let storage = M2mStorage::open(&db, FeeSchedule::default()).expect("open m2m");

        let machine_id = "device-002";
        let tx_hash = [0xAA; 32];
        let tx_id = hex::encode(tx_hash);

        storage.topup(machine_id, 1_000_000, 1000).unwrap();

        let breakdown = M2mFeeBreakdown::new(100, 50, 1, FeeAmount::from_scaled(50_000));
        storage
            .reserve_fee(machine_id, tx_hash, 50_000, breakdown, false, 2000)
            .unwrap();

        let api = M2mOpsApi::new(&storage);
        let resp = api.get_ledger_entry(&tx_id).unwrap();

        assert_eq!(resp.schema_version, 1);
        assert!(resp.entry.is_some());
        let entry = resp.entry.unwrap();
        assert_eq!(entry.state, "reserved");
        assert_eq!(entry.machine_id, machine_id);
    }

    #[test]
    fn ops_api_batch_fees() {
        let dir = tempdir().expect("tmpdir");
        let db = sled::open(dir.path()).expect("open db");
        let storage = M2mStorage::open(&db, FeeSchedule::default()).expect("open m2m");

        let batch_hash = [0xBB; 32];
        let batch_hash_hex = hex::encode(batch_hash);

        let totals = crate::m2m::BatchFeeTotals {
            batch_hash,
            total_fees_scaled: 100_000,
            tx_count: 5,
            total_refunds_scaled: 10_000,
            created_at_ms: 1_700_000_000_000,
        };

        storage.record_batch_fees(&totals).unwrap();

        let api = M2mOpsApi::new(&storage);
        let resp = api.get_batch_fees(&batch_hash_hex).unwrap();

        assert_eq!(resp.schema_version, 1);
        assert!(resp.fees.is_some());
        let fees = resp.fees.unwrap();
        assert_eq!(fees.total_fees_scaled, 100_000);
        assert_eq!(fees.tx_count, 5);
    }

    #[test]
    fn ops_api_account() {
        let dir = tempdir().expect("tmpdir");
        let db = sled::open(dir.path()).expect("open db");
        let storage = M2mStorage::open(&db, FeeSchedule::default()).expect("open m2m");

        let machine_id = "device-003";
        storage.topup(machine_id, 1_000_000, 1000).unwrap();
        storage
            .set_forced_class(machine_id, ForcedClass::ForcedInclusion, 2000)
            .unwrap();

        let api = M2mOpsApi::new(&storage);
        let resp = api.get_account(machine_id).unwrap();

        assert_eq!(resp.schema_version, 1);
        assert!(resp.account.is_some());
        let account = resp.account.unwrap();
        assert_eq!(account.balance_scaled, 1_000_000);
    }
}
