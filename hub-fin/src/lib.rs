#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]
#![deny(clippy::float_cmp)]
#![deny(clippy::disallowed_types)]

//! IPPAN FIN – Finance Hub
//!
//! This crate will host the execution logic for the finance-focused
//! IPPAN L2 Hub (RWA, bonds, funds, stablecoins).
//!
//! For now we define minimal traits and types and rely on l2-core
//! for the shared settlement abstractions.

use serde::{Deserialize, Serialize};

use std::collections::BTreeMap;

use l2_core::l1_contract::{Base64Bytes, FixedAmountV1, HubPayloadEnvelopeV1, L2BatchEnvelopeV1};
use l2_core::{AccountId, AssetId, FixedAmount, L2BatchId, L2HubId, SettlementError};

/// Logical identifier used for IPPAN FIN batches.
pub const HUB_ID: L2HubId = L2HubId::Fin;
pub const FIN_PAYLOAD_SCHEMA_V1: &str = "hub-fin.payload.v1";
pub const FIN_PAYLOAD_CONTENT_TYPE_V1: &str = "application/json";

/// Represents the balance of multiple assets for a single account.
#[derive(Debug, Default, Clone)]
pub struct AccountState {
    /// Balance per asset (scaled FixedAmount).
    pub balances: BTreeMap<AssetId, FixedAmount>,
}

/// In-memory ledger state for the FIN Hub.
///
/// This is a simple placeholder implementation that can later be
/// replaced or backed by a persistent store.
#[derive(Debug, Default, Clone)]
pub struct FinState {
    /// Registered fungible assets.
    pub assets: BTreeMap<AssetId, FungibleAssetMeta>,
    /// Account states keyed by AccountId.
    pub accounts: BTreeMap<AccountId, AccountState>,
}

/// Minimal metadata for a registered fungible asset.
#[derive(Debug, Clone)]
pub struct FungibleAssetMeta {
    pub symbol: String,
    pub name: String,
    pub decimals: u8,
}

/// Abstract interface for accessing and mutating FIN Hub state.
///
/// This allows different storage backends (in-memory, database, etc.)
/// while keeping the engine logic independent from persistence.
pub trait FinStateStore {
    /// Load the current state snapshot.
    fn load_state(&self) -> FinState;

    /// Persist an updated state snapshot.
    fn save_state(&self, state: &FinState) -> Result<(), FinStateError>;
}

#[derive(Debug, thiserror::Error)]
pub enum FinStateError {
    #[error("storage error: {0}")]
    Storage(String),
    #[error("asset already exists: {0}")]
    AssetAlreadyExists(String),
    #[error("invalid decimals: {0}")]
    InvalidDecimals(u8),
    #[error("asset not registered: {0}")]
    UnknownAsset(String),
    #[error("insufficient balance for account: {0}")]
    InsufficientBalance(String),
}

/// Simple in-memory implementation of FinStateStore.
///
/// This is primarily for testing and dev; a production implementation
/// will likely be backed by a database or external storage.
#[derive(Debug, Default)]
pub struct InMemoryFinStateStore {
    state: std::sync::Mutex<FinState>,
}

impl InMemoryFinStateStore {
    pub fn new() -> Self {
        Self {
            state: std::sync::Mutex::new(FinState::default()),
        }
    }

    pub fn with_state(state: FinState) -> Self {
        Self {
            state: std::sync::Mutex::new(state),
        }
    }
}

impl FinStateStore for InMemoryFinStateStore {
    fn load_state(&self) -> FinState {
        self.state.lock().expect("poisoned mutex").clone()
    }

    fn save_state(&self, state: &FinState) -> Result<(), FinStateError> {
        let mut guard = self
            .state
            .lock()
            .map_err(|e| FinStateError::Storage(format!("mutex poisoned: {e}")))?;
        *guard = state.clone();
        Ok(())
    }
}

/// High-level financial operation supported by the FIN Hub.
///
/// This enum is intentionally minimal and will be expanded with
/// richer semantics as the tokenisation layer matures.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum FinOperation {
    /// Register a new fungible asset (e.g., tokenised fund, bond, stablecoin).
    RegisterFungibleAsset {
        asset_id: AssetId,
        symbol: String,
        name: String,
        decimals: u8,
    },

    /// Mint new units of a fungible asset to a target account.
    Mint {
        asset_id: AssetId,
        to: AccountId,
        amount: FixedAmount,
    },

    /// Burn units of a fungible asset from a target account.
    Burn {
        asset_id: AssetId,
        from: AccountId,
        amount: FixedAmount,
    },

    /// Transfer units of a fungible asset between two accounts.
    Transfer {
        asset_id: AssetId,
        from: AccountId,
        to: AccountId,
        amount: FixedAmount,
    },
}

impl FinState {
    /// Apply a single FIN operation to this state, returning an error
    /// if any invariant would be violated.
    pub fn apply_operation(&mut self, op: &FinOperation) -> Result<(), FinStateError> {
        match op {
            FinOperation::RegisterFungibleAsset {
                asset_id,
                symbol,
                name,
                decimals,
            } => {
                if self.assets.contains_key(asset_id) {
                    return Err(FinStateError::AssetAlreadyExists(asset_id.0.clone()));
                }
                if *decimals > 18 {
                    return Err(FinStateError::InvalidDecimals(*decimals));
                }

                self.assets.insert(
                    asset_id.clone(),
                    FungibleAssetMeta {
                        symbol: symbol.clone(),
                        name: name.clone(),
                        decimals: *decimals,
                    },
                );
                Ok(())
            }
            FinOperation::Mint {
                asset_id,
                to,
                amount,
            } => {
                // Require asset to be registered.
                if !self.assets.contains_key(asset_id) {
                    return Err(FinStateError::UnknownAsset(asset_id.0.clone()));
                }

                let account = self.accounts.entry(to.clone()).or_default();
                let entry = account
                    .balances
                    .entry(asset_id.clone())
                    .or_insert_with(|| FixedAmount::from_scaled(0));

                *entry = entry
                    .checked_add(*amount)
                    .ok_or_else(|| FinStateError::Storage("overflow in mint".to_string()))?;
                Ok(())
            }
            FinOperation::Burn {
                asset_id,
                from,
                amount,
            } => {
                if !self.assets.contains_key(asset_id) {
                    return Err(FinStateError::UnknownAsset(asset_id.0.clone()));
                }
                let account = self
                    .accounts
                    .get_mut(from)
                    .ok_or_else(|| FinStateError::InsufficientBalance(from.0.clone()))?;
                let balance = account
                    .balances
                    .get_mut(asset_id)
                    .ok_or_else(|| FinStateError::InsufficientBalance(from.0.clone()))?;

                if balance.into_scaled() < amount.into_scaled() {
                    return Err(FinStateError::InsufficientBalance(from.0.clone()));
                }
                let new_balance = balance
                    .checked_sub(*amount)
                    .ok_or_else(|| FinStateError::InsufficientBalance(from.0.clone()))?;
                *balance = new_balance;
                Ok(())
            }
            FinOperation::Transfer {
                asset_id,
                from,
                to,
                amount,
            } => {
                if !self.assets.contains_key(asset_id) {
                    return Err(FinStateError::UnknownAsset(asset_id.0.clone()));
                }
                // Debit sender.
                {
                    let from_account = self
                        .accounts
                        .get_mut(from)
                        .ok_or_else(|| FinStateError::InsufficientBalance(from.0.clone()))?;
                    let from_balance = from_account
                        .balances
                        .get_mut(asset_id)
                        .ok_or_else(|| FinStateError::InsufficientBalance(from.0.clone()))?;

                    if from_balance.into_scaled() < amount.into_scaled() {
                        return Err(FinStateError::InsufficientBalance(from.0.clone()));
                    }
                    let new_balance = from_balance
                        .checked_sub(*amount)
                        .ok_or_else(|| FinStateError::InsufficientBalance(from.0.clone()))?;
                    *from_balance = new_balance;
                }

                // Credit recipient.
                let to_account = self.accounts.entry(to.clone()).or_default();
                let to_balance = to_account
                    .balances
                    .entry(asset_id.clone())
                    .or_insert_with(|| FixedAmount::from_scaled(0));
                *to_balance = to_balance
                    .checked_add(*amount)
                    .ok_or_else(|| FinStateError::Storage("overflow in transfer".to_string()))?;
                Ok(())
            }
        }
    }
}

/// Represents a FIN transaction as it will be included in a batch.
///
/// Note: This is intentionally compatible with the shared envelope pattern
/// in `l2-core`:
/// `L2TransactionEnvelope<FinOperation> = { hub, tx_id, payload }`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinTransaction {
    /// Opaque identifier for the transaction, unique within the hub context.
    pub tx_id: String,
    /// The operation to be executed.
    pub op: FinOperation,
}

/// Build a hub payload envelope (v1) from FIN transactions.
pub fn to_hub_payload_envelope_v1(
    txs: &[FinTransaction],
) -> Result<HubPayloadEnvelopeV1, SettlementError> {
    let payload = serde_json::to_vec(txs)
        .map_err(|e| SettlementError::Internal(format!("failed to serialize fin payload: {e}")))?;
    Ok(HubPayloadEnvelopeV1 {
        contract_version: l2_core::l1_contract::ContractVersion::V1,
        hub: HUB_ID,
        schema_version: FIN_PAYLOAD_SCHEMA_V1.to_string(),
        content_type: FIN_PAYLOAD_CONTENT_TYPE_V1.to_string(),
        payload: Base64Bytes(payload),
    })
}

/// Engine responsible for building L2 batches from FIN transactions
/// and producing deterministic envelopes for submission to IPPAN CORE.
pub struct FinHubEngine<S: FinStateStore> {
    store: S,
}

impl<S: FinStateStore> FinHubEngine<S> {
    /// Create a new engine with the given state store.
    pub fn new(store: S) -> Self {
        Self { store }
    }

    /// Return a deterministic, read-only snapshot of the current FIN state.
    pub fn snapshot_state(&self) -> FinState {
        self.store.load_state()
    }

    /// Apply a list of FIN transactions to the state and then build an L1-submittable
    /// contract envelope (v1). The hub does **not** talk to L1 directly.
    pub fn build_batch_envelope_v1(
        &self,
        batch_id: L2BatchId,
        sequence: u64,
        txs: &[FinTransaction],
        fee: FixedAmount,
    ) -> Result<L2BatchEnvelopeV1, SettlementError> {
        // Load current state.
        let mut state = self.store.load_state();

        // Apply each operation in order.
        for tx in txs {
            state
                .apply_operation(&tx.op)
                .map_err(|e| SettlementError::Internal(format!("state error: {e}")))?;
        }

        // Persist updated state.
        self.store
            .save_state(&state)
            .map_err(|e| SettlementError::Internal(format!("save error: {e}")))?;

        let payload = to_hub_payload_envelope_v1(txs)?;
        let fee_v1 = FixedAmountV1(fee.into_scaled());
        L2BatchEnvelopeV1::new(
            HUB_ID,
            batch_id.0,
            sequence,
            txs.len() as u64,
            None,
            fee_v1,
            payload,
        )
        .map_err(|e| SettlementError::Internal(format!("contract error: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fin_hub_engine_builds_batch_envelope_and_updates_state() {
        let store = InMemoryFinStateStore::new();
        let engine = FinHubEngine::new(store);

        let asset = AssetId::new("asset-eur-stable");
        let from = AccountId::new("acc-alice");
        let to = AccountId::new("acc-bob");

        let txs = vec![
            FinTransaction {
                tx_id: "tx-1".to_string(),
                op: FinOperation::RegisterFungibleAsset {
                    asset_id: asset.clone(),
                    symbol: "EURX".to_string(),
                    name: "Example Euro Stablecoin".to_string(),
                    decimals: 6,
                },
            },
            FinTransaction {
                tx_id: "tx-2".to_string(),
                op: FinOperation::Mint {
                    asset_id: asset.clone(),
                    to: from.clone(),
                    amount: FixedAmount::from_units(20, 6), // 20.000000
                },
            },
            FinTransaction {
                tx_id: "tx-3".to_string(),
                op: FinOperation::Transfer {
                    asset_id: asset.clone(),
                    from,
                    to,
                    amount: FixedAmount::from_units(10, 6), // 10.000000
                },
            },
        ];

        let batch_id = L2BatchId("batch-001".to_string());
        let fee = FixedAmount::from_units(1, 6); // 1.000000

        let env = engine
            .build_batch_envelope_v1(batch_id.clone(), 0, &txs, fee)
            .unwrap();
        assert_eq!(env.hub, HUB_ID);
        assert_eq!(env.batch_id, batch_id.0);
        assert_eq!(env.tx_count, 3);
        assert_eq!(env.fee.0, 1_000_000);
        assert!(!env.idempotency_key.as_bytes().iter().all(|b| *b == 0));

        let snapshot = engine.snapshot_state();
        let from_balance = snapshot
            .accounts
            .get(&AccountId::new("acc-alice"))
            .and_then(|acc| acc.balances.get(&AssetId::new("asset-eur-stable")))
            .unwrap()
            .into_scaled();
        let to_balance = snapshot
            .accounts
            .get(&AccountId::new("acc-bob"))
            .and_then(|acc| acc.balances.get(&AssetId::new("asset-eur-stable")))
            .unwrap()
            .into_scaled();
        assert_eq!(from_balance, 10_000_000); // 10.000000
        assert_eq!(to_balance, 10_000_000); // 10.000000
    }

    #[test]
    fn fin_payload_canonical_hash_is_stable_for_identical_inputs() {
        let txs = vec![FinTransaction {
            tx_id: "tx-1".to_string(),
            op: FinOperation::RegisterFungibleAsset {
                asset_id: AssetId::new("asset-eurx"),
                symbol: "EURX".to_string(),
                name: "Euro Stable".to_string(),
                decimals: 6,
            },
        }];

        let a = to_hub_payload_envelope_v1(&txs).unwrap();
        let b = to_hub_payload_envelope_v1(&txs).unwrap();
        assert_eq!(
            a.canonical_hash_blake3().unwrap(),
            b.canonical_hash_blake3().unwrap()
        );
    }

    #[test]
    fn fin_state_applies_basic_flow() {
        let mut state = FinState::default();

        let asset = AssetId::new("asset-eurx");
        let alice = AccountId::new("acc-alice");
        let bob = AccountId::new("acc-bob");

        // Register asset
        state
            .apply_operation(&FinOperation::RegisterFungibleAsset {
                asset_id: asset.clone(),
                symbol: "EURX".to_string(),
                name: "Euro Stable".to_string(),
                decimals: 6,
            })
            .unwrap();

        // Mint to Alice
        state
            .apply_operation(&FinOperation::Mint {
                asset_id: asset.clone(),
                to: alice.clone(),
                amount: FixedAmount::from_units(100, 6),
            })
            .unwrap();

        // Transfer from Alice to Bob
        state
            .apply_operation(&FinOperation::Transfer {
                asset_id: asset.clone(),
                from: alice.clone(),
                to: bob.clone(),
                amount: FixedAmount::from_units(30, 6),
            })
            .unwrap();

        let snapshot = state;

        let alice_balance = snapshot
            .accounts
            .get(&alice)
            .and_then(|acc| acc.balances.get(&asset))
            .unwrap()
            .into_scaled();
        let bob_balance = snapshot
            .accounts
            .get(&bob)
            .and_then(|acc| acc.balances.get(&asset))
            .unwrap()
            .into_scaled();

        assert_eq!(alice_balance, 70_000_000); // 70.000000
        assert_eq!(bob_balance, 30_000_000); // 30.000000
    }

    #[test]
    fn fin_state_rejects_duplicate_asset_registration() {
        let mut state = FinState::default();

        let asset = AssetId::new("asset-eurx");

        state
            .apply_operation(&FinOperation::RegisterFungibleAsset {
                asset_id: asset.clone(),
                symbol: "EURX".to_string(),
                name: "Euro Stable".to_string(),
                decimals: 6,
            })
            .unwrap();

        let err = state
            .apply_operation(&FinOperation::RegisterFungibleAsset {
                asset_id: asset,
                symbol: "EURX".to_string(),
                name: "Euro Stable".to_string(),
                decimals: 6,
            })
            .unwrap_err();

        match err {
            FinStateError::AssetAlreadyExists(a) => assert_eq!(a, "asset-eurx"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn fin_state_rejects_mint_for_unregistered_asset() {
        let mut state = FinState::default();

        let asset = AssetId::new("asset-missing");
        let alice = AccountId::new("acc-alice");
        let err = state
            .apply_operation(&FinOperation::Mint {
                asset_id: asset,
                to: alice,
                amount: FixedAmount::from_units(1, 6),
            })
            .unwrap_err();

        match err {
            FinStateError::UnknownAsset(a) => assert_eq!(a, "asset-missing"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn fin_state_rejects_burn_more_than_balance() {
        let mut state = FinState::default();

        let asset = AssetId::new("asset-eurx");
        let alice = AccountId::new("acc-alice");

        state
            .apply_operation(&FinOperation::RegisterFungibleAsset {
                asset_id: asset.clone(),
                symbol: "EURX".to_string(),
                name: "Euro Stable".to_string(),
                decimals: 6,
            })
            .unwrap();

        state
            .apply_operation(&FinOperation::Mint {
                asset_id: asset.clone(),
                to: alice.clone(),
                amount: FixedAmount::from_units(1, 6),
            })
            .unwrap();

        let err = state
            .apply_operation(&FinOperation::Burn {
                asset_id: asset,
                from: alice,
                amount: FixedAmount::from_units(2, 6),
            })
            .unwrap_err();

        match err {
            FinStateError::InsufficientBalance(acc) => assert_eq!(acc, "acc-alice"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn fin_state_rejects_transfer_more_than_balance() {
        let mut state = FinState::default();

        let asset = AssetId::new("asset-eurx");
        let alice = AccountId::new("acc-alice");
        let bob = AccountId::new("acc-bob");

        state
            .apply_operation(&FinOperation::RegisterFungibleAsset {
                asset_id: asset.clone(),
                symbol: "EURX".to_string(),
                name: "Euro Stable".to_string(),
                decimals: 6,
            })
            .unwrap();

        state
            .apply_operation(&FinOperation::Mint {
                asset_id: asset.clone(),
                to: alice.clone(),
                amount: FixedAmount::from_units(1, 6),
            })
            .unwrap();

        let err = state
            .apply_operation(&FinOperation::Transfer {
                asset_id: asset,
                from: alice,
                to: bob,
                amount: FixedAmount::from_units(2, 6),
            })
            .unwrap_err();

        match err {
            FinStateError::InsufficientBalance(acc) => assert_eq!(acc, "acc-alice"),
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn fin_transaction_serializes_to_json() {
        let asset = AssetId::new("asset-eur-stable");
        let tx = FinTransaction {
            tx_id: "tx-serialize".to_string(),
            op: FinOperation::Mint {
                asset_id: asset,
                to: AccountId::new("acc-alice"),
                amount: FixedAmount::from_units(5, 6),
            },
        };

        let json = serde_json::to_string(&tx).expect("serialize");
        assert!(json.contains("tx-serialize"));
    }
}
