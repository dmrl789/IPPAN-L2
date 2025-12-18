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

use l2_core::{
    AccountId, AssetId, FixedAmount, L1SettlementClient, L2Batch, L2BatchId, L2HubId,
    SettlementError, SettlementRequest, SettlementResult,
};

/// Logical identifier used for IPPAN FIN batches.
pub const HUB_ID: L2HubId = L2HubId::Fin;

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
}

impl FinStateStore for InMemoryFinStateStore {
    fn load_state(&self) -> FinState {
        self.state.lock().expect("poisoned mutex").clone()
    }

    fn save_state(&self, state: &FinState) -> Result<(), FinStateError> {
        let mut guard = self.state.lock().map_err(|e| {
            FinStateError::Storage(format!("mutex poisoned: {e}"))
        })?;
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
                // If asset already exists, we can decide to ignore or error.
                // For now, treat re-registration as an error.
                if self.assets.contains_key(asset_id) {
                    return Err(FinStateError::Storage(format!(
                        "asset already registered: {}",
                        asset_id.0
                    )));
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
                let account = self
                    .accounts
                    .get_mut(from)
                    .ok_or_else(|| FinStateError::InsufficientBalance(from.0.clone()))?;
                let balance = account
                    .balances
                    .get_mut(asset_id)
                    .ok_or_else(|| FinStateError::InsufficientBalance(from.0.clone()))?;

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
                *to_balance = to_balance.checked_add(*amount).ok_or_else(|| {
                    FinStateError::Storage("overflow in transfer".to_string())
                })?;
                Ok(())
            }
        }
    }
}

/// Represents a FIN transaction as it will be included in a batch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinTransaction {
    /// Opaque identifier for the transaction, unique within the hub context.
    pub tx_id: String,
    /// The operation to be executed.
    pub op: FinOperation,
}

/// Engine responsible for building L2 batches from FIN transactions
/// and submitting them to IPPAN CORE.
pub struct FinHubEngine<C: L1SettlementClient, S: FinStateStore> {
    client: C,
    store: S,
}

impl<C: L1SettlementClient, S: FinStateStore> FinHubEngine<C, S> {
    /// Create a new engine with the given settlement client and state store.
    pub fn new(client: C, store: S) -> Self {
        Self { client, store }
    }

    /// Apply a list of FIN transactions to the state and then submit a batch
    /// to IPPAN CORE for settlement.
    pub fn submit_batch(
        &self,
        batch_id: L2BatchId,
        txs: &[FinTransaction],
        fee: FixedAmount,
    ) -> Result<SettlementResult, SettlementError> {
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

        let batch = L2Batch::new(HUB_ID, batch_id, txs.len() as u64);
        let request = SettlementRequest {
            hub: HUB_ID,
            batch,
            fee,
        };

        self.client.submit_settlement(request)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn fin_hub_engine_submits_batch() {
        let client = DummyClient;
        let store = InMemoryFinStateStore::new();
        let engine = FinHubEngine::new(client, store);

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

        let result = engine.submit_batch(batch_id.clone(), &txs, fee).unwrap();
        assert_eq!(result.hub, HUB_ID);
        assert_eq!(result.batch_id.0, batch_id.0);
        assert!(result.finalised);
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
