#![forbid(unsafe_code)]

use crate::types::{AmountU128, AssetId32};
use crate::validation::derive_asset_id;
use l2_core::hub_linkage::PurchaseId;
use l2_core::AccountId;
use serde::{Deserialize, Serialize};

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MintPolicyV1 {
    #[default]
    IssuerOnly,
    IssuerOrOperator,
    AdminOnly,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferPolicyV1 {
    #[default]
    Free,
    AllowlistOnly,
    DenylistOnly,
}

/// CREATE_ASSET action (v1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateAssetV1 {
    /// Deterministic id: `blake3(name || issuer || symbol)` (32 bytes, hex in JSON).
    pub asset_id: AssetId32,
    pub name: String,
    pub symbol: String,
    pub issuer: AccountId,
    pub decimals: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_uri: Option<String>,
    /// Actor attempting to create the asset (required in strict mode).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<AccountId>,
    /// Who may mint this asset.
    #[serde(default)]
    pub mint_policy: MintPolicyV1,
    /// How transfers are restricted for this asset.
    #[serde(default)]
    pub transfer_policy: TransferPolicyV1,
}

/// MINT_UNITS action (v1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MintUnitsV1 {
    pub asset_id: AssetId32,
    pub to_account: AccountId,
    /// Scaled integer amount (u128) encoded as a JSON string.
    pub amount: AmountU128,
    /// Actor attempting the mint (required in strict mode).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<AccountId>,
    /// Client-provided idempotency string to prevent duplicates.
    ///
    /// This field is included in the action hash (`action_id`), so replays with the same
    /// `client_tx_id` produce the same `action_id`.
    pub client_tx_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
}

/// TRANSFER_UNITS action (v1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferUnitsV1 {
    pub asset_id: AssetId32,
    pub from_account: AccountId,
    pub to_account: AccountId,
    /// Scaled integer amount (u128) encoded as a JSON string.
    pub amount: AmountU128,
    /// Actor attempting the transfer (required in strict mode).
    ///
    /// - If `actor == from_account`, this is a direct owner transfer.
    /// - If `actor != from_account`, this is an operator transfer and may require delegation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<AccountId>,
    /// Client-provided idempotency string to prevent duplicates.
    pub client_tx_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
    /// Optional linkage identifier for cross-hub workflows.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purchase_id: Option<PurchaseId>,
}

/// FIN action enum (v1).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FinActionV1 {
    CreateAssetV1(CreateAssetV1),
    MintUnitsV1(MintUnitsV1),
    TransferUnitsV1(TransferUnitsV1),
}

/// fin-node request shape for submitting actions.
///
/// For CREATE_ASSET, clients do not send `asset_id`; fin-node derives it deterministically.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum FinActionRequestV1 {
    CreateAssetV1(CreateAssetRequestV1),
    MintUnitsV1(MintUnitsV1),
    TransferUnitsV1(TransferUnitsV1),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateAssetRequestV1 {
    pub name: String,
    pub symbol: String,
    pub issuer: AccountId,
    pub decimals: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actor: Option<AccountId>,
    #[serde(default)]
    pub mint_policy: MintPolicyV1,
    #[serde(default)]
    pub transfer_policy: TransferPolicyV1,
}

impl FinActionRequestV1 {
    pub fn into_action(self) -> FinActionV1 {
        match self {
            FinActionRequestV1::CreateAssetV1(req) => {
                let asset_id = derive_asset_id(&req.name, &req.issuer, &req.symbol);
                FinActionV1::CreateAssetV1(CreateAssetV1 {
                    asset_id,
                    name: req.name,
                    symbol: req.symbol,
                    issuer: req.issuer,
                    decimals: req.decimals,
                    metadata_uri: req.metadata_uri,
                    actor: req.actor,
                    mint_policy: req.mint_policy,
                    transfer_policy: req.transfer_policy,
                })
            }
            FinActionRequestV1::MintUnitsV1(m) => FinActionV1::MintUnitsV1(m),
            FinActionRequestV1::TransferUnitsV1(t) => FinActionV1::TransferUnitsV1(t),
        }
    }
}
