#![forbid(unsafe_code)]

use crate::actions::{CreateAssetV1, MintUnitsV1, TransferUnitsV1};
use crate::types::{AmountU128, AssetId32, Hex32};
use l2_core::AccountId;

/// Configurable validation limits for HUB-FIN.
///
/// These limits affect *admission* only and must not affect hashing semantics.
#[derive(Debug, Clone)]
pub struct ValidationLimits {
    /// Global max size for generic string fields (UTF-8 bytes).
    /// Individual fields also have their own maxima (below).
    pub max_string_bytes: usize,

    pub name_max_len: usize,
    pub symbol_max_len: usize,
    pub metadata_uri_max_len: usize,
    pub memo_max_len: usize,
    pub client_tx_id_max_len: usize,

    /// Max account id length (UTF-8 bytes).
    pub max_account_bytes: usize,
}

impl Default for ValidationLimits {
    fn default() -> Self {
        Self {
            // Preserve previous MVP bounds by default (back-compat + tests).
            max_string_bytes: 1024,
            name_max_len: 128,
            symbol_max_len: 16,
            metadata_uri_max_len: 256,
            memo_max_len: 256,
            client_tx_id_max_len: 64,
            max_account_bytes: 128,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("invalid field: {0}")]
    Invalid(String),
}

pub fn validate_create_asset_v1(a: &CreateAssetV1) -> Result<(), ValidationError> {
    validate_create_asset_v1_with_limits(a, &ValidationLimits::default())
}

pub fn validate_create_asset_v1_with_limits(
    a: &CreateAssetV1,
    limits: &ValidationLimits,
) -> Result<(), ValidationError> {
    validate_bounded(
        "name",
        &a.name,
        limits.name_max_len.min(limits.max_string_bytes),
    )?;
    validate_bounded(
        "symbol",
        &a.symbol,
        limits.symbol_max_len.min(limits.max_string_bytes),
    )?;
    validate_account_id_with_limits("issuer", &a.issuer, limits)?;
    if let Some(uri) = a.metadata_uri.as_deref() {
        validate_bounded(
            "metadata_uri",
            uri,
            limits.metadata_uri_max_len.min(limits.max_string_bytes),
        )?;
    }
    // Leave room for future on-chain compatibility; keep it conservative.
    if a.decimals > 18 {
        return Err(ValidationError::Invalid(format!(
            "decimals out of range (0..=18): {}",
            a.decimals
        )));
    }
    // Ensure deterministic asset id matches derivation.
    let expected = derive_asset_id(&a.name, &a.issuer, &a.symbol);
    if expected != a.asset_id {
        return Err(ValidationError::Invalid(
            "asset_id does not match blake3(name || issuer || symbol)".to_string(),
        ));
    }
    Ok(())
}

pub fn validate_mint_units_v1(a: &MintUnitsV1) -> Result<(), ValidationError> {
    validate_mint_units_v1_with_limits(a, &ValidationLimits::default())
}

pub fn validate_mint_units_v1_with_limits(
    a: &MintUnitsV1,
    limits: &ValidationLimits,
) -> Result<(), ValidationError> {
    validate_account_id_with_limits("to_account", &a.to_account, limits)?;
    validate_bounded(
        "client_tx_id",
        &a.client_tx_id,
        limits.client_tx_id_max_len.min(limits.max_string_bytes),
    )?;
    if let Some(memo) = a.memo.as_deref() {
        validate_bounded(
            "memo",
            memo,
            limits.memo_max_len.min(limits.max_string_bytes),
        )?;
    }
    if let Some(actor) = a.actor.as_ref() {
        validate_account_id_with_limits("actor", actor, limits)?;
    }
    if a.amount.0 == 0 {
        return Err(ValidationError::Invalid("amount must be > 0".to_string()));
    }
    Ok(())
}

pub fn validate_transfer_units_v1(a: &TransferUnitsV1) -> Result<(), ValidationError> {
    validate_transfer_units_v1_with_limits(a, &ValidationLimits::default())
}

pub fn validate_transfer_units_v1_with_limits(
    a: &TransferUnitsV1,
    limits: &ValidationLimits,
) -> Result<(), ValidationError> {
    validate_account_id_with_limits("from_account", &a.from_account, limits)?;
    validate_account_id_with_limits("to_account", &a.to_account, limits)?;
    validate_bounded(
        "client_tx_id",
        &a.client_tx_id,
        limits.client_tx_id_max_len.min(limits.max_string_bytes),
    )?;
    if let Some(memo) = a.memo.as_deref() {
        validate_bounded(
            "memo",
            memo,
            limits.memo_max_len.min(limits.max_string_bytes),
        )?;
    }
    if let Some(actor) = a.actor.as_ref() {
        validate_account_id_with_limits("actor", actor, limits)?;
    }
    if a.amount.0 == 0 {
        return Err(ValidationError::Invalid("amount must be > 0".to_string()));
    }
    Ok(())
}

pub fn validate_account_id(field: &str, a: &AccountId) -> Result<(), ValidationError> {
    validate_account_id_with_limits(field, a, &ValidationLimits::default())
}

pub fn validate_account_id_with_limits(
    field: &str,
    a: &AccountId,
    limits: &ValidationLimits,
) -> Result<(), ValidationError> {
    validate_bounded(field, &a.0, limits.max_account_bytes)
}

fn validate_bounded(field: &str, s: &str, max_len: usize) -> Result<(), ValidationError> {
    let t = s.trim();
    if t.is_empty() {
        return Err(ValidationError::Invalid(format!("{field} is empty")));
    }
    if t.len() > max_len {
        return Err(ValidationError::Invalid(format!(
            "{field} exceeds max length {max_len}"
        )));
    }
    Ok(())
}

/// Deterministically derive an asset id per MVP v1:
/// `asset_id = blake3(name || issuer || symbol)` (UTF-8 bytes, direct concatenation).
pub fn derive_asset_id(name: &str, issuer: &AccountId, symbol: &str) -> AssetId32 {
    let mut h = blake3::Hasher::new();
    h.update(name.as_bytes());
    h.update(issuer.0.as_bytes());
    h.update(symbol.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    Hex32(out)
}

pub fn validate_amount_addition(old: AmountU128, add: AmountU128) -> Result<AmountU128, String> {
    old.0
        .checked_add(add.0)
        .map(AmountU128)
        .ok_or_else(|| "overflow adding amount".to_string())
}

pub fn validate_amount_subtraction(old: AmountU128, sub: AmountU128) -> Result<AmountU128, String> {
    old.0
        .checked_sub(sub.0)
        .map(AmountU128)
        .ok_or_else(|| "insufficient balance".to_string())
}
