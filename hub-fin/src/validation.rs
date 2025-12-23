#![forbid(unsafe_code)]

use crate::actions::{CreateAssetV1, MintUnitsV1};
use crate::types::{AmountU128, AssetId32, Hex32};
use l2_core::AccountId;

pub const NAME_MAX_LEN: usize = 128;
pub const SYMBOL_MAX_LEN: usize = 16;
pub const ISSUER_MAX_LEN: usize = 128;
pub const METADATA_URI_MAX_LEN: usize = 256;
pub const MEMO_MAX_LEN: usize = 256;
pub const ACCOUNT_MAX_LEN: usize = 128;
pub const CLIENT_TX_ID_MAX_LEN: usize = 64;

#[derive(Debug, thiserror::Error)]
pub enum ValidationError {
    #[error("invalid field: {0}")]
    Invalid(String),
}

pub fn validate_create_asset_v1(a: &CreateAssetV1) -> Result<(), ValidationError> {
    validate_bounded("name", &a.name, NAME_MAX_LEN)?;
    validate_bounded("symbol", &a.symbol, SYMBOL_MAX_LEN)?;
    validate_bounded("issuer", &a.issuer, ISSUER_MAX_LEN)?;
    if let Some(uri) = a.metadata_uri.as_deref() {
        validate_bounded("metadata_uri", uri, METADATA_URI_MAX_LEN)?;
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
    validate_account_id("to_account", &a.to_account)?;
    validate_bounded("client_tx_id", &a.client_tx_id, CLIENT_TX_ID_MAX_LEN)?;
    if let Some(memo) = a.memo.as_deref() {
        validate_bounded("memo", memo, MEMO_MAX_LEN)?;
    }
    if a.amount.0 == 0 {
        return Err(ValidationError::Invalid("amount must be > 0".to_string()));
    }
    Ok(())
}

pub fn validate_account_id(field: &str, a: &AccountId) -> Result<(), ValidationError> {
    validate_bounded(field, &a.0, ACCOUNT_MAX_LEN)
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
pub fn derive_asset_id(name: &str, issuer: &str, symbol: &str) -> AssetId32 {
    let mut h = blake3::Hasher::new();
    h.update(name.as_bytes());
    h.update(issuer.as_bytes());
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
