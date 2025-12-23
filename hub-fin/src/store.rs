#![forbid(unsafe_code)]

use crate::actions::CreateAssetV1;
use crate::types::{ActionId, AmountU128, AssetId32};
use sled::IVec;
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("db error: {0}")]
    Db(#[from] sled::Error),
    #[error("decode error: {0}")]
    Decode(String),
}

#[derive(Debug, Clone)]
pub struct FinStore {
    tree: sled::Tree,
}

impl FinStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        let db = sled::open(path)?;
        let tree = db.open_tree("hub-fin")?;
        Ok(Self { tree })
    }

    pub fn get_asset(&self, asset_id: AssetId32) -> Result<Option<CreateAssetV1>, StoreError> {
        let key = keys::asset(asset_id);
        let Some(v) = self.tree.get(key)? else {
            return Ok(None);
        };
        serde_json::from_slice::<CreateAssetV1>(&v)
            .map(Some)
            .map_err(|e| StoreError::Decode(format!("failed decoding asset json: {e}")))
    }

    pub fn put_asset(&self, asset: &CreateAssetV1) -> Result<(), StoreError> {
        let key = keys::asset(asset.asset_id);
        let bytes = serde_json::to_vec(asset)
            .map_err(|e| StoreError::Decode(format!("failed encoding asset json: {e}")))?;
        self.tree.insert(key, bytes)?;
        Ok(())
    }

    pub fn get_balance(
        &self,
        asset_id: AssetId32,
        account: &str,
    ) -> Result<AmountU128, StoreError> {
        let key = keys::balance(asset_id, account);
        let Some(v) = self.tree.get(key)? else {
            return Ok(AmountU128(0));
        };
        decode_u128_be(&v)
            .map(AmountU128)
            .map_err(StoreError::Decode)
    }

    pub fn set_balance(
        &self,
        asset_id: AssetId32,
        account: &str,
        amount: AmountU128,
    ) -> Result<(), StoreError> {
        let key = keys::balance(asset_id, account);
        self.tree.insert(key, encode_u128_be(amount.0).to_vec())?;
        Ok(())
    }

    pub fn is_applied(&self, action_id: ActionId) -> Result<bool, StoreError> {
        Ok(self.tree.contains_key(keys::applied(action_id))?)
    }

    pub fn get_state_version(&self) -> Result<Option<u32>, StoreError> {
        let Some(v) = self.tree.get(keys::state_version())? else {
            return Ok(None);
        };
        let s = String::from_utf8(v.to_vec())
            .map_err(|e| StoreError::Decode(format!("invalid utf8 state_version: {e}")))?;
        let n = s
            .parse::<u32>()
            .map_err(|e| StoreError::Decode(format!("invalid state_version integer: {e}")))?;
        Ok(Some(n))
    }

    pub fn set_state_version(&self, v: u32) -> Result<(), StoreError> {
        self.tree
            .insert(keys::state_version(), v.to_string().into_bytes())?;
        Ok(())
    }

    /// Create/update an operator delegation for a given `(from, operator, asset_id)` tuple.
    pub fn set_delegation(
        &self,
        from_account: &str,
        operator_account: &str,
        asset_id: AssetId32,
    ) -> Result<(), StoreError> {
        self.tree.insert(
            keys::delegation(from_account, operator_account, asset_id),
            IVec::from(&b"1"[..]),
        )?;
        Ok(())
    }

    /// Revoke an operator delegation for a given `(from, operator, asset_id)` tuple.
    pub fn revoke_delegation(
        &self,
        from_account: &str,
        operator_account: &str,
        asset_id: AssetId32,
    ) -> Result<(), StoreError> {
        let _ = self
            .tree
            .remove(keys::delegation(from_account, operator_account, asset_id))?;
        Ok(())
    }

    pub fn has_delegation(
        &self,
        from_account: &str,
        operator_account: &str,
        asset_id: AssetId32,
    ) -> Result<bool, StoreError> {
        Ok(self
            .tree
            .contains_key(keys::delegation(from_account, operator_account, asset_id))?)
    }

    /// Add an account to the transfer allowlist for an asset.
    pub fn add_transfer_allow(&self, asset_id: AssetId32, account: &str) -> Result<(), StoreError> {
        self.tree.insert(
            keys::transfer_allow(asset_id, account),
            IVec::from(&b"1"[..]),
        )?;
        Ok(())
    }

    /// Add an account to the transfer denylist for an asset.
    pub fn add_transfer_deny(&self, asset_id: AssetId32, account: &str) -> Result<(), StoreError> {
        self.tree.insert(
            keys::transfer_deny(asset_id, account),
            IVec::from(&b"1"[..]),
        )?;
        Ok(())
    }

    pub fn is_transfer_allowlisted(
        &self,
        asset_id: AssetId32,
        account: &str,
    ) -> Result<bool, StoreError> {
        Ok(self
            .tree
            .contains_key(keys::transfer_allow(asset_id, account))?)
    }

    pub fn is_transfer_denylisted(
        &self,
        asset_id: AssetId32,
        account: &str,
    ) -> Result<bool, StoreError> {
        Ok(self
            .tree
            .contains_key(keys::transfer_deny(asset_id, account))?)
    }

    pub fn mark_applied(&self, action_id: ActionId) -> Result<(), StoreError> {
        self.tree
            .insert(keys::applied(action_id), IVec::from(&b"1"[..]))?;
        Ok(())
    }

    pub fn put_receipt(&self, action_id: ActionId, receipt_json: &[u8]) -> Result<(), StoreError> {
        self.tree
            .insert(keys::apply_receipt(action_id), receipt_json)?;
        Ok(())
    }

    pub fn get_receipt(&self, action_id: ActionId) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self
            .tree
            .get(keys::apply_receipt(action_id))?
            .map(|v| v.to_vec()))
    }

    /// Store a fin-node receipt (includes L1 submission metadata).
    pub fn put_final_receipt(
        &self,
        action_id: ActionId,
        receipt_json: &[u8],
    ) -> Result<(), StoreError> {
        self.tree.insert(keys::receipt(action_id), receipt_json)?;
        Ok(())
    }

    pub fn get_final_receipt(&self, action_id: ActionId) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.tree.get(keys::receipt(action_id))?.map(|v| v.to_vec()))
    }

    pub(crate) fn tree(&self) -> &sled::Tree {
        &self.tree
    }
}

pub mod keys {
    use super::*;

    pub fn asset(asset_id: AssetId32) -> Vec<u8> {
        format!("asset:{}", asset_id.to_hex()).into_bytes()
    }

    pub fn balance(asset_id: AssetId32, account: &str) -> Vec<u8> {
        format!("bal:{}:{account}", asset_id.to_hex()).into_bytes()
    }

    pub fn applied(action_id: ActionId) -> Vec<u8> {
        format!("applied:{}", action_id.to_hex()).into_bytes()
    }

    pub fn state_version() -> &'static [u8] {
        b"state_version"
    }

    pub fn delegation(from_account: &str, operator_account: &str, asset_id: AssetId32) -> Vec<u8> {
        format!(
            "delegation:{from_account}:{operator_account}:{}",
            asset_id.to_hex()
        )
        .into_bytes()
    }

    pub fn transfer_allow(asset_id: AssetId32, account: &str) -> Vec<u8> {
        format!("transfer_allow:{}:{account}", asset_id.to_hex()).into_bytes()
    }

    pub fn transfer_deny(asset_id: AssetId32, account: &str) -> Vec<u8> {
        format!("transfer_deny:{}:{account}", asset_id.to_hex()).into_bytes()
    }

    pub fn receipt(action_id: ActionId) -> Vec<u8> {
        format!("receipt:{}", action_id.to_hex()).into_bytes()
    }

    pub fn apply_receipt(action_id: ActionId) -> Vec<u8> {
        format!("apply_receipt:{}", action_id.to_hex()).into_bytes()
    }
}

fn encode_u128_be(v: u128) -> [u8; 16] {
    v.to_be_bytes()
}

fn decode_u128_be(v: &IVec) -> Result<u128, String> {
    if v.len() != 16 {
        return Err(format!("expected 16 bytes for u128, got {}", v.len()));
    }
    let mut b = [0u8; 16];
    b.copy_from_slice(v.as_ref());
    Ok(u128::from_be_bytes(b))
}
