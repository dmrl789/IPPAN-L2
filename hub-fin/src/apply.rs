#![forbid(unsafe_code)]

use crate::actions::{
    CreateAssetV1, FinActionV1, MintPolicyV1, MintUnitsV1, TransferPolicyV1, TransferUnitsV1,
};
use crate::canonical::canonical_json_bytes;
use crate::envelope::FinEnvelopeV1;
use crate::store::{keys, ChangelogTxCtx, FinStore, StoreError};
use crate::types::{ActionId, AmountU128, AssetId32};
use crate::validation::{
    validate_amount_addition, validate_amount_subtraction, validate_create_asset_v1_with_limits,
    validate_mint_units_v1_with_limits, validate_transfer_units_v1_with_limits, ValidationError,
    ValidationLimits,
};
use l2_core::hub_linkage::PurchaseId;
use l2_core::policy::{PolicyDenyCode, PolicyMode};
use l2_core::storage_encryption::SledValueCipher;
use l2_core::AccountId;
use serde::{Deserialize, Serialize};
use sled::transaction::{ConflictableTransactionError, TransactionError, TransactionalTree};
use sled::Transactional;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApplyOutcome {
    Applied,
    AlreadyApplied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplyReceipt {
    pub schema_version: u32,
    pub outcome: ApplyOutcome,
    pub action_id: ActionId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset_id: Option<AssetId32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_account: Option<AccountId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_account: Option<AccountId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<AmountU128>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purchase_id: Option<PurchaseId>,
}

#[derive(Debug, thiserror::Error)]
pub enum ApplyError {
    #[error("validation error: {0}")]
    Validation(String),
    #[error("rejected: {0}")]
    Rejected(String),
    #[error("store error: {0}")]
    Store(String),
}

pub fn apply(env: &FinEnvelopeV1, store: &FinStore) -> Result<ApplyReceipt, ApplyError> {
    apply_with_policy(env, store, PolicyMode::Permissive, &[])
}

pub fn apply_with_policy(
    env: &FinEnvelopeV1,
    store: &FinStore,
    mode: PolicyMode,
    admin_accounts: &[AccountId],
) -> Result<ApplyReceipt, ApplyError> {
    apply_with_policy_and_limits(
        env,
        store,
        mode,
        admin_accounts,
        &ValidationLimits::default(),
    )
}

pub fn apply_with_policy_and_limits(
    env: &FinEnvelopeV1,
    store: &FinStore,
    mode: PolicyMode,
    admin_accounts: &[AccountId],
    limits: &ValidationLimits,
) -> Result<ApplyReceipt, ApplyError> {
    let action = env.action.clone();
    let action_id = env.action_id;

    let cipher = store.value_cipher();
    let r = (store.tree(), store.changelog_tree()).transaction(|(tree, clog)| {
        let mut ctx = ChangelogTxCtx::load(clog)
            .map_err(|e| ConflictableTransactionError::Abort(TxError::Store(e.to_string())))?;
        let receipt = apply_tx_with_changelog(
            tree,
            clog,
            &mut ctx,
            cipher,
            action_id,
            &action,
            mode,
            admin_accounts,
            limits,
        )?;
        ctx.store(clog)
            .map_err(|e| ConflictableTransactionError::Abort(TxError::Store(e.to_string())))?;
        Ok(receipt)
    });

    match r {
        Ok(receipt) => Ok(receipt),
        Err(TransactionError::Abort(e)) => match e {
            TxError::Validation(s) => Err(ApplyError::Validation(s)),
            TxError::Rejected(s) => Err(ApplyError::Rejected(s)),
            TxError::Store(s) => Err(ApplyError::Store(s)),
        },
        Err(TransactionError::Storage(e)) => Err(ApplyError::Store(e.to_string())),
    }
}

#[derive(Debug)]
enum TxError {
    Validation(String),
    Rejected(String),
    Store(String),
}

impl From<ValidationError> for TxError {
    fn from(e: ValidationError) -> Self {
        TxError::Validation(e.to_string())
    }
}

impl From<StoreError> for TxError {
    fn from(e: StoreError) -> Self {
        TxError::Store(e.to_string())
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_tx_with_changelog(
    tree: &TransactionalTree,
    changelog: &TransactionalTree,
    ctx: &mut ChangelogTxCtx,
    cipher: Option<&SledValueCipher>,
    action_id: ActionId,
    action: &FinActionV1,
    mode: PolicyMode,
    admin_accounts: &[AccountId],
    limits: &ValidationLimits,
) -> Result<ApplyReceipt, ConflictableTransactionError<TxError>> {
    // Idempotency: already applied => success/no-op.
    if tree
        .get(keys::applied(action_id))?
        .map(|_| true)
        .unwrap_or(false)
    {
        if let Some(existing) =
            tx_get_plain(tree, cipher, keys::apply_receipt(action_id).as_slice())?
        {
            let mut receipt: ApplyReceipt = serde_json::from_slice(&existing)
                .map_err(|e| ConflictableTransactionError::Abort(TxError::Store(e.to_string())))?;
            receipt.outcome = ApplyOutcome::AlreadyApplied;
            return Ok(receipt);
        }
        return Ok(ApplyReceipt {
            schema_version: 1,
            outcome: ApplyOutcome::AlreadyApplied,
            action_id,
            asset_id: None,
            from_account: None,
            to_account: None,
            amount: None,
            purchase_id: None,
        });
    }

    let receipt = match action {
        FinActionV1::CreateAssetV1(a) => apply_create_asset_v1_tx(
            tree,
            changelog,
            ctx,
            cipher,
            action_id,
            a,
            mode,
            admin_accounts,
            limits,
        )?,
        FinActionV1::MintUnitsV1(a) => apply_mint_units_v1_tx(
            tree,
            changelog,
            ctx,
            cipher,
            action_id,
            a,
            mode,
            admin_accounts,
            limits,
        )?,
        FinActionV1::TransferUnitsV1(a) => apply_transfer_units_v1_tx(
            tree,
            changelog,
            ctx,
            cipher,
            action_id,
            a,
            mode,
            admin_accounts,
            limits,
        )?,
    };

    let receipt_bytes = canonical_json_bytes(&receipt).map_err(|e| {
        ConflictableTransactionError::Abort(TxError::Store(format!(
            "receipt canonicalization failed: {e}"
        )))
    })?;
    tx_put_plain(
        tree,
        cipher,
        keys::apply_receipt(action_id).as_slice(),
        receipt_bytes.as_slice(),
    )?;
    ctx.record_put(changelog, &keys::apply_receipt(action_id), &receipt_bytes)
        .map_err(|e| ConflictableTransactionError::Abort(TxError::Store(e.to_string())))?;

    tx_put_plain(tree, cipher, keys::applied(action_id).as_slice(), b"1")?;
    ctx.record_put(changelog, &keys::applied(action_id), b"1")
        .map_err(|e| ConflictableTransactionError::Abort(TxError::Store(e.to_string())))?;
    Ok(receipt)
}

#[allow(clippy::too_many_arguments)]
fn apply_create_asset_v1_tx(
    tree: &TransactionalTree,
    changelog: &TransactionalTree,
    ctx: &mut ChangelogTxCtx,
    cipher: Option<&SledValueCipher>,
    action_id: ActionId,
    a: &CreateAssetV1,
    mode: PolicyMode,
    admin_accounts: &[AccountId],
    limits: &ValidationLimits,
) -> Result<ApplyReceipt, ConflictableTransactionError<TxError>> {
    validate_create_asset_v1_with_limits(a, limits)
        .map_err(|e| ConflictableTransactionError::Abort(TxError::from(e)))?;

    // Policy: actor must equal issuer (or admin in strict).
    let actor = a.actor.as_ref().unwrap_or(&a.issuer);
    if mode == PolicyMode::Strict && a.actor.is_none() {
        return Err(policy_deny(PolicyDenyCode::MissingActor, "missing actor"));
    }
    if actor != &a.issuer && !(mode == PolicyMode::Strict && is_admin(actor, admin_accounts)) {
        return Err(policy_deny(
            PolicyDenyCode::Unauthorized,
            "actor not permitted to create asset",
        ));
    }

    if tree.get(keys::asset(a.asset_id))?.is_some() {
        return Err(ConflictableTransactionError::Abort(TxError::Rejected(
            "asset_id already exists".to_string(),
        )));
    }
    let bytes = serde_json::to_vec(a)
        .map_err(|e| ConflictableTransactionError::Abort(TxError::Store(e.to_string())))?;
    tx_put_plain(
        tree,
        cipher,
        keys::asset(a.asset_id).as_slice(),
        bytes.as_slice(),
    )?;
    ctx.record_put(changelog, &keys::asset(a.asset_id), &bytes)
        .map_err(|e| ConflictableTransactionError::Abort(TxError::Store(e.to_string())))?;
    Ok(ApplyReceipt {
        schema_version: 1,
        outcome: ApplyOutcome::Applied,
        action_id,
        asset_id: Some(a.asset_id),
        from_account: None,
        to_account: None,
        amount: None,
        purchase_id: None,
    })
}

#[allow(clippy::too_many_arguments)]
fn apply_mint_units_v1_tx(
    tree: &TransactionalTree,
    changelog: &TransactionalTree,
    ctx: &mut ChangelogTxCtx,
    cipher: Option<&SledValueCipher>,
    action_id: ActionId,
    a: &MintUnitsV1,
    mode: PolicyMode,
    admin_accounts: &[AccountId],
    limits: &ValidationLimits,
) -> Result<ApplyReceipt, ConflictableTransactionError<TxError>> {
    validate_mint_units_v1_with_limits(a, limits)
        .map_err(|e| ConflictableTransactionError::Abort(TxError::from(e)))?;

    let asset = get_asset_tx(tree, cipher, a.asset_id)?.ok_or_else(|| {
        ConflictableTransactionError::Abort(TxError::Rejected("asset_id not found".to_string()))
    })?;

    // Policy: mint permissions based on asset.mint_policy.
    if mode == PolicyMode::Strict && a.actor.is_none() {
        return Err(policy_deny(PolicyDenyCode::MissingActor, "missing actor"));
    }
    let actor = a.actor.as_ref().unwrap_or(&asset.issuer);
    let mint_ok = match asset.mint_policy {
        MintPolicyV1::IssuerOnly => actor == &asset.issuer,
        MintPolicyV1::IssuerOrOperator => {
            actor == &asset.issuer
                || tree
                    .get(keys::delegation(&asset.issuer.0, &actor.0, a.asset_id))?
                    .is_some()
        }
        MintPolicyV1::AdminOnly => is_admin(actor, admin_accounts),
    };
    if !mint_ok {
        return Err(policy_deny(
            PolicyDenyCode::Unauthorized,
            "actor not permitted to mint",
        ));
    }

    let bal_key = keys::balance(a.asset_id, &a.to_account.0);
    let old = match tx_get_plain(tree, cipher, &bal_key)? {
        Some(v) => AmountU128(decode_u128_be_plain(v.as_slice())?),
        None => AmountU128(0),
    };
    let new = validate_amount_addition(old, a.amount)
        .map_err(|e| ConflictableTransactionError::Abort(TxError::Rejected(e)))?;
    let bal_bytes = encode_u128_be(new.0).to_vec();
    tx_put_plain(tree, cipher, bal_key.as_slice(), bal_bytes.as_slice())?;
    ctx.record_put(changelog, &bal_key, &bal_bytes)
        .map_err(|e| ConflictableTransactionError::Abort(TxError::Store(e.to_string())))?;

    Ok(ApplyReceipt {
        schema_version: 1,
        outcome: ApplyOutcome::Applied,
        action_id,
        asset_id: Some(a.asset_id),
        from_account: None,
        to_account: Some(a.to_account.clone()),
        amount: Some(a.amount),
        purchase_id: None,
    })
}

#[allow(clippy::too_many_arguments)]
fn apply_transfer_units_v1_tx(
    tree: &TransactionalTree,
    changelog: &TransactionalTree,
    ctx: &mut ChangelogTxCtx,
    cipher: Option<&SledValueCipher>,
    action_id: ActionId,
    a: &TransferUnitsV1,
    mode: PolicyMode,
    admin_accounts: &[AccountId],
    limits: &ValidationLimits,
) -> Result<ApplyReceipt, ConflictableTransactionError<TxError>> {
    validate_transfer_units_v1_with_limits(a, limits)
        .map_err(|e| ConflictableTransactionError::Abort(TxError::from(e)))?;

    let asset = get_asset_tx(tree, cipher, a.asset_id)?.ok_or_else(|| {
        ConflictableTransactionError::Abort(TxError::Rejected("asset_id not found".to_string()))
    })?;

    // Policy: transfers must be initiated by owner, or operator with delegation (strict).
    if mode == PolicyMode::Strict && a.actor.is_none() {
        return Err(policy_deny(PolicyDenyCode::MissingActor, "missing actor"));
    }
    let actor = a.actor.as_ref().unwrap_or(&a.from_account);
    if actor != &a.from_account {
        let delegated = tree
            .get(keys::delegation(&a.from_account.0, &actor.0, a.asset_id))?
            .is_some();
        if mode == PolicyMode::Strict && !delegated && !is_admin(actor, admin_accounts) {
            return Err(policy_deny(
                PolicyDenyCode::DelegationRequired,
                "operator delegation required",
            ));
        }
    }

    // Policy: optional transfer allow/deny lists (deterministic hub state).
    match asset.transfer_policy {
        TransferPolicyV1::Free => {}
        TransferPolicyV1::AllowlistOnly => {
            let ok = tree
                .get(keys::transfer_allow(a.asset_id, &a.to_account.0))?
                .is_some();
            if !ok {
                return Err(policy_deny(
                    PolicyDenyCode::Unauthorized,
                    "recipient not allowlisted",
                ));
            }
        }
        TransferPolicyV1::DenylistOnly => {
            let blocked = tree
                .get(keys::transfer_deny(a.asset_id, &a.to_account.0))?
                .is_some();
            if blocked {
                return Err(policy_deny(
                    PolicyDenyCode::Unauthorized,
                    "recipient denylisted",
                ));
            }
        }
    }

    let from_key = keys::balance(a.asset_id, &a.from_account.0);
    let to_key = keys::balance(a.asset_id, &a.to_account.0);
    let from_old = match tx_get_plain(tree, cipher, &from_key)? {
        Some(v) => AmountU128(decode_u128_be_plain(v.as_slice())?),
        None => AmountU128(0),
    };
    let to_old = match tx_get_plain(tree, cipher, &to_key)? {
        Some(v) => AmountU128(decode_u128_be_plain(v.as_slice())?),
        None => AmountU128(0),
    };

    let from_new = validate_amount_subtraction(from_old, a.amount)
        .map_err(|e| ConflictableTransactionError::Abort(TxError::Rejected(e)))?;
    let to_new = validate_amount_addition(to_old, a.amount)
        .map_err(|e| ConflictableTransactionError::Abort(TxError::Rejected(e)))?;

    let from_bytes = encode_u128_be(from_new.0).to_vec();
    let to_bytes = encode_u128_be(to_new.0).to_vec();
    tx_put_plain(tree, cipher, from_key.as_slice(), from_bytes.as_slice())?;
    ctx.record_put(changelog, &from_key, &from_bytes)
        .map_err(|e| ConflictableTransactionError::Abort(TxError::Store(e.to_string())))?;
    tx_put_plain(tree, cipher, to_key.as_slice(), to_bytes.as_slice())?;
    ctx.record_put(changelog, &to_key, &to_bytes)
        .map_err(|e| ConflictableTransactionError::Abort(TxError::Store(e.to_string())))?;

    Ok(ApplyReceipt {
        schema_version: 1,
        outcome: ApplyOutcome::Applied,
        action_id,
        asset_id: Some(a.asset_id),
        from_account: Some(a.from_account.clone()),
        to_account: Some(a.to_account.clone()),
        amount: Some(a.amount),
        purchase_id: a.purchase_id,
    })
}

fn encode_u128_be(v: u128) -> [u8; 16] {
    v.to_be_bytes()
}

fn decode_u128_be_plain(v: &[u8]) -> Result<u128, ConflictableTransactionError<TxError>> {
    if v.len() != 16 {
        return Err(ConflictableTransactionError::Abort(TxError::Store(
            "invalid u128 encoding".to_string(),
        )));
    }
    let mut b = [0u8; 16];
    b.copy_from_slice(v);
    Ok(u128::from_be_bytes(b))
}

fn is_admin(actor: &AccountId, admin_accounts: &[AccountId]) -> bool {
    admin_accounts.iter().any(|a| a == actor)
}

fn policy_deny(
    code: PolicyDenyCode,
    message: &'static str,
) -> ConflictableTransactionError<TxError> {
    ConflictableTransactionError::Abort(TxError::Rejected(format!(
        "policy:{}:{}",
        code.as_str(),
        message
    )))
}

fn get_asset_tx(
    tree: &TransactionalTree,
    cipher: Option<&SledValueCipher>,
    asset_id: AssetId32,
) -> Result<Option<CreateAssetV1>, ConflictableTransactionError<TxError>> {
    let key = keys::asset(asset_id);
    let Some(v) = tx_get_plain(tree, cipher, key.as_slice())? else {
        return Ok(None);
    };
    serde_json::from_slice::<CreateAssetV1>(&v)
        .map(Some)
        .map_err(|e| ConflictableTransactionError::Abort(TxError::Store(e.to_string())))
}

fn tx_get_plain(
    tree: &TransactionalTree,
    cipher: Option<&SledValueCipher>,
    key: &[u8],
) -> Result<Option<Vec<u8>>, ConflictableTransactionError<TxError>> {
    let Some(v) = tree.get(key)? else {
        return Ok(None);
    };
    if let Some(c) = cipher {
        let plain = c
            .decrypt_value(key, v.as_ref())
            .map_err(|e| ConflictableTransactionError::Abort(TxError::Store(e.to_string())))?;
        Ok(Some(plain))
    } else {
        Ok(Some(v.to_vec()))
    }
}

fn tx_put_plain(
    tree: &TransactionalTree,
    cipher: Option<&SledValueCipher>,
    key: &[u8],
    plaintext: &[u8],
) -> Result<(), ConflictableTransactionError<TxError>> {
    if let Some(c) = cipher {
        let stored = c
            .encrypt_value(key, plaintext)
            .map_err(|e| ConflictableTransactionError::Abort(TxError::Store(e.to_string())))?;
        tree.insert(key, stored.as_slice())?;
    } else {
        tree.insert(key, plaintext)?;
    }
    Ok(())
}
