#![forbid(unsafe_code)]

use crate::actions::{
    AddAttestorV1, AddLicensorV1, AttestationPolicyV1, CreateListingV1, DataActionV1,
    GrantEntitlementV1, IssueLicenseV1, RegisterDatasetV1,
};
use crate::canonical::canonical_json_bytes;
use crate::envelope::DataEnvelopeV1;
use crate::store::{keys, DataStore, StoreError};
use crate::types::{ActionId, AttestationId, DatasetId, LicenseId, ListingId};
use crate::validation::{
    validate_append_attestation_v1, validate_create_listing_v1, validate_grant_entitlement_v1,
    validate_issue_license_v1, validate_register_dataset_v1, ValidationError,
};
use l2_core::policy::{PolicyDenyCode, PolicyMode};
use l2_core::AccountId;
use serde::{Deserialize, Serialize};
use sled::transaction::{ConflictableTransactionError, TransactionError, TransactionalTree};

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
    pub dataset_id: Option<DatasetId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license_id: Option<LicenseId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_id: Option<AttestationId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listing_id: Option<ListingId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purchase_id: Option<String>,
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

pub fn apply(env: &DataEnvelopeV1, store: &DataStore) -> Result<ApplyReceipt, ApplyError> {
    apply_with_policy(env, store, PolicyMode::Permissive, &[])
}

pub fn apply_with_policy(
    env: &DataEnvelopeV1,
    store: &DataStore,
    mode: PolicyMode,
    admin_accounts: &[AccountId],
) -> Result<ApplyReceipt, ApplyError> {
    let action = env.action.clone();
    let action_id = env.action_id;

    let r = store
        .tree()
        .transaction(|tree| apply_tx(tree, action_id, &action, mode, admin_accounts));

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

fn apply_tx(
    tree: &TransactionalTree,
    action_id: ActionId,
    action: &DataActionV1,
    mode: PolicyMode,
    admin_accounts: &[AccountId],
) -> Result<ApplyReceipt, ConflictableTransactionError<TxError>> {
    // Idempotency: already applied => success/no-op.
    if tree
        .get(keys::applied(action_id))?
        .map(|_| true)
        .unwrap_or(false)
    {
        if let Some(existing) = tree.get(keys::apply_receipt(action_id))? {
            let mut receipt: ApplyReceipt = serde_json::from_slice(&existing).map_err(|e| {
                ConflictableTransactionError::Abort(TxError::Store(format!(
                    "failed decoding apply receipt: {e}"
                )))
            })?;
            receipt.outcome = ApplyOutcome::AlreadyApplied;
            return Ok(receipt);
        }
        return Ok(ApplyReceipt {
            schema_version: 1,
            outcome: ApplyOutcome::AlreadyApplied,
            action_id,
            dataset_id: None,
            license_id: None,
            attestation_id: None,
            listing_id: None,
            purchase_id: None,
        });
    }

    let receipt = match action {
        DataActionV1::RegisterDatasetV1(a) => apply_register_dataset_v1_tx(tree, action_id, a)?,
        DataActionV1::IssueLicenseV1(a) => {
            apply_issue_license_v1_tx(tree, action_id, a, mode, admin_accounts)?
        }
        DataActionV1::AppendAttestationV1(a) => {
            apply_append_attestation_v1_tx(tree, action_id, a, mode)?
        }
        DataActionV1::CreateListingV1(a) => apply_create_listing_v1_tx(tree, action_id, a, mode)?,
        DataActionV1::GrantEntitlementV1(a) => {
            apply_grant_entitlement_v1_tx(tree, action_id, a, mode, admin_accounts)?
        }
        DataActionV1::AddLicensorV1(a) => apply_add_licensor_v1_tx(tree, action_id, a, mode)?,
        DataActionV1::AddAttestorV1(a) => apply_add_attestor_v1_tx(tree, action_id, a, mode)?,
    };

    let receipt_bytes = canonical_json_bytes(&receipt).map_err(|e| {
        ConflictableTransactionError::Abort(TxError::Store(format!(
            "receipt canonicalization failed: {e}"
        )))
    })?;
    tree.insert(keys::apply_receipt(action_id), receipt_bytes)?;
    tree.insert(keys::applied(action_id), sled::IVec::from(&b"1"[..]))?;
    Ok(receipt)
}

fn apply_register_dataset_v1_tx(
    tree: &TransactionalTree,
    action_id: ActionId,
    a: &RegisterDatasetV1,
) -> Result<ApplyReceipt, ConflictableTransactionError<TxError>> {
    validate_register_dataset_v1(a)
        .map_err(|e| ConflictableTransactionError::Abort(TxError::from(e)))?;
    if tree.get(keys::dataset(a.dataset_id))?.is_some() {
        return Err(ConflictableTransactionError::Abort(TxError::Rejected(
            "dataset_id already exists".to_string(),
        )));
    }
    let bytes = serde_json::to_vec(a)
        .map_err(|e| ConflictableTransactionError::Abort(TxError::Store(e.to_string())))?;
    tree.insert(keys::dataset(a.dataset_id), bytes)?;
    Ok(ApplyReceipt {
        schema_version: 1,
        outcome: ApplyOutcome::Applied,
        action_id,
        dataset_id: Some(a.dataset_id),
        license_id: None,
        attestation_id: None,
        listing_id: None,
        purchase_id: None,
    })
}

fn apply_issue_license_v1_tx(
    tree: &TransactionalTree,
    action_id: ActionId,
    a: &IssueLicenseV1,
    mode: PolicyMode,
    _admin_accounts: &[AccountId],
) -> Result<ApplyReceipt, ConflictableTransactionError<TxError>> {
    let dataset = get_dataset_tx(tree, a.dataset_id)?.ok_or_else(|| {
        ConflictableTransactionError::Abort(TxError::Rejected("dataset_id not found".to_string()))
    })?;
    validate_issue_license_v1(a)
        .map_err(|e| ConflictableTransactionError::Abort(TxError::from(e)))?;

    // Policy: licensor must be dataset owner or allowlisted.
    let ok = a.licensor == dataset.owner
        || tree
            .get(keys::licensor_allow(a.dataset_id, &a.licensor.0))?
            .is_some();
    if !ok && mode == PolicyMode::Strict {
        return Err(policy_deny(
            PolicyDenyCode::Unauthorized,
            "licensor not permitted for dataset",
        ));
    }
    if !ok && mode == PolicyMode::Permissive {
        // Backcompat posture: in permissive mode, allow legacy behaviour (owner-only),
        // but don't silently authorize a non-owner without explicit allowlist.
        return Err(ConflictableTransactionError::Abort(TxError::Rejected(
            "licensor not permitted for dataset".to_string(),
        )));
    }

    // Idempotency by license_id: duplicates are a success/no-op.
    if tree.get(keys::license(a.license_id))?.is_some() {
        return Ok(ApplyReceipt {
            schema_version: 1,
            outcome: ApplyOutcome::AlreadyApplied,
            action_id,
            dataset_id: Some(a.dataset_id),
            license_id: Some(a.license_id),
            attestation_id: None,
            listing_id: None,
            purchase_id: None,
        });
    }

    let bytes = serde_json::to_vec(a)
        .map_err(|e| ConflictableTransactionError::Abort(TxError::Store(e.to_string())))?;
    tree.insert(keys::license(a.license_id), bytes)?;
    tree.insert(
        keys::license_by_dataset(a.dataset_id, a.license_id),
        sled::IVec::from(&b"1"[..]),
    )?;
    Ok(ApplyReceipt {
        schema_version: 1,
        outcome: ApplyOutcome::Applied,
        action_id,
        dataset_id: Some(a.dataset_id),
        license_id: Some(a.license_id),
        attestation_id: None,
        listing_id: None,
        purchase_id: None,
    })
}

fn apply_append_attestation_v1_tx(
    tree: &TransactionalTree,
    action_id: ActionId,
    a: &crate::actions::AppendAttestationV1,
    mode: PolicyMode,
) -> Result<ApplyReceipt, ConflictableTransactionError<TxError>> {
    let dataset = get_dataset_tx(tree, a.dataset_id)?.ok_or_else(|| {
        ConflictableTransactionError::Abort(TxError::Rejected("dataset_id not found".to_string()))
    })?;
    validate_append_attestation_v1(a)
        .map_err(|e| ConflictableTransactionError::Abort(TxError::from(e)))?;

    // Policy: enforce attestation allowlist if enabled on dataset.
    if dataset.attestation_policy == AttestationPolicyV1::AllowlistOnly {
        let ok = tree
            .get(keys::attestor_allow(a.dataset_id, &a.attestor.0))?
            .is_some();
        if !ok && mode == PolicyMode::Strict {
            return Err(policy_deny(
                PolicyDenyCode::Unauthorized,
                "attestor not allowlisted",
            ));
        }
        if !ok && mode == PolicyMode::Permissive {
            return Err(ConflictableTransactionError::Abort(TxError::Rejected(
                "attestor not allowlisted".to_string(),
            )));
        }
    }

    // Idempotency by attestation_id: duplicates are a success/no-op.
    if tree.get(keys::attestation(a.attestation_id))?.is_some() {
        return Ok(ApplyReceipt {
            schema_version: 1,
            outcome: ApplyOutcome::AlreadyApplied,
            action_id,
            dataset_id: Some(a.dataset_id),
            license_id: None,
            attestation_id: Some(a.attestation_id),
            listing_id: None,
            purchase_id: None,
        });
    }

    let bytes = serde_json::to_vec(a)
        .map_err(|e| ConflictableTransactionError::Abort(TxError::Store(e.to_string())))?;
    tree.insert(keys::attestation(a.attestation_id), bytes)?;
    tree.insert(
        keys::attestation_by_dataset(a.dataset_id, a.attestation_id),
        sled::IVec::from(&b"1"[..]),
    )?;
    Ok(ApplyReceipt {
        schema_version: 1,
        outcome: ApplyOutcome::Applied,
        action_id,
        dataset_id: Some(a.dataset_id),
        license_id: None,
        attestation_id: Some(a.attestation_id),
        listing_id: None,
        purchase_id: None,
    })
}

fn apply_create_listing_v1_tx(
    tree: &TransactionalTree,
    action_id: ActionId,
    a: &CreateListingV1,
    mode: PolicyMode,
) -> Result<ApplyReceipt, ConflictableTransactionError<TxError>> {
    let dataset = get_dataset_tx(tree, a.dataset_id)?.ok_or_else(|| {
        ConflictableTransactionError::Abort(TxError::Rejected("dataset_id not found".to_string()))
    })?;
    validate_create_listing_v1(a)
        .map_err(|e| ConflictableTransactionError::Abort(TxError::from(e)))?;

    // Policy: licensor must be dataset owner or allowlisted.
    let ok = a.licensor == dataset.owner
        || tree
            .get(keys::licensor_allow(a.dataset_id, &a.licensor.0))?
            .is_some();
    if !ok && mode == PolicyMode::Strict {
        return Err(policy_deny(
            PolicyDenyCode::Unauthorized,
            "licensor not permitted for dataset",
        ));
    }
    if !ok && mode == PolicyMode::Permissive {
        return Err(ConflictableTransactionError::Abort(TxError::Rejected(
            "licensor not permitted for dataset".to_string(),
        )));
    }

    if let Some(existing) = tree.get(keys::listing(a.listing_id))? {
        let existing_listing: CreateListingV1 = serde_json::from_slice(&existing).map_err(|e| {
            ConflictableTransactionError::Abort(TxError::Store(format!(
                "failed decoding existing listing: {e}"
            )))
        })?;
        if existing_listing == *a {
            return Ok(ApplyReceipt {
                schema_version: 1,
                outcome: ApplyOutcome::AlreadyApplied,
                action_id,
                dataset_id: Some(a.dataset_id),
                license_id: None,
                attestation_id: None,
                listing_id: Some(a.listing_id),
                purchase_id: None,
            });
        }
        return Err(ConflictableTransactionError::Abort(TxError::Rejected(
            "listing_id already exists with different definition".to_string(),
        )));
    }

    let bytes = serde_json::to_vec(a)
        .map_err(|e| ConflictableTransactionError::Abort(TxError::Store(e.to_string())))?;
    tree.insert(keys::listing(a.listing_id), bytes)?;
    tree.insert(
        keys::listing_by_dataset(a.dataset_id, a.listing_id),
        sled::IVec::from(&b"1"[..]),
    )?;
    Ok(ApplyReceipt {
        schema_version: 1,
        outcome: ApplyOutcome::Applied,
        action_id,
        dataset_id: Some(a.dataset_id),
        license_id: None,
        attestation_id: None,
        listing_id: Some(a.listing_id),
        purchase_id: None,
    })
}

fn apply_grant_entitlement_v1_tx(
    tree: &TransactionalTree,
    action_id: ActionId,
    a: &GrantEntitlementV1,
    mode: PolicyMode,
    admin_accounts: &[AccountId],
) -> Result<ApplyReceipt, ConflictableTransactionError<TxError>> {
    // Listing must exist (and be consistent with dataset_id).
    let listing_bytes = tree.get(keys::listing(a.listing_id))?.ok_or_else(|| {
        ConflictableTransactionError::Abort(TxError::Rejected("listing_id not found".to_string()))
    })?;
    let listing: CreateListingV1 = serde_json::from_slice(&listing_bytes).map_err(|e| {
        ConflictableTransactionError::Abort(TxError::Store(format!("failed decoding listing: {e}")))
    })?;
    if listing.dataset_id != a.dataset_id {
        return Err(ConflictableTransactionError::Abort(TxError::Rejected(
            "dataset_id does not match listing.dataset_id".to_string(),
        )));
    }

    validate_grant_entitlement_v1(a)
        .map_err(|e| ConflictableTransactionError::Abort(TxError::from(e)))?;

    // Policy: entitlement grant must be performed by dataset.owner (or admin in strict).
    let dataset = get_dataset_tx(tree, a.dataset_id)?.ok_or_else(|| {
        ConflictableTransactionError::Abort(TxError::Rejected("dataset_id not found".to_string()))
    })?;
    if mode == PolicyMode::Strict && a.actor.is_none() {
        return Err(policy_deny(PolicyDenyCode::MissingActor, "missing actor"));
    }
    let actor = a.actor.as_ref().unwrap_or(&dataset.owner);
    let ok =
        actor == &dataset.owner || (mode == PolicyMode::Strict && is_admin(actor, admin_accounts));
    if !ok {
        return Err(policy_deny(
            PolicyDenyCode::Unauthorized,
            "actor not permitted to grant entitlement",
        ));
    }

    // Idempotency by purchase_id: duplicates are a success/no-op.
    if let Some(existing) = tree.get(keys::entitlement(a.purchase_id))? {
        let existing_ent: GrantEntitlementV1 = serde_json::from_slice(&existing).map_err(|e| {
            ConflictableTransactionError::Abort(TxError::Store(format!(
                "failed decoding existing entitlement: {e}"
            )))
        })?;
        if existing_ent == *a {
            return Ok(ApplyReceipt {
                schema_version: 1,
                outcome: ApplyOutcome::AlreadyApplied,
                action_id,
                dataset_id: Some(a.dataset_id),
                license_id: Some(a.license_id),
                attestation_id: None,
                listing_id: Some(a.listing_id),
                purchase_id: Some(a.purchase_id.to_hex()),
            });
        }
        return Err(ConflictableTransactionError::Abort(TxError::Rejected(
            "entitlement already exists with different definition".to_string(),
        )));
    }

    let bytes = serde_json::to_vec(a)
        .map_err(|e| ConflictableTransactionError::Abort(TxError::Store(e.to_string())))?;
    tree.insert(keys::entitlement(a.purchase_id), bytes)?;
    tree.insert(
        keys::ent_by_dataset(a.dataset_id, a.purchase_id),
        sled::IVec::from(&b"1"[..]),
    )?;
    tree.insert(
        keys::ent_by_licensee(&a.licensee.0, a.purchase_id),
        sled::IVec::from(&b"1"[..]),
    )?;

    Ok(ApplyReceipt {
        schema_version: 1,
        outcome: ApplyOutcome::Applied,
        action_id,
        dataset_id: Some(a.dataset_id),
        license_id: Some(a.license_id),
        attestation_id: None,
        listing_id: Some(a.listing_id),
        purchase_id: Some(a.purchase_id.to_hex()),
    })
}

fn apply_add_licensor_v1_tx(
    tree: &TransactionalTree,
    action_id: ActionId,
    a: &AddLicensorV1,
    mode: PolicyMode,
) -> Result<ApplyReceipt, ConflictableTransactionError<TxError>> {
    let dataset = get_dataset_tx(tree, a.dataset_id)?.ok_or_else(|| {
        ConflictableTransactionError::Abort(TxError::Rejected("dataset_id not found".to_string()))
    })?;
    if mode == PolicyMode::Strict && a.actor != dataset.owner {
        return Err(policy_deny(
            PolicyDenyCode::Unauthorized,
            "only dataset owner may add licensors",
        ));
    }
    let key = keys::licensor_allow(a.dataset_id, &a.licensor.0);
    let already = tree.get(&key)?.is_some();
    if !already {
        tree.insert(key, sled::IVec::from(&b"1"[..]))?;
    }
    Ok(ApplyReceipt {
        schema_version: 1,
        outcome: if already {
            ApplyOutcome::AlreadyApplied
        } else {
            ApplyOutcome::Applied
        },
        action_id,
        dataset_id: Some(a.dataset_id),
        license_id: None,
        attestation_id: None,
        listing_id: None,
        purchase_id: None,
    })
}

fn apply_add_attestor_v1_tx(
    tree: &TransactionalTree,
    action_id: ActionId,
    a: &AddAttestorV1,
    mode: PolicyMode,
) -> Result<ApplyReceipt, ConflictableTransactionError<TxError>> {
    let dataset = get_dataset_tx(tree, a.dataset_id)?.ok_or_else(|| {
        ConflictableTransactionError::Abort(TxError::Rejected("dataset_id not found".to_string()))
    })?;
    if mode == PolicyMode::Strict && a.actor != dataset.owner {
        return Err(policy_deny(
            PolicyDenyCode::Unauthorized,
            "only dataset owner may add attestors",
        ));
    }
    let key = keys::attestor_allow(a.dataset_id, &a.attestor.0);
    let already = tree.get(&key)?.is_some();
    if !already {
        tree.insert(key, sled::IVec::from(&b"1"[..]))?;
    }
    Ok(ApplyReceipt {
        schema_version: 1,
        outcome: if already {
            ApplyOutcome::AlreadyApplied
        } else {
            ApplyOutcome::Applied
        },
        action_id,
        dataset_id: Some(a.dataset_id),
        license_id: None,
        attestation_id: None,
        listing_id: None,
        purchase_id: None,
    })
}

fn get_dataset_tx(
    tree: &TransactionalTree,
    dataset_id: DatasetId,
) -> Result<Option<RegisterDatasetV1>, ConflictableTransactionError<TxError>> {
    let Some(v) = tree.get(keys::dataset(dataset_id))? else {
        return Ok(None);
    };
    serde_json::from_slice::<RegisterDatasetV1>(&v)
        .map(Some)
        .map_err(|e| ConflictableTransactionError::Abort(TxError::Store(e.to_string())))
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

#[allow(dead_code)]
fn validate_account_id_for_queries(_a: &AccountId) {
    // placeholder: query-time constraints may evolve.
}
