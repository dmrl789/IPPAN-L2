#![forbid(unsafe_code)]

use crate::actions::{DataActionV1, IssueLicenseV1, RegisterDatasetV1};
use crate::canonical::canonical_json_bytes;
use crate::envelope::DataEnvelopeV1;
use crate::store::{keys, DataStore, StoreError};
use crate::types::{ActionId, AttestationId, DatasetId, LicenseId};
use crate::validation::{
    validate_append_attestation_v1, validate_issue_license_v1, validate_register_dataset_v1,
    ValidationError,
};
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
    let action = env.action.clone();
    let action_id = env.action_id;

    let r = store
        .tree()
        .transaction(|tree| apply_tx(tree, action_id, &action));

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
        });
    }

    let receipt = match action {
        DataActionV1::RegisterDatasetV1(a) => apply_register_dataset_v1_tx(tree, action_id, a)?,
        DataActionV1::IssueLicenseV1(a) => apply_issue_license_v1_tx(tree, action_id, a)?,
        DataActionV1::AppendAttestationV1(a) => apply_append_attestation_v1_tx(tree, action_id, a)?,
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
    })
}

fn apply_issue_license_v1_tx(
    tree: &TransactionalTree,
    action_id: ActionId,
    a: &IssueLicenseV1,
) -> Result<ApplyReceipt, ConflictableTransactionError<TxError>> {
    let dataset = get_dataset_tx(tree, a.dataset_id)?.ok_or_else(|| {
        ConflictableTransactionError::Abort(TxError::Rejected("dataset_id not found".to_string()))
    })?;
    validate_issue_license_v1(a, &dataset.owner)
        .map_err(|e| ConflictableTransactionError::Abort(TxError::from(e)))?;

    // Idempotency by license_id: duplicates are a success/no-op.
    if tree.get(keys::license(a.license_id))?.is_some() {
        return Ok(ApplyReceipt {
            schema_version: 1,
            outcome: ApplyOutcome::AlreadyApplied,
            action_id,
            dataset_id: Some(a.dataset_id),
            license_id: Some(a.license_id),
            attestation_id: None,
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
    })
}

fn apply_append_attestation_v1_tx(
    tree: &TransactionalTree,
    action_id: ActionId,
    a: &crate::actions::AppendAttestationV1,
) -> Result<ApplyReceipt, ConflictableTransactionError<TxError>> {
    if get_dataset_tx(tree, a.dataset_id)?.is_none() {
        return Err(ConflictableTransactionError::Abort(TxError::Rejected(
            "dataset_id not found".to_string(),
        )));
    }
    validate_append_attestation_v1(a)
        .map_err(|e| ConflictableTransactionError::Abort(TxError::from(e)))?;

    // Idempotency by attestation_id: duplicates are a success/no-op.
    if tree.get(keys::attestation(a.attestation_id))?.is_some() {
        return Ok(ApplyReceipt {
            schema_version: 1,
            outcome: ApplyOutcome::AlreadyApplied,
            action_id,
            dataset_id: Some(a.dataset_id),
            license_id: None,
            attestation_id: Some(a.attestation_id),
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

#[allow(dead_code)]
fn validate_account_id_for_queries(_a: &AccountId) {
    // placeholder: query-time constraints may evolve.
}
