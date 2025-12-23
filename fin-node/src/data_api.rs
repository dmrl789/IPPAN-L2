#![forbid(unsafe_code)]

use base64::Engine as _;
use hub_data::apply::ApplyError as DataApplyError;
use hub_data::{
    apply, AppendAttestationRequestV1, ApplyOutcome, DataActionV1, DataEnvelopeV1, DataStore,
    Hex32, IssueLicenseRequestV1, RegisterDatasetRequestV1,
};
use l2_core::l1_contract::{
    FixedAmountV1, HubPayloadEnvelopeV1, L1Client, L1SubmitResult, L2BatchEnvelopeV1,
};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use time::format_description::well_known::Rfc3339;

#[derive(Clone)]
pub struct DataApi {
    l1: Arc<dyn L1Client + Send + Sync>,
    store: DataStore,
    receipts_dir: PathBuf,
}

impl DataApi {
    pub fn new(
        l1: Arc<dyn L1Client + Send + Sync>,
        store: DataStore,
        receipts_dir: PathBuf,
    ) -> Self {
        Self {
            l1,
            store,
            receipts_dir,
        }
    }

    pub fn submit_register_dataset(
        &self,
        req: RegisterDatasetRequestV1,
    ) -> Result<SubmitDataActionResponseV1, ApiError> {
        self.submit_action(hub_data::DataActionRequestV1::RegisterDatasetV1(req).into_action())
    }

    pub fn submit_issue_license(
        &self,
        req: IssueLicenseRequestV1,
    ) -> Result<SubmitDataActionResponseV1, ApiError> {
        self.submit_action(hub_data::DataActionRequestV1::IssueLicenseV1(req).into_action())
    }

    pub fn submit_append_attestation(
        &self,
        req: AppendAttestationRequestV1,
    ) -> Result<SubmitDataActionResponseV1, ApiError> {
        self.submit_action(hub_data::DataActionRequestV1::AppendAttestationV1(req).into_action())
    }

    fn submit_action(&self, action: DataActionV1) -> Result<SubmitDataActionResponseV1, ApiError> {
        let env = DataEnvelopeV1::new(action).map_err(|e| ApiError::BadRequest(e.to_string()))?;

        // 1) Apply locally (sled)
        let local = apply(&env, &self.store).map_err(ApiError::from_apply)?;

        // 2) Wrap into L1 contract envelope (single-item batch)
        let payload: HubPayloadEnvelopeV1 = (&env).into();
        let batch_id = format!("data-action-{}", env.action_id.to_hex());
        let batch = L2BatchEnvelopeV1::new(
            l2_core::L2HubId::Data,
            batch_id.clone(),
            0,
            1,
            None,
            FixedAmountV1(0),
            payload,
        )
        .map_err(|e| ApiError::Internal(e.to_string()))?;

        // 3) Submit to L1
        let submit = self
            .l1
            .submit_batch(&batch)
            .map_err(|e| ApiError::Upstream(e.to_string()))?;

        // 4) Persist action receipt
        let receipt =
            DataActionReceiptV1::from_parts(&env.action_id, &local, &batch_id, &batch, &submit);
        let receipt_path = self.persist_action_receipt(&receipt)?;

        Ok(SubmitDataActionResponseV1 {
            schema_version: 1,
            action_id: env.action_id.to_hex(),
            local_apply_outcome: local.outcome,
            dataset_id: local.dataset_id.map(|x| x.to_hex()),
            license_id: local.license_id.map(|x| x.to_hex()),
            attestation_id: local.attestation_id.map(|x| x.to_hex()),
            batch_id,
            idempotency_key: b64url32(batch.idempotency_key.as_bytes()),
            l1_submit_result: submit,
            receipt_path: receipt_path.to_string_lossy().to_string(),
        })
    }

    pub fn get_dataset(&self, dataset_id_hex: &str) -> Result<Option<serde_json::Value>, ApiError> {
        let dataset_id = Hex32::from_hex(dataset_id_hex)
            .map_err(|e| ApiError::BadRequest(format!("invalid dataset_id hex: {e}")))?;
        let v = self
            .store
            .get_dataset(dataset_id)
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        Ok(v.map(|x| serde_json::to_value(x).expect("serde value")))
    }

    pub fn get_license(&self, license_id_hex: &str) -> Result<Option<serde_json::Value>, ApiError> {
        let license_id = Hex32::from_hex(license_id_hex)
            .map_err(|e| ApiError::BadRequest(format!("invalid license_id hex: {e}")))?;
        let v = self
            .store
            .get_license(license_id)
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        Ok(v.map(|x| serde_json::to_value(x).expect("serde value")))
    }

    pub fn list_licenses_by_dataset(
        &self,
        dataset_id_hex: &str,
    ) -> Result<Vec<serde_json::Value>, ApiError> {
        let dataset_id = Hex32::from_hex(dataset_id_hex)
            .map_err(|e| ApiError::BadRequest(format!("invalid dataset_id hex: {e}")))?;
        let list = self
            .store
            .list_licenses_by_dataset(dataset_id)
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        Ok(list
            .into_iter()
            .map(|x| serde_json::to_value(x).expect("serde value"))
            .collect())
    }

    pub fn list_attestations_by_dataset(
        &self,
        dataset_id_hex: &str,
    ) -> Result<Vec<serde_json::Value>, ApiError> {
        let dataset_id = Hex32::from_hex(dataset_id_hex)
            .map_err(|e| ApiError::BadRequest(format!("invalid dataset_id hex: {e}")))?;
        let list = self
            .store
            .list_attestations_by_dataset(dataset_id)
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        Ok(list
            .into_iter()
            .map(|x| serde_json::to_value(x).expect("serde value"))
            .collect())
    }

    pub fn get_receipt(&self, action_id_hex: &str) -> Result<Option<Vec<u8>>, ApiError> {
        let action_id = Hex32::from_hex(action_id_hex)
            .map_err(|e| ApiError::BadRequest(format!("invalid action_id hex: {e}")))?;
        let from_db = self
            .store
            .get_final_receipt(action_id)
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        if from_db.is_some() {
            return Ok(from_db);
        }
        let path = self.action_receipt_path(action_id_hex);
        if !path.exists() {
            return Ok(None);
        }
        let raw = fs::read(path).map_err(|e| ApiError::Internal(e.to_string()))?;
        Ok(Some(raw))
    }

    fn action_receipt_path(&self, action_id_hex: &str) -> PathBuf {
        self.receipts_dir
            .join("data")
            .join(format!("{action_id_hex}.json"))
    }

    fn persist_action_receipt(&self, receipt: &DataActionReceiptV1) -> Result<PathBuf, ApiError> {
        let dir = self.receipts_dir.join("data");
        fs::create_dir_all(&dir).map_err(|e| ApiError::Internal(e.to_string()))?;

        let out = dir.join(format!("{}.json", receipt.action_id));
        let bytes =
            serde_json::to_vec_pretty(receipt).map_err(|e| ApiError::Internal(e.to_string()))?;
        fs::write(&out, &bytes).map_err(|e| ApiError::Internal(e.to_string()))?;

        // Store a copy in sled under `receipt:<action_id>`
        let action_id = Hex32::from_hex(&receipt.action_id)
            .map_err(|e| ApiError::Internal(format!("invalid receipt action_id: {e}")))?;
        self.store
            .put_final_receipt(action_id, &bytes)
            .map_err(|e| ApiError::Internal(e.to_string()))?;

        Ok(out)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("upstream error: {0}")]
    Upstream(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl ApiError {
    fn from_apply(e: DataApplyError) -> Self {
        match e {
            DataApplyError::Validation(s) => ApiError::BadRequest(s),
            DataApplyError::Rejected(s) => ApiError::BadRequest(s),
            DataApplyError::Store(s) => ApiError::Internal(s),
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SubmitDataActionResponseV1 {
    pub schema_version: u32,
    pub action_id: String,
    pub local_apply_outcome: ApplyOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_id: Option<String>,
    pub batch_id: String,
    pub idempotency_key: String,
    pub l1_submit_result: L1SubmitResult,
    pub receipt_path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DataActionReceiptV1 {
    pub schema_version: u32,
    pub action_id: String,
    pub local_apply_outcome: ApplyOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dataset_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub license_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attestation_id: Option<String>,
    pub batch_id: String,
    pub idempotency_key: String,
    pub batch_canonical_hash: String,
    pub l1_submit_result: L1SubmitResult,
    pub written_at: String,
}

impl DataActionReceiptV1 {
    fn from_parts(
        action_id: &Hex32,
        local: &hub_data::ApplyReceipt,
        batch_id: &str,
        batch: &L2BatchEnvelopeV1,
        submit: &L1SubmitResult,
    ) -> Self {
        let written_at = time::OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "unknown".to_string());
        let batch_canonical_hash = b64url32(
            &batch
                .canonical_hash_blake3()
                .expect("batch canonical hash should be infallible"),
        );
        Self {
            schema_version: 1,
            action_id: action_id.to_hex(),
            local_apply_outcome: local.outcome,
            dataset_id: local.dataset_id.map(|x| x.to_hex()),
            license_id: local.license_id.map(|x| x.to_hex()),
            attestation_id: local.attestation_id.map(|x| x.to_hex()),
            batch_id: batch_id.to_string(),
            idempotency_key: b64url32(batch.idempotency_key.as_bytes()),
            batch_canonical_hash,
            l1_submit_result: submit.clone(),
            written_at,
        }
    }
}

fn b64url32(bytes: &[u8; 32]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use l2_core::l1_contract::mock_client::MockL1Client;
    use l2_core::AccountId;

    #[test]
    fn register_dataset_persists_state_and_writes_receipt() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts = tmp.path().join("receipts");
        let db = tmp.path().join("data_db");
        let l1 = Arc::new(MockL1Client::default());

        let store = DataStore::open(&db).unwrap();
        let api = DataApi::new(l1, store.clone(), receipts.clone());

        let req = RegisterDatasetRequestV1 {
            owner: AccountId::new("acc-alice"),
            name: "Example Dataset v1".to_string(),
            description: None,
            content_hash: Hex32::from_hex(
                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            )
            .unwrap(),
            pointer_uri: None,
            mime_type: None,
            tags: vec!["Example".to_string(), "dataset".to_string()],
            schema_version: 1,
        };

        let res = api.submit_register_dataset(req).unwrap();
        assert_eq!(res.schema_version, 1);
        assert!(res.dataset_id.is_some());
        assert!(res.action_id.len() == 64);

        // dataset stored
        let ds = api.get_dataset(res.dataset_id.as_ref().unwrap()).unwrap();
        assert!(ds.is_some());

        // receipt written
        let receipt_path = PathBuf::from(&res.receipt_path);
        assert!(receipt_path.exists());
        let raw = std::fs::read_to_string(receipt_path).unwrap();
        assert!(raw.contains(&res.action_id));
    }

    #[test]
    fn issue_license_indexes_and_is_queryable() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts = tmp.path().join("receipts");
        let db = tmp.path().join("data_db");
        let l1 = Arc::new(MockL1Client::default());

        let store = DataStore::open(&db).unwrap();
        let api = DataApi::new(l1, store.clone(), receipts.clone());

        // register dataset
        let reg = api
            .submit_register_dataset(RegisterDatasetRequestV1 {
                owner: AccountId::new("acc-alice"),
                name: "Example Dataset v1".to_string(),
                description: None,
                content_hash: Hex32::from_hex(
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                )
                .unwrap(),
                pointer_uri: None,
                mime_type: None,
                tags: vec![],
                schema_version: 1,
            })
            .unwrap();
        let dataset_id = reg.dataset_id.clone().unwrap();

        let lic = api
            .submit_issue_license(IssueLicenseRequestV1 {
                dataset_id: Hex32::from_hex(&dataset_id).unwrap(),
                licensor: AccountId::new("acc-alice"),
                licensee: AccountId::new("acc-bob"),
                rights: hub_data::LicenseRightsV1::Use,
                terms_uri: None,
                terms_hash: None,
                expires_at: None,
                price_microunits: None,
                nonce: "lic-001".to_string(),
            })
            .unwrap();
        assert!(lic.license_id.is_some());
        let license_id = lic.license_id.clone().unwrap();

        let got = api.get_license(&license_id).unwrap();
        assert!(got.is_some());

        let list = api.list_licenses_by_dataset(&dataset_id).unwrap();
        assert_eq!(list.len(), 1);
    }

    #[test]
    fn append_attestation_indexes_and_is_queryable() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let receipts = tmp.path().join("receipts");
        let db = tmp.path().join("data_db");
        let l1 = Arc::new(MockL1Client::default());

        let store = DataStore::open(&db).unwrap();
        let api = DataApi::new(l1, store.clone(), receipts.clone());

        // register dataset
        let reg = api
            .submit_register_dataset(RegisterDatasetRequestV1 {
                owner: AccountId::new("acc-alice"),
                name: "Example Dataset v1".to_string(),
                description: None,
                content_hash: Hex32::from_hex(
                    "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
                )
                .unwrap(),
                pointer_uri: None,
                mime_type: None,
                tags: vec![],
                schema_version: 1,
            })
            .unwrap();
        let dataset_id = reg.dataset_id.clone().unwrap();

        let att = api
            .submit_append_attestation(AppendAttestationRequestV1 {
                dataset_id: Hex32::from_hex(&dataset_id).unwrap(),
                attestor: AccountId::new("acc-carol"),
                statement: Some("quality:good".to_string()),
                statement_hash: None,
                ref_hash: None,
                ref_uri: None,
                nonce: "att-001".to_string(),
            })
            .unwrap();
        assert!(att.attestation_id.is_some());

        let list = api.list_attestations_by_dataset(&dataset_id).unwrap();
        assert_eq!(list.len(), 1);
    }
}
