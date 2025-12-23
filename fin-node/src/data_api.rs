#![forbid(unsafe_code)]

use base64::Engine as _;
use hub_data::apply::ApplyError as DataApplyError;
use hub_data::{
    apply_with_policy, AppendAttestationRequestV1, ApplyOutcome, CreateListingRequestV1,
    CreateListingV1, DataActionV1, DataEnvelopeV1, DataStore, GrantEntitlementV1, Hex32,
    IssueLicenseRequestV1, RegisterDatasetRequestV1,
};
use l2_core::finality::SubmitState;
use l2_core::l1_contract::{
    FixedAmountV1, HubPayloadEnvelopeV1, L1Client, L1SubmitResult, L2BatchEnvelopeV1,
};
use l2_core::policy::{PolicyDenyCode, PolicyError};
use l2_core::AccountId;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use time::format_description::well_known::Rfc3339;
use tracing::{info, warn};

use crate::policy_runtime::{ComplianceStrategy, PolicyRuntime};
use crate::recon_store::{ReconKind, ReconMetadata, ReconStore};

#[derive(Clone)]
pub struct DataApi {
    l1: Arc<dyn L1Client + Send + Sync>,
    store: DataStore,
    receipts_dir: PathBuf,
    policy: PolicyRuntime,
    recon: Option<ReconStore>,
}

impl DataApi {
    #[allow(dead_code)]
    pub fn new(
        l1: Arc<dyn L1Client + Send + Sync>,
        store: DataStore,
        receipts_dir: PathBuf,
    ) -> Self {
        Self {
            l1,
            store,
            receipts_dir,
            policy: PolicyRuntime::default(),
            recon: None,
        }
    }

    #[allow(dead_code)]
    pub fn new_with_policy(
        l1: Arc<dyn L1Client + Send + Sync>,
        store: DataStore,
        receipts_dir: PathBuf,
        policy: PolicyRuntime,
    ) -> Self {
        Self::new_with_policy_and_recon(l1, store, receipts_dir, policy, None)
    }

    pub fn new_with_policy_and_recon(
        l1: Arc<dyn L1Client + Send + Sync>,
        store: DataStore,
        receipts_dir: PathBuf,
        policy: PolicyRuntime,
        recon: Option<ReconStore>,
    ) -> Self {
        Self {
            l1,
            store,
            receipts_dir,
            policy,
            recon,
        }
    }

    pub fn submit_register_dataset(
        &self,
        req: RegisterDatasetRequestV1,
    ) -> Result<SubmitDataActionResponseV1, ApiError> {
        self.submit_action_obj(hub_data::DataActionRequestV1::RegisterDatasetV1(req).into_action())
    }

    pub fn submit_issue_license(
        &self,
        req: IssueLicenseRequestV1,
    ) -> Result<SubmitDataActionResponseV1, ApiError> {
        self.submit_action_obj(hub_data::DataActionRequestV1::IssueLicenseV1(req).into_action())
    }

    pub fn submit_append_attestation(
        &self,
        req: AppendAttestationRequestV1,
    ) -> Result<SubmitDataActionResponseV1, ApiError> {
        self.submit_action_obj(
            hub_data::DataActionRequestV1::AppendAttestationV1(req).into_action(),
        )
    }

    pub fn submit_create_listing(
        &self,
        req: CreateListingRequestV1,
    ) -> Result<SubmitDataActionResponseV1, ApiError> {
        self.submit_action_obj(hub_data::DataActionRequestV1::CreateListingV1(req).into_action())
    }

    pub fn submit_add_licensor(
        &self,
        req: hub_data::AddLicensorRequestV1,
    ) -> Result<SubmitDataActionResponseV1, ApiError> {
        self.submit_action_obj(hub_data::DataActionRequestV1::AddLicensorV1(req).into_action())
    }

    pub fn submit_add_attestor(
        &self,
        req: hub_data::AddAttestorRequestV1,
    ) -> Result<SubmitDataActionResponseV1, ApiError> {
        self.submit_action_obj(hub_data::DataActionRequestV1::AddAttestorV1(req).into_action())
    }

    pub fn submit_action_obj(
        &self,
        action: DataActionV1,
    ) -> Result<SubmitDataActionResponseV1, ApiError> {
        let env = DataEnvelopeV1::new(action).map_err(|e| ApiError::BadRequest(e.to_string()))?;
        let context_id = env.action_id.to_hex();

        info!(
            event = "action_attempted",
            hub = "data",
            action_kind = %data_action_kind(&env.action),
            action_id = %context_id
        );

        self.enforce_compliance(&env.action, &context_id)?;

        // 1) Apply locally (sled)
        let local =
            match apply_with_policy(&env, &self.store, self.policy.mode, &self.policy.admins) {
                Ok(x) => x,
                Err(e) => {
                    let api_err = ApiError::from_apply_with_context(e, context_id.clone());
                    if let ApiError::PolicyDenied(p) = &api_err {
                        warn!(
                            event = "action_denied",
                            hub = "data",
                            action_kind = %data_action_kind(&env.action),
                            action_id = %context_id,
                            code = ?p.code,
                            message = %p.message
                        );
                    }
                    return Err(api_err);
                }
            };

        info!(
            event = "action_applied",
            hub = "data",
            action_kind = %data_action_kind(&env.action),
            action_id = %context_id,
            outcome = ?local.outcome
        );

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

        info!(
            event = "action_submitted_to_l1",
            hub = "data",
            action_kind = %data_action_kind(&env.action),
            action_id = %context_id,
            accepted = submit.accepted,
            already_known = submit.already_known,
            l1_tx_id = submit.l1_tx_id.as_ref().map(|x| x.0.as_str()).unwrap_or("")
        );

        // 4) Persist action receipt
        let receipt =
            DataActionReceiptV1::from_parts(&env.action_id, &local, &batch_id, &batch, &submit);
        let receipt_path = self.persist_action_receipt(&receipt)?;

        // Enqueue for reconciliation (restart-safe).
        if let Some(recon) = self.recon.as_ref() {
            let now = unix_now_secs();
            let meta = ReconMetadata::new(now);
            let _ = recon.enqueue(ReconKind::DataAction, &context_id, &meta);
        }

        Ok(SubmitDataActionResponseV1 {
            schema_version: 1,
            action_id: env.action_id.to_hex(),
            local_apply_outcome: local.outcome,
            dataset_id: local.dataset_id.map(|x| x.to_hex()),
            license_id: local.license_id.map(|x| x.to_hex()),
            attestation_id: local.attestation_id.map(|x| x.to_hex()),
            listing_id: local.listing_id.map(|x| x.to_hex()),
            purchase_id: local.purchase_id,
            batch_id,
            idempotency_key: b64url32(batch.idempotency_key.as_bytes()),
            l1_submit_result: submit,
            receipt_path: receipt_path.to_string_lossy().to_string(),
        })
    }

    fn enforce_compliance(&self, action: &DataActionV1, context_id: &str) -> Result<(), ApiError> {
        if !self.policy.compliance.enabled
            || self.policy.compliance.strategy == ComplianceStrategy::None
        {
            return Ok(());
        }

        let mut accounts: Vec<AccountId> = Vec::new();
        match action {
            DataActionV1::RegisterDatasetV1(a) => accounts.push(a.owner.clone()),
            DataActionV1::IssueLicenseV1(a) => {
                accounts.push(a.licensor.clone());
                accounts.push(a.licensee.clone());
            }
            DataActionV1::AppendAttestationV1(a) => accounts.push(a.attestor.clone()),
            DataActionV1::CreateListingV1(a) => accounts.push(a.licensor.clone()),
            DataActionV1::GrantEntitlementV1(a) => {
                self.policy
                    .require_actor_if_compliance_enabled(a.actor.as_ref())
                    .map_err(|s| policy_denied_from_str(&s, context_id))?;
                if let Some(actor) = a.actor.as_ref() {
                    accounts.push(actor.clone());
                }
                accounts.push(a.licensee.clone());
            }
            DataActionV1::AddLicensorV1(a) => {
                accounts.push(a.actor.clone());
                accounts.push(a.licensor.clone());
            }
            DataActionV1::AddAttestorV1(a) => {
                accounts.push(a.actor.clone());
                accounts.push(a.attestor.clone());
            }
        }

        accounts.sort_by(|a, b| a.0.cmp(&b.0));
        accounts.dedup_by(|a, b| a.0 == b.0);

        self.policy
            .compliance_check_accounts(&accounts)
            .map_err(|s| {
                warn!(
                    event = "action_denied",
                    hub = "data",
                    action_kind = %data_action_kind(action),
                    action_id = %context_id,
                    reason = %s
                );
                policy_denied_from_str(&s, context_id)
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

    pub fn get_listing_typed(
        &self,
        listing_id: Hex32,
    ) -> Result<Option<CreateListingV1>, ApiError> {
        self.store
            .get_listing(listing_id)
            .map_err(|e| ApiError::Internal(e.to_string()))
    }

    pub fn list_listings_by_dataset_typed(
        &self,
        dataset_id: Hex32,
    ) -> Result<Vec<CreateListingV1>, ApiError> {
        self.store
            .list_listings_by_dataset(dataset_id)
            .map_err(|e| ApiError::Internal(e.to_string()))
    }

    pub fn list_entitlements_by_dataset_typed(
        &self,
        dataset_id: Hex32,
    ) -> Result<Vec<GrantEntitlementV1>, ApiError> {
        self.store
            .list_entitlements_by_dataset(dataset_id)
            .map_err(|e| ApiError::Internal(e.to_string()))
    }

    pub fn list_entitlements_by_licensee_typed(
        &self,
        licensee: &str,
    ) -> Result<Vec<GrantEntitlementV1>, ApiError> {
        self.store
            .list_entitlements_by_licensee(licensee)
            .map_err(|e| ApiError::Internal(e.to_string()))
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

    pub fn get_receipt_typed(
        &self,
        action_id_hex: &str,
    ) -> Result<Option<DataActionReceiptV1>, ApiError> {
        let raw = match self.get_receipt(action_id_hex)? {
            Some(r) => r,
            None => return Ok(None),
        };
        let v: DataActionReceiptV1 =
            serde_json::from_slice(&raw).map_err(|e| ApiError::Internal(e.to_string()))?;
        Ok(Some(v))
    }

    #[allow(dead_code)]
    pub fn update_submit_state(
        &self,
        action_id_hex: &str,
        submit_state: SubmitState,
    ) -> Result<(), ApiError> {
        let mut r = self
            .get_receipt_typed(action_id_hex)?
            .ok_or_else(|| ApiError::Internal("missing data receipt".to_string()))?;
        r.submit_state = submit_state;
        let _ = self.persist_action_receipt(&r)?;
        Ok(())
    }

    pub fn persist_receipt_typed(&self, receipt: &DataActionReceiptV1) -> Result<(), ApiError> {
        let _ = self.persist_action_receipt(receipt)?;
        Ok(())
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
    #[error("{0}")]
    PolicyDenied(PolicyError),
    #[error("upstream error: {0}")]
    Upstream(String),
    #[error("internal error: {0}")]
    Internal(String),
}

impl ApiError {
    fn from_apply_with_context(e: DataApplyError, context_id: String) -> Self {
        match e {
            DataApplyError::Validation(s) => ApiError::BadRequest(s),
            DataApplyError::Rejected(s) => match parse_policy_error(&s, context_id.clone()) {
                Some(p) => ApiError::PolicyDenied(p),
                None => ApiError::BadRequest(s),
            },
            DataApplyError::Store(s) => ApiError::Internal(s),
        }
    }
}

fn data_action_kind(a: &DataActionV1) -> &'static str {
    match a {
        DataActionV1::RegisterDatasetV1(_) => "data_register_dataset",
        DataActionV1::IssueLicenseV1(_) => "data_issue_license",
        DataActionV1::AppendAttestationV1(_) => "data_append_attestation",
        DataActionV1::CreateListingV1(_) => "data_create_listing",
        DataActionV1::GrantEntitlementV1(_) => "data_grant_entitlement",
        DataActionV1::AddLicensorV1(_) => "data_add_licensor",
        DataActionV1::AddAttestorV1(_) => "data_add_attestor",
    }
}

fn policy_denied_from_str(s: &str, context_id: &str) -> ApiError {
    if let Some(p) = parse_policy_error(s, context_id.to_string()) {
        return ApiError::PolicyDenied(p);
    }
    ApiError::BadRequest(s.to_string())
}

fn parse_policy_error(s: &str, context_id: String) -> Option<PolicyError> {
    let rest = s.strip_prefix("policy:")?;
    let mut it = rest.splitn(2, ':');
    let code_s = it.next()?.trim();
    let msg = it.next().unwrap_or("").trim().to_string();
    let code = match code_s {
        "missing_actor" => PolicyDenyCode::MissingActor,
        "unauthorized" => PolicyDenyCode::Unauthorized,
        "delegation_required" => PolicyDenyCode::DelegationRequired,
        "not_found" => PolicyDenyCode::NotFound,
        "compliance_denied" => PolicyDenyCode::ComplianceDenied,
        "invalid_policy_input" => PolicyDenyCode::InvalidPolicyInput,
        _ => return None,
    };
    Some(PolicyError {
        code,
        message: msg,
        context_id,
    })
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listing_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purchase_id: Option<String>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listing_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purchase_id: Option<String>,
    pub batch_id: String,
    pub idempotency_key: String,
    pub batch_canonical_hash: String,
    pub l1_submit_result: L1SubmitResult,
    #[serde(default)]
    pub submit_state: SubmitState,
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
        let idempotency_key = b64url32(batch.idempotency_key.as_bytes());
        Self {
            schema_version: 2,
            action_id: action_id.to_hex(),
            local_apply_outcome: local.outcome,
            dataset_id: local.dataset_id.map(|x| x.to_hex()),
            license_id: local.license_id.map(|x| x.to_hex()),
            attestation_id: local.attestation_id.map(|x| x.to_hex()),
            listing_id: local.listing_id.map(|x| x.to_hex()),
            purchase_id: local.purchase_id.clone(),
            batch_id: batch_id.to_string(),
            idempotency_key: idempotency_key.clone(),
            batch_canonical_hash,
            l1_submit_result: submit.clone(),
            submit_state: SubmitState::Submitted {
                idempotency_key,
                l1_tx_id: submit.l1_tx_id.as_ref().map(|x| x.0.clone()),
            },
            written_at,
        }
    }
}

fn b64url32(bytes: &[u8; 32]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
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
            attestation_policy: hub_data::AttestationPolicyV1::Anyone,
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
                attestation_policy: hub_data::AttestationPolicyV1::Anyone,
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
                attestation_policy: hub_data::AttestationPolicyV1::Anyone,
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
