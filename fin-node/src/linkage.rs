#![forbid(unsafe_code)]

use crate::data_api::ApiError as DataApiError;
use crate::fin_api::ApiError as FinApiError;
use crate::{data_api::DataApi, fin_api::FinApi};
use hub_fin::{AmountU128, FinActionV1, FinEnvelopeV1, TransferUnitsV1};
use l2_core::finality::SubmitState;
use l2_core::hub_linkage::{
    derive_purchase_id_v1, EntitlementPolicy, EntitlementRef, Hex32 as LinkHex32,
    LinkageOverallStatus, LinkageReceiptV1, LinkageStatus, PaymentRef,
};
use l2_core::AccountId;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

use crate::audit_store::{AuditStore, AuditSubjectsV1, EventRecordV1};
use crate::bootstrap_store::BootstrapStore;
use crate::recon_store::{ReconKind, ReconMetadata, ReconStore};

#[derive(Clone)]
pub struct LinkageApi {
    fin: FinApi,
    data: DataApi,
    receipts_dir: PathBuf,
    entitlement_policy: EntitlementPolicy,
    recon: Option<ReconStore>,
    bootstrap: Option<BootstrapStore>,
    audit: Option<AuditStore>,
}

impl LinkageApi {
    #[allow(dead_code)]
    pub fn new(fin: FinApi, data: DataApi, receipts_dir: PathBuf) -> Self {
        Self::new_with_policy_and_recon(
            fin,
            data,
            receipts_dir,
            EntitlementPolicy::Optimistic,
            None,
        )
    }

    #[allow(dead_code)]
    pub fn new_with_policy(
        fin: FinApi,
        data: DataApi,
        receipts_dir: PathBuf,
        entitlement_policy: EntitlementPolicy,
    ) -> Self {
        Self::new_with_policy_and_recon(fin, data, receipts_dir, entitlement_policy, None)
    }

    pub fn new_with_policy_and_recon(
        fin: FinApi,
        data: DataApi,
        receipts_dir: PathBuf,
        entitlement_policy: EntitlementPolicy,
        recon: Option<ReconStore>,
    ) -> Self {
        Self {
            fin,
            data,
            receipts_dir,
            entitlement_policy,
            recon,
            bootstrap: None,
            audit: None,
        }
    }

    pub fn with_bootstrap(mut self, bootstrap: Option<BootstrapStore>) -> Self {
        self.bootstrap = bootstrap;
        self
    }

    pub fn with_audit(mut self, audit: Option<AuditStore>) -> Self {
        self.audit = audit;
        self
    }

    pub fn buy_license(&self, req: BuyLicenseRequestV1) -> Result<LinkageReceiptV1, ApiError> {
        // Load listing (source of truth for price/currency/seller/terms).
        let listing = self
            .data
            .get_listing_typed(req.listing_id)
            .map_err(ApiError::from_data_api)?
            .ok_or_else(|| ApiError::BadRequest("listing_id not found".to_string()))?;

        if listing.dataset_id != req.dataset_id {
            return Err(ApiError::BadRequest(
                "dataset_id does not match listing.dataset_id".to_string(),
            ));
        }

        let dataset_id_link = LinkHex32(listing.dataset_id.0);
        let listing_id_link = LinkHex32(listing.listing_id.0);
        let currency_asset_id_link = LinkHex32(listing.currency_asset_id.0);
        let terms_hash_link = listing.terms_hash.as_ref().map(|x| LinkHex32(x.0));
        let nonce = req.nonce.as_deref().unwrap_or("");

        let purchase_id = derive_purchase_id_v1(
            &dataset_id_link,
            &req.buyer_account,
            listing.price_microunits.0,
            &currency_asset_id_link,
            terms_hash_link.as_ref(),
            nonce,
        );

        // Load or initialize linkage receipt.
        let mut receipt = self.load_or_init_receipt(
            purchase_id,
            dataset_id_link,
            listing_id_link,
            req.buyer_account.clone(),
            listing.price_microunits.0,
            currency_asset_id_link,
        )?;

        // Persist the policy choice at creation time (do not silently change existing purchases).
        if receipt.overall_status == LinkageOverallStatus::Created
            && receipt.policy == EntitlementPolicy::Optimistic
        {
            receipt.policy = self.entitlement_policy;
        }

        // If already entitled, return immediately (idempotent).
        if receipt.status == LinkageStatus::Entitled && receipt.entitlement_ref.is_some() {
            return Ok(receipt);
        }

        // Step 1: payment (FIN transfer).
        if receipt.payment_ref.is_none() {
            match self.execute_payment(&listing, &receipt, req.memo.as_deref()) {
                Ok((payment_ref, submit_state, status)) => {
                    receipt.payment_ref = Some(payment_ref);
                    receipt.status = status;
                    receipt.payment_submit_state = submit_state;
                    receipt.overall_status = match receipt.policy {
                        EntitlementPolicy::Optimistic => LinkageOverallStatus::PaidFinal,
                        EntitlementPolicy::FinalityRequired => {
                            LinkageOverallStatus::PaymentPendingFinality
                        }
                    };
                    receipt.last_error = None;
                    self.persist_receipt(&receipt)?;

                    if receipt.policy == EntitlementPolicy::FinalityRequired {
                        if let Some(recon) = self.recon.as_ref() {
                            let now = unix_now_secs();
                            let meta = ReconMetadata::new(now);
                            let _ = recon.enqueue(
                                ReconKind::LinkagePurchase,
                                &receipt.purchase_id.to_hex(),
                                &meta,
                            );
                        }
                    }
                }
                Err(e) => {
                    receipt.status = LinkageStatus::FailedRecoverable;
                    receipt.overall_status = LinkageOverallStatus::FailedRecoverable;
                    receipt.last_error = Some(sanitize_error(&e.to_string()));
                    self.persist_receipt(&receipt)?;
                    return Err(e);
                }
            }
        } else if receipt.status == LinkageStatus::Created {
            // Recover from partial state where `payment_ref` was written but status was not.
            receipt.status = LinkageStatus::Paid;
            if receipt.overall_status == LinkageOverallStatus::Created {
                receipt.overall_status = match receipt.policy {
                    EntitlementPolicy::Optimistic => LinkageOverallStatus::PaidFinal,
                    EntitlementPolicy::FinalityRequired => {
                        LinkageOverallStatus::PaymentPendingFinality
                    }
                };
            }
            self.persist_receipt(&receipt)?;
        }

        // Finality-gated mode stops here; the reconciliation loop will continue once payment is final.
        if receipt.policy == EntitlementPolicy::FinalityRequired {
            return Ok(receipt);
        }

        // Step 2: entitlement (DATA grant).
        if receipt.entitlement_ref.is_none() && self.failpoint_after_payment_exists() {
            receipt.status = LinkageStatus::FailedRecoverable;
            receipt.overall_status = LinkageOverallStatus::FailedRecoverable;
            receipt.last_error = Some("failpoint:after_payment".to_string());
            self.persist_receipt(&receipt)?;
            return Err(ApiError::Internal("failpoint after_payment".to_string()));
        }

        if receipt.entitlement_ref.is_none() {
            let payment_ref = receipt.payment_ref.ok_or_else(|| {
                ApiError::Internal("missing payment_ref after payment step".to_string())
            })?;
            match self.execute_entitlement(&listing, &receipt, payment_ref) {
                Ok((ent_ref, submit_state)) => {
                    receipt.entitlement_ref = Some(ent_ref);
                    receipt.status = LinkageStatus::Entitled;
                    receipt.entitlement_submit_state = submit_state;
                    receipt.overall_status = LinkageOverallStatus::EntitledFinal;
                    receipt.last_error = None;
                    self.persist_receipt(&receipt)?;
                }
                Err(e) => {
                    receipt.status = LinkageStatus::FailedRecoverable;
                    receipt.overall_status = LinkageOverallStatus::FailedRecoverable;
                    receipt.last_error = Some(sanitize_error(&e.to_string()));
                    self.persist_receipt(&receipt)?;
                    return Err(e);
                }
            }
        }

        Ok(receipt)
    }

    pub fn get_purchase_receipt(
        &self,
        purchase_id_hex: &str,
    ) -> Result<Option<LinkageReceiptV1>, ApiError> {
        let pid = LinkHex32::from_hex(purchase_id_hex)
            .map_err(|e| ApiError::BadRequest(format!("invalid purchase_id: {e}")))?;
        let path = self.receipt_path(pid);
        if !path.exists() {
            return Ok(None);
        }
        let raw = fs::read(&path).map_err(|e| ApiError::Internal(e.to_string()))?;
        let v: LinkageReceiptV1 =
            serde_json::from_slice(&raw).map_err(|e| ApiError::Internal(e.to_string()))?;
        Ok(Some(v))
    }

    pub fn persist_purchase_receipt(&self, receipt: &LinkageReceiptV1) -> Result<(), ApiError> {
        self.persist_receipt(receipt)
    }

    pub fn audit_event_for_receipt(
        &self,
        kind: &str,
        receipt: &LinkageReceiptV1,
        submit_state: Option<SubmitState>,
    ) {
        self.audit_linkage_event(kind, receipt, submit_state);
    }

    /// Continue the workflow by submitting the DATA entitlement grant.
    ///
    /// This is intended for the reconciliation loop (resume-safe continuation).
    pub fn submit_entitlement_for_receipt(
        &self,
        receipt: &LinkageReceiptV1,
    ) -> Result<(EntitlementRef, l2_core::finality::SubmitState), ApiError> {
        let listing_id = hub_data::Hex32(receipt.listing_id.0);
        let listing = self
            .data
            .get_listing_typed(listing_id)
            .map_err(ApiError::from_data_api)?
            .ok_or_else(|| ApiError::BadRequest("listing_id not found".to_string()))?;

        let payment_ref = receipt.payment_ref.ok_or_else(|| {
            ApiError::Internal("missing payment_ref while continuing entitlement".to_string())
        })?;

        self.execute_entitlement(&listing, receipt, payment_ref)
    }

    fn execute_payment(
        &self,
        listing: &hub_data::CreateListingV1,
        receipt: &LinkageReceiptV1,
        memo: Option<&str>,
    ) -> Result<(PaymentRef, l2_core::finality::SubmitState, LinkageStatus), ApiError> {
        let asset_id = hub_fin::Hex32(listing.currency_asset_id.0);
        let amount = AmountU128(listing.price_microunits.0);

        // `client_tx_id` participates in action_id; use purchase_id hex for deterministic idempotency.
        let client_tx_id = receipt.purchase_id.to_hex();
        let transfer = TransferUnitsV1 {
            asset_id,
            from_account: receipt.licensee.clone(),
            to_account: listing.licensor.clone(),
            amount,
            actor: Some(receipt.licensee.clone()),
            client_tx_id,
            memo: memo.map(str::to_string),
            purchase_id: Some(receipt.purchase_id),
        };

        let action = FinActionV1::TransferUnitsV1(transfer);
        let env = FinEnvelopeV1::new(action).map_err(|e| ApiError::BadRequest(format!("{e}")))?;
        let action_id = env.action_id;
        let action = env.action.clone();
        let env_bytes = env.canonical_bytes().map_err(|e| {
            ApiError::Internal(format!("fin envelope canonicalization failed: {e}"))
        })?;
        let mut env_hash = [0u8; 32];
        env_hash.copy_from_slice(blake3::hash(&env_bytes).as_bytes());

        // Submit via fin api (apply + L1 submit + receipt persistence).
        let submit = self
            .fin
            .submit_action_obj(action)
            .map_err(ApiError::from_fin_api)?;

        let submit_state = l2_core::finality::SubmitState::Submitted {
            idempotency_key: submit.idempotency_key.clone(),
            l1_tx_id: submit
                .l1_submit_result
                .l1_tx_id
                .as_ref()
                .map(|x| x.0.clone()),
        };

        Ok((
            PaymentRef {
                fin_action_id: LinkHex32(action_id.0),
                fin_receipt_hash: LinkHex32(env_hash),
            },
            submit_state,
            LinkageStatus::Paid,
        ))
    }

    fn execute_entitlement(
        &self,
        listing: &hub_data::CreateListingV1,
        receipt: &LinkageReceiptV1,
        payment_ref: PaymentRef,
    ) -> Result<(EntitlementRef, l2_core::finality::SubmitState), ApiError> {
        let req = hub_data::GrantEntitlementRequestV1 {
            purchase_id: receipt.purchase_id,
            listing_id: listing.listing_id,
            dataset_id: listing.dataset_id,
            licensee: receipt.licensee.clone(),
            payment_ref,
            actor: Some(listing.licensor.clone()),
        };
        let action = hub_data::DataActionRequestV1::GrantEntitlementV1(req).into_action();
        let env = hub_data::DataEnvelopeV1::new(action)
            .map_err(|e| ApiError::BadRequest(format!("{e}")))?;

        let data_action_id = LinkHex32(env.action_id.0);
        let license_id = match &env.action {
            hub_data::DataActionV1::GrantEntitlementV1(x) => LinkHex32(x.license_id.0),
            _ => {
                return Err(ApiError::Internal(
                    "unexpected action variant while granting entitlement".to_string(),
                ))
            }
        };

        let submit = self
            .data
            .submit_action_obj(env.action)
            .map_err(ApiError::from_data_api)?;

        let submit_state = l2_core::finality::SubmitState::Submitted {
            idempotency_key: submit.idempotency_key.clone(),
            l1_tx_id: submit
                .l1_submit_result
                .l1_tx_id
                .as_ref()
                .map(|x| x.0.clone()),
        };

        Ok((
            EntitlementRef {
                data_action_id,
                license_id,
            },
            submit_state,
        ))
    }

    fn load_or_init_receipt(
        &self,
        purchase_id: LinkHex32,
        dataset_id: LinkHex32,
        listing_id: LinkHex32,
        licensee: AccountId,
        price_microunits: u128,
        currency_asset_id: LinkHex32,
    ) -> Result<LinkageReceiptV1, ApiError> {
        let path = self.receipt_path(purchase_id);
        if path.exists() {
            let raw = fs::read(&path).map_err(|e| ApiError::Internal(e.to_string()))?;
            let v: LinkageReceiptV1 =
                serde_json::from_slice(&raw).map_err(|e| ApiError::Internal(e.to_string()))?;
            return Ok(v);
        }

        let v = LinkageReceiptV1 {
            purchase_id,
            dataset_id,
            listing_id,
            licensee,
            price_microunits,
            currency_asset_id,
            payment_ref: None,
            entitlement_ref: None,
            policy: self.entitlement_policy,
            payment_submit_state: l2_core::finality::SubmitState::NotSubmitted,
            entitlement_submit_state: l2_core::finality::SubmitState::NotSubmitted,
            overall_status: LinkageOverallStatus::Created,
            status: LinkageStatus::Created,
            last_error: None,
        };
        self.persist_receipt(&v)?;
        Ok(v)
    }

    fn persist_receipt(&self, receipt: &LinkageReceiptV1) -> Result<(), ApiError> {
        let dir = self.receipts_dir.join("linkage");
        fs::create_dir_all(&dir).map_err(|e| ApiError::Internal(e.to_string()))?;
        let out = dir.join(format!("{}.json", receipt.purchase_id.to_hex()));
        let bytes =
            serde_json::to_vec_pretty(receipt).map_err(|e| ApiError::Internal(e.to_string()))?;
        fs::write(&out, bytes).map_err(|e| ApiError::Internal(e.to_string()))?;

        if let Some(b) = self.bootstrap.as_ref() {
            if let Ok(rel) = out.strip_prefix(&self.receipts_dir) {
                let rel_s = rel.to_string_lossy().replace('\\', "/");
                let bytes2 = serde_json::to_vec_pretty(receipt).unwrap_or_else(|_| Vec::new());
                // Linkage receipts are in their own namespace (also stored separately in base snapshot).
                let _ = b.record_put("linkage", rel_s.as_bytes(), &bytes2);
            }
        }

        self.audit_linkage_event("receipt_written", receipt, None);

        Ok(())
    }

    fn audit_linkage_event(
        &self,
        kind: &str,
        receipt: &LinkageReceiptV1,
        submit_state: Option<SubmitState>,
    ) {
        let Some(a) = self.audit.as_ref() else {
            return;
        };
        let epoch = self
            .bootstrap
            .as_ref()
            .and_then(|b| b.epoch().ok())
            .unwrap_or(0);

        let mut subjects = AuditSubjectsV1::default();
        subjects.dataset_ids.push(receipt.dataset_id.to_hex());
        subjects.asset_ids.push(receipt.currency_asset_id.to_hex());
        subjects.accounts.push(receipt.licensee.0.clone());

        let receipt_ref = format!("receipts/linkage/{}.json", receipt.purchase_id.to_hex());
        let _ = a.append_event(EventRecordV1 {
            schema_version: 1,
            seq: 0,
            occurred_at_unix_secs: unix_now_secs(),
            epoch,
            hub: "linkage".to_string(),
            kind: kind.to_string(),
            action_id: None,
            purchase_id: Some(receipt.purchase_id.to_hex()),
            envelope_hash: None,
            receipt_ref: Some(receipt_ref),
            submit_state,
            signer_pubkey: None,
            subjects: subjects.normalize(),
        });
    }

    fn receipt_path(&self, purchase_id: LinkHex32) -> PathBuf {
        self.receipts_dir
            .join("linkage")
            .join(format!("{}.json", purchase_id.to_hex()))
    }

    fn failpoint_after_payment_exists(&self) -> bool {
        // Test-only hook: if this file exists, simulate a crash after payment.
        //
        // This is intentionally file-scoped (under receipts dir) so tests can run in parallel
        // without global process state like env vars.
        self.receipts_dir
            .join("linkage")
            .join("_fail_after_payment")
            .exists()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuyLicenseRequestV1 {
    pub dataset_id: hub_data::Hex32,
    pub listing_id: hub_data::Hex32,
    pub buyer_account: AccountId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
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
    fn from_fin_api(e: FinApiError) -> Self {
        match e {
            FinApiError::BadRequest(s) => ApiError::BadRequest(s),
            FinApiError::PolicyDenied(p) => ApiError::BadRequest(p.to_string()),
            FinApiError::Upstream(s) => ApiError::Upstream(s),
            FinApiError::Internal(s) => ApiError::Internal(s),
        }
    }

    fn from_data_api(e: DataApiError) -> Self {
        match e {
            DataApiError::BadRequest(s) => ApiError::BadRequest(s),
            DataApiError::PolicyDenied(p) => ApiError::BadRequest(p.to_string()),
            DataApiError::Upstream(s) => ApiError::Upstream(s),
            DataApiError::Internal(s) => ApiError::Internal(s),
        }
    }
}

fn sanitize_error(s: &str) -> String {
    // Keep it deterministic and safe for logs/JSON.
    let mut out = s.replace(['\n', '\r', '\t'], " ");
    out = out.trim().to_string();
    const MAX: usize = 256;
    if out.len() > MAX {
        out.truncate(MAX);
    }
    out
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
