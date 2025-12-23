#![forbid(unsafe_code)]

use crate::data_api::ApiError as DataApiError;
use crate::fin_api::ApiError as FinApiError;
use crate::{data_api::DataApi, fin_api::FinApi};
use hub_fin::{AmountU128, FinActionV1, FinEnvelopeV1, TransferUnitsV1};
use l2_core::hub_linkage::{
    derive_purchase_id_v1, EntitlementRef, Hex32 as LinkHex32, LinkageReceiptV1, LinkageStatus,
    PaymentRef,
};
use l2_core::AccountId;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Clone)]
pub struct LinkageApi {
    fin: FinApi,
    data: DataApi,
    receipts_dir: PathBuf,
}

impl LinkageApi {
    pub fn new(fin: FinApi, data: DataApi, receipts_dir: PathBuf) -> Self {
        Self {
            fin,
            data,
            receipts_dir,
        }
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

        // If already entitled, return immediately (idempotent).
        if receipt.status == LinkageStatus::Entitled && receipt.entitlement_ref.is_some() {
            return Ok(receipt);
        }

        // Step 1: payment (FIN transfer).
        if receipt.payment_ref.is_none() {
            match self.execute_payment(&listing, &receipt, req.memo.as_deref()) {
                Ok((payment_ref, status)) => {
                    receipt.payment_ref = Some(payment_ref);
                    receipt.status = status;
                    receipt.last_error = None;
                    self.persist_receipt(&receipt)?;
                }
                Err(e) => {
                    receipt.status = LinkageStatus::FailedRecoverable;
                    receipt.last_error = Some(sanitize_error(&e.to_string()));
                    self.persist_receipt(&receipt)?;
                    return Err(e);
                }
            }
        } else if receipt.status == LinkageStatus::Created {
            // Recover from partial state where `payment_ref` was written but status was not.
            receipt.status = LinkageStatus::Paid;
            self.persist_receipt(&receipt)?;
        }

        // Step 2: entitlement (DATA grant).
        if receipt.entitlement_ref.is_none() && self.failpoint_after_payment_exists() {
            receipt.status = LinkageStatus::FailedRecoverable;
            receipt.last_error = Some("failpoint:after_payment".to_string());
            self.persist_receipt(&receipt)?;
            return Err(ApiError::Internal("failpoint after_payment".to_string()));
        }

        if receipt.entitlement_ref.is_none() {
            let payment_ref = receipt.payment_ref.ok_or_else(|| {
                ApiError::Internal("missing payment_ref after payment step".to_string())
            })?;
            match self.execute_entitlement(&listing, &receipt, payment_ref) {
                Ok(ent_ref) => {
                    receipt.entitlement_ref = Some(ent_ref);
                    receipt.status = LinkageStatus::Entitled;
                    receipt.last_error = None;
                    self.persist_receipt(&receipt)?;
                }
                Err(e) => {
                    receipt.status = LinkageStatus::FailedRecoverable;
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

    fn execute_payment(
        &self,
        listing: &hub_data::CreateListingV1,
        receipt: &LinkageReceiptV1,
        memo: Option<&str>,
    ) -> Result<(PaymentRef, LinkageStatus), ApiError> {
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
        let _ = self
            .fin
            .submit_action_obj(action)
            .map_err(ApiError::from_fin_api)?;

        Ok((
            PaymentRef {
                fin_action_id: LinkHex32(action_id.0),
                fin_receipt_hash: LinkHex32(env_hash),
            },
            LinkageStatus::Paid,
        ))
    }

    fn execute_entitlement(
        &self,
        listing: &hub_data::CreateListingV1,
        receipt: &LinkageReceiptV1,
        payment_ref: PaymentRef,
    ) -> Result<EntitlementRef, ApiError> {
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

        let _ = self
            .data
            .submit_action_obj(env.action)
            .map_err(ApiError::from_data_api)?;

        Ok(EntitlementRef {
            data_action_id,
            license_id,
        })
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
        Ok(())
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
