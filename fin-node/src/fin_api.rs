#![forbid(unsafe_code)]

use base64::Engine as _;
use hub_fin::apply::ApplyError;
use hub_fin::{
    apply_with_policy, ApplyOutcome, FinActionRequestV1, FinActionV1, FinEnvelopeV1, FinStore,
    Hex32,
};
use l2_core::finality::SubmitState;
use l2_core::l1_contract::{
    FixedAmountV1, HubPayloadEnvelopeV1, L1Client, L1SubmitResult, L2BatchEnvelopeV1,
};
use l2_core::policy::{PolicyDenyCode, PolicyError};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use time::format_description::well_known::Rfc3339;
use tracing::{info, warn};

use crate::policy_runtime::PolicyRuntime;
use crate::recon_store::{ReconKind, ReconMetadata, ReconStore};

#[derive(Clone)]
pub struct FinApi {
    l1: Arc<dyn L1Client + Send + Sync>,
    store: FinStore,
    receipts_dir: PathBuf,
    policy: PolicyRuntime,
    recon: Option<ReconStore>,
}

impl FinApi {
    #[allow(dead_code)]
    pub fn new(
        l1: Arc<dyn L1Client + Send + Sync>,
        store: FinStore,
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
        store: FinStore,
        receipts_dir: PathBuf,
        policy: PolicyRuntime,
    ) -> Self {
        Self::new_with_policy_and_recon(l1, store, receipts_dir, policy, None)
    }

    pub fn new_with_policy_and_recon(
        l1: Arc<dyn L1Client + Send + Sync>,
        store: FinStore,
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

    pub fn submit_action(&self, body: &[u8]) -> Result<SubmitActionResponseV1, ApiError> {
        let req: FinActionRequestV1 =
            serde_json::from_slice(body).map_err(|e| ApiError::BadRequest(e.to_string()))?;
        self.submit_action_obj(req.into_action())
    }

    pub fn submit_action_obj(
        &self,
        action: FinActionV1,
    ) -> Result<SubmitActionResponseV1, ApiError> {
        let env = FinEnvelopeV1::new(action).map_err(|e| ApiError::BadRequest(e.to_string()))?;
        let context_id = env.action_id.to_hex();

        info!(
            event = "action_attempted",
            hub = "fin",
            action_kind = %fin_action_kind(&env.action),
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
                            hub = "fin",
                            action_kind = %fin_action_kind(&env.action),
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
            hub = "fin",
            action_kind = %fin_action_kind(&env.action),
            action_id = %context_id,
            outcome = ?local.outcome
        );

        // 2) Wrap into L1 contract envelope (single-item batch)
        let payload: HubPayloadEnvelopeV1 = (&env).into();
        let batch_id = format!("fin-action-{}", env.action_id.to_hex());
        let batch = L2BatchEnvelopeV1::new(
            l2_core::L2HubId::Fin,
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
            hub = "fin",
            action_kind = %fin_action_kind(&env.action),
            action_id = %context_id,
            accepted = submit.accepted,
            already_known = submit.already_known,
            l1_tx_id = submit.l1_tx_id.as_ref().map(|x| x.0.as_str()).unwrap_or("")
        );

        // 4) Persist action receipt (includes L1 submission result)
        let receipt =
            FinActionReceiptV1::from_parts(&env.action_id, &local, &batch_id, &batch, &submit);
        let receipt_path = self.persist_action_receipt(&receipt)?;

        // Also persist batch receipt (same format as CLI path) for operator parity.
        let _ = self.persist_batch_receipt(&batch, &submit);

        // Enqueue for reconciliation (restart-safe).
        if let Some(recon) = self.recon.as_ref() {
            let now = unix_now_secs();
            let meta = ReconMetadata::new(now);
            let _ = recon.enqueue(ReconKind::FinAction, &context_id, &meta);
        }

        Ok(SubmitActionResponseV1 {
            schema_version: 1,
            action_id: env.action_id.to_hex(),
            local_apply_outcome: local.outcome,
            asset_id: local.asset_id.map(|x| x.to_hex()),
            from_account: local.from_account.map(|x| x.0),
            to_account: local.to_account.map(|x| x.0),
            amount: local.amount.map(|x| x.0.to_string()),
            purchase_id: local.purchase_id.map(|x| x.to_hex()),
            batch_id,
            idempotency_key: b64url32(batch.idempotency_key.as_bytes()),
            l1_submit_result: submit,
            receipt_path: receipt_path.to_string_lossy().to_string(),
        })
    }

    pub fn get_asset(&self, asset_id_hex: &str) -> Result<Option<serde_json::Value>, ApiError> {
        let asset_id = Hex32::from_hex(asset_id_hex)
            .map_err(|e| ApiError::BadRequest(format!("invalid asset_id hex: {e}")))?;
        let asset = self
            .store
            .get_asset(asset_id)
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        Ok(asset.map(|a| serde_json::to_value(a).expect("serde value")))
    }

    pub fn get_balance(&self, asset_id_hex: &str, account: &str) -> Result<String, ApiError> {
        let asset_id = Hex32::from_hex(asset_id_hex)
            .map_err(|e| ApiError::BadRequest(format!("invalid asset_id hex: {e}")))?;
        let bal = self
            .store
            .get_balance(asset_id, account)
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        Ok(bal.0.to_string())
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
        // Fallback: read from disk if present.
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
    ) -> Result<Option<FinActionReceiptV1>, ApiError> {
        let raw = match self.get_receipt(action_id_hex)? {
            Some(r) => r,
            None => return Ok(None),
        };
        let v: FinActionReceiptV1 =
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
            .ok_or_else(|| ApiError::Internal("missing fin receipt".to_string()))?;
        r.submit_state = submit_state;
        let _ = self.persist_action_receipt(&r)?;
        Ok(())
    }

    pub fn persist_receipt_typed(&self, receipt: &FinActionReceiptV1) -> Result<(), ApiError> {
        let _ = self.persist_action_receipt(receipt)?;
        Ok(())
    }

    fn action_receipt_path(&self, action_id_hex: &str) -> PathBuf {
        self.receipts_dir
            .join("fin")
            .join("actions")
            .join(format!("{action_id_hex}.json"))
    }

    fn persist_action_receipt(&self, receipt: &FinActionReceiptV1) -> Result<PathBuf, ApiError> {
        let dir = self.receipts_dir.join("fin").join("actions");
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

    fn persist_batch_receipt(
        &self,
        env: &L2BatchEnvelopeV1,
        result: &L1SubmitResult,
    ) -> Result<(), ApiError> {
        // Keep same semantics as CLI receipts: receipts/<idempotency_key>.json
        fs::create_dir_all(&self.receipts_dir).map_err(|e| ApiError::Internal(e.to_string()))?;

        let canonical_hash = b64url32(
            &env.canonical_hash_blake3()
                .map_err(|e| ApiError::Internal(format!("canonical hash failed: {e}")))?,
        );
        let key = b64url32(env.idempotency_key.as_bytes());
        let submitted_at = time::OffsetDateTime::now_utc()
            .format(&Rfc3339)
            .unwrap_or_else(|_| "unknown".to_string());

        #[derive(Serialize)]
        struct SubmitReceipt<'a> {
            submitted_at: String,
            status: &'a str,
            contract_version: String,
            canonical_hash: String,
            idempotency_key: String,
            #[serde(skip_serializing_if = "Option::is_none")]
            l1_tx_id: Option<String>,
        }

        let status = if result.accepted {
            if result.already_known {
                "already_known"
            } else {
                "accepted"
            }
        } else {
            "rejected"
        };

        let receipt = SubmitReceipt {
            submitted_at,
            status,
            contract_version: env.contract_version.as_str().to_string(),
            canonical_hash,
            idempotency_key: key.clone(),
            l1_tx_id: result.l1_tx_id.as_ref().map(|x| x.0.clone()),
        };

        let out_path = self.receipts_dir.join(format!("{key}.json"));
        fs::write(&out_path, serde_json::to_vec_pretty(&receipt).unwrap())
            .map_err(|e| ApiError::Internal(e.to_string()))?;
        Ok(())
    }

    fn enforce_compliance(&self, action: &FinActionV1, context_id: &str) -> Result<(), ApiError> {
        if self.policy.compliance.strategy == crate::policy_runtime::ComplianceStrategy::None
            || !self.policy.compliance.enabled
        {
            return Ok(());
        }

        let mut accounts: Vec<l2_core::AccountId> = Vec::new();
        match action {
            FinActionV1::CreateAssetV1(a) => {
                let actor = a.actor.as_ref().unwrap_or(&a.issuer);
                accounts.push(actor.clone());
                accounts.push(a.issuer.clone());
            }
            FinActionV1::MintUnitsV1(a) => {
                self.policy
                    .require_actor_if_compliance_enabled(a.actor.as_ref())
                    .map_err(|s| policy_denied_from_str(&s, context_id))?;
                if let Some(actor) = a.actor.as_ref() {
                    accounts.push(actor.clone());
                }
                accounts.push(a.to_account.clone());
            }
            FinActionV1::TransferUnitsV1(a) => {
                let actor = a.actor.as_ref().unwrap_or(&a.from_account);
                accounts.push(actor.clone());
                accounts.push(a.from_account.clone());
                accounts.push(a.to_account.clone());
            }
        }

        // de-dup for predictable behaviour
        accounts.sort_by(|a, b| a.0.cmp(&b.0));
        accounts.dedup_by(|a, b| a.0 == b.0);

        self.policy
            .compliance_check_accounts(&accounts)
            .map_err(|s| {
                warn!(
                    event = "action_denied",
                    hub = "fin",
                    action_kind = %fin_action_kind(action),
                    action_id = %context_id,
                    reason = %s
                );
                policy_denied_from_str(&s, context_id)
            })
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
    fn from_apply_with_context(e: ApplyError, context_id: String) -> Self {
        match e {
            ApplyError::Validation(s) => ApiError::BadRequest(s),
            ApplyError::Rejected(s) => match parse_policy_error(&s, context_id.clone()) {
                Some(p) => ApiError::PolicyDenied(p),
                None => ApiError::BadRequest(s),
            },
            ApplyError::Store(s) => ApiError::Internal(s),
        }
    }
}

fn fin_action_kind(a: &FinActionV1) -> &'static str {
    match a {
        FinActionV1::CreateAssetV1(_) => "fin_create_asset",
        FinActionV1::MintUnitsV1(_) => "fin_mint_units",
        FinActionV1::TransferUnitsV1(_) => "fin_transfer_units",
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
pub struct SubmitActionResponseV1 {
    pub schema_version: u32,
    pub action_id: String,
    pub local_apply_outcome: ApplyOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_account: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_account: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub purchase_id: Option<String>,
    pub batch_id: String,
    pub idempotency_key: String,
    pub l1_submit_result: L1SubmitResult,
    pub receipt_path: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FinActionReceiptV1 {
    pub schema_version: u32,
    pub action_id: String,
    pub local_apply_outcome: ApplyOutcome,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub asset_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_account: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_account: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub amount: Option<String>,
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

impl FinActionReceiptV1 {
    fn from_parts(
        action_id: &Hex32,
        local: &hub_fin::ApplyReceipt,
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
            asset_id: local.asset_id.map(|x| x.to_hex()),
            from_account: local.from_account.clone().map(|x| x.0),
            to_account: local.to_account.clone().map(|x| x.0),
            amount: local.amount.map(|x| x.0.to_string()),
            purchase_id: local.purchase_id.map(|x| x.to_hex()),
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
