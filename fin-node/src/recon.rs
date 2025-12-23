#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]
#![deny(clippy::float_cmp)]

use crate::data_api::DataApi;
use crate::fin_api::FinApi;
use crate::linkage::{ApiError as LinkageApiError, LinkageApi};
use crate::metrics;
use crate::recon_store::{ReconItem, ReconKind, ReconStore};
use base64::Engine as _;
use l2_core::finality::SubmitState;
use l2_core::hub_linkage::{
    EntitlementPolicy, LinkageOverallStatus, LinkageReceiptV1, LinkageStatus,
};
use l2_core::l1_contract::{IdempotencyKey, L1Client, L1ClientError, L1InclusionProof, L1TxId};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tracing::{info, warn};

#[derive(Debug, Clone)]
pub struct ReconLoopConfig {
    pub interval_secs: u64,
    pub batch_limit: usize,
    pub max_scan: usize,
    pub max_attempts: u32,
    pub base_delay_secs: u64,
    pub max_delay_secs: u64,
}

#[derive(Clone)]
pub struct Reconciler {
    l1: Arc<dyn L1Client + Send + Sync>,
    fin: FinApi,
    data: DataApi,
    linkage: LinkageApi,
    recon: ReconStore,
    cfg: ReconLoopConfig,
}

impl Reconciler {
    pub fn new(
        l1: Arc<dyn L1Client + Send + Sync>,
        fin: FinApi,
        data: DataApi,
        linkage: LinkageApi,
        recon: ReconStore,
        cfg: ReconLoopConfig,
    ) -> Self {
        Self {
            l1,
            fin,
            data,
            linkage,
            recon,
            cfg,
        }
    }

    pub fn tick(&self, now_secs: u64) {
        // Update gauges (bounded scan).
        if let Ok(counts) = self.recon.counts_by_kind(self.cfg.max_scan) {
            for (kind, count) in counts {
                metrics::RECON_PENDING_TOTAL
                    .with_label_values(&[kind.as_str()])
                    .set(i64::try_from(count).unwrap_or(i64::MAX));
            }
        }

        let due = match self
            .recon
            .fetch_due(now_secs, self.cfg.batch_limit, self.cfg.max_scan)
        {
            Ok(v) => v,
            Err(e) => {
                warn!(event = "recon_fetch_due_failed", error = %e);
                return;
            }
        };

        for item in due {
            self.process_item(now_secs, item);
        }
    }

    fn process_item(&self, now_secs: u64, item: ReconItem) {
        match item.kind {
            ReconKind::FinAction => self.process_fin_action(now_secs, item),
            ReconKind::DataAction => self.process_data_action(now_secs, item),
            ReconKind::LinkagePurchase => self.process_linkage_purchase(now_secs, item),
        }
    }

    fn process_fin_action(&self, now_secs: u64, item: ReconItem) {
        let action_id = item.id.clone();
        let mut receipt = match self.fin.get_receipt_typed(&action_id) {
            Ok(Some(r)) => r,
            Ok(None) => {
                let _ = self.recon.dequeue(item.kind, &action_id);
                return;
            }
            Err(e) => {
                self.reschedule_error(item, now_secs, &format!("read_receipt:{e}"));
                return;
            }
        };

        match advance_submit_state(
            &*self.l1,
            &receipt.submit_state,
            receipt.l1_submit_result.l1_tx_id.as_ref(),
        ) {
            AdvanceOutcome::NoChange => self.reschedule_ok(item, now_secs),
            AdvanceOutcome::Included {
                proof_hash,
                l1_tx_id,
            } => {
                receipt.submit_state = SubmitState::Included {
                    proof_hash,
                    l1_tx_id: Some(l1_tx_id.0.clone()),
                };
                if receipt.l1_submit_result.l1_tx_id.is_none() {
                    receipt.l1_submit_result.l1_tx_id = Some(l1_tx_id);
                }
                if let Err(e) = self.fin.persist_receipt_typed(&receipt) {
                    self.reschedule_error(item, now_secs, &format!("persist_receipt:{e}"));
                    return;
                }
                metrics::RECON_CHECKS_TOTAL
                    .with_label_values(&[item.kind.as_str(), "included"])
                    .inc();
                self.reschedule_ok(item, now_secs);
            }
            AdvanceOutcome::Finalized {
                proof_hash,
                l1_tx_id,
            } => {
                receipt.submit_state = SubmitState::Finalized {
                    proof_hash,
                    l1_tx_id: l1_tx_id.map(|x| x.0.clone()),
                };
                if let Err(e) = self.fin.persist_receipt_typed(&receipt) {
                    self.reschedule_error(item, now_secs, &format!("persist_receipt:{e}"));
                    return;
                }
                metrics::RECON_CHECKS_TOTAL
                    .with_label_values(&[item.kind.as_str(), "finalized"])
                    .inc();
                let _ = self.recon.dequeue(item.kind, &action_id);
            }
            AdvanceOutcome::TransientErr { code, message } => {
                metrics::RECON_FAILURES_TOTAL
                    .with_label_values(&[item.kind.as_str(), code.as_str()])
                    .inc();
                self.reschedule_error(item, now_secs, &message);
            }
            AdvanceOutcome::PermanentErr { code, message } => {
                metrics::RECON_FAILURES_TOTAL
                    .with_label_values(&[item.kind.as_str(), code.as_str()])
                    .inc();
                receipt.submit_state = SubmitState::Failed { error_code: code };
                let _ = self.fin.persist_receipt_typed(&receipt);
                let _ = self.recon.dequeue(item.kind, &action_id);
                warn!(event = "recon_permanent_error", kind = item.kind.as_str(), id = %action_id, error = %message);
            }
        }
    }

    fn process_data_action(&self, now_secs: u64, item: ReconItem) {
        let action_id = item.id.clone();
        let mut receipt = match self.data.get_receipt_typed(&action_id) {
            Ok(Some(r)) => r,
            Ok(None) => {
                let _ = self.recon.dequeue(item.kind, &action_id);
                return;
            }
            Err(e) => {
                self.reschedule_error(item, now_secs, &format!("read_receipt:{e}"));
                return;
            }
        };

        match advance_submit_state(
            &*self.l1,
            &receipt.submit_state,
            receipt.l1_submit_result.l1_tx_id.as_ref(),
        ) {
            AdvanceOutcome::NoChange => self.reschedule_ok(item, now_secs),
            AdvanceOutcome::Included {
                proof_hash,
                l1_tx_id,
            } => {
                receipt.submit_state = SubmitState::Included {
                    proof_hash,
                    l1_tx_id: Some(l1_tx_id.0.clone()),
                };
                if receipt.l1_submit_result.l1_tx_id.is_none() {
                    receipt.l1_submit_result.l1_tx_id = Some(l1_tx_id);
                }
                if let Err(e) = self.data.persist_receipt_typed(&receipt) {
                    self.reschedule_error(item, now_secs, &format!("persist_receipt:{e}"));
                    return;
                }
                metrics::RECON_CHECKS_TOTAL
                    .with_label_values(&[item.kind.as_str(), "included"])
                    .inc();
                self.reschedule_ok(item, now_secs);
            }
            AdvanceOutcome::Finalized {
                proof_hash,
                l1_tx_id,
            } => {
                receipt.submit_state = SubmitState::Finalized {
                    proof_hash,
                    l1_tx_id: l1_tx_id.map(|x| x.0.clone()),
                };
                if let Err(e) = self.data.persist_receipt_typed(&receipt) {
                    self.reschedule_error(item, now_secs, &format!("persist_receipt:{e}"));
                    return;
                }
                metrics::RECON_CHECKS_TOTAL
                    .with_label_values(&[item.kind.as_str(), "finalized"])
                    .inc();
                let _ = self.recon.dequeue(item.kind, &action_id);
            }
            AdvanceOutcome::TransientErr { code, message } => {
                metrics::RECON_FAILURES_TOTAL
                    .with_label_values(&[item.kind.as_str(), code.as_str()])
                    .inc();
                self.reschedule_error(item, now_secs, &message);
            }
            AdvanceOutcome::PermanentErr { code, message } => {
                metrics::RECON_FAILURES_TOTAL
                    .with_label_values(&[item.kind.as_str(), code.as_str()])
                    .inc();
                receipt.submit_state = SubmitState::Failed { error_code: code };
                let _ = self.data.persist_receipt_typed(&receipt);
                let _ = self.recon.dequeue(item.kind, &action_id);
                warn!(event = "recon_permanent_error", kind = item.kind.as_str(), id = %action_id, error = %message);
            }
        }
    }

    fn process_linkage_purchase(&self, now_secs: u64, item: ReconItem) {
        let purchase_id_hex = item.id.clone();
        let mut receipt = match self.linkage.get_purchase_receipt(&purchase_id_hex) {
            Ok(Some(r)) => r,
            Ok(None) => {
                let _ = self.recon.dequeue(item.kind, &purchase_id_hex);
                return;
            }
            Err(e) => {
                self.reschedule_error(item, now_secs, &format!("read_receipt:{e}"));
                return;
            }
        };

        // Only the finality-required policy needs reconciliation to progress workflow.
        if receipt.policy != EntitlementPolicy::FinalityRequired {
            let _ = self.recon.dequeue(item.kind, &purchase_id_hex);
            return;
        }

        // Normalize older receipts that might still use the legacy status only.
        if receipt.overall_status == LinkageOverallStatus::Created
            && receipt.payment_ref.is_some()
            && receipt.entitlement_ref.is_none()
        {
            receipt.overall_status = LinkageOverallStatus::PaymentPendingFinality;
            receipt.status = LinkageStatus::Paid;
        }

        // 1) Payment finality tracking.
        if matches!(
            receipt.overall_status,
            LinkageOverallStatus::PaymentPendingFinality | LinkageOverallStatus::FailedRecoverable
        ) && receipt.entitlement_ref.is_none()
        {
            match advance_submit_state_for_linkage(&*self.l1, &receipt.payment_submit_state) {
                AdvanceOutcome::NoChange => {
                    let _ = self.linkage.persist_purchase_receipt(&receipt);
                    self.reschedule_ok(item, now_secs);
                    return;
                }
                AdvanceOutcome::Included {
                    proof_hash,
                    l1_tx_id,
                } => {
                    receipt.payment_submit_state = SubmitState::Included {
                        proof_hash,
                        l1_tx_id: Some(l1_tx_id.0.clone()),
                    };
                    receipt.last_error = None;
                    let _ = self.linkage.persist_purchase_receipt(&receipt);
                    metrics::RECON_CHECKS_TOTAL
                        .with_label_values(&[item.kind.as_str(), "included"])
                        .inc();
                    self.reschedule_ok(item, now_secs);
                    return;
                }
                AdvanceOutcome::Finalized {
                    proof_hash,
                    l1_tx_id,
                } => {
                    receipt.payment_submit_state = SubmitState::Finalized {
                        proof_hash,
                        l1_tx_id: l1_tx_id.map(|x| x.0.clone()),
                    };
                    receipt.overall_status = LinkageOverallStatus::PaidFinal;
                    receipt.status = LinkageStatus::Paid;
                    receipt.last_error = None;
                    if let Err(e) = self.linkage.persist_purchase_receipt(&receipt) {
                        self.reschedule_error(item, now_secs, &format!("persist_receipt:{e}"));
                        return;
                    }
                    metrics::RECON_CHECKS_TOTAL
                        .with_label_values(&[item.kind.as_str(), "finalized"])
                        .inc();
                    // Continue workflow: grant entitlement (DATA) and enqueue again.
                    if receipt.entitlement_ref.is_none() {
                        match self.continue_entitlement(&mut receipt) {
                            Ok(()) => {
                                let _ = self.linkage.persist_purchase_receipt(&receipt);
                                self.reschedule_ok(item, now_secs);
                            }
                            Err(e) => {
                                receipt.overall_status = LinkageOverallStatus::FailedRecoverable;
                                receipt.status = LinkageStatus::FailedRecoverable;
                                receipt.last_error = Some(sanitize_error(&e.to_string()));
                                let _ = self.linkage.persist_purchase_receipt(&receipt);
                                self.reschedule_error(
                                    item,
                                    now_secs,
                                    &format!("continue_entitlement:{e}"),
                                );
                            }
                        }
                        return;
                    }
                    // No entitlement to continue; fall through to entitlement tracking.
                }
                AdvanceOutcome::TransientErr { code, message } => {
                    metrics::RECON_FAILURES_TOTAL
                        .with_label_values(&[item.kind.as_str(), code.as_str()])
                        .inc();
                    receipt.overall_status = LinkageOverallStatus::FailedRecoverable;
                    receipt.status = LinkageStatus::FailedRecoverable;
                    receipt.last_error = Some(sanitize_error(&message));
                    let _ = self.linkage.persist_purchase_receipt(&receipt);
                    self.reschedule_error(item, now_secs, &message);
                    return;
                }
                AdvanceOutcome::PermanentErr { code, message } => {
                    metrics::RECON_FAILURES_TOTAL
                        .with_label_values(&[item.kind.as_str(), code.as_str()])
                        .inc();
                    receipt.overall_status = LinkageOverallStatus::FailedRecoverable;
                    receipt.status = LinkageStatus::FailedRecoverable;
                    receipt.payment_submit_state = SubmitState::Failed { error_code: code };
                    receipt.last_error = Some(sanitize_error(&message));
                    let _ = self.linkage.persist_purchase_receipt(&receipt);
                    let _ = self.recon.dequeue(item.kind, &purchase_id_hex);
                    warn!(event = "recon_permanent_error", kind = item.kind.as_str(), id = %purchase_id_hex, error = %message);
                    return;
                }
            }
        }

        // 2) Entitlement finality tracking.
        if receipt.entitlement_ref.is_none()
            && matches!(receipt.overall_status, LinkageOverallStatus::PaidFinal)
        {
            // PaidFinal but entitlement missing; try to continue (resume-safe).
            match self.continue_entitlement(&mut receipt) {
                Ok(()) => {
                    let _ = self.linkage.persist_purchase_receipt(&receipt);
                    self.reschedule_ok(item, now_secs);
                }
                Err(e) => {
                    receipt.overall_status = LinkageOverallStatus::FailedRecoverable;
                    receipt.status = LinkageStatus::FailedRecoverable;
                    receipt.last_error = Some(sanitize_error(&e.to_string()));
                    let _ = self.linkage.persist_purchase_receipt(&receipt);
                    self.reschedule_error(item, now_secs, &format!("continue_entitlement:{e}"));
                }
            }
            return;
        }

        if matches!(
            receipt.overall_status,
            LinkageOverallStatus::EntitlementPendingFinality
                | LinkageOverallStatus::FailedRecoverable
        ) && receipt.entitlement_ref.is_some()
        {
            match advance_submit_state_for_linkage(&*self.l1, &receipt.entitlement_submit_state) {
                AdvanceOutcome::NoChange => {
                    let _ = self.linkage.persist_purchase_receipt(&receipt);
                    self.reschedule_ok(item, now_secs);
                }
                AdvanceOutcome::Included {
                    proof_hash,
                    l1_tx_id,
                } => {
                    receipt.entitlement_submit_state = SubmitState::Included {
                        proof_hash,
                        l1_tx_id: Some(l1_tx_id.0.clone()),
                    };
                    receipt.last_error = None;
                    let _ = self.linkage.persist_purchase_receipt(&receipt);
                    metrics::RECON_CHECKS_TOTAL
                        .with_label_values(&[item.kind.as_str(), "included"])
                        .inc();
                    self.reschedule_ok(item, now_secs);
                }
                AdvanceOutcome::Finalized {
                    proof_hash,
                    l1_tx_id,
                } => {
                    receipt.entitlement_submit_state = SubmitState::Finalized {
                        proof_hash,
                        l1_tx_id: l1_tx_id.map(|x| x.0.clone()),
                    };
                    receipt.overall_status = LinkageOverallStatus::EntitledFinal;
                    receipt.status = LinkageStatus::Entitled;
                    receipt.last_error = None;
                    let _ = self.linkage.persist_purchase_receipt(&receipt);
                    metrics::RECON_CHECKS_TOTAL
                        .with_label_values(&[item.kind.as_str(), "finalized"])
                        .inc();
                    let _ = self.recon.dequeue(item.kind, &purchase_id_hex);
                }
                AdvanceOutcome::TransientErr { code, message } => {
                    metrics::RECON_FAILURES_TOTAL
                        .with_label_values(&[item.kind.as_str(), code.as_str()])
                        .inc();
                    receipt.overall_status = LinkageOverallStatus::FailedRecoverable;
                    receipt.status = LinkageStatus::FailedRecoverable;
                    receipt.last_error = Some(sanitize_error(&message));
                    let _ = self.linkage.persist_purchase_receipt(&receipt);
                    self.reschedule_error(item, now_secs, &message);
                }
                AdvanceOutcome::PermanentErr { code, message } => {
                    metrics::RECON_FAILURES_TOTAL
                        .with_label_values(&[item.kind.as_str(), code.as_str()])
                        .inc();
                    receipt.overall_status = LinkageOverallStatus::FailedRecoverable;
                    receipt.status = LinkageStatus::FailedRecoverable;
                    receipt.entitlement_submit_state = SubmitState::Failed { error_code: code };
                    receipt.last_error = Some(sanitize_error(&message));
                    let _ = self.linkage.persist_purchase_receipt(&receipt);
                    let _ = self.recon.dequeue(item.kind, &purchase_id_hex);
                    warn!(event = "recon_permanent_error", kind = item.kind.as_str(), id = %purchase_id_hex, error = %message);
                }
            }
            return;
        }

        // Nothing actionable; avoid hot-looping.
        self.reschedule_ok(item, now_secs);
    }

    fn continue_entitlement(&self, receipt: &mut LinkageReceiptV1) -> Result<(), LinkageApiError> {
        // Load listing by id and grant entitlement using existing LinkageApi logic.
        let (ent_ref, submit_state) = self.linkage.submit_entitlement_for_receipt(receipt)?;

        receipt.entitlement_ref = Some(ent_ref);
        receipt.entitlement_submit_state = submit_state;
        receipt.overall_status = LinkageOverallStatus::EntitlementPendingFinality;
        receipt.status = LinkageStatus::Paid;
        receipt.last_error = None;

        Ok(())
    }

    fn reschedule_ok(&self, mut item: ReconItem, now_secs: u64) {
        item.meta.next_check_at = now_secs.saturating_add(self.cfg.interval_secs);
        item.meta.last_error.clear();
        let _ = self.recon.update(item.kind, &item.id, &item.meta);
        metrics::RECON_CHECKS_TOTAL
            .with_label_values(&[item.kind.as_str(), "checked"])
            .inc();
    }

    fn reschedule_error(&self, mut item: ReconItem, now_secs: u64, message: &str) {
        item.meta.attempts = item.meta.attempts.saturating_add(1);
        item.meta.last_error = sanitize_error(message);
        if item.meta.attempts >= self.cfg.max_attempts {
            // Dequeue; the receipt has already been marked failed by the caller where applicable.
            let _ = self.recon.dequeue(item.kind, &item.id);
            warn!(
                event = "recon_max_attempts",
                kind = item.kind.as_str(),
                id = %item.id,
                attempts = item.meta.attempts
            );
            return;
        }
        let delay = backoff_secs(
            self.cfg.base_delay_secs,
            self.cfg.max_delay_secs,
            item.meta.attempts,
        );
        item.meta.next_check_at = now_secs.saturating_add(delay);
        let _ = self.recon.update(item.kind, &item.id, &item.meta);
    }
}

#[derive(Clone)]
pub struct ReconLoop {
    reconciler: Reconciler,
    interval_secs: u64,
}

impl ReconLoop {
    pub fn new(reconciler: Reconciler, interval_secs: u64) -> Self {
        Self {
            reconciler,
            interval_secs: interval_secs.max(1),
        }
    }

    pub fn start(self, stop: Arc<AtomicBool>) -> std::thread::JoinHandle<()> {
        std::thread::spawn(move || {
            info!(
                event = "recon_loop_started",
                interval_secs = self.interval_secs
            );
            let interval = std::time::Duration::from_secs(self.interval_secs);
            while !stop.load(Ordering::Relaxed) {
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                self.reconciler.tick(now);
                // Sleep in small chunks so shutdown/step-down is responsive.
                let mut slept = std::time::Duration::from_secs(0);
                while slept < interval && !stop.load(Ordering::Relaxed) {
                    let step = std::time::Duration::from_millis(250);
                    std::thread::sleep(step);
                    slept += step;
                }
            }
            info!(event = "recon_loop_stopped");
        })
    }
}

#[derive(Debug)]
enum AdvanceOutcome {
    NoChange,
    Included {
        proof_hash: String,
        l1_tx_id: L1TxId,
    },
    Finalized {
        proof_hash: String,
        l1_tx_id: Option<L1TxId>,
    },
    TransientErr {
        code: String,
        message: String,
    },
    PermanentErr {
        code: String,
        message: String,
    },
}

fn advance_submit_state(
    l1: &dyn L1Client,
    state: &SubmitState,
    l1_tx_id: Option<&L1TxId>,
) -> AdvanceOutcome {
    match state {
        SubmitState::Submitted {
            idempotency_key,
            l1_tx_id: _state_tx,
        } => {
            let key = match parse_idempotency_key(idempotency_key) {
                Ok(k) => k,
                Err(e) => {
                    return AdvanceOutcome::PermanentErr {
                        code: "bad_idempotency_key".to_string(),
                        message: e,
                    }
                }
            };
            match l1.get_inclusion(&key) {
                Ok(None) => AdvanceOutcome::NoChange,
                Ok(Some(p)) => AdvanceOutcome::Included {
                    proof_hash: proof_hash(&p),
                    l1_tx_id: p.l1_tx_id,
                },
                Err(e) => classify_l1_error("get_inclusion", &e),
            }
        }
        SubmitState::Included {
            l1_tx_id: state_tx, ..
        } => {
            let tx = match state_tx.as_deref().map(|s| L1TxId(s.to_string())) {
                Some(x) => x,
                None => match l1_tx_id.cloned() {
                    Some(x) => x,
                    None => {
                        return AdvanceOutcome::TransientErr {
                            code: "missing_l1_tx_id".to_string(),
                            message: "missing l1_tx_id for finality check".to_string(),
                        };
                    }
                },
            };
            match l1.get_finality(&tx) {
                Ok(None) => AdvanceOutcome::NoChange,
                Ok(Some(p)) => AdvanceOutcome::Finalized {
                    proof_hash: proof_hash(&p),
                    l1_tx_id: Some(p.l1_tx_id),
                },
                Err(e) => classify_l1_error("get_finality", &e),
            }
        }
        SubmitState::Finalized {
            proof_hash,
            l1_tx_id,
        } => AdvanceOutcome::Finalized {
            proof_hash: proof_hash.clone(),
            l1_tx_id: l1_tx_id.as_deref().map(|s| L1TxId(s.to_string())),
        },
        SubmitState::Failed { error_code } => AdvanceOutcome::PermanentErr {
            code: error_code.clone(),
            message: "already_failed".to_string(),
        },
        SubmitState::NotSubmitted => AdvanceOutcome::PermanentErr {
            code: "not_submitted".to_string(),
            message: "cannot reconcile NotSubmitted".to_string(),
        },
    }
}

fn advance_submit_state_for_linkage(l1: &dyn L1Client, state: &SubmitState) -> AdvanceOutcome {
    match state {
        SubmitState::Submitted {
            idempotency_key,
            l1_tx_id: _,
        } => {
            let key = match parse_idempotency_key(idempotency_key) {
                Ok(k) => k,
                Err(e) => {
                    return AdvanceOutcome::PermanentErr {
                        code: "bad_idempotency_key".to_string(),
                        message: e,
                    };
                }
            };
            match l1.get_inclusion(&key) {
                Ok(None) => AdvanceOutcome::NoChange,
                Ok(Some(p)) => AdvanceOutcome::Included {
                    proof_hash: proof_hash(&p),
                    l1_tx_id: p.l1_tx_id,
                },
                Err(e) => classify_l1_error("get_inclusion", &e),
            }
        }
        SubmitState::Included { l1_tx_id, .. } => {
            let Some(tx) = l1_tx_id.as_deref().map(|s| L1TxId(s.to_string())) else {
                return AdvanceOutcome::TransientErr {
                    code: "missing_l1_tx_id".to_string(),
                    message: "missing l1_tx_id for finality check".to_string(),
                };
            };
            match l1.get_finality(&tx) {
                Ok(None) => AdvanceOutcome::NoChange,
                Ok(Some(p)) => AdvanceOutcome::Finalized {
                    proof_hash: proof_hash(&p),
                    l1_tx_id: Some(p.l1_tx_id),
                },
                Err(e) => classify_l1_error("get_finality", &e),
            }
        }
        SubmitState::Finalized {
            proof_hash,
            l1_tx_id,
        } => AdvanceOutcome::Finalized {
            proof_hash: proof_hash.clone(),
            l1_tx_id: l1_tx_id.as_deref().map(|s| L1TxId(s.to_string())),
        },
        SubmitState::Failed { error_code } => AdvanceOutcome::PermanentErr {
            code: error_code.clone(),
            message: "already_failed".to_string(),
        },
        SubmitState::NotSubmitted => AdvanceOutcome::PermanentErr {
            code: "not_submitted".to_string(),
            message: "cannot reconcile NotSubmitted".to_string(),
        },
    }
}

fn parse_idempotency_key(s: &str) -> Result<IdempotencyKey, String> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(s.as_bytes())
        .map_err(|e| format!("invalid base64url idempotency_key: {e}"))?;
    if bytes.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", bytes.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(IdempotencyKey(out))
}

fn proof_hash(p: &L1InclusionProof) -> String {
    let h = blake3::hash(&p.proof.0);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(h.as_bytes())
}

fn classify_l1_error(method: &'static str, e: &L1ClientError) -> AdvanceOutcome {
    let code = match e {
        L1ClientError::EndpointMissing(_) => "endpoint_missing",
        L1ClientError::Config(_) => "config",
        L1ClientError::DecodeError(_) => "decode_error",
        L1ClientError::Timeout => "timeout",
        L1ClientError::RetryExhausted { .. } => "retry_exhausted",
        L1ClientError::Network(_) => "network",
        L1ClientError::HttpStatus(code) => {
            if is_transient_http_status(*code) {
                "http_transient"
            } else {
                "http_permanent"
            }
        }
    }
    .to_string();

    let msg = format!("{method}:{e}");

    match e {
        L1ClientError::EndpointMissing(_)
        | L1ClientError::Config(_)
        | L1ClientError::DecodeError(_) => AdvanceOutcome::PermanentErr { code, message: msg },
        L1ClientError::HttpStatus(code_num) => {
            if is_transient_http_status(*code_num) {
                AdvanceOutcome::TransientErr { code, message: msg }
            } else {
                AdvanceOutcome::PermanentErr { code, message: msg }
            }
        }
        L1ClientError::Timeout
        | L1ClientError::RetryExhausted { .. }
        | L1ClientError::Network(_) => AdvanceOutcome::TransientErr { code, message: msg },
    }
}

fn is_transient_http_status(code: u16) -> bool {
    matches!(code, 408 | 425 | 429) || (500..=599).contains(&code)
}

fn backoff_secs(base: u64, max: u64, attempts: u32) -> u64 {
    // attempts starts at 1.
    let pow = attempts.saturating_sub(1);
    let mut delay = base;
    // cap exponentiation to avoid overflow shifts
    let shift = u32::min(pow, 20);
    let factor = 1u64.checked_shl(shift).unwrap_or(u64::MAX);
    delay = delay.saturating_mul(factor);
    if delay > max {
        max
    } else {
        delay
    }
}

fn sanitize_error(s: &str) -> String {
    let mut out = s.replace(['\n', '\r', '\t'], " ");
    out = out.trim().to_string();
    const MAX: usize = 256;
    if out.len() > MAX {
        out.truncate(MAX);
    }
    out
}
