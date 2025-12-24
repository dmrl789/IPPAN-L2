#![forbid(unsafe_code)]

use crate::audit_store::{AuditStore, EventRecordV1};
use hub_data::DataEnvelopeV1;
use hub_fin::FinEnvelopeV1;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("io error: {0}")]
    Io(String),
    #[error("audit store error: {0}")]
    Store(String),
    #[error("invalid bundle: {0}")]
    InvalidBundle(String),
    #[error("serde error: {0}")]
    Serde(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestFileV1 {
    pub path: String,
    pub blake3: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExportScopeV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub from_epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub to_epoch: Option<u64>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hubs: Vec<String>,
    #[serde(default)]
    pub subjects: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditManifestV1 {
    pub audit_bundle_version: u32,
    pub ippan_l2_version: String,
    pub exported_at: u64,
    pub export_scope: ExportScopeV1,
    pub files: Vec<ManifestFileV1>,
    pub root_hash: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub optional_operator_signature: Option<OperatorSignatureV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorSignatureV1 {
    pub pubkey: String,
    pub sig: String,
}

#[derive(Debug, Clone)]
pub struct AuditExportOptions {
    pub out: PathBuf,
    pub from_epoch: Option<u64>,
    pub to_epoch: Option<u64>,
    pub hubs: BTreeSet<String>,
    pub dataset_id: Option<String>,
    pub asset_id: Option<String>,
    pub account: Option<String>,
    pub include_proofs: bool,
    pub include_envelopes: bool,
}

#[derive(Debug, Clone)]
pub struct AuditReplayOptions {
    pub from: PathBuf,
    pub verify: bool,
}

pub fn export_audit_bundle_v1(
    audit_db_dir: &str,
    fin_db_dir: &str,
    data_db_dir: &str,
    receipts_dir: &str,
    opt: AuditExportOptions,
) -> Result<(), AuditError> {
    let audit = AuditStore::open(audit_db_dir).map_err(|e| AuditError::Store(e.to_string()))?;
    let receipts_dir = PathBuf::from(receipts_dir);

    let events = audit
        .iter_events_filtered(
            opt.from_epoch,
            opt.to_epoch,
            &opt.hubs,
            opt.dataset_id.as_deref(),
            opt.asset_id.as_deref(),
            opt.account.as_deref(),
        )
        .map_err(|e| AuditError::Store(e.to_string()))?;

    let max_occurred = events
        .iter()
        .map(|e| e.occurred_at_unix_secs)
        .max()
        .unwrap_or(0);

    let tmp = tempfile::tempdir().map_err(|e| AuditError::Io(e.to_string()))?;
    let root = tmp.path();

    // 1) Indexes: events.jsonl
    write_events_index(root, &events)?;

    // 2) Envelopes + receipts (dedup by path/action_id)
    let mut wrote_envelopes: HashSet<(String, String)> = HashSet::new();
    let mut wrote_receipts: HashSet<String> = HashSet::new();
    let mut receipts_for_proofs: Vec<(String, serde_json::Value)> = Vec::new();

    for e in &events {
        if opt.include_envelopes {
            if let (Some(action_id), hub) = (e.action_id.as_ref(), e.hub.as_str()) {
                if hub == "fin" || hub == "data" {
                    let key = (hub.to_string(), action_id.clone());
                    if !wrote_envelopes.contains(&key) {
                        let bytes = audit
                            .get_envelope(hub, action_id)
                            .map_err(|er| AuditError::Store(er.to_string()))?
                            .ok_or_else(|| {
                                AuditError::InvalidBundle(format!(
                                    "missing canonical envelope in audit store: hub={hub} action_id={action_id}"
                                ))
                            })?;
                        let out_path = root
                            .join("envelopes")
                            .join(hub)
                            .join(format!("{action_id}.json"));
                        write_file(&out_path, &bytes)?;
                        wrote_envelopes.insert(key);
                    }
                }
            }
        }

        if let Some(ref_path) = e.receipt_ref.as_ref() {
            if wrote_receipts.contains(ref_path) {
                continue;
            }
            // Bundle path is `receipts/...`; map to on-disk receipts root.
            let disk_rel = ref_path.strip_prefix("receipts/").unwrap_or(ref_path);
            let disk_path = receipts_dir.join(disk_rel);
            let raw = fs::read(&disk_path).map_err(|e| {
                AuditError::Io(format!(
                    "failed reading receipt {}: {e}",
                    disk_path.display()
                ))
            })?;
            let v: serde_json::Value =
                serde_json::from_slice(&raw).map_err(|e| AuditError::Serde(e.to_string()))?;

            let out_path = root.join(ref_path);
            write_file(&out_path, &raw)?;
            wrote_receipts.insert(ref_path.clone());

            receipts_for_proofs.push((ref_path.clone(), v));
        }
    }

    // 3) actions.csv (summary)
    write_actions_index(root, &events)?;

    // 4) state hashes (optional cross-check)
    write_state_hashes(root, fin_db_dir, data_db_dir)?;

    // 5) proof refs
    if opt.include_proofs {
        write_proof_refs(root, &receipts_for_proofs)?;
    }

    // 6) report bundle
    write_report(root, &events, opt.include_envelopes)?;

    // 7) manifest + tar
    let scope = ExportScopeV1 {
        from_epoch: opt.from_epoch,
        to_epoch: opt.to_epoch,
        hubs: opt.hubs.iter().cloned().collect(),
        subjects: serde_json::json!({
            "dataset_id": opt.dataset_id,
            "asset_id": opt.asset_id,
            "account": opt.account,
            "include_proofs": opt.include_proofs,
            "include_envelopes": opt.include_envelopes
        }),
    };

    let (files, root_hash) = build_file_manifest(root)?;
    let manifest = AuditManifestV1 {
        audit_bundle_version: 1,
        ippan_l2_version: env!("CARGO_PKG_VERSION").to_string(),
        exported_at: max_occurred,
        export_scope: scope,
        files,
        root_hash,
        optional_operator_signature: None,
    };
    let manifest_bytes =
        serde_json::to_vec_pretty(&manifest).map_err(|e| AuditError::Serde(e.to_string()))?;
    write_file(&root.join("manifest.json"), &manifest_bytes)?;

    // Build tar deterministically (sorted paths, normalized headers).
    build_deterministic_tar(root, &opt.out)?;

    Ok(())
}

pub fn replay_audit_bundle_v1(opt: AuditReplayOptions) -> Result<(), AuditError> {
    let tmp = tempfile::tempdir().map_err(|e| AuditError::Io(e.to_string()))?;
    let root = tmp.path();

    extract_tar(&opt.from, root)?;
    let manifest_path = root.join("manifest.json");
    let manifest_raw = fs::read(&manifest_path).map_err(|e| AuditError::Io(e.to_string()))?;
    let manifest: AuditManifestV1 =
        serde_json::from_slice(&manifest_raw).map_err(|e| AuditError::Serde(e.to_string()))?;

    if opt.verify {
        verify_manifest(root, &manifest)?;
        verify_root_hash(&manifest)?;
        verify_operator_signature_if_present(&manifest)?;
    }

    // Reconstruct hub state by applying envelopes in seq order (idempotent).
    let events = read_events_index(root)?;

    let fin_db = root.join("_replay").join("fin_db");
    let data_db = root.join("_replay").join("data_db");
    fs::create_dir_all(fin_db.parent().unwrap()).map_err(|e| AuditError::Io(e.to_string()))?;

    let fin_store = hub_fin::FinStore::open(&fin_db).map_err(|e| AuditError::Io(e.to_string()))?;
    let data_store =
        hub_data::DataStore::open(&data_db).map_err(|e| AuditError::Io(e.to_string()))?;

    let mut applied: HashSet<(String, String)> = HashSet::new();
    for e in &events {
        let Some(action_id) = e.action_id.as_ref() else {
            continue;
        };
        if e.hub != "fin" && e.hub != "data" {
            continue;
        }
        let key = (e.hub.clone(), action_id.clone());
        if applied.contains(&key) {
            continue;
        }
        let env_path = root
            .join("envelopes")
            .join(&e.hub)
            .join(format!("{action_id}.json"));
        if !env_path.exists() {
            // If envelopes weren't included, replay can't proceed.
            return Err(AuditError::InvalidBundle(format!(
                "missing envelope file for replay: {}",
                env_path.display()
            )));
        }
        let bytes = fs::read(&env_path).map_err(|e| AuditError::Io(e.to_string()))?;
        let hash_hex = hex::encode(blake3::hash(&bytes).as_bytes());
        if opt.verify {
            if let Some(expected) = e.envelope_hash.as_ref() {
                if expected != &hash_hex {
                    return Err(AuditError::InvalidBundle(format!(
                        "envelope hash mismatch for {} {}: expected {expected}, got {hash_hex}",
                        e.hub, action_id
                    )));
                }
            }
        }

        match e.hub.as_str() {
            "fin" => {
                let env: FinEnvelopeV1 =
                    serde_json::from_slice(&bytes).map_err(|e| AuditError::Serde(e.to_string()))?;
                let _ = hub_fin::apply::apply(&env, &fin_store)
                    .map_err(|e| AuditError::InvalidBundle(format!("fin apply failed: {e}")))?;
            }
            "data" => {
                let env: DataEnvelopeV1 =
                    serde_json::from_slice(&bytes).map_err(|e| AuditError::Serde(e.to_string()))?;
                let _ = hub_data::apply::apply(&env, &data_store)
                    .map_err(|e| AuditError::InvalidBundle(format!("data apply failed: {e}")))?;
            }
            _ => {}
        }

        applied.insert(key);
    }

    // Rehydrate node-level "final receipt" keys into hub stores (so state hashes match exports).
    //
    // These receipts are not part of hub consensus state, but they *are* stored in the sled trees
    // that `export_kv_v1` hashes.
    replay_put_final_receipts(root, &fin_store, &data_store)?;

    // Optional state hash check
    if opt.verify {
        let state_hashes_path = root.join("indexes").join("state_hashes.json");
        if state_hashes_path.exists() {
            let raw = fs::read(&state_hashes_path).map_err(|e| AuditError::Io(e.to_string()))?;
            let expected: BTreeMap<String, String> =
                serde_json::from_slice(&raw).map_err(|e| AuditError::Serde(e.to_string()))?;
            let got = compute_state_hashes(&fin_store, &data_store)?;
            for (k, expected_hash) in expected {
                if let Some(got_hash) = got.get(&k) {
                    if got_hash != &expected_hash {
                        return Err(AuditError::InvalidBundle(format!(
                            "state hash mismatch for {k}: expected {expected_hash}, got {got_hash}"
                        )));
                    }
                }
            }
        }
    }

    Ok(())
}

fn replay_put_final_receipts(
    bundle_root: &Path,
    fin: &hub_fin::FinStore,
    data: &hub_data::DataStore,
) -> Result<(), AuditError> {
    // FIN receipts: receipts/fin/actions/<action_id>.json
    let fin_dir = bundle_root.join("receipts").join("fin").join("actions");
    if fin_dir.exists() {
        for p in sorted_dir_files(&fin_dir)? {
            if p.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let raw = fs::read(&p).map_err(|e| AuditError::Io(e.to_string()))?;
            let v: serde_json::Value =
                serde_json::from_slice(&raw).map_err(|e| AuditError::Serde(e.to_string()))?;
            let id = v
                .get("action_id")
                .and_then(|x| x.as_str())
                .ok_or_else(|| AuditError::InvalidBundle("fin receipt missing action_id".into()))?;
            let action_id = hub_fin::Hex32::from_hex(id)
                .map_err(|e| AuditError::InvalidBundle(format!("invalid fin action_id: {e}")))?;
            fin.put_final_receipt(action_id, &raw)
                .map_err(|e| AuditError::Io(e.to_string()))?;
        }
    }

    // DATA receipts: receipts/data/<action_id>.json
    let data_dir = bundle_root.join("receipts").join("data");
    if data_dir.exists() {
        for p in sorted_dir_files(&data_dir)? {
            if p.extension().and_then(|s| s.to_str()) != Some("json") {
                continue;
            }
            let raw = fs::read(&p).map_err(|e| AuditError::Io(e.to_string()))?;
            let v: serde_json::Value =
                serde_json::from_slice(&raw).map_err(|e| AuditError::Serde(e.to_string()))?;
            let id = v.get("action_id").and_then(|x| x.as_str()).ok_or_else(|| {
                AuditError::InvalidBundle("data receipt missing action_id".into())
            })?;
            let action_id = hub_data::Hex32::from_hex(id)
                .map_err(|e| AuditError::InvalidBundle(format!("invalid data action_id: {e}")))?;
            data.put_final_receipt(action_id, &raw)
                .map_err(|e| AuditError::Io(e.to_string()))?;
        }
    }

    Ok(())
}

pub fn sign_audit_bundle_v1(bundle_path: &Path, key_path: &Path) -> Result<(), AuditError> {
    // Feature-gated signing; implemented only when the workspace enables bootstrap-signing.
    #[cfg(feature = "bootstrap-signing")]
    {
        use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};

        let tmp = tempfile::tempdir().map_err(|e| AuditError::Io(e.to_string()))?;
        let root = tmp.path();
        extract_tar(bundle_path, root)?;

        let manifest_path = root.join("manifest.json");
        let raw = fs::read(&manifest_path).map_err(|e| AuditError::Io(e.to_string()))?;
        let mut manifest: AuditManifestV1 =
            serde_json::from_slice(&raw).map_err(|e| AuditError::Serde(e.to_string()))?;

        // Sign root_hash bytes (hex decoded).
        let root_hash_bytes = hex::decode(&manifest.root_hash).map_err(|e| {
            AuditError::InvalidBundle(format!("invalid root_hash hex in manifest: {e}"))
        })?;

        let key_raw =
            fs::read(key_path).map_err(|e| AuditError::Io(format!("read key failed: {e}")))?;
        let sk_bytes: [u8; 32] = key_raw
            .try_into()
            .map_err(|_| AuditError::InvalidBundle("expected 32-byte ed25519 secret key".into()))?;
        let signing = SigningKey::from_bytes(&sk_bytes);
        let sig = signing.sign(&root_hash_bytes);
        let vk: VerifyingKey = signing.verifying_key();

        manifest.optional_operator_signature = Some(OperatorSignatureV1 {
            pubkey: hex::encode(vk.as_bytes()),
            sig: hex::encode(sig.to_bytes()),
        });

        let new_manifest =
            serde_json::to_vec_pretty(&manifest).map_err(|e| AuditError::Serde(e.to_string()))?;
        write_file(&manifest_path, &new_manifest)?;
        build_deterministic_tar(root, bundle_path)?;
        Ok(())
    }
    #[cfg(not(feature = "bootstrap-signing"))]
    {
        let _ = (bundle_path, key_path);
        Err(AuditError::InvalidBundle(
            "manifest signing requires feature: bootstrap-signing".to_string(),
        ))
    }
}

fn write_events_index(root: &Path, events: &[EventRecordV1]) -> Result<(), AuditError> {
    let p = root.join("indexes").join("events.jsonl");
    fs::create_dir_all(p.parent().unwrap()).map_err(|e| AuditError::Io(e.to_string()))?;
    let mut out = Vec::new();
    for e in events {
        let line = serde_json::to_string(e).map_err(|e| AuditError::Serde(e.to_string()))?;
        out.extend_from_slice(line.as_bytes());
        out.push(b'\n');
    }
    write_file(&p, &out)
}

fn read_events_index(root: &Path) -> Result<Vec<EventRecordV1>, AuditError> {
    let p = root.join("indexes").join("events.jsonl");
    let raw = fs::read(&p).map_err(|e| AuditError::Io(e.to_string()))?;
    let s = String::from_utf8(raw).map_err(|e| AuditError::Serde(e.to_string()))?;
    let mut out = Vec::new();
    for (i, line) in s.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let e: EventRecordV1 =
            serde_json::from_str(line).map_err(|e| AuditError::Serde(format!("{i}: {e}")))?;
        out.push(e);
    }
    Ok(out)
}

fn write_actions_index(root: &Path, events: &[EventRecordV1]) -> Result<(), AuditError> {
    #[derive(Default, Clone)]
    struct Row {
        hub: String,
        last_kind: String,
        last_submit_state: String,
        signer: String,
    }
    let mut rows: BTreeMap<String, Row> = BTreeMap::new();
    for e in events {
        let Some(action_id) = e.action_id.as_ref() else {
            continue;
        };
        let mut r = rows.get(action_id).cloned().unwrap_or_default();
        r.hub = e.hub.clone();
        r.last_kind = e.kind.clone();
        r.last_submit_state = submit_state_label(e.submit_state.as_ref());
        r.signer = e.signer_pubkey.clone().unwrap_or_default();
        rows.insert(action_id.clone(), r);
    }
    let mut csv = String::new();
    csv.push_str("action_id,hub,last_event,submit_state,signer_pubkey\n");
    for (id, r) in rows {
        csv.push_str(&format!(
            "{id},{},{},{},{}\n",
            r.hub, r.last_kind, r.last_submit_state, r.signer
        ));
    }
    write_file(
        root.join("indexes").join("actions.csv").as_path(),
        csv.as_bytes(),
    )
}

fn submit_state_label(s: Option<&l2_core::finality::SubmitState>) -> String {
    let Some(s) = s else {
        return "".to_string();
    };
    match s {
        l2_core::finality::SubmitState::NotSubmitted => "not_submitted",
        l2_core::finality::SubmitState::Submitted { .. } => "submitted",
        l2_core::finality::SubmitState::Included { .. } => "included",
        l2_core::finality::SubmitState::Finalized { .. } => "finalized",
        l2_core::finality::SubmitState::Failed { .. } => "failed",
    }
    .to_string()
}

fn write_state_hashes(root: &Path, fin_db_dir: &str, data_db_dir: &str) -> Result<(), AuditError> {
    let fin = hub_fin::FinStore::open(fin_db_dir).map_err(|e| AuditError::Io(e.to_string()))?;
    let data = hub_data::DataStore::open(data_db_dir).map_err(|e| AuditError::Io(e.to_string()))?;
    let hashes = compute_state_hashes(&fin, &data)?;
    let bytes = serde_json::to_vec_pretty(&hashes).map_err(|e| AuditError::Serde(e.to_string()))?;
    write_file(&root.join("indexes").join("state_hashes.json"), &bytes)
}

fn compute_state_hashes(
    fin: &hub_fin::FinStore,
    data: &hub_data::DataStore,
) -> Result<BTreeMap<String, String>, AuditError> {
    let mut out: BTreeMap<String, String> = BTreeMap::new();

    let mut fin_kv = Vec::new();
    fin.export_kv_v1(&mut fin_kv)
        .map_err(|e| AuditError::Io(e.to_string()))?;
    out.insert(
        "hub-fin.kv_v1.blake3".to_string(),
        hex::encode(blake3::hash(&fin_kv).as_bytes()),
    );

    let mut data_kv = Vec::new();
    data.export_kv_v1(&mut data_kv)
        .map_err(|e| AuditError::Io(e.to_string()))?;
    out.insert(
        "hub-data.kv_v1.blake3".to_string(),
        hex::encode(blake3::hash(&data_kv).as_bytes()),
    );

    Ok(out)
}

fn write_proof_refs(
    root: &Path,
    receipts: &[(String, serde_json::Value)],
) -> Result<(), AuditError> {
    for (path, v) in receipts {
        // Fin/data: submit_state; linkage: payment_submit_state + entitlement_submit_state.
        if let Some(ss) = v.get("submit_state") {
            write_proof_refs_for_submit_state(root, path, "submit_state", ss)?;
        }
        if let Some(ss) = v.get("payment_submit_state") {
            write_proof_refs_for_submit_state(root, path, "payment_submit_state", ss)?;
        }
        if let Some(ss) = v.get("entitlement_submit_state") {
            write_proof_refs_for_submit_state(root, path, "entitlement_submit_state", ss)?;
        }
    }
    Ok(())
}

fn write_proof_refs_for_submit_state(
    root: &Path,
    receipt_path: &str,
    field: &str,
    ss: &serde_json::Value,
) -> Result<(), AuditError> {
    // Proof refs are JSON objects (not blobs) unless upstream stores raw proofs.
    let proof_hash = ss.get("proof_hash").cloned();
    let l1_tx_id = ss.get("l1_tx_id").cloned();
    let idempotency_key = ss.get("idempotency_key").cloned();
    let kind = match ss.get("state").and_then(|x| x.as_str()) {
        Some("included") => "inclusion",
        Some("finalized") => "finality",
        _ => return Ok(()),
    };

    let id = receipt_path
        .rsplit('/')
        .next()
        .unwrap_or("unknown")
        .trim_end_matches(".json");
    let out_name = format!("{id}.{field}.{kind}.json");
    let out = root.join("proofs").join(out_name);
    let obj = serde_json::json!({
        "receipt": receipt_path,
        "field": field,
        "kind": kind,
        "state": ss.get("state").cloned(),
        "idempotency_key": idempotency_key,
        "l1_tx_id": l1_tx_id,
        "proof_hash": proof_hash,
    });
    let bytes = serde_json::to_vec_pretty(&obj).map_err(|e| AuditError::Serde(e.to_string()))?;
    write_file(&out, &bytes)
}

fn write_report(
    root: &Path,
    events: &[EventRecordV1],
    include_envelopes: bool,
) -> Result<(), AuditError> {
    let mut counts_by_hub: BTreeMap<String, u64> = BTreeMap::new();
    let mut counts_by_kind: BTreeMap<String, u64> = BTreeMap::new();
    for e in events {
        *counts_by_hub.entry(e.hub.clone()).or_insert(0) += 1;
        *counts_by_kind.entry(e.kind.clone()).or_insert(0) += 1;
    }

    let mut summary = String::new();
    summary.push_str("# Audit Summary\n\n");
    summary.push_str(&format!("- events: {}\n", events.len()));
    summary.push_str("\n## Counts by hub\n\n");
    for (hub, n) in counts_by_hub {
        summary.push_str(&format!("- {hub}: {n}\n"));
    }
    summary.push_str("\n## Counts by event kind\n\n");
    for (k, n) in counts_by_kind {
        summary.push_str(&format!("- {k}: {n}\n"));
    }
    write_file(&root.join("report").join("summary.md"), summary.as_bytes())?;

    // Minimal domain reports from envelopes (if present).
    if include_envelopes {
        write_report_fin(root)?;
        write_report_data(root)?;
    } else {
        write_file(
            &root.join("report").join("fin_assets.md"),
            b"# FIN Assets\n\n(envelopes not included)\n",
        )?;
        write_file(
            &root.join("report").join("data_datasets.md"),
            b"# DATA Datasets\n\n(envelopes not included)\n",
        )?;
    }
    write_file(
        &root.join("report").join("linkage.md"),
        b"# Linkage\n\nSee receipts/linkage/*.json and indexes/events.jsonl\n",
    )?;

    Ok(())
}

fn write_report_fin(root: &Path) -> Result<(), AuditError> {
    let dir = root.join("envelopes").join("fin");
    if !dir.exists() {
        return write_file(
            &root.join("report").join("fin_assets.md"),
            b"# FIN Assets\n\n(no fin envelopes)\n",
        );
    }
    let mut assets: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    let mut minted: BTreeMap<String, u128> = BTreeMap::new();
    for entry in sorted_dir_files(&dir)? {
        let bytes = fs::read(&entry).map_err(|e| AuditError::Io(e.to_string()))?;
        let env: FinEnvelopeV1 =
            serde_json::from_slice(&bytes).map_err(|e| AuditError::Serde(e.to_string()))?;
        match env.action {
            hub_fin::FinActionV1::CreateAssetV1(a) => {
                assets.insert(
                    a.asset_id.to_hex(),
                    serde_json::json!({
                        "asset_id": a.asset_id.to_hex(),
                        "name": a.name,
                        "symbol": a.symbol,
                        "issuer": a.issuer.0,
                        "decimals": a.decimals
                    }),
                );
            }
            hub_fin::FinActionV1::MintUnitsV1(a) => {
                *minted.entry(a.asset_id.to_hex()).or_insert(0) += a.amount.0;
            }
            hub_fin::FinActionV1::TransferUnitsV1(_) => {}
        }
    }
    let mut md = String::new();
    md.push_str("# FIN Assets\n\n");
    md.push_str("## Assets\n\n");
    for v in assets.values() {
        md.push_str(&format!(
            "- {} ({}) issuer={}\n",
            v["asset_id"].as_str().unwrap_or(""),
            v["symbol"].as_str().unwrap_or(""),
            v["issuer"].as_str().unwrap_or("")
        ));
    }
    md.push_str("\n## Minted totals (from envelopes)\n\n");
    for (asset_id, amt) in minted {
        md.push_str(&format!("- {asset_id}: {amt}\n"));
    }
    write_file(&root.join("report").join("fin_assets.md"), md.as_bytes())
}

fn write_report_data(root: &Path) -> Result<(), AuditError> {
    let dir = root.join("envelopes").join("data");
    if !dir.exists() {
        return write_file(
            &root.join("report").join("data_datasets.md"),
            b"# DATA Datasets\n\n(no data envelopes)\n",
        );
    }
    let mut datasets: BTreeMap<String, String> = BTreeMap::new();
    let mut counts: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
    for entry in sorted_dir_files(&dir)? {
        let bytes = fs::read(&entry).map_err(|e| AuditError::Io(e.to_string()))?;
        let env: DataEnvelopeV1 =
            serde_json::from_slice(&bytes).map_err(|e| AuditError::Serde(e.to_string()))?;
        match env.action {
            hub_data::DataActionV1::RegisterDatasetV1(a) => {
                datasets.insert(a.dataset_id.to_hex(), a.name);
                *counts
                    .entry(a.dataset_id.to_hex())
                    .or_default()
                    .entry("register_dataset".to_string())
                    .or_insert(0) += 1;
            }
            hub_data::DataActionV1::CreateListingV1(a) => {
                *counts
                    .entry(a.dataset_id.to_hex())
                    .or_default()
                    .entry("create_listing".to_string())
                    .or_insert(0) += 1;
            }
            hub_data::DataActionV1::IssueLicenseV1(a) => {
                *counts
                    .entry(a.dataset_id.to_hex())
                    .or_default()
                    .entry("issue_license".to_string())
                    .or_insert(0) += 1;
            }
            hub_data::DataActionV1::GrantEntitlementV1(a) => {
                *counts
                    .entry(a.dataset_id.to_hex())
                    .or_default()
                    .entry("grant_entitlement".to_string())
                    .or_insert(0) += 1;
            }
            hub_data::DataActionV1::AppendAttestationV1(a) => {
                *counts
                    .entry(a.dataset_id.to_hex())
                    .or_default()
                    .entry("append_attestation".to_string())
                    .or_insert(0) += 1;
            }
            hub_data::DataActionV1::AddLicensorV1(a) => {
                *counts
                    .entry(a.dataset_id.to_hex())
                    .or_default()
                    .entry("add_licensor".to_string())
                    .or_insert(0) += 1;
            }
            hub_data::DataActionV1::AddAttestorV1(a) => {
                *counts
                    .entry(a.dataset_id.to_hex())
                    .or_default()
                    .entry("add_attestor".to_string())
                    .or_insert(0) += 1;
            }
        }
    }
    let mut md = String::new();
    md.push_str("# DATA Datasets\n\n");
    for (id, name) in datasets {
        md.push_str(&format!("## {id}\n\n- name: {name}\n"));
        if let Some(c) = counts.get(&id) {
            md.push_str("- counts:\n");
            for (k, v) in c {
                md.push_str(&format!("  - {k}: {v}\n"));
            }
        }
        md.push('\n');
    }
    write_file(&root.join("report").join("data_datasets.md"), md.as_bytes())
}

fn build_file_manifest(root: &Path) -> Result<(Vec<ManifestFileV1>, String), AuditError> {
    let mut files: Vec<(String, Vec<u8>)> = Vec::new();
    collect_files(root, root, &mut files)?;

    // Exclude manifest.json from the hashed list (self-reference).
    files.retain(|(p, _)| p != "manifest.json");

    files.sort_by(|(a, _), (b, _)| a.cmp(b));

    let mut out: Vec<ManifestFileV1> = Vec::with_capacity(files.len());
    let mut concat_hashes: Vec<u8> = Vec::with_capacity(files.len() * 32);
    for (path, bytes) in files {
        let h = blake3::hash(&bytes);
        concat_hashes.extend_from_slice(h.as_bytes());
        out.push(ManifestFileV1 {
            path,
            blake3: hex::encode(h.as_bytes()),
            bytes: u64::try_from(bytes.len()).unwrap_or(u64::MAX),
        });
    }
    let root_hash = blake3::hash(&concat_hashes);
    Ok((out, hex::encode(root_hash.as_bytes())))
}

fn collect_files(
    root: &Path,
    dir: &Path,
    out: &mut Vec<(String, Vec<u8>)>,
) -> Result<(), AuditError> {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .map_err(|e| AuditError::Io(e.to_string()))?
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|a| a.file_name());
    for e in entries {
        let p = e.path();
        let ft = e.file_type().map_err(|e| AuditError::Io(e.to_string()))?;
        if ft.is_dir() {
            collect_files(root, &p, out)?;
        } else if ft.is_file() {
            let rel = p
                .strip_prefix(root)
                .map_err(|e| AuditError::Io(e.to_string()))?
                .to_string_lossy()
                .replace('\\', "/");
            let bytes = fs::read(&p).map_err(|e| AuditError::Io(e.to_string()))?;
            out.push((rel, bytes));
        }
    }
    Ok(())
}

fn verify_manifest(root: &Path, manifest: &AuditManifestV1) -> Result<(), AuditError> {
    for f in &manifest.files {
        let p = root.join(&f.path);
        let bytes = fs::read(&p)
            .map_err(|e| AuditError::InvalidBundle(format!("missing file {}: {e}", f.path)))?;
        let h = hex::encode(blake3::hash(&bytes).as_bytes());
        if h != f.blake3 {
            return Err(AuditError::InvalidBundle(format!(
                "hash mismatch for {}: expected {}, got {}",
                f.path, f.blake3, h
            )));
        }
        let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if len != f.bytes {
            return Err(AuditError::InvalidBundle(format!(
                "size mismatch for {}: expected {}, got {}",
                f.path, f.bytes, len
            )));
        }
    }
    Ok(())
}

fn verify_root_hash(manifest: &AuditManifestV1) -> Result<(), AuditError> {
    let mut files = manifest.files.clone();
    files.sort_by(|a, b| a.path.cmp(&b.path));
    let mut concat = Vec::with_capacity(files.len() * 32);
    for f in files {
        let bytes = hex::decode(f.blake3).map_err(|e| AuditError::Serde(e.to_string()))?;
        if bytes.len() != 32 {
            return Err(AuditError::InvalidBundle(
                "invalid file hash length".to_string(),
            ));
        }
        concat.extend_from_slice(&bytes);
    }
    let got = hex::encode(blake3::hash(&concat).as_bytes());
    if got != manifest.root_hash {
        return Err(AuditError::InvalidBundle(format!(
            "root_hash mismatch: expected {}, got {}",
            manifest.root_hash, got
        )));
    }
    Ok(())
}

fn verify_operator_signature_if_present(manifest: &AuditManifestV1) -> Result<(), AuditError> {
    let Some(sig) = manifest.optional_operator_signature.as_ref() else {
        return Ok(());
    };
    #[cfg(feature = "bootstrap-signing")]
    {
        use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
        let root_hash = hex::decode(&manifest.root_hash)
            .map_err(|e| AuditError::InvalidBundle(format!("invalid root_hash hex: {e}")))?;
        let pk = hex::decode(&sig.pubkey)
            .map_err(|e| AuditError::InvalidBundle(format!("invalid pubkey hex: {e}")))?;
        let pk: [u8; 32] = pk
            .try_into()
            .map_err(|_| AuditError::InvalidBundle("invalid pubkey length".into()))?;
        let vk = VerifyingKey::from_bytes(&pk)
            .map_err(|e| AuditError::InvalidBundle(format!("invalid pubkey: {e}")))?;
        let sb = hex::decode(&sig.sig)
            .map_err(|e| AuditError::InvalidBundle(format!("invalid sig hex: {e}")))?;
        let sb: [u8; 64] = sb
            .try_into()
            .map_err(|_| AuditError::InvalidBundle("invalid sig length".into()))?;
        let signature = Signature::from_bytes(&sb);
        vk.verify(&root_hash, &signature)
            .map_err(|e| AuditError::InvalidBundle(format!("signature verify failed: {e}")))?;
        Ok(())
    }
    #[cfg(not(feature = "bootstrap-signing"))]
    {
        let _ = sig;
        Err(AuditError::InvalidBundle(
            "bundle is signed but verifier is not enabled (feature: bootstrap-signing)".to_string(),
        ))
    }
}

fn build_deterministic_tar(root: &Path, out_path: &Path) -> Result<(), AuditError> {
    // Collect all relative file paths (including manifest.json).
    let mut rels: Vec<String> = Vec::new();
    collect_rel_paths(root, root, &mut rels)?;
    rels.sort();

    // Directories: ensure parent directories are emitted first.
    let mut dirs: BTreeSet<String> = BTreeSet::new();
    for p in &rels {
        if let Some(parent) = Path::new(p).parent() {
            let mut cur = PathBuf::new();
            for comp in parent.components() {
                cur.push(comp);
                let s = cur.to_string_lossy().replace('\\', "/");
                if !s.is_empty() {
                    dirs.insert(s);
                }
            }
        }
    }

    if let Some(parent) = out_path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| AuditError::Io(e.to_string()))?;
        }
    }
    let f = fs::File::create(out_path).map_err(|e| AuditError::Io(e.to_string()))?;
    let mut builder = tar::Builder::new(f);
    builder.follow_symlinks(false);

    for d in dirs {
        let mut hdr = tar::Header::new_gnu();
        hdr.set_entry_type(tar::EntryType::Directory);
        hdr.set_mode(0o755);
        hdr.set_uid(0);
        hdr.set_gid(0);
        hdr.set_mtime(0);
        hdr.set_size(0);
        hdr.set_cksum();
        builder
            .append_data(&mut hdr, format!("{d}/"), std::io::empty())
            .map_err(|e| AuditError::Io(e.to_string()))?;
    }

    for p in rels {
        let full = root.join(&p);
        let bytes = fs::read(&full).map_err(|e| AuditError::Io(e.to_string()))?;
        let mut hdr = tar::Header::new_gnu();
        hdr.set_entry_type(tar::EntryType::Regular);
        hdr.set_mode(0o644);
        hdr.set_uid(0);
        hdr.set_gid(0);
        hdr.set_mtime(0);
        hdr.set_size(u64::try_from(bytes.len()).unwrap_or(u64::MAX));
        hdr.set_cksum();
        builder
            .append_data(&mut hdr, p, bytes.as_slice())
            .map_err(|e| AuditError::Io(e.to_string()))?;
    }

    builder
        .finish()
        .map_err(|e| AuditError::Io(e.to_string()))?;
    Ok(())
}

fn collect_rel_paths(root: &Path, dir: &Path, out: &mut Vec<String>) -> Result<(), AuditError> {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .map_err(|e| AuditError::Io(e.to_string()))?
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|a| a.file_name());
    for e in entries {
        let p = e.path();
        let ft = e.file_type().map_err(|e| AuditError::Io(e.to_string()))?;
        if ft.is_dir() {
            collect_rel_paths(root, &p, out)?;
        } else if ft.is_file() {
            let rel = p
                .strip_prefix(root)
                .map_err(|e| AuditError::Io(e.to_string()))?
                .to_string_lossy()
                .replace('\\', "/");
            out.push(rel);
        }
    }
    Ok(())
}

fn extract_tar(src: &Path, dst: &Path) -> Result<(), AuditError> {
    let f = fs::File::open(src).map_err(|e| AuditError::Io(e.to_string()))?;
    let mut ar = tar::Archive::new(f);
    ar.unpack(dst).map_err(|e| AuditError::Io(e.to_string()))?;
    Ok(())
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), AuditError> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| AuditError::Io(e.to_string()))?;
    }
    fs::write(path, bytes)
        .map_err(|e| AuditError::Io(format!("write {} failed: {e}", path.display())))
}

fn sorted_dir_files(dir: &Path) -> Result<Vec<PathBuf>, AuditError> {
    let mut out = Vec::new();
    let mut entries: Vec<_> = fs::read_dir(dir)
        .map_err(|e| AuditError::Io(e.to_string()))?
        .filter_map(|e| e.ok())
        .collect();
    entries.sort_by_key(|a| a.file_name());
    for e in entries {
        let p = e.path();
        let ft = e.file_type().map_err(|e| AuditError::Io(e.to_string()))?;
        if ft.is_file() {
            out.push(p);
        }
    }
    Ok(out)
}
