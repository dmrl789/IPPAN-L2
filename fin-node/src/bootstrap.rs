#![forbid(unsafe_code)]

use base64::Engine as _;
use hub_data::DataStore;
use hub_fin::FinStore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};

use crate::bootstrap_store::BootstrapStore;
use crate::recon_store::ReconStore;
use crate::snapshot::SnapshotManifestV1;

pub mod source;

pub const DELTA_SNAPSHOT_VERSION_V1: u32 = 1;

#[derive(Debug, thiserror::Error)]
pub enum BootstrapError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("tar error: {0}")]
    Tar(String),
    #[error("hash mismatch")]
    HashMismatch,
    #[error("corrupt: {0}")]
    Corrupt(String),
    #[error("store error: {0}")]
    Store(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaManifestV1 {
    pub delta_version: u32,
    pub ippan_l2_version: String,
    pub base_snapshot_id: String,
    pub from_epoch: u64,
    pub to_epoch: u64,
    pub created_at: u64,
    pub counts: BTreeMap<String, u64>,
    /// blake3(changes.jsonl bytes)
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeltaChangeV1 {
    pub store: String,
    pub op: String,
    pub key_hex: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seq: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct DeltaSources<'a> {
    pub fin: &'a FinStore,
    pub data: &'a DataStore,
    pub recon: Option<&'a ReconStore>,
    pub bootstrap: &'a BootstrapStore,
}

pub struct ParsedDeltaV1 {
    pub manifest: DeltaManifestV1,
    pub changes: Vec<DeltaChangeV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapProgressV1 {
    pub schema_version: u32,
    pub base_snapshot_id: String,
    pub last_applied_to_epoch: u64,
}

pub fn create_delta_snapshot_v1_tar(
    out_path: &Path,
    base_snapshot_id: &str,
    from_epoch: u64,
    to_epoch: u64,
    sources: DeltaSources<'_>,
) -> Result<DeltaManifestV1, BootstrapError> {
    let mut changes: Vec<(String, String, String, u64, Option<String>)> = Vec::new();

    // hub-fin changelog entries
    for e in sources
        .fin
        .export_changelog_epoch_v1(from_epoch)
        .map_err(|e| BootstrapError::Store(e.to_string()))?
    {
        changes.push(("fin".to_string(), e.op, e.key_hex, e.seq, e.value_b64));
    }

    // hub-data changelog entries
    for e in sources
        .data
        .export_changelog_epoch_v1(from_epoch)
        .map_err(|e| BootstrapError::Store(e.to_string()))?
    {
        changes.push(("data".to_string(), e.op, e.key_hex, e.seq, e.value_b64));
    }

    // recon changelog entries (optional)
    if let Some(r) = sources.recon {
        for e in r
            .export_changelog_epoch_v1(from_epoch)
            .map_err(|e| BootstrapError::Store(e.to_string()))?
        {
            changes.push(("recon".to_string(), e.op, e.key_hex, e.seq, e.value_b64));
        }
    }

    // file changelog entries (receipts/linkage)
    for e in sources
        .bootstrap
        .export_changelog_epoch_v1(from_epoch)
        .map_err(|e| BootstrapError::Store(e.to_string()))?
    {
        changes.push((e.store, e.op, e.key_hex, e.seq, e.value_b64));
    }

    // Deterministic sort: (store, key_hex, op, seq)
    changes.sort_by(|a, b| {
        (a.0.as_str(), a.2.as_str(), a.1.as_str(), a.3).cmp(&(
            b.0.as_str(),
            b.2.as_str(),
            b.1.as_str(),
            b.3,
        ))
    });

    let mut puts = 0u64;
    let mut dels = 0u64;
    let mut jsonl = String::new();
    for (store, op, key_hex, seq, value_b64) in changes {
        if op == "put" {
            puts += 1;
        } else if op == "del" {
            dels += 1;
        }
        let rec = DeltaChangeV1 {
            store,
            op,
            key_hex,
            value_b64,
            seq: Some(seq),
        };
        jsonl.push_str(&serde_json::to_string(&rec)?);
        jsonl.push('\n');
    }
    let changes_bytes = jsonl.into_bytes();
    let hash = blake3::hash(&changes_bytes).to_hex().to_string();

    let mut counts = BTreeMap::new();
    counts.insert("puts".to_string(), puts);
    counts.insert("dels".to_string(), dels);

    let manifest = DeltaManifestV1 {
        delta_version: DELTA_SNAPSHOT_VERSION_V1,
        ippan_l2_version: env!("CARGO_PKG_VERSION").to_string(),
        base_snapshot_id: base_snapshot_id.to_string(),
        from_epoch,
        to_epoch,
        created_at: unix_now_secs(),
        counts,
        hash,
    };

    write_delta_tar_atomic(out_path, &manifest, &changes_bytes)?;
    Ok(manifest)
}

pub fn parse_delta_snapshot_v1_tar(path: &Path) -> Result<ParsedDeltaV1, BootstrapError> {
    let extracted = extract_tar_to_temp(path)?;
    let manifest: DeltaManifestV1 = {
        let raw = fs::read(extracted.dir.join("delta_manifest.json"))?;
        serde_json::from_slice(&raw)?
    };
    if manifest.delta_version != DELTA_SNAPSHOT_VERSION_V1 {
        return Err(BootstrapError::Corrupt(format!(
            "unsupported delta_version {}",
            manifest.delta_version
        )));
    }
    let changes_bytes = fs::read(extracted.dir.join("changes.jsonl"))?;
    let expected = blake3::hash(&changes_bytes).to_hex().to_string();
    if expected != manifest.hash {
        return Err(BootstrapError::HashMismatch);
    }

    let mut changes = Vec::new();
    for line in changes_bytes.split(|b| *b == b'\n') {
        if line.is_empty() {
            continue;
        }
        let rec: DeltaChangeV1 = serde_json::from_slice(line)?;
        changes.push(rec);
    }
    Ok(ParsedDeltaV1 { manifest, changes })
}

pub fn apply_delta_changes_v1(
    changes: &[DeltaChangeV1],
    fin: &FinStore,
    data: &DataStore,
    recon: Option<&ReconStore>,
    receipts_dir: &Path,
) -> Result<(), BootstrapError> {
    for c in changes {
        let key = hex::decode(&c.key_hex).map_err(|e| BootstrapError::Corrupt(e.to_string()))?;
        match (c.store.as_str(), c.op.as_str()) {
            ("fin", "put") => {
                let v = decode_b64_required(c.value_b64.as_deref())?;
                fin.raw_put(&key, &v)
                    .map_err(|e| BootstrapError::Store(e.to_string()))?;
            }
            ("fin", "del") => {
                fin.raw_del(&key)
                    .map_err(|e| BootstrapError::Store(e.to_string()))?;
            }
            ("data", "put") => {
                let v = decode_b64_required(c.value_b64.as_deref())?;
                data.raw_put(&key, &v)
                    .map_err(|e| BootstrapError::Store(e.to_string()))?;
            }
            ("data", "del") => {
                data.raw_del(&key)
                    .map_err(|e| BootstrapError::Store(e.to_string()))?;
            }
            ("recon", "put") => {
                let Some(r) = recon else { continue };
                let v = decode_b64_required(c.value_b64.as_deref())?;
                r.raw_put(&key, &v)
                    .map_err(|e| BootstrapError::Store(e.to_string()))?;
            }
            ("recon", "del") => {
                let Some(r) = recon else { continue };
                r.raw_del(&key)
                    .map_err(|e| BootstrapError::Store(e.to_string()))?;
            }
            ("receipts", "put") | ("linkage", "put") => {
                let rel = std::str::from_utf8(&key)
                    .map_err(|_| BootstrapError::Corrupt("invalid utf8 file key".to_string()))?;
                let v = decode_b64_required(c.value_b64.as_deref())?;
                let out_path = receipts_dir.join(rel);
                if let Some(parent) = out_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::write(out_path, v)?;
            }
            ("receipts", "del") | ("linkage", "del") => {
                let rel = std::str::from_utf8(&key)
                    .map_err(|_| BootstrapError::Corrupt("invalid utf8 file key".to_string()))?;
                let out_path = receipts_dir.join(rel);
                let _ = fs::remove_file(out_path);
            }
            _ => {
                return Err(BootstrapError::Corrupt(format!(
                    "unknown change store/op: {}/{}",
                    c.store, c.op
                )));
            }
        }
    }
    Ok(())
}

pub fn read_progress(path: &Path) -> Result<Option<BootstrapProgressV1>, BootstrapError> {
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read(path)?;
    let p: BootstrapProgressV1 = serde_json::from_slice(&raw)?;
    Ok(Some(p))
}

pub fn write_progress_atomic(path: &Path, p: &BootstrapProgressV1) -> Result<(), BootstrapError> {
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(p)?;
    fs::write(&tmp, bytes)?;
    fs::rename(tmp, path)?;
    Ok(())
}

fn decode_b64_required(v: Option<&str>) -> Result<Vec<u8>, BootstrapError> {
    let Some(v) = v else {
        return Err(BootstrapError::Corrupt(
            "missing value_b64 for put".to_string(),
        ));
    };
    base64::engine::general_purpose::STANDARD
        .decode(v.as_bytes())
        .map_err(|e| BootstrapError::Corrupt(format!("invalid base64: {e}")))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapIndexV1 {
    pub schema_version: u32,
    pub latest: BootstrapSetV1,
    #[serde(default)]
    pub history: Vec<BootstrapSetV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapSetV1 {
    pub base: BootstrapBaseRefV1,
    pub deltas: Vec<BootstrapDeltaRefV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapBaseRefV1 {
    pub path: String,
    pub hash: String,
    pub created_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Optional content-addressed path, e.g. `artifacts/base/<hash>.tar`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_path: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapDeltaRefV1 {
    pub path: String,
    pub hash: String,
    pub from_epoch: u64,
    pub to_epoch: u64,
    pub created_at: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size: Option<u64>,
    /// Optional content-addressed path, e.g. `artifacts/delta/<hash>.tar`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ca_path: Option<String>,
}

pub fn publish_index_v1(dir: &Path) -> Result<(), BootstrapError> {
    let mut bases: Vec<(SnapshotManifestV1, PathBuf)> = Vec::new();
    let mut deltas: Vec<(DeltaManifestV1, PathBuf)> = Vec::new();

    // Scan top-level dir and ./deltas subdir (if present).
    for p in list_tar_files(dir)? {
        if let Some(m) = read_base_manifest(&p)? {
            bases.push((m, p));
            continue;
        }
        if let Some(m) = read_delta_manifest(&p)? {
            deltas.push((m, p));
        }
    }
    let deltas_dir = dir.join("deltas");
    for p in list_tar_files(&deltas_dir).unwrap_or_default() {
        if let Some(m) = read_delta_manifest(&p)? {
            deltas.push((m, p));
        }
    }

    if bases.is_empty() {
        return Err(BootstrapError::Corrupt(format!(
            "no base snapshots found in {}",
            dir.display()
        )));
    }

    // Newest base by created_at.
    bases.sort_by(|a, b| a.0.created_at.cmp(&b.0.created_at));
    let (latest_base_manifest, latest_base_path) = bases.last().cloned().unwrap();
    let latest_base_hash = latest_base_manifest.hash.clone();

    let latest = build_set_for_base(dir, &latest_base_manifest, &latest_base_path, &deltas)?;

    let mut history = Vec::new();
    for (m, p) in bases
        .into_iter()
        .filter(|(m, _p)| m.hash != latest_base_hash)
    {
        if let Ok(set) = build_set_for_base(dir, &m, &p, &deltas) {
            history.push(set);
        }
    }

    let idx = BootstrapIndexV1 {
        schema_version: 1,
        latest,
        history,
    };
    let out_path = dir.join("index.json");
    fs::write(out_path, serde_json::to_vec_pretty(&idx)?)?;
    Ok(())
}

/// Best-effort retention for base+delta artifacts.
///
/// Safety:
/// - Never deletes the newest `retain_bases` bases.
/// - Deletes deltas whose `base_snapshot_id` references a deleted base.
/// - Never deletes deltas for retained bases (conservative).
pub fn rotate_bootstrap_dir_v1(dir: &Path, retain_bases: usize, retain_deltas_per_base: usize) {
    if retain_bases < 1 {
        return;
    }
    let Ok(files) = list_tar_files(dir) else {
        return;
    };
    let mut bases: Vec<(SnapshotManifestV1, PathBuf)> = Vec::new();
    let mut deltas: Vec<(DeltaManifestV1, PathBuf)> = Vec::new();

    for p in files {
        if let Ok(Some(m)) = read_base_manifest(&p) {
            bases.push((m, p));
            continue;
        }
        if let Ok(Some(m)) = read_delta_manifest(&p) {
            deltas.push((m, p));
        }
    }
    let delta_dir = dir.join("deltas");
    if let Ok(delta_files) = list_tar_files(&delta_dir) {
        for p in delta_files {
            if let Ok(Some(m)) = read_delta_manifest(&p) {
                deltas.push((m, p));
            }
        }
    }

    bases.sort_by(|a, b| a.0.created_at.cmp(&b.0.created_at));
    let latest_base_hash = bases.last().map(|x| x.0.hash.clone());

    let to_delete = bases.len().saturating_sub(retain_bases);
    let mut deleted_hashes: Vec<String> = Vec::new();
    for (m, p) in bases.iter().take(to_delete).cloned() {
        deleted_hashes.push(m.hash);
        let _ = fs::remove_file(p);
    }
    // Remaining (retained) bases.
    let retained_hashes: Vec<String> = bases
        .into_iter()
        .skip(to_delete)
        .map(|(m, _p)| m.hash)
        .collect();

    // Partition deltas by base.
    let mut by_base: std::collections::BTreeMap<String, Vec<(DeltaManifestV1, PathBuf)>> =
        std::collections::BTreeMap::new();
    for (m, p) in deltas {
        by_base
            .entry(m.base_snapshot_id.clone())
            .or_default()
            .push((m, p));
    }

    // Delete all deltas for deleted bases.
    for h in &deleted_hashes {
        if let Some(list) = by_base.get(h) {
            for (_m, p) in list {
                let _ = fs::remove_file(p);
            }
        }
    }

    // For retained, non-latest bases, prune old deltas (best-effort) to limit disk usage.
    // For the latest base, keep all deltas (so a new node can reach latest state).
    if let Some(latest) = latest_base_hash {
        for h in retained_hashes {
            if h == latest {
                continue;
            }
            let Some(list) = by_base.get_mut(&h) else {
                continue;
            };
            list.sort_by(|a, b| {
                (a.0.from_epoch, a.0.to_epoch, a.0.created_at).cmp(&(
                    b.0.from_epoch,
                    b.0.to_epoch,
                    b.0.created_at,
                ))
            });
            if list.len() <= retain_deltas_per_base.max(1) {
                continue;
            }
            let excess = list.len().saturating_sub(retain_deltas_per_base.max(1));
            for (_m, p) in list.iter().take(excess) {
                let _ = fs::remove_file(p);
            }
        }
    }
}

fn build_set_for_base(
    root: &Path,
    base_manifest: &SnapshotManifestV1,
    base_path: &Path,
    deltas: &[(DeltaManifestV1, PathBuf)],
) -> Result<BootstrapSetV1, BootstrapError> {
    let base_hash = base_manifest.hash.clone();
    let base_ref = BootstrapBaseRefV1 {
        path: rel_path(root, base_path),
        hash: base_hash.clone(),
        created_at: base_manifest.created_at,
        size: std::fs::metadata(base_path).ok().map(|m| m.len()),
        ca_path: Some(format!("artifacts/base/{base_hash}.tar")),
    };

    let mut ds: Vec<(DeltaManifestV1, PathBuf)> = deltas
        .iter()
        .filter(|(m, _p)| m.base_snapshot_id == base_hash)
        .cloned()
        .collect();
    ds.sort_by(|a, b| {
        (a.0.from_epoch, a.0.to_epoch, a.0.created_at).cmp(&(
            b.0.from_epoch,
            b.0.to_epoch,
            b.0.created_at,
        ))
    });

    let mut delta_refs = Vec::new();
    for (m, p) in ds {
        let delta_hash = m.hash.clone();
        delta_refs.push(BootstrapDeltaRefV1 {
            path: rel_path(root, &p),
            hash: delta_hash.clone(),
            from_epoch: m.from_epoch,
            to_epoch: m.to_epoch,
            created_at: m.created_at,
            size: std::fs::metadata(&p).ok().map(|mm| mm.len()),
            ca_path: Some(format!("artifacts/delta/{delta_hash}.tar")),
        });
    }

    Ok(BootstrapSetV1 {
        base: base_ref,
        deltas: delta_refs,
    })
}

fn list_tar_files(dir: &Path) -> Result<Vec<PathBuf>, BootstrapError> {
    let mut out = Vec::new();
    let Ok(rd) = fs::read_dir(dir) else {
        return Ok(out);
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_file() && p.extension().and_then(|s| s.to_str()) == Some("tar") {
            out.push(p);
        }
    }
    Ok(out)
}

fn rel_path(root: &Path, p: &Path) -> String {
    p.strip_prefix(root)
        .unwrap_or(p)
        .to_string_lossy()
        .replace('\\', "/")
}

fn read_base_manifest(path: &Path) -> Result<Option<SnapshotManifestV1>, BootstrapError> {
    let raw = read_tar_member(path, "manifest.json")?;
    let Some(raw) = raw else { return Ok(None) };
    let m: SnapshotManifestV1 = serde_json::from_slice(&raw)?;
    Ok(Some(m))
}

fn read_delta_manifest(path: &Path) -> Result<Option<DeltaManifestV1>, BootstrapError> {
    let raw = read_tar_member(path, "delta_manifest.json")?;
    let Some(raw) = raw else { return Ok(None) };
    let m: DeltaManifestV1 = serde_json::from_slice(&raw)?;
    Ok(Some(m))
}

fn read_tar_member(path: &Path, name: &str) -> Result<Option<Vec<u8>>, BootstrapError> {
    let file = fs::File::open(path)?;
    let mut archive = tar::Archive::new(file);
    for entry in archive
        .entries()
        .map_err(|e| BootstrapError::Tar(e.to_string()))?
    {
        let mut entry = entry.map_err(|e| BootstrapError::Tar(e.to_string()))?;
        let Ok(entry_path) = entry.path() else {
            continue;
        };
        if entry_path.as_os_str() == name {
            let mut buf = Vec::new();
            entry.read_to_end(&mut buf)?;
            return Ok(Some(buf));
        }
    }
    Ok(None)
}

fn write_delta_tar_atomic(
    out_path: &Path,
    manifest: &DeltaManifestV1,
    changes_bytes: &[u8],
) -> Result<(), BootstrapError> {
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp_path = out_path.with_extension("tar.tmp");
    let file = fs::File::create(&tmp_path)?;
    let mut builder = tar::Builder::new(file);
    append_bytes_to_tar(&mut builder, "changes.jsonl", changes_bytes)?;
    let manifest_bytes = serde_json::to_vec_pretty(manifest)?;
    append_bytes_to_tar(&mut builder, "delta_manifest.json", &manifest_bytes)?;
    builder
        .finish()
        .map_err(|e| BootstrapError::Tar(e.to_string()))?;
    fs::rename(&tmp_path, out_path)?;
    Ok(())
}

fn append_bytes_to_tar(
    builder: &mut tar::Builder<fs::File>,
    name: &str,
    bytes: &[u8],
) -> Result<(), BootstrapError> {
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_uid(0);
    header.set_gid(0);
    header.set_cksum();
    builder
        .append_data(&mut header, name, std::io::Cursor::new(bytes))
        .map_err(|e| BootstrapError::Tar(e.to_string()))?;
    Ok(())
}

struct ExtractedTar {
    _tmp: tempfile::TempDir,
    dir: PathBuf,
}

fn extract_tar_to_temp(from_path: &Path) -> Result<ExtractedTar, BootstrapError> {
    let tmp = tempfile::tempdir()?;
    let dir = tmp.path().to_path_buf();
    let file = fs::File::open(from_path)?;
    let mut archive = tar::Archive::new(file);
    archive
        .unpack(&dir)
        .map_err(|e| BootstrapError::Tar(e.to_string()))?;
    Ok(ExtractedTar { _tmp: tmp, dir })
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
