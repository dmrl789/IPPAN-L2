#![forbid(unsafe_code)]

use crate::config::SnapshotsConfig;
use crate::metrics;
use crate::recon_store::ReconStore;
use hub_data::DataStore;
use hub_fin::FinStore;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("tar error: {0}")]
    Tar(String),
    #[error("store error: {0}")]
    Store(String),
    #[error("snapshot disabled")]
    Disabled,
    #[error("existing state detected (use --force to overwrite)")]
    ExistingState,
    #[error("snapshot corrupt or incomplete: {0}")]
    Corrupt(String),
    #[error("snapshot hash mismatch")]
    HashMismatch,
    #[error("hook failed: {0}")]
    HookFailed(String),
}

pub const SNAPSHOT_VERSION_V1: u32 = 1;

/// Snapshot manifest (v1).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotManifestV1 {
    pub snapshot_version: u32,
    pub ippan_l2_version: String,
    pub created_at: u64,
    pub node_id: String,
    pub state_versions: BTreeMap<String, u32>,
    pub counts: BTreeMap<String, u64>,
    /// Integrity hash (blake3) over canonical ordered contents.
    pub hash: String,
}

#[derive(Debug, Clone)]
pub struct SnapshotSources<'a> {
    pub fin: &'a FinStore,
    pub data: &'a DataStore,
    pub recon: Option<&'a ReconStore>,
    pub receipts_dir: &'a Path,
    pub node_id: &'a str,
}

/// Create a SnapshotV1 tar archive.
///
/// This is designed for operational DR/migration and does not participate in consensus.
pub fn create_snapshot_v1_tar(
    cfg: &SnapshotsConfig,
    out_path: &Path,
    sources: SnapshotSources<'_>,
) -> Result<SnapshotManifestV1, SnapshotError> {
    if !cfg.enabled {
        return Err(SnapshotError::Disabled);
    }

    // Build all component files in a temp dir so we can:
    // - compute integrity hash
    // - write tar atomically
    let tmp = tempfile::tempdir()?;
    let tmpdir = tmp.path();

    let fin_kv = tmpdir.join("hub-fin.kv");
    let data_kv = tmpdir.join("hub-data.kv");
    let recon_kv = tmpdir.join("recon.kv");
    let receipts_kv = tmpdir.join("receipts.kv");
    let linkage_kv = tmpdir.join("linkage.kv");

    write_store_kv(&fin_kv, "hub-fin", |w| {
        sources.fin.export_kv_v1(w).map_err(|e| e.to_string())
    })?;
    write_store_kv(&data_kv, "hub-data", |w| {
        sources.data.export_kv_v1(w).map_err(|e| e.to_string())
    })?;

    // Recon is optional but always included as a file for format stability.
    write_store_kv(&recon_kv, "recon", |w| {
        if let Some(r) = sources.recon {
            r.export_kv_v1(w).map_err(|e| e.to_string())
        } else {
            Ok(())
        }
    })?;

    // Receipts/linkage (filesystem KV, deterministic by relative path).
    write_files_kv(&receipts_kv, sources.receipts_dir, FileKvScope::Receipts)?;
    write_files_kv(&linkage_kv, sources.receipts_dir, FileKvScope::Linkage)?;

    // Gather manifest fields.
    let created_at = unix_now_secs();
    let ippan_l2_version = env!("CARGO_PKG_VERSION").to_string();

    let mut state_versions: BTreeMap<String, u32> = BTreeMap::new();
    state_versions.insert(
        "fin".to_string(),
        sources
            .fin
            .get_state_version()
            .map_err(|e| SnapshotError::Store(e.to_string()))?
            .unwrap_or(0),
    );
    state_versions.insert(
        "data".to_string(),
        sources
            .data
            .get_state_version()
            .map_err(|e| SnapshotError::Store(e.to_string()))?
            .unwrap_or(0),
    );
    state_versions.insert("linkage".to_string(), 1);
    state_versions.insert("recon".to_string(), 1);

    let counts = compute_counts(&fin_kv, &data_kv, &receipts_kv, &linkage_kv)?;

    // Compute integrity hash (does not impact consensus).
    let hash = compute_integrity_hash(&[
        ("hub-fin.kv", &fin_kv),
        ("hub-data.kv", &data_kv),
        ("linkage.kv", &linkage_kv),
        ("receipts.kv", &receipts_kv),
        ("recon.kv", &recon_kv),
    ])?;

    let manifest = SnapshotManifestV1 {
        snapshot_version: SNAPSHOT_VERSION_V1,
        ippan_l2_version,
        created_at,
        node_id: sources.node_id.to_string(),
        state_versions,
        counts,
        hash,
    };

    // Write tar atomically.
    write_tar_atomic(
        out_path,
        &manifest,
        &[
            ("hub-fin.kv", &fin_kv),
            ("hub-data.kv", &data_kv),
            ("linkage.kv", &linkage_kv),
            ("receipts.kv", &receipts_kv),
            ("recon.kv", &recon_kv),
        ],
    )?;

    if let Some(hook) = cfg
        .post_snapshot_hook
        .as_deref()
        .filter(|s| !s.trim().is_empty())
    {
        run_hook(hook, out_path).inspect_err(|_e| {
            metrics::SNAPSHOT_FAILURES_TOTAL
                .with_label_values(&["create", "post_hook"])
                .inc();
        })?;
    }

    metrics::SNAPSHOTS_CREATED_TOTAL
        .with_label_values(&["ok"])
        .inc();
    Ok(manifest)
}

/// Restore SnapshotV1 from a tar archive into the provided stores/receipts dir.
///
/// Safety:
/// - If `force` is false, fails when existing state is detected.
/// - Validates manifest integrity hash.
pub fn restore_snapshot_v1_tar(
    cfg: &SnapshotsConfig,
    from_path: &Path,
    fin: &FinStore,
    data: &DataStore,
    recon: Option<&ReconStore>,
    receipts_dir: &Path,
    force: bool,
) -> Result<SnapshotManifestV1, SnapshotError> {
    if !cfg.enabled {
        return Err(SnapshotError::Disabled);
    }
    if let Some(hook) = cfg
        .pre_restore_hook
        .as_deref()
        .filter(|s| !s.trim().is_empty())
    {
        run_hook(hook, from_path).inspect_err(|_e| {
            metrics::SNAPSHOT_FAILURES_TOTAL
                .with_label_values(&["restore", "pre_hook"])
                .inc();
        })?;
    }

    let recon_empty = recon
        .map(|r| r.is_empty())
        .transpose()
        .map_err(|e| SnapshotError::Store(e.to_string()))?
        .unwrap_or(true);
    if !force
        && (!fin
            .is_empty()
            .map_err(|e| SnapshotError::Store(e.to_string()))?
            || !data
                .is_empty()
                .map_err(|e| SnapshotError::Store(e.to_string()))?
            || !recon_empty
            || receipts_dir_has_state(receipts_dir)?)
    {
        return Err(SnapshotError::ExistingState);
    }

    let extracted = extract_snapshot_tar_to_temp(from_path)?;
    let manifest: SnapshotManifestV1 = {
        let raw = fs::read(extracted.dir.join("manifest.json"))?;
        serde_json::from_slice(&raw)?
    };

    // Validate required files.
    let required = [
        "hub-fin.kv",
        "hub-data.kv",
        "linkage.kv",
        "receipts.kv",
        "recon.kv",
    ];
    for f in required {
        let p = extracted.dir.join(f);
        if !p.exists() {
            return Err(SnapshotError::Corrupt(format!("missing {f}")));
        }
    }

    let expected = compute_integrity_hash(&[
        ("hub-fin.kv", &extracted.dir.join("hub-fin.kv")),
        ("hub-data.kv", &extracted.dir.join("hub-data.kv")),
        ("linkage.kv", &extracted.dir.join("linkage.kv")),
        ("receipts.kv", &extracted.dir.join("receipts.kv")),
        ("recon.kv", &extracted.dir.join("recon.kv")),
    ])?;
    if expected != manifest.hash {
        metrics::SNAPSHOT_FAILURES_TOTAL
            .with_label_values(&["restore", "hash_mismatch"])
            .inc();
        return Err(SnapshotError::HashMismatch);
    }

    // Wipe then import.
    if force {
        fin.clear_all()
            .map_err(|e| SnapshotError::Store(e.to_string()))?;
        data.clear_all()
            .map_err(|e| SnapshotError::Store(e.to_string()))?;
        if let Some(r) = recon {
            r.clear_all()
                .map_err(|e| SnapshotError::Store(e.to_string()))?;
        }
        // Receipts dir: only delete snapshot-managed files.
        wipe_receipts_dir(receipts_dir)?;
    }

    fin.import_kv_v1_into(&fs::read(extracted.dir.join("hub-fin.kv"))?)
        .map_err(|e| SnapshotError::Store(e.to_string()))?;
    data.import_kv_v1_into(&fs::read(extracted.dir.join("hub-data.kv"))?)
        .map_err(|e| SnapshotError::Store(e.to_string()))?;
    if let Some(r) = recon {
        r.import_kv_v1(&fs::read(extracted.dir.join("recon.kv"))?)
            .map_err(|e| SnapshotError::Store(e.to_string()))?;
    }
    restore_files_kv(receipts_dir, &fs::read(extracted.dir.join("receipts.kv"))?)?;
    restore_files_kv(receipts_dir, &fs::read(extracted.dir.join("linkage.kv"))?)?;

    // Best-effort flush.
    let _ = fin.flush();
    let _ = data.flush();
    if let Some(r) = recon {
        let _ = r.flush();
    }

    metrics::SNAPSHOTS_CREATED_TOTAL
        .with_label_values(&["restore_ok"])
        .inc();
    Ok(manifest)
}

fn write_store_kv<F>(path: &Path, label: &'static str, f: F) -> Result<(), SnapshotError>
where
    F: FnOnce(&mut fs::File) -> Result<(), String>,
{
    let mut file = fs::File::create(path)?;
    f(&mut file).map_err(|e| {
        metrics::SNAPSHOT_FAILURES_TOTAL
            .with_label_values(&["create", label])
            .inc();
        SnapshotError::Store(e)
    })?;
    file.flush()?;
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum FileKvScope {
    Receipts,
    Linkage,
}

fn write_files_kv(
    out: &Path,
    receipts_dir: &Path,
    scope: FileKvScope,
) -> Result<(), SnapshotError> {
    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();

    let root = receipts_dir.to_path_buf();
    if !root.exists() {
        // No receipts yet; write empty file deterministically.
        fs::write(out, [])?;
        return Ok(());
    }

    collect_files(&root, &root, &mut entries)?;
    // Filter scopes + exclude non-state files.
    entries.retain(|(rel, _)| match scope {
        FileKvScope::Receipts => !rel.starts_with("linkage/"),
        FileKvScope::Linkage => rel.starts_with("linkage/"),
    });
    entries.retain(|(rel, _)| {
        // Exclude test failpoints and hidden temp files.
        let file = rel.rsplit('/').next().unwrap_or(rel);
        if file.starts_with('_') {
            return false;
        }
        if scope == FileKvScope::Linkage {
            return rel.ends_with(".json");
        }
        true
    });

    entries.sort_by(|a, b| a.0.cmp(&b.0));

    let mut w = fs::File::create(out)?;
    for (k, v) in entries {
        write_kv_record_v1(&mut w, k.as_bytes(), &v)?;
    }
    w.flush()?;
    Ok(())
}

fn restore_files_kv(receipts_dir: &Path, bytes: &[u8]) -> Result<(), SnapshotError> {
    let mut cur = bytes;
    while !cur.is_empty() {
        if cur.len() < 8 {
            return Err(SnapshotError::Corrupt(
                "truncated file kv header".to_string(),
            ));
        }
        let k_len = u32::from_be_bytes(cur[0..4].try_into().unwrap()) as usize;
        let v_len = u32::from_be_bytes(cur[4..8].try_into().unwrap()) as usize;
        cur = &cur[8..];
        if cur.len() < k_len.saturating_add(v_len) {
            return Err(SnapshotError::Corrupt(
                "truncated file kv payload".to_string(),
            ));
        }
        let rel = std::str::from_utf8(&cur[..k_len])
            .map_err(|_| SnapshotError::Corrupt("invalid utf8 file key".to_string()))?;
        let data = &cur[k_len..k_len + v_len];
        let out_path = receipts_dir.join(rel);
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(out_path, data)?;
        cur = &cur[k_len + v_len..];
    }
    Ok(())
}

fn wipe_receipts_dir(receipts_dir: &Path) -> Result<(), SnapshotError> {
    if !receipts_dir.exists() {
        return Ok(());
    }
    // Delete only JSON receipts + known subtrees; do not delete unrelated operator files.
    let mut to_delete: Vec<PathBuf> = Vec::new();
    collect_paths_for_wipe(receipts_dir, receipts_dir, &mut to_delete)?;
    for p in to_delete {
        let _ = fs::remove_file(p);
    }
    Ok(())
}

fn collect_paths_for_wipe(
    root: &Path,
    dir: &Path,
    out: &mut Vec<PathBuf>,
) -> Result<(), SnapshotError> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let p = entry.path();
        if p.is_dir() {
            collect_paths_for_wipe(root, &p, out)?;
        } else {
            let rel = p.strip_prefix(root).unwrap_or(&p);
            let rel_s = rel.to_string_lossy();
            // Snapshot-managed receipt files.
            if rel_s.ends_with(".json") {
                out.push(p);
            }
        }
    }
    Ok(())
}

fn receipts_dir_has_state(receipts_dir: &Path) -> Result<bool, SnapshotError> {
    if !receipts_dir.exists() {
        return Ok(false);
    }
    for entry in fs::read_dir(receipts_dir)? {
        let entry = entry?;
        let p = entry.path();
        if p.is_file() {
            return Ok(true);
        }
        if p.is_dir() {
            // any file under dir counts as state
            if dir_has_any_file(&p)? {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn dir_has_any_file(dir: &Path) -> Result<bool, SnapshotError> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let p = entry.path();
        if p.is_file() {
            return Ok(true);
        }
        if p.is_dir() && dir_has_any_file(&p)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn collect_files(
    dir: &Path,
    root: &Path,
    out: &mut Vec<(String, Vec<u8>)>,
) -> Result<(), SnapshotError> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let p = entry.path();
        if p.is_dir() {
            collect_files(&p, root, out)?;
        } else if p.is_file() {
            let rel = p
                .strip_prefix(root)
                .unwrap_or(&p)
                .to_string_lossy()
                .replace('\\', "/");
            let bytes = fs::read(&p)?;
            out.push((rel, bytes));
        }
    }
    Ok(())
}

fn compute_counts(
    fin_kv: &Path,
    data_kv: &Path,
    receipts_kv: &Path,
    linkage_kv: &Path,
) -> Result<BTreeMap<String, u64>, SnapshotError> {
    let fin = fs::read(fin_kv)?;
    let data = fs::read(data_kv)?;
    let receipts = fs::read(receipts_kv)?;
    let linkage = fs::read(linkage_kv)?;

    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    // HUB-FIN
    count_prefix(&fin, b"asset:", "assets", &mut counts)?;
    count_prefix(&fin, b"bal:", "balances", &mut counts)?;
    count_prefix(&fin, b"delegation:", "delegations", &mut counts)?;
    count_prefix(&fin, b"applied:", "fin_applied", &mut counts)?;
    count_prefix(&fin, b"receipt:", "fin_receipts", &mut counts)?;
    // HUB-DATA
    count_prefix(&data, b"dataset:", "datasets", &mut counts)?;
    count_prefix(&data, b"license:", "licenses", &mut counts)?;
    count_prefix(&data, b"entitlement:", "entitlements", &mut counts)?;
    count_prefix(&data, b"applied:", "data_applied", &mut counts)?;
    count_prefix(&data, b"receipt:", "data_receipts", &mut counts)?;
    // Files
    counts.insert("receipts_files".to_string(), count_kv_records(&receipts)?);
    counts.insert("linkage_receipts".to_string(), count_kv_records(&linkage)?);
    Ok(counts)
}

fn count_prefix(
    kv_bytes: &[u8],
    prefix: &[u8],
    out_key: &str,
    counts: &mut BTreeMap<String, u64>,
) -> Result<(), SnapshotError> {
    let mut n = 0u64;
    for (k, _v) in iter_kv_records(kv_bytes)? {
        if k.starts_with(prefix) {
            n = n.saturating_add(1);
        }
    }
    counts.insert(out_key.to_string(), n);
    Ok(())
}

fn count_kv_records(kv_bytes: &[u8]) -> Result<u64, SnapshotError> {
    Ok(u64::try_from(iter_kv_records(kv_bytes)?.len()).unwrap_or(u64::MAX))
}

type KvPairs = Vec<(Vec<u8>, Vec<u8>)>;

fn iter_kv_records(bytes: &[u8]) -> Result<KvPairs, SnapshotError> {
    let mut out = Vec::new();
    let mut cur = bytes;
    while !cur.is_empty() {
        if cur.len() < 8 {
            return Err(SnapshotError::Corrupt("truncated kv header".to_string()));
        }
        let k_len = u32::from_be_bytes(cur[0..4].try_into().unwrap()) as usize;
        let v_len = u32::from_be_bytes(cur[4..8].try_into().unwrap()) as usize;
        cur = &cur[8..];
        if cur.len() < k_len.saturating_add(v_len) {
            return Err(SnapshotError::Corrupt("truncated kv payload".to_string()));
        }
        let k = cur[..k_len].to_vec();
        let v = cur[k_len..k_len + v_len].to_vec();
        cur = &cur[k_len + v_len..];
        out.push((k, v));
    }
    Ok(out)
}

fn compute_integrity_hash(files: &[(&str, &Path)]) -> Result<String, SnapshotError> {
    let mut hasher = blake3::Hasher::new();
    // Canonical ordering by file name.
    let mut sorted = files.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    for (name, path) in sorted {
        let bytes = fs::read(path)?;
        hasher.update(name.as_bytes());
        hasher.update(&[0]);
        hasher.update(&bytes);
        hasher.update(&[0]);
    }
    Ok(hasher.finalize().to_hex().to_string())
}

fn write_tar_atomic(
    out_path: &Path,
    manifest: &SnapshotManifestV1,
    files: &[(&str, &Path)],
) -> Result<(), SnapshotError> {
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }
    let tmp_path = out_path.with_extension("tar.tmp");
    let file = fs::File::create(&tmp_path)?;
    let mut builder = tar::Builder::new(file);

    // Add content files first.
    let mut sorted = files.to_vec();
    sorted.sort_by(|a, b| a.0.cmp(b.0));
    for (name, path) in sorted {
        append_file_to_tar(&mut builder, name, path)?;
    }

    // Add manifest.json last (not included in hash).
    let manifest_bytes = serde_json::to_vec_pretty(manifest)?;
    append_bytes_to_tar(&mut builder, "manifest.json", &manifest_bytes)?;

    builder
        .finish()
        .map_err(|e| SnapshotError::Tar(e.to_string()))?;

    // Atomic replace.
    fs::rename(&tmp_path, out_path)?;
    Ok(())
}

fn append_file_to_tar(
    builder: &mut tar::Builder<fs::File>,
    name: &str,
    path: &Path,
) -> Result<(), SnapshotError> {
    let mut f = fs::File::open(path)?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf)?;
    append_bytes_to_tar(builder, name, &buf)
}

fn append_bytes_to_tar(
    builder: &mut tar::Builder<fs::File>,
    name: &str,
    bytes: &[u8],
) -> Result<(), SnapshotError> {
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_uid(0);
    header.set_gid(0);
    header.set_cksum();
    builder
        .append_data(&mut header, name, std::io::Cursor::new(bytes))
        .map_err(|e| SnapshotError::Tar(e.to_string()))?;
    Ok(())
}

struct ExtractedSnapshot {
    _tmp: tempfile::TempDir,
    dir: PathBuf,
}

fn extract_snapshot_tar_to_temp(from_path: &Path) -> Result<ExtractedSnapshot, SnapshotError> {
    let tmp = tempfile::tempdir()?;
    let dir = tmp.path().to_path_buf();
    let file = fs::File::open(from_path)?;
    let mut archive = tar::Archive::new(file);
    archive
        .unpack(&dir)
        .map_err(|e| SnapshotError::Tar(e.to_string()))?;
    Ok(ExtractedSnapshot { _tmp: tmp, dir })
}

fn run_hook(hook: &str, path: &Path) -> Result<(), SnapshotError> {
    // Simple hook runner: split by whitespace (operator-friendly).
    let mut parts = hook.split_whitespace();
    let Some(bin) = parts.next() else {
        return Ok(());
    };
    let mut cmd = std::process::Command::new(bin);
    for a in parts {
        cmd.arg(a);
    }
    cmd.arg(path);
    let out = cmd.output().map_err(SnapshotError::Io)?;
    if !out.status.success() {
        return Err(SnapshotError::HookFailed(format!(
            "exit={} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        )));
    }
    Ok(())
}

fn write_kv_record_v1<W: Write>(w: &mut W, k: &[u8], v: &[u8]) -> std::io::Result<()> {
    let k_len = u32::try_from(k.len()).unwrap_or(u32::MAX);
    let v_len = u32::try_from(v.len()).unwrap_or(u32::MAX);
    w.write_all(&k_len.to_be_bytes())?;
    w.write_all(&v_len.to_be_bytes())?;
    w.write_all(k)?;
    w.write_all(v)?;
    Ok(())
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
