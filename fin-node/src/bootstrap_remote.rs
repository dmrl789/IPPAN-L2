#![forbid(unsafe_code)]

use crate::bootstrap::{BootstrapIndexV1, BootstrapSetV1};
use crate::config::FinNodeConfig;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

#[derive(Debug, thiserror::Error)]
pub enum BootstrapRemoteError {
    #[error("{code}: {message}")]
    Coded { code: &'static str, message: String },
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("http error: {0}")]
    Http(String),
    #[error("config error: {0}")]
    Config(String),
}

impl BootstrapRemoteError {
    pub fn coded(code: &'static str, message: impl Into<String>) -> Self {
        Self::Coded {
            code,
            message: message.into(),
        }
    }
}

// Error codes (Phase 4 requirement)
pub const BOOTSTRAP_INDEX_INVALID: &str = "BOOTSTRAP_INDEX_INVALID";
pub const BOOTSTRAP_HASH_MISMATCH: &str = "BOOTSTRAP_HASH_MISMATCH";
pub const BOOTSTRAP_INCOMPATIBLE: &str = "BOOTSTRAP_INCOMPATIBLE";
pub const BOOTSTRAP_TOO_LARGE: &str = "BOOTSTRAP_TOO_LARGE";
pub const BOOTSTRAP_SIGNATURE_INVALID: &str = "BOOTSTRAP_SIGNATURE_INVALID";

/// Remote bootstrap status persisted in the download cache directory.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BootstrapStatusV1 {
    pub schema_version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_fetched_base_hash: Option<String>,
    #[serde(default)]
    pub last_fetched_delta_hashes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_restored_base_hash: Option<String>,
    #[serde(default)]
    pub last_restored_delta_hashes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_updated_at_unix: Option<u64>,
}

/// Provenance for a completed fetch-and-restore run.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BootstrapProvenanceV1 {
    pub schema_version: u32,
    pub fetched_from: String,
    pub index_path: String,
    pub base_hash: String,
    #[serde(default)]
    pub delta_hashes: Vec<String>,
    pub restored_to_epoch: u64,
    pub restored_at_unix: u64,
}

pub fn read_bootstrap_status(
    cfg: &FinNodeConfig,
) -> Result<Option<BootstrapStatusV1>, BootstrapRemoteError> {
    let dir = cfg.bootstrap.remote.download_dir.as_str();
    let path = Path::new(dir).join("bootstrap_status.json");
    if !path.exists() {
        return Ok(None);
    }
    let raw = std::fs::read(path)?;
    let st: BootstrapStatusV1 = serde_json::from_slice(&raw)?;
    Ok(Some(st))
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct FetchPlanV1 {
    schema_version: u32,
    remote: String,
    index_url: String,
    max_download_bytes: u64,
    total_download_bytes: u64,
    artifacts: Vec<FetchArtifactV1>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct FetchArtifactV1 {
    kind: String, // "base" | "delta"
    path: String,
    url: String,
    expected_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    from_epoch: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    to_epoch: Option<u64>,
    size_bytes: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct DownloadStateV1 {
    schema_version: u32,
    downloads: Vec<DownloadEntryV1>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct DownloadEntryV1 {
    file: String,
    expected_hash: String,
    bytes_downloaded: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    etag: Option<String>,
}

pub fn fetch_remote_bootstrap(
    cfg: &FinNodeConfig,
    remote_name: &str,
    dry_run: bool,
) -> Result<(), BootstrapRemoteError> {
    // Metrics are exposed when fin-node runs with its HTTP server, but we also
    // increment them for CLI invocations for consistent accounting.
    let r = fetch_remote_bootstrap_inner(cfg, remote_name, dry_run);
    match &r {
        Ok(_) => crate::metrics::BOOTSTRAP_FETCH_TOTAL
            .with_label_values(&["ok"])
            .inc(),
        Err(e) => {
            crate::metrics::BOOTSTRAP_FETCH_TOTAL
                .with_label_values(&["err"])
                .inc();
            let _ = record_bootstrap_error(cfg, e);
        }
    }
    r
}

fn fetch_remote_bootstrap_inner(
    cfg: &FinNodeConfig,
    remote_name: &str,
    dry_run: bool,
) -> Result<(), BootstrapRemoteError> {
    cfg.bootstrap
        .validate()
        .map_err(BootstrapRemoteError::Config)?;
    if !cfg.bootstrap.remote.enabled {
        return Err(BootstrapRemoteError::coded(
            BOOTSTRAP_INDEX_INVALID,
            "remote bootstrap is disabled: set [bootstrap.remote].enabled=true",
        ));
    }
    if remote_name != cfg.bootstrap.remote.name {
        return Err(BootstrapRemoteError::coded(
            BOOTSTRAP_INDEX_INVALID,
            format!(
                "unknown remote '{remote_name}' (expected {})",
                cfg.bootstrap.remote.name
            ),
        ));
    }

    let remote = &cfg.bootstrap.remote;
    let base_url = remote.base_url.trim_end_matches('/').to_string();
    let index_path = remote.index_path.trim();
    validate_relative_path(index_path)
        .map_err(|e| BootstrapRemoteError::coded(BOOTSTRAP_INDEX_INVALID, e))?;
    let index_url = join_url(&base_url, index_path);

    // 1) Fetch index.json
    let client = http_client(cfg)?;
    let index_bytes = http_get_bytes(&client, &index_url)?;

    // Optional signature verification (Phase 5)
    verify_index_signature(cfg, &client, &base_url, index_path, &index_bytes)?;
    let index: BootstrapIndexV1 = parse_and_validate_index(&index_bytes)?;

    // 2) Select base + required deltas (latest set)
    let latest = select_latest_set(&index)?;
    validate_set_paths(&latest)?;

    // 3) Enforce max total download size (HEAD each artifact)
    let max_download_bytes = remote
        .max_download_mb
        .saturating_mul(1024)
        .saturating_mul(1024);
    let mut artifacts: Vec<FetchArtifactV1> = Vec::new();

    // base
    {
        let url = join_url(&base_url, &latest.base.path);
        let size = http_head_len(&client, &url)?;
        artifacts.push(FetchArtifactV1 {
            kind: "base".to_string(),
            path: latest.base.path.clone(),
            url,
            expected_hash: latest.base.hash.clone(),
            from_epoch: None,
            to_epoch: None,
            size_bytes: size,
        });
    }
    // deltas
    for d in &latest.deltas {
        let url = join_url(&base_url, &d.path);
        let size = http_head_len(&client, &url)?;
        artifacts.push(FetchArtifactV1 {
            kind: "delta".to_string(),
            path: d.path.clone(),
            url,
            expected_hash: d.hash.clone(),
            from_epoch: Some(d.from_epoch),
            to_epoch: Some(d.to_epoch),
            size_bytes: size,
        });
    }

    let total_download_bytes = artifacts
        .iter()
        .fold(0u64, |acc, a| acc.saturating_add(a.size_bytes));
    if total_download_bytes > max_download_bytes {
        return Err(BootstrapRemoteError::coded(
            BOOTSTRAP_TOO_LARGE,
            format!(
                "planned download too large: total_bytes={total_download_bytes} > max_bytes={max_download_bytes}"
            ),
        ));
    }

    let plan = FetchPlanV1 {
        schema_version: 1,
        remote: remote.name.clone(),
        index_url,
        max_download_bytes,
        total_download_bytes,
        artifacts,
    };

    // Persist the fetched index for auditing (always).
    let cache_dir = PathBuf::from(&remote.download_dir);
    std::fs::create_dir_all(&cache_dir)?;
    std::fs::write(cache_dir.join("index.json"), &index_bytes)?;

    if dry_run {
        println!("{}", serde_json::to_string_pretty(&plan)?);
        return Ok(());
    }

    // 4) Download artifacts (resume-safe).
    let artifacts_dir = cache_dir.join("artifacts");
    std::fs::create_dir_all(&artifacts_dir)?;
    let state_path = cache_dir.join("download_state.json");
    let state = Arc::new(Mutex::new(load_download_state(&state_path)?));

    download_all(
        &client,
        &artifacts_dir,
        &state_path,
        state.clone(),
        &plan.artifacts,
        remote.concurrency,
    )?;

    // 5) Verify hashes + compatibility.
    if let Err(e) = verify_downloaded_set(&plan.artifacts, &artifacts_dir, &latest) {
        crate::metrics::BOOTSTRAP_VERIFY_FAILURES_TOTAL.inc();
        return Err(e);
    }

    // 6) Update status file.
    write_bootstrap_status(
        &cache_dir,
        BootstrapStatusV1 {
            schema_version: 1,
            last_fetched_base_hash: Some(latest.base.hash.clone()),
            last_fetched_delta_hashes: latest.deltas.iter().map(|d| d.hash.clone()).collect(),
            last_restored_base_hash: None,
            last_restored_delta_hashes: Vec::new(),
            last_error: None,
            last_updated_at_unix: Some(unix_now_secs()),
        },
    )?;

    println!("{}", serde_json::to_string_pretty(&plan)?);
    Ok(())
}

pub fn fetch_and_restore(
    cfg: &FinNodeConfig,
    remote_name: &str,
    progress_path: &Path,
    force: bool,
) -> Result<(), BootstrapRemoteError> {
    let r = fetch_and_restore_inner(cfg, remote_name, progress_path, force);
    match &r {
        Ok(_) => crate::metrics::BOOTSTRAP_RESTORE_TOTAL
            .with_label_values(&["ok"])
            .inc(),
        Err(e) => {
            crate::metrics::BOOTSTRAP_RESTORE_TOTAL
                .with_label_values(&["err"])
                .inc();
            let _ = record_bootstrap_error(cfg, e);
        }
    }
    r
}

fn fetch_and_restore_inner(
    cfg: &FinNodeConfig,
    remote_name: &str,
    progress_path: &Path,
    force: bool,
) -> Result<(), BootstrapRemoteError> {
    cfg.bootstrap
        .validate()
        .map_err(BootstrapRemoteError::Config)?;
    if !cfg.snapshots.enabled {
        return Err(BootstrapRemoteError::coded(
            BOOTSTRAP_INDEX_INVALID,
            "snapshots are disabled: set [snapshots].enabled = true",
        ));
    }

    // 1) Fetch/download/verify artifacts.
    fetch_remote_bootstrap(cfg, remote_name, false)?;

    // 2) Load the cached index to locate downloaded files.
    let remote = &cfg.bootstrap.remote;
    let cache_dir = PathBuf::from(&remote.download_dir);
    let artifacts_dir = cache_dir.join("artifacts");
    let idx_bytes = std::fs::read(cache_dir.join("index.json"))?;
    let idx = parse_and_validate_index(&idx_bytes)?;
    let latest = select_latest_set(&idx)?;
    validate_set_paths(&latest)?;

    let base_tar = artifacts_dir.join(&latest.base.path);
    let delta_tars: Vec<PathBuf> = latest
        .deltas
        .iter()
        .map(|d| artifacts_dir.join(&d.path))
        .collect();

    // 3) Restore base + apply deltas (reuse existing restore/apply logic).
    let receipts_dir = Path::new(cfg.storage.receipts_dir.as_str());
    let fin_db_dir = cfg.storage.fin_db_dir.as_str();
    let data_db_dir = cfg.storage.data_db_dir.as_str();
    let recon_db_dir = cfg.storage.recon_db_dir.as_str();
    let bootstrap_db_dir = cfg.storage.bootstrap_db_dir.as_str();

    let fin = hub_fin::FinStore::open(fin_db_dir)
        .map_err(|e| BootstrapRemoteError::coded(BOOTSTRAP_INDEX_INVALID, e.to_string()))?;
    let data = hub_data::DataStore::open(data_db_dir)
        .map_err(|e| BootstrapRemoteError::coded(BOOTSTRAP_INDEX_INVALID, e.to_string()))?;
    let recon = crate::recon_store::ReconStore::open(recon_db_dir).ok();
    let bootstrap = crate::bootstrap_store::BootstrapStore::open(bootstrap_db_dir)
        .map_err(|e| BootstrapRemoteError::coded(BOOTSTRAP_INDEX_INVALID, e.to_string()))?;

    // Restore base snapshot.
    let base_manifest = crate::snapshot::restore_snapshot_v1_tar(
        &cfg.snapshots,
        &base_tar,
        &fin,
        &data,
        recon.as_ref(),
        receipts_dir,
        force,
    )
    .map_err(|e| BootstrapRemoteError::coded(BOOTSTRAP_INDEX_INVALID, e.to_string()))?;

    let base_snapshot_id = base_manifest.hash.clone();
    let _ = bootstrap.set_base_snapshot_id(&base_snapshot_id);

    // Initialize / validate progress.
    let mut prog = crate::bootstrap::read_progress(progress_path)
        .map_err(|e| BootstrapRemoteError::coded(BOOTSTRAP_INDEX_INVALID, e.to_string()))?
        .unwrap_or(crate::bootstrap::BootstrapProgressV1 {
            schema_version: 1,
            base_snapshot_id: base_snapshot_id.clone(),
            // Base restore represents a boundary; deltas start at epoch 1.
            last_applied_to_epoch: 1,
        });
    if prog.base_snapshot_id != base_snapshot_id {
        return Err(BootstrapRemoteError::coded(
            BOOTSTRAP_INDEX_INVALID,
            "progress file base_snapshot_id mismatch (refusing resume)",
        ));
    }
    if prog.last_applied_to_epoch < 1 {
        prog.last_applied_to_epoch = 1;
    }
    crate::bootstrap::write_progress_atomic(progress_path, &prog)
        .map_err(|e| BootstrapRemoteError::coded(BOOTSTRAP_INDEX_INVALID, e.to_string()))?;

    // Apply deltas in order (resume-capable).
    let mut cur_epoch = prog.last_applied_to_epoch;
    let mut applied_delta_hashes: Vec<String> = Vec::new();
    for (i, p) in delta_tars.iter().enumerate() {
        let d = crate::bootstrap::parse_delta_snapshot_v1_tar(p)
            .map_err(|e| BootstrapRemoteError::coded(BOOTSTRAP_INDEX_INVALID, e.to_string()))?;
        if d.manifest.base_snapshot_id != base_snapshot_id {
            return Err(BootstrapRemoteError::coded(
                BOOTSTRAP_INCOMPATIBLE,
                "delta base_snapshot_id mismatch (refusing restore)",
            ));
        }
        // Enforce the expected hash from the index (aligned to latest.deltas ordering).
        let expected = latest.deltas.get(i).map(|x| x.hash.as_str()).unwrap_or("");
        if d.manifest.hash != expected {
            return Err(BootstrapRemoteError::coded(
                BOOTSTRAP_HASH_MISMATCH,
                "delta hash mismatch vs index",
            ));
        }
        if d.manifest.to_epoch <= cur_epoch {
            continue;
        }
        if d.manifest.from_epoch != cur_epoch {
            return Err(BootstrapRemoteError::coded(
                BOOTSTRAP_INCOMPATIBLE,
                "delta epoch chain mismatch (missing or out-of-order delta)",
            ));
        }
        crate::bootstrap::apply_delta_changes_v1(
            &d.changes,
            &fin,
            &data,
            recon.as_ref(),
            receipts_dir,
        )
        .map_err(|e| BootstrapRemoteError::coded(BOOTSTRAP_INDEX_INVALID, e.to_string()))?;

        cur_epoch = d.manifest.to_epoch;
        applied_delta_hashes.push(d.manifest.hash);
        prog.last_applied_to_epoch = cur_epoch;
        crate::bootstrap::write_progress_atomic(progress_path, &prog)
            .map_err(|e| BootstrapRemoteError::coded(BOOTSTRAP_INDEX_INVALID, e.to_string()))?;
    }

    // Set epochs for subsequent delta cuts.
    let _ = fin.set_changelog_epoch(cur_epoch);
    let _ = data.set_changelog_epoch(cur_epoch);
    if let Some(r) = recon.as_ref() {
        let _ = r.set_changelog_epoch(cur_epoch);
    }
    let _ = bootstrap.set_epoch(cur_epoch);

    // 4) Write provenance file.
    write_bootstrap_provenance(
        &cache_dir,
        BootstrapProvenanceV1 {
            schema_version: 1,
            fetched_from: cfg.bootstrap.remote.base_url.clone(),
            index_path: cfg.bootstrap.remote.index_path.clone(),
            base_hash: base_snapshot_id.clone(),
            delta_hashes: latest.deltas.iter().map(|d| d.hash.clone()).collect(),
            restored_to_epoch: cur_epoch,
            restored_at_unix: unix_now_secs(),
        },
    )?;

    // 5) Update status.
    let prev = read_bootstrap_status(cfg).ok().flatten();
    write_bootstrap_status(
        &cache_dir,
        BootstrapStatusV1 {
            schema_version: 1,
            last_fetched_base_hash: prev
                .as_ref()
                .and_then(|p| p.last_fetched_base_hash.clone())
                .or(Some(latest.base.hash.clone())),
            last_fetched_delta_hashes: prev
                .as_ref()
                .map(|p| p.last_fetched_delta_hashes.clone())
                .unwrap_or_else(|| latest.deltas.iter().map(|d| d.hash.clone()).collect()),
            last_restored_base_hash: Some(base_snapshot_id),
            last_restored_delta_hashes: applied_delta_hashes,
            last_error: None,
            last_updated_at_unix: Some(unix_now_secs()),
        },
    )?;

    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "schema_version": 1,
            "base_snapshot_id": latest.base.hash,
            "applied_to_epoch": cur_epoch,
            "progress_file": progress_path.display().to_string(),
            "provenance_file": cache_dir.join("bootstrap_provenance.json").display().to_string()
        }))?
    );
    Ok(())
}

fn http_client(cfg: &FinNodeConfig) -> Result<reqwest::blocking::Client, BootstrapRemoteError> {
    let rcfg = &cfg.bootstrap.remote;
    let connect = std::time::Duration::from_millis(rcfg.connect_timeout_ms);
    let read = std::time::Duration::from_millis(rcfg.read_timeout_ms);
    reqwest::blocking::Client::builder()
        .connect_timeout(connect)
        .timeout(read)
        .build()
        .map_err(|e| BootstrapRemoteError::Http(e.to_string()))
}

fn http_get_bytes(
    client: &reqwest::blocking::Client,
    url: &str,
) -> Result<Vec<u8>, BootstrapRemoteError> {
    let resp = client
        .get(url)
        .send()
        .map_err(|e| BootstrapRemoteError::Http(e.to_string()))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(BootstrapRemoteError::Http(format!(
            "GET {url} failed: http_status={status}"
        )));
    }
    resp.bytes()
        .map(|b| b.to_vec())
        .map_err(|e| BootstrapRemoteError::Http(e.to_string()))
}

fn http_head_len(
    client: &reqwest::blocking::Client,
    url: &str,
) -> Result<u64, BootstrapRemoteError> {
    // Prefer HEAD, but fall back to GET range probe (some servers omit Content-Length for HEAD).
    if let Ok(resp) = client.head(url).send() {
        let status = resp.status();
        if status.is_success() {
            if let Some(len) = resp
                .headers()
                .get(reqwest::header::CONTENT_LENGTH)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
            {
                return Ok(len);
            }
        }
    }

    // Range probe: request 1 byte and parse Content-Range.
    let resp = client
        .get(url)
        .header(reqwest::header::RANGE, "bytes=0-0")
        .send()
        .map_err(|e| BootstrapRemoteError::Http(e.to_string()))?;
    let status = resp.status();
    if status == reqwest::StatusCode::PARTIAL_CONTENT {
        let cr = resp
            .headers()
            .get(reqwest::header::CONTENT_RANGE)
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                BootstrapRemoteError::coded(
                    BOOTSTRAP_INDEX_INVALID,
                    format!("missing Content-Range for {url}"),
                )
            })?;
        // Format: bytes 0-0/1234
        let total = cr
            .split('/')
            .nth(1)
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or_else(|| {
                BootstrapRemoteError::coded(
                    BOOTSTRAP_INDEX_INVALID,
                    format!("invalid Content-Range for {url}: {cr}"),
                )
            })?;
        return Ok(total);
    }
    if status.is_success() {
        if let Some(len) = resp
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
        {
            return Ok(len);
        }
    }
    Err(BootstrapRemoteError::coded(
        BOOTSTRAP_INDEX_INVALID,
        format!("missing or invalid Content-Length for {url}"),
    ))
}

fn parse_and_validate_index(bytes: &[u8]) -> Result<BootstrapIndexV1, BootstrapRemoteError> {
    let idx: BootstrapIndexV1 = serde_json::from_slice(bytes).map_err(|e| {
        BootstrapRemoteError::coded(BOOTSTRAP_INDEX_INVALID, format!("invalid index.json: {e}"))
    })?;
    if idx.schema_version != 1 {
        return Err(BootstrapRemoteError::coded(
            BOOTSTRAP_INDEX_INVALID,
            format!("unsupported index schema_version {}", idx.schema_version),
        ));
    }
    Ok(idx)
}

fn select_latest_set(idx: &BootstrapIndexV1) -> Result<BootstrapSetV1, BootstrapRemoteError> {
    let latest = idx.latest.clone();
    if latest.base.path.trim().is_empty() || latest.base.hash.trim().is_empty() {
        return Err(BootstrapRemoteError::coded(
            BOOTSTRAP_INDEX_INVALID,
            "latest.base is missing path/hash",
        ));
    }
    Ok(latest)
}

fn validate_set_paths(set: &BootstrapSetV1) -> Result<(), BootstrapRemoteError> {
    validate_relative_path(&set.base.path)
        .map_err(|e| BootstrapRemoteError::coded(BOOTSTRAP_INDEX_INVALID, e))?;
    for d in &set.deltas {
        validate_relative_path(&d.path)
            .map_err(|e| BootstrapRemoteError::coded(BOOTSTRAP_INDEX_INVALID, e))?;
    }

    // Validate delta chain ordering/continuity (best-effort guard).
    let mut prev_to: Option<u64> = None;
    for d in &set.deltas {
        if let Some(prev) = prev_to {
            if d.from_epoch != prev {
                return Err(BootstrapRemoteError::coded(
                    BOOTSTRAP_INDEX_INVALID,
                    "delta chain is not contiguous (from_epoch != previous to_epoch)",
                ));
            }
        }
        if d.to_epoch <= d.from_epoch {
            return Err(BootstrapRemoteError::coded(
                BOOTSTRAP_INDEX_INVALID,
                "delta has invalid epoch range (to_epoch <= from_epoch)",
            ));
        }
        prev_to = Some(d.to_epoch);
    }
    Ok(())
}

fn validate_relative_path(p: &str) -> Result<(), String> {
    let p = p.trim();
    if p.is_empty() {
        return Err("empty path".to_string());
    }
    if p.contains('\\') {
        return Err("invalid path separator (backslash)".to_string());
    }
    let path = Path::new(p);
    if path.is_absolute() {
        return Err("absolute paths are not allowed".to_string());
    }
    for c in path.components() {
        match c {
            std::path::Component::ParentDir => {
                return Err("path traversal ('..') is not allowed".to_string())
            }
            std::path::Component::CurDir => {
                return Err("path segment '.' is not allowed".to_string())
            }
            std::path::Component::RootDir | std::path::Component::Prefix(_) => {
                return Err("invalid path component".to_string())
            }
            std::path::Component::Normal(_) => {}
        }
    }
    Ok(())
}

fn join_url(base_url: &str, rel_path: &str) -> String {
    format!(
        "{}/{}",
        base_url.trim_end_matches('/'),
        rel_path.trim_start_matches('/')
    )
}

fn load_download_state(path: &Path) -> Result<DownloadStateV1, BootstrapRemoteError> {
    if !path.exists() {
        return Ok(DownloadStateV1 {
            schema_version: 1,
            downloads: Vec::new(),
        });
    }
    let raw = std::fs::read(path)?;
    let st: DownloadStateV1 = serde_json::from_slice(&raw)?;
    Ok(st)
}

fn write_download_state_atomic(
    path: &Path,
    st: &DownloadStateV1,
) -> Result<(), BootstrapRemoteError> {
    let tmp = path.with_extension("json.tmp");
    let bytes = serde_json::to_vec_pretty(st)?;
    std::fs::write(&tmp, bytes)?;
    std::fs::rename(tmp, path)?;
    Ok(())
}

fn write_bootstrap_status(
    cache_dir: &Path,
    st: BootstrapStatusV1,
) -> Result<(), BootstrapRemoteError> {
    let path = cache_dir.join("bootstrap_status.json");
    let tmp = cache_dir.join("bootstrap_status.json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&st)?)?;
    std::fs::rename(tmp, path)?;
    Ok(())
}

fn record_bootstrap_error(
    cfg: &FinNodeConfig,
    e: &BootstrapRemoteError,
) -> Result<(), BootstrapRemoteError> {
    let dir = cfg.bootstrap.remote.download_dir.trim();
    if dir.is_empty() {
        return Ok(());
    }
    let cache_dir = PathBuf::from(dir);
    let _ = std::fs::create_dir_all(&cache_dir);
    let prev = read_bootstrap_status(cfg).ok().flatten();
    write_bootstrap_status(
        &cache_dir,
        BootstrapStatusV1 {
            schema_version: 1,
            last_fetched_base_hash: prev.as_ref().and_then(|p| p.last_fetched_base_hash.clone()),
            last_fetched_delta_hashes: prev
                .as_ref()
                .map(|p| p.last_fetched_delta_hashes.clone())
                .unwrap_or_default(),
            last_restored_base_hash: prev
                .as_ref()
                .and_then(|p| p.last_restored_base_hash.clone()),
            last_restored_delta_hashes: prev
                .as_ref()
                .map(|p| p.last_restored_delta_hashes.clone())
                .unwrap_or_default(),
            last_error: Some(e.to_string()),
            last_updated_at_unix: Some(unix_now_secs()),
        },
    )?;
    Ok(())
}

fn write_bootstrap_provenance(
    cache_dir: &Path,
    p: BootstrapProvenanceV1,
) -> Result<(), BootstrapRemoteError> {
    let path = cache_dir.join("bootstrap_provenance.json");
    let tmp = cache_dir.join("bootstrap_provenance.json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&p)?)?;
    std::fs::rename(tmp, path)?;
    Ok(())
}

fn download_all(
    client: &reqwest::blocking::Client,
    artifacts_dir: &Path,
    state_path: &Path,
    state: Arc<Mutex<DownloadStateV1>>,
    artifacts: &[FetchArtifactV1],
    concurrency: usize,
) -> Result<(), BootstrapRemoteError> {
    let concurrency = concurrency.clamp(1, 32);
    let (tx, rx) = std::sync::mpsc::channel::<Result<(), BootstrapRemoteError>>();
    let mut in_flight = 0usize;
    let mut iter = artifacts.iter();

    loop {
        while in_flight < concurrency {
            let Some(a) = iter.next().cloned() else { break };
            let client = client.clone();
            let artifacts_dir = artifacts_dir.to_path_buf();
            let state_path = state_path.to_path_buf();
            let state = state.clone();
            let tx = tx.clone();
            std::thread::spawn(move || {
                let r = download_one(&client, &artifacts_dir, &state_path, state, &a);
                let _ = tx.send(r);
            });
            in_flight += 1;
        }

        if in_flight == 0 {
            break;
        }

        match rx.recv() {
            Ok(Ok(())) => {
                in_flight = in_flight.saturating_sub(1);
            }
            Ok(Err(e)) => return Err(e),
            Err(_e) => {
                return Err(BootstrapRemoteError::coded(
                    BOOTSTRAP_INDEX_INVALID,
                    "download worker channel closed unexpectedly",
                ))
            }
        }
    }
    Ok(())
}

fn download_one(
    client: &reqwest::blocking::Client,
    artifacts_dir: &Path,
    state_path: &Path,
    state: Arc<Mutex<DownloadStateV1>>,
    a: &FetchArtifactV1,
) -> Result<(), BootstrapRemoteError> {
    // Ensure the output path is confined under artifacts_dir.
    validate_relative_path(&a.path)
        .map_err(|e| BootstrapRemoteError::coded(BOOTSTRAP_INDEX_INVALID, e))?;
    let out_path = artifacts_dir.join(&a.path);
    if let Some(parent) = out_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let file_name = out_path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| BootstrapRemoteError::coded(BOOTSTRAP_INDEX_INVALID, "invalid file name"))?;
    let part_path = out_path.with_file_name(format!("{file_name}.part"));

    // If complete file exists and size matches, skip download (verification happens later).
    if let Ok(meta) = std::fs::metadata(&out_path) {
        if meta.is_file() && meta.len() == a.size_bytes {
            update_download_entry(&state, state_path, a, a.size_bytes)?;
            return Ok(());
        }
    }

    let mut downloaded = std::fs::metadata(&part_path).map(|m| m.len()).unwrap_or(0);
    if downloaded > a.size_bytes {
        // Corrupt partial file; restart.
        let _ = std::fs::remove_file(&part_path);
        downloaded = 0;
    }

    let mut attempt = 0u32;
    loop {
        attempt = attempt.saturating_add(1);
        let etag = lookup_etag(&state, &a.path, &a.expected_hash);
        let mut req = client.get(&a.url);
        if downloaded > 0 {
            req = req.header(reqwest::header::RANGE, format!("bytes={downloaded}-"));
            if let Some(etag) = etag.as_ref() {
                req = req.header(reqwest::header::IF_RANGE, etag.as_str());
            }
        }

        let resp = match req.send() {
            Ok(r) => r,
            Err(e) => {
                if attempt >= 5 {
                    return Err(BootstrapRemoteError::Http(e.to_string()));
                }
                std::thread::sleep(backoff(attempt));
                continue;
            }
        };
        let status = resp.status();

        // Update ETag best-effort.
        if let Some(etag_val) = resp
            .headers()
            .get(reqwest::header::ETAG)
            .and_then(|v| v.to_str().ok())
        {
            set_etag(&state, state_path, a, etag_val.to_string())?;
        }

        if status == reqwest::StatusCode::RANGE_NOT_SATISFIABLE {
            // If we've already got the full content, accept.
            if downloaded == a.size_bytes {
                break;
            }
            // Otherwise restart.
            let _ = std::fs::remove_file(&part_path);
            downloaded = 0;
            continue;
        }

        if !(status.is_success()) {
            if attempt >= 5 {
                return Err(BootstrapRemoteError::Http(format!(
                    "GET {} failed: http_status={status}",
                    a.url
                )));
            }
            std::thread::sleep(backoff(attempt));
            continue;
        }

        // If server ignored range and returned full content, restart from zero.
        if downloaded > 0 && status == reqwest::StatusCode::OK {
            let _ = std::fs::remove_file(&part_path);
            downloaded = 0;
        }

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(downloaded > 0)
            .truncate(downloaded == 0)
            .open(&part_path)?;

        let mut reader = resp;
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = std::io::Read::read(&mut reader, &mut buf)?;
            if n == 0 {
                break;
            }
            std::io::Write::write_all(&mut file, &buf[..n])?;
            crate::metrics::BOOTSTRAP_BYTES_DOWNLOADED_TOTAL
                .inc_by(u64::try_from(n).unwrap_or(u64::MAX));
            downloaded = downloaded.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
            if downloaded > a.size_bytes {
                return Err(BootstrapRemoteError::coded(
                    BOOTSTRAP_INDEX_INVALID,
                    format!("download exceeded expected size for {}", a.path),
                ));
            }
            // Best-effort persist progress.
            update_download_entry(&state, state_path, a, downloaded)?;
        }
        break;
    }

    // Final size check.
    let meta = std::fs::metadata(&part_path)?;
    if meta.len() != a.size_bytes {
        return Err(BootstrapRemoteError::coded(
            BOOTSTRAP_INDEX_INVALID,
            format!(
                "incomplete download for {}: have={} expected={}",
                a.path,
                meta.len(),
                a.size_bytes
            ),
        ));
    }

    // Atomic promote.
    std::fs::rename(&part_path, &out_path)?;
    update_download_entry(&state, state_path, a, a.size_bytes)?;
    Ok(())
}

fn update_download_entry(
    state: &Arc<Mutex<DownloadStateV1>>,
    state_path: &Path,
    a: &FetchArtifactV1,
    bytes: u64,
) -> Result<(), BootstrapRemoteError> {
    let mut st = state.lock().map_err(|_| {
        BootstrapRemoteError::coded(BOOTSTRAP_INDEX_INVALID, "download state mutex poisoned")
    })?;
    if let Some(e) = st
        .downloads
        .iter_mut()
        .find(|e| e.file == a.path && e.expected_hash == a.expected_hash)
    {
        e.bytes_downloaded = bytes;
    } else {
        st.downloads.push(DownloadEntryV1 {
            file: a.path.clone(),
            expected_hash: a.expected_hash.clone(),
            bytes_downloaded: bytes,
            etag: None,
        });
    }
    write_download_state_atomic(state_path, &st)?;
    Ok(())
}

fn lookup_etag(
    state: &Arc<Mutex<DownloadStateV1>>,
    file: &str,
    expected_hash: &str,
) -> Option<String> {
    let st = state.lock().ok()?;
    st.downloads
        .iter()
        .find(|e| e.file == file && e.expected_hash == expected_hash)
        .and_then(|e| e.etag.clone())
}

fn set_etag(
    state: &Arc<Mutex<DownloadStateV1>>,
    state_path: &Path,
    a: &FetchArtifactV1,
    etag: String,
) -> Result<(), BootstrapRemoteError> {
    let mut st = state.lock().map_err(|_| {
        BootstrapRemoteError::coded(BOOTSTRAP_INDEX_INVALID, "download state mutex poisoned")
    })?;
    if let Some(e) = st
        .downloads
        .iter_mut()
        .find(|e| e.file == a.path && e.expected_hash == a.expected_hash)
    {
        e.etag = Some(etag);
    } else {
        st.downloads.push(DownloadEntryV1 {
            file: a.path.clone(),
            expected_hash: a.expected_hash.clone(),
            bytes_downloaded: 0,
            etag: Some(etag),
        });
    }
    write_download_state_atomic(state_path, &st)?;
    Ok(())
}

fn backoff(attempt: u32) -> std::time::Duration {
    // Deterministic exponential backoff: 200ms, 400ms, 800ms, 1600ms...
    let base_ms = 200u64;
    let pow = attempt.saturating_sub(1).min(5);
    let factor = 1u64.checked_shl(pow).unwrap_or(u64::MAX);
    let ms = base_ms.saturating_mul(factor);
    std::time::Duration::from_millis(ms)
}

fn verify_downloaded_set(
    artifacts: &[FetchArtifactV1],
    artifacts_dir: &Path,
    latest: &BootstrapSetV1,
) -> Result<(), BootstrapRemoteError> {
    // Base
    let base_path = artifacts_dir.join(&latest.base.path);
    let base_manifest = crate::snapshot::verify_snapshot_v1_tar(&base_path).map_err(|e| {
        BootstrapRemoteError::coded(BOOTSTRAP_HASH_MISMATCH, format!("base verify failed: {e}"))
    })?;
    if base_manifest.hash != latest.base.hash {
        return Err(BootstrapRemoteError::coded(
            BOOTSTRAP_HASH_MISMATCH,
            "base snapshot manifest hash mismatch vs index",
        ));
    }
    ensure_compatible_snapshot(&base_manifest)?;

    // Deltas
    let mut expected_delta_hashes: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for a in artifacts.iter().filter(|a| a.kind == "delta") {
        expected_delta_hashes.insert(a.path.clone(), a.expected_hash.clone());
    }
    for d in &latest.deltas {
        let p = artifacts_dir.join(&d.path);
        let parsed = crate::bootstrap::parse_delta_snapshot_v1_tar(&p).map_err(|e| {
            BootstrapRemoteError::coded(
                BOOTSTRAP_HASH_MISMATCH,
                format!("delta verify failed: {e}"),
            )
        })?;
        if parsed.manifest.hash != d.hash {
            return Err(BootstrapRemoteError::coded(
                BOOTSTRAP_HASH_MISMATCH,
                "delta manifest hash mismatch vs index",
            ));
        }
        if parsed.manifest.base_snapshot_id != latest.base.hash {
            return Err(BootstrapRemoteError::coded(
                BOOTSTRAP_INCOMPATIBLE,
                "delta base_snapshot_id mismatch vs latest.base.hash",
            ));
        }
        let cur_mm = version_major_minor(env!("CARGO_PKG_VERSION"));
        let delta_mm = version_major_minor(&parsed.manifest.ippan_l2_version);
        if cur_mm != delta_mm {
            return Err(BootstrapRemoteError::coded(
                BOOTSTRAP_INCOMPATIBLE,
                "delta ippan_l2_version incompatible (major/minor mismatch)",
            ));
        }
        // Ensure we only accept the deltas referenced by the index (no extra).
        if expected_delta_hashes.get(&d.path).map(|h| h.as_str())
            != Some(parsed.manifest.hash.as_str())
        {
            return Err(BootstrapRemoteError::coded(
                BOOTSTRAP_INDEX_INVALID,
                "delta expected hash mapping mismatch",
            ));
        }
    }
    Ok(())
}

fn ensure_compatible_snapshot(
    m: &crate::snapshot::SnapshotManifestV1,
) -> Result<(), BootstrapRemoteError> {
    if m.snapshot_version != crate::snapshot::SNAPSHOT_VERSION_V1 {
        return Err(BootstrapRemoteError::coded(
            BOOTSTRAP_INCOMPATIBLE,
            "unsupported snapshot_version",
        ));
    }
    let cur_mm = version_major_minor(env!("CARGO_PKG_VERSION"));
    let snap_mm = version_major_minor(&m.ippan_l2_version);
    if cur_mm != snap_mm {
        return Err(BootstrapRemoteError::coded(
            BOOTSTRAP_INCOMPATIBLE,
            "snapshot ippan_l2_version incompatible (major/minor mismatch)",
        ));
    }
    let target = target_state_version();
    let fin_v = m.state_versions.get("fin").copied().unwrap_or(0);
    let data_v = m.state_versions.get("data").copied().unwrap_or(0);
    if fin_v < target || data_v < target {
        return Err(BootstrapRemoteError::coded(
            BOOTSTRAP_INCOMPATIBLE,
            "snapshot state_versions are incompatible",
        ));
    }
    Ok(())
}

fn target_state_version() -> u32 {
    // Keep in sync with `TARGET_STATE_VERSION` in `fin-node/src/main.rs`.
    2
}

fn version_major_minor(v: &str) -> (u64, u64) {
    let mut it = v.split('.');
    let major = it.next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
    let minor = it.next().and_then(|s| s.parse::<u64>().ok()).unwrap_or(0);
    (major, minor)
}

fn verify_index_signature(
    cfg: &FinNodeConfig,
    client: &reqwest::blocking::Client,
    base_url: &str,
    index_path: &str,
    index_bytes: &[u8],
) -> Result<(), BootstrapRemoteError> {
    let scfg = &cfg.bootstrap.signing;
    if !scfg.enabled {
        return Ok(());
    }
    if !cfg!(feature = "bootstrap-signing") {
        return Err(BootstrapRemoteError::coded(
            BOOTSTRAP_INDEX_INVALID,
            "bootstrap.signing is enabled but fin-node was built without feature bootstrap-signing",
        ));
    }

    let sig_rel = index_sig_rel_path(index_path);
    let sig_url = join_url(base_url, &sig_rel);

    let sig_bytes = match http_get_bytes(client, &sig_url) {
        Ok(b) => b,
        Err(e) => {
            if scfg.required {
                return Err(BootstrapRemoteError::coded(
                    BOOTSTRAP_SIGNATURE_INVALID,
                    format!("missing index signature (required): {e}"),
                ));
            }
            // Optional signatures: allow missing `index.sig`.
            return Ok(());
        }
    };

    #[cfg(feature = "bootstrap-signing")]
    {
        verify_index_signature_bytes(scfg.publisher_pubkeys.as_slice(), index_bytes, &sig_bytes)
    }
    #[cfg(not(feature = "bootstrap-signing"))]
    {
        let _ = sig_bytes;
        Err(BootstrapRemoteError::coded(
            BOOTSTRAP_INDEX_INVALID,
            "bootstrap-signing feature is disabled",
        ))
    }
}

fn index_sig_rel_path(index_path: &str) -> String {
    let p = Path::new(index_path);
    match p.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent
            .join("index.sig")
            .to_string_lossy()
            .replace('\\', "/"),
        _ => "index.sig".to_string(),
    }
}

#[cfg(feature = "bootstrap-signing")]
fn verify_index_signature_bytes(
    publisher_pubkeys_hex: &[String],
    index_bytes: &[u8],
    sig_bytes: &[u8],
) -> Result<(), BootstrapRemoteError> {
    use ed25519_dalek::VerifyingKey;

    let sig = parse_signature(sig_bytes)?;
    let msg = signing_message(index_bytes);

    for (i, pk_hex) in publisher_pubkeys_hex.iter().enumerate() {
        let raw = hex::decode(pk_hex).map_err(|e| {
            BootstrapRemoteError::coded(
                BOOTSTRAP_INDEX_INVALID,
                format!("invalid publisher_pubkeys[{i}] hex: {e}"),
            )
        })?;
        if raw.len() != 32 {
            continue;
        }
        let mut pk = [0u8; 32];
        pk.copy_from_slice(&raw);
        let vk = match VerifyingKey::from_bytes(&pk) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if vk.verify_strict(&msg, &sig).is_ok() {
            return Ok(());
        }
    }

    Err(BootstrapRemoteError::coded(
        BOOTSTRAP_SIGNATURE_INVALID,
        "index signature verification failed (no matching publisher key)",
    ))
}

#[cfg(feature = "bootstrap-signing")]
fn parse_signature(sig_bytes: &[u8]) -> Result<ed25519_dalek::Signature, BootstrapRemoteError> {
    let s = std::str::from_utf8(sig_bytes).map_err(|_| {
        BootstrapRemoteError::coded(BOOTSTRAP_SIGNATURE_INVALID, "index.sig is not utf-8")
    })?;
    let raw = hex::decode(s.trim()).map_err(|e| {
        BootstrapRemoteError::coded(
            BOOTSTRAP_SIGNATURE_INVALID,
            format!("index.sig invalid hex: {e}"),
        )
    })?;
    if raw.len() != 64 {
        return Err(BootstrapRemoteError::coded(
            BOOTSTRAP_SIGNATURE_INVALID,
            format!("index.sig must be 64 bytes (got {})", raw.len()),
        ));
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&raw);
    Ok(ed25519_dalek::Signature::from_bytes(&out))
}

#[cfg(feature = "bootstrap-signing")]
fn signing_message(index_bytes: &[u8]) -> Vec<u8> {
    const DOMAIN: &[u8] = b"IPPAN-L2:BOOTSTRAP_INDEX:V1\n";
    let mut out = Vec::with_capacity(DOMAIN.len() + index_bytes.len());
    out.extend_from_slice(DOMAIN);
    out.extend_from_slice(index_bytes);
    out
}

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::validate_relative_path;

    #[test]
    fn rejects_path_traversal() {
        assert!(validate_relative_path("../x.tar").is_err());
        assert!(validate_relative_path("deltas/../../x.tar").is_err());
        assert!(validate_relative_path("/abs.tar").is_err());
        assert!(validate_relative_path("deltas\\x.tar").is_err());
    }
}
