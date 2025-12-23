#![forbid(unsafe_code)]
// Prometheus histograms require `f64` observations.
#![allow(clippy::float_arithmetic)]
#![allow(clippy::float_cmp)]
#![allow(clippy::disallowed_types)]

use crate::bootstrap::source::{
    BootstrapSource as _, BootstrapSourceError, HttpSource, PeerSource,
};
use crate::bootstrap::{BootstrapIndexV1, BootstrapSetV1};
use crate::bootstrap_mirror_health::MirrorHealthStore;
use crate::config::FinNodeConfig;
use crate::config::{BootstrapArtifactQuorumMode, BootstrapSourcesMode};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

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
    #[error("source error: {0}")]
    Source(String),
}

impl BootstrapRemoteError {
    pub fn coded(code: &'static str, message: impl Into<String>) -> Self {
        Self::Coded {
            code,
            message: message.into(),
        }
    }
}

impl From<BootstrapSourceError> for BootstrapRemoteError {
    fn from(e: BootstrapSourceError) -> Self {
        BootstrapRemoteError::Source(e.to_string())
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
    #[serde(default)]
    pub index_fetched_from: Option<String>,
    pub base_hash: String,
    #[serde(default)]
    pub delta_hashes: Vec<String>,
    #[serde(default)]
    pub artifact_sources: Vec<BootstrapArtifactSourceV1>,
    pub restored_to_epoch: u64,
    pub restored_at_unix: u64,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BootstrapArtifactSourceV1 {
    pub kind: String, // "base" | "delta"
    pub path: String,
    pub expected_hash: String,
    /// Distinct peers that independently produced a valid artifact (quorum).
    #[serde(default)]
    pub fetched_from: Vec<String>,
    /// Whether the final file was obtained via primary HTTP fallback.
    #[serde(default)]
    pub used_http_fallback: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BootstrapFetchProvenanceV1 {
    pub schema_version: u32,
    pub index_path: String,
    pub index_fetched_from: String,
    #[serde(default)]
    pub index_quorum_sources: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub index_hash: Option<String>,
    #[serde(default)]
    pub artifacts: Vec<BootstrapArtifactSourceV1>,
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
    /// Local storage path under the cache `artifacts/` directory (derived from index `path`).
    path: String,
    /// Relative path to request from the primary HTTP source (typically index `path`).
    primary_path: String,
    /// Relative path to request from peers (typically `ca_path` if present, else `path`).
    peer_path: String,
    /// Human-friendly primary URL for planning/auditing.
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
    // Ensure new metrics are registered even if not triggered yet.
    let _ = &*crate::metrics::BOOTSTRAP_ROLLBACK_BLOCKED_TOTAL;
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
    let index_path = remote.index_path.trim();
    validate_relative_path(index_path)
        .map_err(|e| BootstrapRemoteError::coded(BOOTSTRAP_INDEX_INVALID, e))?;
    let index_url = join_url(&remote.base_url, index_path);

    // 1) Fetch index.json (single/mirrors/mirrors_quorum).
    let primary = build_primary_source(cfg)?;
    let peers = build_peer_sources(cfg)?;
    let (index_bytes, index_fetched_from, index_quorum_sources, index_hash) =
        match cfg.bootstrap.sources.mode {
            BootstrapSourcesMode::MirrorsQuorum => fetch_index_with_quorum(cfg, index_path)?,
            _ => {
                // Backward-compatible single-source fetch with fallback.
                let (b, from) = fetch_index_with_fallback(cfg, &primary, peers.as_slice())?;
                // Optional signature verification for the chosen source.
                verify_index_signature(cfg, &primary, index_path, &b, &from, peers.as_slice())?;
                let h = blake3::hash(b.as_ref()).to_hex().to_string();
                (b, from, Vec::new(), h)
            }
        };
    let index: BootstrapIndexV1 = parse_and_validate_index(index_bytes.as_ref())?;

    // 2) Select base + required deltas (latest set)
    let latest = select_latest_set(&index)?;
    validate_set_paths(&latest)?;

    // 3) Enforce max total download size (index sizes preferred; else HEAD probe)
    let max_download_bytes = remote
        .max_download_mb
        .saturating_mul(1024)
        .saturating_mul(1024);
    let mut artifacts: Vec<FetchArtifactV1> = Vec::new();

    // base
    {
        let primary_path = latest.base.path.clone();
        let peer_path = latest
            .base
            .ca_path
            .clone()
            .unwrap_or_else(|| latest.base.path.clone());
        let url = primary.url_for(&primary_path);
        let size = resolve_artifact_size(
            &primary,
            peers.as_slice(),
            latest.base.size,
            &primary_path,
            &peer_path,
        )?;
        artifacts.push(FetchArtifactV1 {
            kind: "base".to_string(),
            path: latest.base.path.clone(),
            primary_path,
            peer_path,
            url,
            expected_hash: latest.base.hash.clone(),
            from_epoch: None,
            to_epoch: None,
            size_bytes: size,
        });
    }
    // deltas
    for d in &latest.deltas {
        let primary_path = d.path.clone();
        let peer_path = d.ca_path.clone().unwrap_or_else(|| d.path.clone());
        let url = primary.url_for(&primary_path);
        let size = resolve_artifact_size(
            &primary,
            peers.as_slice(),
            d.size,
            &primary_path,
            &peer_path,
        )?;
        artifacts.push(FetchArtifactV1 {
            kind: "delta".to_string(),
            path: d.path.clone(),
            primary_path,
            peer_path,
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
    std::fs::write(cache_dir.join("index.json"), index_bytes.as_ref())?;
    // Persist fetch provenance for later restore/provenance reporting.
    let _ = std::fs::write(
        cache_dir.join("bootstrap_fetch_provenance.json"),
        serde_json::to_vec_pretty(&BootstrapFetchProvenanceV1 {
            schema_version: 1,
            index_path: index_path.to_string(),
            index_fetched_from: index_fetched_from.clone(),
            index_quorum_sources: index_quorum_sources.clone(),
            index_hash: Some(index_hash.clone()),
            artifacts: Vec::new(),
        })
        .unwrap_or_default(),
    );

    if dry_run {
        println!("{}", serde_json::to_string_pretty(&plan)?);
        return Ok(());
    }

    // 4) Download artifacts (resume-safe).
    let artifacts_dir = cache_dir.join("artifacts");
    std::fs::create_dir_all(&artifacts_dir)?;
    let state_path = cache_dir.join("download_state.json");
    let state = Arc::new(Mutex::new(load_download_state(&state_path)?));

    let transfer = &cfg.bootstrap.transfer;
    let limiter = ByteRateLimiter::new(transfer.max_mbps);
    let max_conc = transfer
        .max_concurrency
        .min(remote.concurrency)
        .clamp(1, 32);

    let http_sources = build_http_sources_for_artifacts(cfg, &primary)?;
    let mut fetch_artifact_prov: Vec<BootstrapArtifactSourceV1> = Vec::new();
    download_all(
        http_sources.as_slice(),
        peers.as_slice(),
        cfg,
        &artifacts_dir,
        &state_path,
        state.clone(),
        &plan.artifacts,
        max_conc,
        limiter.clone(),
        &mut fetch_artifact_prov,
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

    // Best-effort persist fetch provenance with per-artifact sources.
    let _ = std::fs::write(
        cache_dir.join("bootstrap_fetch_provenance.json"),
        serde_json::to_vec_pretty(&BootstrapFetchProvenanceV1 {
            schema_version: 1,
            index_path: index_path.to_string(),
            index_fetched_from: index_fetched_from.clone(),
            index_quorum_sources: index_quorum_sources.clone(),
            index_hash: Some(index_hash.clone()),
            artifacts: fetch_artifact_prov,
        })
        .unwrap_or_default(),
    );
    Ok(())
}

#[derive(Clone)]
struct IndexSource {
    name: String,
    base_url: String,
    src: HttpSource,
}

fn fetch_index_with_quorum(
    cfg: &FinNodeConfig,
    index_path: &str,
) -> Result<(bytes::Bytes, String, Vec<String>, String), BootstrapRemoteError> {
    let sources = build_index_sources(cfg)?;
    let max_sources = cfg.bootstrap.sources.max_sources.clamp(1, 10);
    let quorum = cfg.bootstrap.sources.quorum.max(1);
    let mut sources = sources;
    sources.truncate(max_sources);

    let mh = MirrorHealthStore::open(cfg.storage.bootstrap_db_dir.as_str()).ok();
    let now_ms = unix_now_millis();

    let (tx, rx) = std::sync::mpsc::channel::<(
        String,
        String,
        u128,
        Result<bytes::Bytes, BootstrapRemoteError>,
    )>();
    for s in sources.iter().cloned() {
        let tx = tx.clone();
        let cfg = cfg.clone();
        let index_path = index_path.to_string();
        std::thread::spawn(move || {
            let started = std::time::Instant::now();
            let r = fetch_index_one(&cfg, &s, &index_path);
            let latency_ms = started.elapsed().as_millis();
            let _ = tx.send((s.name.clone(), s.base_url.clone(), latency_ms, r));
        });
    }

    let mut results: Vec<(IndexSource, u128, bytes::Bytes)> = Vec::new();
    for _ in 0..sources.len() {
        let Ok((name, base_url, latency_ms, r)) = rx.recv() else {
            break;
        };
        let latency_ms_u32 =
            u32::try_from(latency_ms.min(u128::from(u32::MAX))).unwrap_or(u32::MAX);
        crate::metrics::BOOTSTRAP_MIRROR_LATENCY_MS
            .with_label_values(&[base_url.as_str()])
            .observe(f64::from(latency_ms_u32));
        match r {
            Ok(bytes) => {
                if let Some(mh) = mh.as_ref() {
                    let _ = mh.record_success(
                        &base_url,
                        u64::try_from(latency_ms).unwrap_or(u64::MAX),
                        now_ms,
                    );
                }
                if let Some(src) = sources.iter().find(|s| s.base_url == base_url) {
                    results.push((src.clone(), latency_ms, bytes));
                }
            }
            Err(_e) => {
                if let Some(mh) = mh.as_ref() {
                    let _ = mh.record_timeout(&base_url, now_ms);
                }
                // Best-effort failure accounting happens via health store (Phase 3).
                let _ = name;
            }
        }
    }

    // Group by blake3(index_bytes).
    let mut by_hash: std::collections::BTreeMap<String, Vec<(IndexSource, bytes::Bytes)>> =
        std::collections::BTreeMap::new();
    for (src, _lat, bytes) in results {
        let h = blake3::hash(bytes.as_ref()).to_hex().to_string();
        by_hash.entry(h).or_default().push((src, bytes));
    }

    // Pick winner by highest count; tie-break by hash lexicographically.
    let mut best: Option<(String, usize)> = None;
    for (h, list) in &by_hash {
        let n = list.len();
        match best.as_ref() {
            None => best = Some((h.clone(), n)),
            Some((best_h, best_n)) => {
                if n > *best_n || (n == *best_n && h < best_h) {
                    best = Some((h.clone(), n));
                }
            }
        }
    }

    let Some((winning_hash, count)) = best else {
        crate::metrics::BOOTSTRAP_INDEX_QUORUM_FAILURES_TOTAL.inc();
        return Err(BootstrapRemoteError::coded(
            BOOTSTRAP_INDEX_INVALID,
            "index quorum failed: no successful sources",
        ));
    };
    if count < quorum {
        crate::metrics::BOOTSTRAP_INDEX_QUORUM_FAILURES_TOTAL.inc();
        for (h, list) in &by_hash {
            if h != &winning_hash {
                for (src, _bytes) in list {
                    crate::metrics::BOOTSTRAP_MIRROR_HASH_MISMATCH_TOTAL
                        .with_label_values(&[src.base_url.as_str()])
                        .inc();
                    if let Some(mh) = mh.as_ref() {
                        let _ = mh.record_hash_mismatch(src.base_url.as_str(), now_ms);
                    }
                }
            }
        }
        return Err(BootstrapRemoteError::coded(
            BOOTSTRAP_INDEX_INVALID,
            format!(
                "index quorum failed: need quorum={}, best_count={}, hashes={}",
                quorum,
                count,
                by_hash
                    .iter()
                    .map(|(h, v)| format!("{h}:{}", v.len()))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
        ));
    }

    // Winner: pick the lowest base_url among sources that match (deterministic).
    let mut winners = by_hash.get(&winning_hash).cloned().unwrap_or_default();
    winners.sort_by(|a, b| a.0.base_url.cmp(&b.0.base_url));
    let quorum_sources = winners.iter().map(|(s, _)| s.base_url.clone()).collect();
    let (winner_src, winner_bytes) = winners.into_iter().next().expect("non-empty");
    Ok((
        winner_bytes,
        winner_src.base_url,
        quorum_sources,
        winning_hash,
    ))
}

fn build_index_sources(cfg: &FinNodeConfig) -> Result<Vec<IndexSource>, BootstrapRemoteError> {
    let remote = &cfg.bootstrap.remote;
    let sources_cfg = &cfg.bootstrap.sources;
    let connect = Duration::from_millis(remote.connect_timeout_ms);
    let timeout = Duration::from_millis(remote.read_timeout_ms);

    let primary_url = if sources_cfg.primary.trim().is_empty() {
        remote.base_url.trim().to_string()
    } else {
        sources_cfg.primary.trim().to_string()
    };

    let mut urls: Vec<(String, String)> = Vec::new();
    urls.push(("primary".to_string(), primary_url));
    for (i, m) in sources_cfg.mirrors.iter().enumerate() {
        urls.push((format!("mirror[{i}]"), m.trim().to_string()));
    }

    // Optional peers can also participate in quorum (HTTP gateways).
    if cfg.bootstrap.p2p.enabled {
        for (i, p) in cfg.bootstrap.p2p.peers.iter().enumerate() {
            urls.push((format!("peer[{i}]"), p.trim().to_string()));
        }
    }

    // Deduplicate by base_url (stable).
    let mut seen = std::collections::BTreeSet::<String>::new();
    let mut out = Vec::new();
    for (label, url) in urls {
        if url.trim().is_empty() {
            continue;
        }
        let url_norm = url.trim_end_matches('/').to_string();
        if !seen.insert(url_norm.clone()) {
            continue;
        }
        let src = HttpSource::new(
            format!("sources:{label}:{url_norm}"),
            url_norm.clone(),
            remote.index_path.clone(),
            connect,
            timeout,
        )?;
        out.push(IndexSource {
            name: label,
            base_url: url_norm,
            src,
        });
    }
    Ok(out)
}

fn fetch_index_one(
    cfg: &FinNodeConfig,
    src: &IndexSource,
    index_path: &str,
) -> Result<bytes::Bytes, BootstrapRemoteError> {
    let index_bytes = src.src.fetch_index().map_err(BootstrapRemoteError::from)?;

    // If signing is enabled, each candidate must pass signature verification to count toward quorum.
    if cfg.bootstrap.signing.enabled {
        let sig_rel = index_sig_rel_path(index_path);
        let sig_bytes = src
            .src
            .fetch_artifact(&sig_rel, None)
            .map_err(BootstrapRemoteError::from)?
            .to_vec();

        #[cfg(feature = "bootstrap-signing")]
        {
            verify_index_signature_bytes(
                cfg.bootstrap.signing.publisher_pubkeys.as_slice(),
                index_bytes.as_ref(),
                &sig_bytes,
            )?;
        }
        #[cfg(not(feature = "bootstrap-signing"))]
        {
            let _ = sig_bytes;
            return Err(BootstrapRemoteError::coded(
                BOOTSTRAP_INDEX_INVALID,
                "bootstrap.signing is enabled but fin-node was built without feature bootstrap-signing",
            ));
        }
    }

    Ok(index_bytes)
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
    let fetch_prov: Option<BootstrapFetchProvenanceV1> =
        std::fs::read(cache_dir.join("bootstrap_fetch_provenance.json"))
            .ok()
            .and_then(|b| serde_json::from_slice::<BootstrapFetchProvenanceV1>(&b).ok());
    write_bootstrap_provenance(
        &cache_dir,
        BootstrapProvenanceV1 {
            schema_version: 2,
            fetched_from: cfg.bootstrap.remote.base_url.clone(),
            index_path: cfg.bootstrap.remote.index_path.clone(),
            index_fetched_from: fetch_prov.as_ref().map(|p| p.index_fetched_from.clone()),
            base_hash: base_snapshot_id.clone(),
            delta_hashes: latest.deltas.iter().map(|d| d.hash.clone()).collect(),
            artifact_sources: fetch_prov
                .as_ref()
                .map(|p| p.artifacts.clone())
                .unwrap_or_default(),
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
    if let Some(p) = set.base.ca_path.as_deref() {
        validate_relative_path(p)
            .map_err(|e| BootstrapRemoteError::coded(BOOTSTRAP_INDEX_INVALID, e))?;
    }
    for d in &set.deltas {
        validate_relative_path(&d.path)
            .map_err(|e| BootstrapRemoteError::coded(BOOTSTRAP_INDEX_INVALID, e))?;
        if let Some(p) = d.ca_path.as_deref() {
            validate_relative_path(p)
                .map_err(|e| BootstrapRemoteError::coded(BOOTSTRAP_INDEX_INVALID, e))?;
        }
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

fn build_primary_source(cfg: &FinNodeConfig) -> Result<HttpSource, BootstrapRemoteError> {
    let r = &cfg.bootstrap.remote;
    let connect = Duration::from_millis(r.connect_timeout_ms);
    let timeout = Duration::from_millis(r.read_timeout_ms);
    Ok(HttpSource::new(
        format!("primary:{}", r.name),
        r.base_url.clone(),
        r.index_path.clone(),
        connect,
        timeout,
    )?)
}

fn build_http_sources_for_artifacts(
    cfg: &FinNodeConfig,
    primary: &HttpSource,
) -> Result<Vec<HttpSource>, BootstrapRemoteError> {
    let remote = &cfg.bootstrap.remote;
    let connect = Duration::from_millis(remote.connect_timeout_ms);
    let timeout = Duration::from_millis(remote.read_timeout_ms);

    let mut out = Vec::new();
    // Always include the primary source first for backward compatibility.
    out.push(primary.clone());

    // Only add mirrors when sources.mode is mirrors* or pinned (where we still fetch via mirrors).
    let mode = cfg.bootstrap.sources.mode;
    if matches!(
        mode,
        BootstrapSourcesMode::Mirrors
            | BootstrapSourcesMode::MirrorsQuorum
            | BootstrapSourcesMode::Pinned
    ) {
        for (i, m) in cfg.bootstrap.sources.mirrors.iter().enumerate() {
            let url = m.trim();
            if url.is_empty() {
                continue;
            }
            out.push(HttpSource::new(
                format!("mirror[{i}]:{url}"),
                url.to_string(),
                remote.index_path.clone(),
                connect,
                timeout,
            )?);
        }
    }

    // Deduplicate by base_url (stable first-wins).
    let mut seen = std::collections::BTreeSet::<String>::new();
    let mut dedup = Vec::new();
    for s in out {
        let key = s.base_url().to_string();
        if seen.insert(key) {
            dedup.push(s);
        }
    }
    // Prefer highest-scoring sources (Phase 3), deterministically.
    if let Ok(mh) = MirrorHealthStore::open(cfg.storage.bootstrap_db_dir.as_str()) {
        let now_ms = unix_now_millis();
        const QUARANTINE_MS: u64 = 60 * 60 * 1000;
        dedup.sort_by(|a, b| {
            let sa = mh.score_for(a.base_url());
            let sb = mh.score_for(b.base_url());
            sb.cmp(&sa).then(a.base_url().cmp(b.base_url()))
        });
        // Drop recently mismatching sources unless that would remove all sources.
        let filtered: Vec<HttpSource> = dedup
            .iter()
            .filter(|s| !mh.quarantined_recent_mismatch(s.base_url(), now_ms, QUARANTINE_MS))
            .cloned()
            .collect();
        if !filtered.is_empty() {
            return Ok(filtered);
        }
        // If all are quarantined, return the ranked list (operator may still want progress).
        return Ok(dedup);
    }
    Ok(dedup)
}

fn build_peer_sources(cfg: &FinNodeConfig) -> Result<Vec<PeerSource>, BootstrapRemoteError> {
    if !cfg.bootstrap.p2p.enabled {
        return Ok(Vec::new());
    }
    let r = &cfg.bootstrap.remote;
    let t = &cfg.bootstrap.transfer;
    let connect = Duration::from_millis(r.connect_timeout_ms.min(t.per_peer_timeout_ms));
    let timeout = Duration::from_millis(t.per_peer_timeout_ms);
    let mut out = Vec::new();
    for (i, peer_url) in cfg.bootstrap.p2p.peers.iter().enumerate() {
        let src = HttpSource::new(
            format!("peer[{i}]:{}", peer_url.trim_end_matches('/')),
            peer_url.clone(),
            r.index_path.clone(),
            connect,
            timeout,
        )?;
        out.push(PeerSource::new(src));
    }
    Ok(out)
}

fn fetch_index_with_fallback(
    _cfg: &FinNodeConfig,
    primary: &HttpSource,
    peers: &[PeerSource],
) -> Result<(bytes::Bytes, String), BootstrapRemoteError> {
    match primary.fetch_index() {
        Ok(b) => return Ok((b, primary.base_url().to_string())),
        Err(_e) => {
            // fall through to peers
        }
    }
    for p in peers {
        if let Ok(b) = p.fetch_index() {
            return Ok((b, p.base_url().to_string()));
        }
    }
    Err(BootstrapRemoteError::coded(
        BOOTSTRAP_INDEX_INVALID,
        "failed to fetch index.json from primary and peers",
    ))
}

fn resolve_artifact_size(
    primary: &HttpSource,
    peers: &[PeerSource],
    size_opt: Option<u64>,
    primary_path: &str,
    peer_path: &str,
) -> Result<u64, BootstrapRemoteError> {
    if let Some(s) = size_opt {
        return Ok(s);
    }
    // Primary probe first.
    let url = primary.url_for(primary_path);
    if let Ok(s) = http_head_len(primary.client(), &url) {
        return Ok(s);
    }
    // Peer probe fallback.
    for p in peers {
        let url = p.url_for(peer_path);
        if let Ok(s) = http_head_len(p.client(), &url) {
            return Ok(s);
        }
    }
    Err(BootstrapRemoteError::coded(
        BOOTSTRAP_INDEX_INVALID,
        "unable to determine artifact size (no index.size and HEAD probes failed)",
    ))
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

#[derive(Debug, Clone)]
struct ByteRateLimiter {
    inner: Option<Arc<Mutex<ByteBucket>>>,
}

#[derive(Debug)]
struct ByteBucket {
    tokens_scaled: u128,
    last_ms: u64,
    cap_scaled: u128,
    rate_per_ms_scaled: u128,
}

impl ByteRateLimiter {
    fn new(max_mbps: u64) -> Self {
        if max_mbps == 0 {
            return Self { inner: None };
        }
        // Megabits/sec -> bytes/sec (decimal Mbps).
        let bytes_per_sec = max_mbps.saturating_mul(1_000_000).saturating_div(8).max(1);
        const SCALE: u128 = 1_000_000;
        let rate_per_ms_scaled = (u128::from(bytes_per_sec).saturating_mul(SCALE) / 1000).max(1);
        let cap_scaled = u128::from(bytes_per_sec).saturating_mul(SCALE); // 1s bucket
        Self {
            inner: Some(Arc::new(Mutex::new(ByteBucket {
                tokens_scaled: cap_scaled,
                last_ms: unix_now_millis(),
                cap_scaled,
                rate_per_ms_scaled,
            }))),
        }
    }

    fn acquire(&self, bytes: u64) {
        let Some(inner) = self.inner.as_ref() else {
            return;
        };
        const SCALE: u128 = 1_000_000;
        let want = u128::from(bytes).saturating_mul(SCALE);
        loop {
            let wait_ms_opt = {
                let now = unix_now_millis();
                let mut b = inner.lock().expect("byte limiter mutex poisoned");
                let elapsed = now.saturating_sub(b.last_ms);
                if elapsed > 0 {
                    let refill = u128::from(elapsed).saturating_mul(b.rate_per_ms_scaled);
                    b.tokens_scaled = (b.tokens_scaled + refill).min(b.cap_scaled);
                    b.last_ms = now;
                }
                if b.tokens_scaled >= want {
                    b.tokens_scaled -= want;
                    None
                } else {
                    let missing = want - b.tokens_scaled;
                    let wait_ms_u128 = missing.div_ceil(b.rate_per_ms_scaled).max(1);
                    Some(u64::try_from(wait_ms_u128).unwrap_or(u64::MAX))
                }
            };
            match wait_ms_opt {
                None => return,
                Some(ms) => std::thread::sleep(Duration::from_millis(ms.min(200))),
            }
        }
    }
}

#[derive(Clone)]
struct DownloadPermits {
    inner: Arc<(std::sync::Mutex<usize>, std::sync::Condvar)>,
}

struct PermitGuard {
    inner: Arc<(std::sync::Mutex<usize>, std::sync::Condvar)>,
}

impl DownloadPermits {
    fn new(max_inflight: usize) -> Self {
        Self {
            inner: Arc::new((
                std::sync::Mutex::new(max_inflight.max(1)),
                std::sync::Condvar::new(),
            )),
        }
    }

    fn acquire(&self) -> PermitGuard {
        let (lock, cv) = &*self.inner;
        let mut n = lock.lock().expect("permit mutex poisoned");
        while *n == 0 {
            n = cv.wait(n).expect("permit condvar poisoned");
        }
        *n = n.saturating_sub(1);
        PermitGuard {
            inner: self.inner.clone(),
        }
    }
}

impl Drop for PermitGuard {
    fn drop(&mut self) {
        let (lock, cv) = &*self.inner;
        let mut n = lock.lock().expect("permit mutex poisoned");
        *n = n.saturating_add(1);
        cv.notify_one();
    }
}

#[allow(clippy::too_many_arguments)]
fn download_all(
    http_sources: &[HttpSource],
    peers: &[PeerSource],
    cfg: &FinNodeConfig,
    artifacts_dir: &Path,
    state_path: &Path,
    state: Arc<Mutex<DownloadStateV1>>,
    artifacts: &[FetchArtifactV1],
    concurrency: usize,
    limiter: ByteRateLimiter,
    prov_out: &mut Vec<BootstrapArtifactSourceV1>,
) -> Result<(), BootstrapRemoteError> {
    let concurrency = concurrency.clamp(1, 32);
    let permits = DownloadPermits::new(concurrency);
    let (tx, rx) =
        std::sync::mpsc::channel::<Result<BootstrapArtifactSourceV1, BootstrapRemoteError>>();
    let mut in_flight = 0usize;
    let mut iter = artifacts.iter();

    loop {
        while in_flight < concurrency {
            let Some(a) = iter.next().cloned() else { break };
            let http_sources = http_sources.to_vec();
            let peers = peers.to_vec();
            let cfg = cfg.clone();
            let artifacts_dir = artifacts_dir.to_path_buf();
            let state_path = state_path.to_path_buf();
            let state = state.clone();
            let tx = tx.clone();
            let limiter = limiter.clone();
            let permits = permits.clone();
            std::thread::spawn(move || {
                let r = download_one_with_sources(
                    http_sources.as_slice(),
                    peers.as_slice(),
                    &cfg,
                    &artifacts_dir,
                    &state_path,
                    state,
                    &a,
                    limiter,
                    permits,
                );
                let _ = tx.send(r);
            });
            in_flight += 1;
        }

        if in_flight == 0 {
            break;
        }

        match rx.recv() {
            Ok(Ok(p)) => {
                prov_out.push(p);
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

#[allow(clippy::too_many_arguments)]
fn download_one_with_sources(
    http_sources: &[HttpSource],
    peers: &[PeerSource],
    cfg: &FinNodeConfig,
    artifacts_dir: &Path,
    state_path: &Path,
    state: Arc<Mutex<DownloadStateV1>>,
    a: &FetchArtifactV1,
    limiter: ByteRateLimiter,
    permits: DownloadPermits,
) -> Result<BootstrapArtifactSourceV1, BootstrapRemoteError> {
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
            return Ok(BootstrapArtifactSourceV1 {
                kind: a.kind.clone(),
                path: a.path.clone(),
                expected_hash: a.expected_hash.clone(),
                fetched_from: Vec::new(),
                used_http_fallback: false,
            });
        }
    }

    // Prefer peer-list mode when enabled; fall back to primary HTTP if quorum cannot be met.
    if cfg.bootstrap.p2p.enabled && !peers.is_empty() {
        match download_from_peers_quorum(
            peers,
            &permits,
            &limiter,
            &a.kind,
            &a.peer_path,
            &out_path,
            a.size_bytes,
            &a.expected_hash,
            cfg.bootstrap.p2p.quorum.max(1),
            cfg.bootstrap.p2p.max_failures.max(1),
        ) {
            Ok(peer_names) => {
                update_download_entry(&state, state_path, a, a.size_bytes)?;
                return Ok(BootstrapArtifactSourceV1 {
                    kind: a.kind.clone(),
                    path: a.path.clone(),
                    expected_hash: a.expected_hash.clone(),
                    fetched_from: peer_names,
                    used_http_fallback: false,
                });
            }
            Err(_e) => {
                crate::metrics::BOOTSTRAP_QUORUM_MISMATCHES_TOTAL.inc();
                // Continue into HTTP fallback.
            }
        }
    }

    // HTTP path (mirrors): either bytes_quorum or hash_only with failover.
    if cfg.bootstrap.sources.artifact_quorum_mode == BootstrapArtifactQuorumMode::BytesQuorum
        && cfg.bootstrap.sources.artifact_quorum >= 2
        && http_sources.len() >= cfg.bootstrap.sources.artifact_quorum
    {
        let _permit = permits.acquire();
        match download_from_http_sources_bytes_quorum(
            http_sources,
            &permits,
            &limiter,
            &a.kind,
            &a.primary_path,
            &out_path,
            a.size_bytes,
            &a.expected_hash,
            cfg.bootstrap.sources.artifact_quorum,
        ) {
            Ok(used) => {
                update_download_entry(&state, state_path, a, a.size_bytes)?;
                return Ok(BootstrapArtifactSourceV1 {
                    kind: a.kind.clone(),
                    path: a.path.clone(),
                    expected_hash: a.expected_hash.clone(),
                    fetched_from: used,
                    used_http_fallback: true,
                });
            }
            Err(e) => {
                crate::metrics::BOOTSTRAP_ARTIFACT_QUORUM_FAILURES_TOTAL.inc();
                return Err(e);
            }
        }
    }

    // Hash-only: try sources in order, resume-safe only for the first source.
    for (i, src) in http_sources.iter().enumerate() {
        let _permit = permits.acquire();
        // When falling back to non-primary sources, restart from zero (avoid cross-source range resume).
        if i > 0 {
            let _ = std::fs::remove_file(&part_path);
        }
        let url = src.url_for(&a.primary_path);
        let prov = download_one_http(
            src.client(),
            &limiter,
            artifacts_dir,
            state_path,
            state.clone(),
            a,
            &url,
            &part_path,
            &out_path,
        );
        if let Ok(mut p) = prov {
            // Record actual URL used.
            if p.fetched_from.is_empty() {
                p.fetched_from = vec![url];
            }
            return Ok(p);
        }
    }

    Err(BootstrapRemoteError::coded(
        BOOTSTRAP_INDEX_INVALID,
        "failed to download artifact from any HTTP source",
    ))
}

#[allow(clippy::too_many_arguments)]
fn download_one_http(
    client: &reqwest::blocking::Client,
    limiter: &ByteRateLimiter,
    artifacts_dir: &Path,
    state_path: &Path,
    state: Arc<Mutex<DownloadStateV1>>,
    a: &FetchArtifactV1,
    url: &str,
    part_path: &Path,
    out_path: &Path,
) -> Result<BootstrapArtifactSourceV1, BootstrapRemoteError> {
    let _ = artifacts_dir;
    let mut downloaded = std::fs::metadata(part_path).map(|m| m.len()).unwrap_or(0);
    if downloaded > a.size_bytes {
        // Corrupt partial file; restart.
        let _ = std::fs::remove_file(part_path);
        downloaded = 0;
    }

    let mut attempt = 0u32;
    loop {
        attempt = attempt.saturating_add(1);
        let etag = lookup_etag(&state, &a.path, &a.expected_hash);
        let mut req = client.get(url);
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
            let _ = std::fs::remove_file(part_path);
            downloaded = 0;
            continue;
        }

        if !(status.is_success()) {
            if attempt >= 5 {
                return Err(BootstrapRemoteError::Http(format!(
                    "GET {} failed: http_status={status}",
                    url
                )));
            }
            std::thread::sleep(backoff(attempt));
            continue;
        }

        // If server ignored range and returned full content, restart from zero.
        if downloaded > 0 && status == reqwest::StatusCode::OK {
            let _ = std::fs::remove_file(part_path);
            downloaded = 0;
        }

        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .append(downloaded > 0)
            .truncate(downloaded == 0)
            .open(part_path)?;

        let mut reader = resp;
        let mut buf = [0u8; 64 * 1024];
        loop {
            let n = std::io::Read::read(&mut reader, &mut buf)?;
            if n == 0 {
                break;
            }
            limiter.acquire(u64::try_from(n).unwrap_or(u64::MAX));
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
    let meta = std::fs::metadata(part_path)?;
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
    std::fs::rename(part_path, out_path)?;
    update_download_entry(&state, state_path, a, a.size_bytes)?;
    Ok(BootstrapArtifactSourceV1 {
        kind: a.kind.clone(),
        path: a.path.clone(),
        expected_hash: a.expected_hash.clone(),
        fetched_from: vec![url.to_string()],
        used_http_fallback: true,
    })
}

#[allow(clippy::too_many_arguments)]
fn download_from_peers_quorum(
    peers: &[PeerSource],
    permits: &DownloadPermits,
    limiter: &ByteRateLimiter,
    kind: &str,
    rel_path: &str,
    out_path: &Path,
    expected_size: u64,
    expected_hash: &str,
    quorum: usize,
    max_failures: usize,
) -> Result<Vec<String>, BootstrapRemoteError> {
    let quorum = quorum.max(1);
    let mut successes: Vec<(String, PathBuf)> = Vec::new();
    let (tx, rx) = std::sync::mpsc::channel::<(String, Result<PathBuf, BootstrapRemoteError>)>();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let total_peers = peers.len();

    // Start attempts for all peers; global permits bound actual download concurrency.
    for (i, p) in peers.iter().cloned().enumerate() {
        let tx = tx.clone();
        let rel_path = rel_path.to_string();
        let out_dir = out_path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        let file_name = out_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("artifact");
        let tmp_path = out_dir.join(format!("{file_name}.peer{i}.tmp"));
        let kind = kind.to_string();
        let expected_hash = expected_hash.to_string();
        let stop = stop.clone();
        let limiter = limiter.clone();
        let permits = permits.clone();
        std::thread::spawn(move || {
            if stop.load(std::sync::atomic::Ordering::Relaxed) {
                return;
            }
            let r = download_peer_to_temp_and_verify(
                &p,
                &permits,
                &limiter,
                &kind,
                &rel_path,
                &tmp_path,
                expected_size,
                &expected_hash,
            );
            let _ = tx.send((p.name().to_string(), r));
        });
    }

    let mut failures = 0usize;
    let mut received = 0usize;
    while successes.len() < quorum && received < total_peers && failures < max_failures {
        let Ok((peer_name, r)) = rx.recv() else {
            break;
        };
        received = received.saturating_add(1);
        match r {
            Ok(tmp_path) => {
                successes.push((peer_name, tmp_path));
                if successes.len() >= quorum {
                    stop.store(true, std::sync::atomic::Ordering::Relaxed);
                    break;
                }
            }
            Err(e) => {
                failures = failures.saturating_add(1);
                crate::metrics::BOOTSTRAP_PEER_FAILURES_TOTAL
                    .with_label_values(&[peer_name.as_str()])
                    .inc();
                // Best-effort: keep receiving; other peers may still succeed.
                let _ = e;
            }
        }
    }

    if successes.len() < quorum {
        // Clean up any partial successes.
        for (_peer, p) in successes {
            let _ = std::fs::remove_file(p);
        }
        return Err(BootstrapRemoteError::coded(
            BOOTSTRAP_HASH_MISMATCH,
            "peer quorum not satisfied",
        ));
    }

    // Promote the first successful temp file to the target output path; delete the rest.
    let mut used: Vec<String> = Vec::new();
    for (i, (peer, tmp)) in successes.into_iter().enumerate() {
        used.push(peer);
        if i == 0 {
            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::rename(&tmp, out_path)?;
        } else {
            let _ = std::fs::remove_file(tmp);
        }
    }
    Ok(used)
}

#[allow(clippy::too_many_arguments)]
fn download_peer_to_temp_and_verify(
    peer: &PeerSource,
    permits: &DownloadPermits,
    limiter: &ByteRateLimiter,
    kind: &str,
    rel_path: &str,
    tmp_path: &Path,
    expected_size: u64,
    expected_hash: &str,
) -> Result<PathBuf, BootstrapRemoteError> {
    let _permit = permits.acquire();
    let url = peer.url_for(rel_path);
    let resp = peer
        .client()
        .get(&url)
        .send()
        .map_err(|e| BootstrapRemoteError::Http(e.to_string()))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(BootstrapRemoteError::Http(format!(
            "GET {url} failed: http_status={status}"
        )));
    }

    if let Some(parent) = tmp_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::File::create(tmp_path)?;
    let mut reader = resp;
    let mut buf = [0u8; 64 * 1024];
    let mut downloaded = 0u64;
    loop {
        let n = std::io::Read::read(&mut reader, &mut buf)?;
        if n == 0 {
            break;
        }
        limiter.acquire(u64::try_from(n).unwrap_or(u64::MAX));
        std::io::Write::write_all(&mut file, &buf[..n])?;
        downloaded = downloaded.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        if downloaded > expected_size {
            let _ = std::fs::remove_file(tmp_path);
            return Err(BootstrapRemoteError::coded(
                BOOTSTRAP_INDEX_INVALID,
                "peer download exceeded expected size",
            ));
        }
    }
    if downloaded != expected_size {
        let _ = std::fs::remove_file(tmp_path);
        return Err(BootstrapRemoteError::coded(
            BOOTSTRAP_INDEX_INVALID,
            "peer download incomplete",
        ));
    }

    // Verify expected hash via existing artifact verifiers.
    if kind == "base" {
        let m = crate::snapshot::verify_snapshot_v1_tar(tmp_path)
            .map_err(|e| BootstrapRemoteError::coded(BOOTSTRAP_HASH_MISMATCH, e.to_string()))?;
        if m.hash != expected_hash {
            let _ = std::fs::remove_file(tmp_path);
            return Err(BootstrapRemoteError::coded(
                BOOTSTRAP_HASH_MISMATCH,
                "peer base hash mismatch",
            ));
        }
    } else {
        let d = crate::bootstrap::parse_delta_snapshot_v1_tar(tmp_path)
            .map_err(|e| BootstrapRemoteError::coded(BOOTSTRAP_HASH_MISMATCH, e.to_string()))?;
        if d.manifest.hash != expected_hash {
            let _ = std::fs::remove_file(tmp_path);
            return Err(BootstrapRemoteError::coded(
                BOOTSTRAP_HASH_MISMATCH,
                "peer delta hash mismatch",
            ));
        }
    }

    Ok(tmp_path.to_path_buf())
}

#[allow(clippy::too_many_arguments)]
fn download_from_http_sources_bytes_quorum(
    sources: &[HttpSource],
    permits: &DownloadPermits,
    limiter: &ByteRateLimiter,
    kind: &str,
    rel_path: &str,
    out_path: &Path,
    expected_size: u64,
    expected_hash: &str,
    quorum: usize,
) -> Result<Vec<String>, BootstrapRemoteError> {
    let quorum = quorum.max(1);
    let (tx, rx) =
        std::sync::mpsc::channel::<(String, Result<(PathBuf, String), BootstrapRemoteError>)>();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));

    for (i, s) in sources.iter().cloned().enumerate() {
        let tx = tx.clone();
        let rel_path = rel_path.to_string();
        let out_dir = out_path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."));
        let file_name = out_path
            .file_name()
            .and_then(|s| s.to_str())
            .unwrap_or("artifact");
        let tmp_path = out_dir.join(format!("{file_name}.http{i}.tmp"));
        let kind = kind.to_string();
        let expected_hash = expected_hash.to_string();
        let stop = stop.clone();
        let limiter = limiter.clone();
        let permits = permits.clone();
        std::thread::spawn(move || {
            if stop.load(std::sync::atomic::Ordering::Relaxed) {
                return;
            }
            let r = download_http_to_temp_and_verify(
                &s,
                &permits,
                &limiter,
                &kind,
                &rel_path,
                &tmp_path,
                expected_size,
                &expected_hash,
            );
            let _ = tx.send((s.base_url().to_string(), r));
        });
    }

    let mut received = 0usize;
    let mut successes: Vec<(String, PathBuf, String)> = Vec::new(); // (source, tmp_path, bytes_hash)
    while received < sources.len() {
        let Ok((src_url, r)) = rx.recv() else {
            break;
        };
        received = received.saturating_add(1);
        match r {
            Ok((tmp_path, bytes_hash)) => {
                successes.push((src_url, tmp_path, bytes_hash));
            }
            Err(_e) => {
                // Best-effort: continue collecting other sources.
            }
        }
    }

    if successes.is_empty() {
        return Err(BootstrapRemoteError::coded(
            BOOTSTRAP_HASH_MISMATCH,
            "bytes_quorum failed: no valid sources",
        ));
    }

    // Group by bytes hash, pick most common (tie-break by hash).
    let mut by_hash: std::collections::BTreeMap<String, Vec<(String, PathBuf)>> =
        std::collections::BTreeMap::new();
    for (src, p, h) in successes {
        by_hash.entry(h).or_default().push((src, p));
    }
    let mut best: Option<(String, usize)> = None;
    for (h, v) in &by_hash {
        let n = v.len();
        match best.as_ref() {
            None => best = Some((h.clone(), n)),
            Some((bh, bn)) => {
                if n > *bn || (n == *bn && h < bh) {
                    best = Some((h.clone(), n));
                }
            }
        }
    }
    let (winning_hash, count) = best.expect("non-empty");
    if count < quorum {
        return Err(BootstrapRemoteError::coded(
            BOOTSTRAP_HASH_MISMATCH,
            format!(
                "bytes_quorum failed: need quorum={}, best_count={}",
                quorum, count
            ),
        ));
    }

    let mut winners = by_hash.remove(&winning_hash).unwrap_or_default();
    winners.sort_by(|a, b| a.0.cmp(&b.0));
    let used: Vec<String> = winners.iter().map(|(s, _)| s.clone()).collect();

    // Promote the first winner to out_path; delete remaining temps.
    for (i, (_src, tmp)) in winners.into_iter().enumerate() {
        if i == 0 {
            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::rename(&tmp, out_path)?;
        } else {
            let _ = std::fs::remove_file(tmp);
        }
    }
    Ok(used)
}

#[allow(clippy::too_many_arguments)]
fn download_http_to_temp_and_verify(
    src: &HttpSource,
    permits: &DownloadPermits,
    limiter: &ByteRateLimiter,
    kind: &str,
    rel_path: &str,
    tmp_path: &Path,
    expected_size: u64,
    expected_hash: &str,
) -> Result<(PathBuf, String), BootstrapRemoteError> {
    let _permit = permits.acquire();
    let url = src.url_for(rel_path);
    let resp = src
        .client()
        .get(&url)
        .send()
        .map_err(|e| BootstrapRemoteError::Http(e.to_string()))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(BootstrapRemoteError::Http(format!(
            "GET {url} failed: http_status={status}"
        )));
    }

    if let Some(parent) = tmp_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let mut file = std::fs::File::create(tmp_path)?;
    let mut reader = resp;
    let mut buf = [0u8; 64 * 1024];
    let mut downloaded = 0u64;
    let mut hasher = blake3::Hasher::new();
    loop {
        let n = std::io::Read::read(&mut reader, &mut buf)?;
        if n == 0 {
            break;
        }
        limiter.acquire(u64::try_from(n).unwrap_or(u64::MAX));
        std::io::Write::write_all(&mut file, &buf[..n])?;
        hasher.update(&buf[..n]);
        downloaded = downloaded.saturating_add(u64::try_from(n).unwrap_or(u64::MAX));
        if downloaded > expected_size {
            let _ = std::fs::remove_file(tmp_path);
            return Err(BootstrapRemoteError::coded(
                BOOTSTRAP_INDEX_INVALID,
                "http download exceeded expected size",
            ));
        }
    }
    if downloaded != expected_size {
        let _ = std::fs::remove_file(tmp_path);
        return Err(BootstrapRemoteError::coded(
            BOOTSTRAP_INDEX_INVALID,
            "http download incomplete",
        ));
    }

    // Verify expected hash via existing artifact verifiers.
    if kind == "base" {
        let m = crate::snapshot::verify_snapshot_v1_tar(tmp_path)
            .map_err(|e| BootstrapRemoteError::coded(BOOTSTRAP_HASH_MISMATCH, e.to_string()))?;
        if m.hash != expected_hash {
            let _ = std::fs::remove_file(tmp_path);
            return Err(BootstrapRemoteError::coded(
                BOOTSTRAP_HASH_MISMATCH,
                "http base hash mismatch",
            ));
        }
    } else {
        let d = crate::bootstrap::parse_delta_snapshot_v1_tar(tmp_path)
            .map_err(|e| BootstrapRemoteError::coded(BOOTSTRAP_HASH_MISMATCH, e.to_string()))?;
        if d.manifest.hash != expected_hash {
            let _ = std::fs::remove_file(tmp_path);
            return Err(BootstrapRemoteError::coded(
                BOOTSTRAP_HASH_MISMATCH,
                "http delta hash mismatch",
            ));
        }
    }

    Ok((
        tmp_path.to_path_buf(),
        hasher.finalize().to_hex().to_string(),
    ))
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
    primary: &HttpSource,
    index_path: &str,
    _index_bytes: &bytes::Bytes,
    index_fetched_from: &str,
    peers: &[PeerSource],
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
    let sig_fetch = if primary.base_url() == index_fetched_from {
        primary.fetch_artifact(&sig_rel, None)
    } else if let Some(p) = peers.iter().find(|p| p.base_url() == index_fetched_from) {
        p.fetch_artifact(&sig_rel, None)
    } else {
        // If we can't identify the index source, fall back to primary.
        primary.fetch_artifact(&sig_rel, None)
    };

    let sig_bytes = match sig_fetch {
        Ok(b) => b.to_vec(),
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
        verify_index_signature_bytes(
            scfg.publisher_pubkeys.as_slice(),
            _index_bytes.as_ref(),
            &sig_bytes,
        )
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

fn unix_now_millis() -> u64 {
    let ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    u64::try_from(ms).unwrap_or(u64::MAX)
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
