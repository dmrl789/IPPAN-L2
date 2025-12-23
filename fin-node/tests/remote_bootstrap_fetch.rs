use assert_cmd::prelude::*;
use fin_node::bootstrap;
use fin_node::bootstrap_store::BootstrapStore;
use fin_node::snapshot;
use hub_data::DataStore;
use hub_fin::FinStore;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tar::Header;

fn write_minimal_config(path: &Path, base_url: &str, download_dir: &Path, max_download_mb: u64) {
    // Minimal config for bootstrap commands in mock mode.
    // NOTE: `fin-node` only validates L1 config in `--l1-mode http`, so these are dummy values.
    let toml = format!(
        r#"
[node]
label = "test-node"

[l1]
base_url = "http://localhost"

[l1.endpoints]
chain_status = ""
submit_batch = ""
get_inclusion = ""
get_finality = ""

[l1.retry]
max_attempts = 1
base_delay_ms = 1
max_delay_ms = 1

[snapshots]
enabled = true
output_dir = "snapshots"

[storage]
receipts_dir = "{receipts}"
fin_db_dir = "{fin_db}"
data_db_dir = "{data_db}"
policy_db_dir = "{policy_db}"
recon_db_dir = "{recon_db}"
bootstrap_db_dir = "{bootstrap_db}"

[bootstrap.remote]
enabled = true
name = "default"
base_url = "{base_url}"
index_path = "index.json"
download_dir = "{download_dir}"
max_download_mb = {max_download_mb}
connect_timeout_ms = 3000
read_timeout_ms = 30000
concurrency = 2
"#,
        receipts = download_dir.join("receipts").display(),
        fin_db = download_dir.join("fin_db").display(),
        data_db = download_dir.join("data_db").display(),
        policy_db = download_dir.join("policy_db").display(),
        recon_db = download_dir.join("recon_db").display(),
        bootstrap_db = download_dir.join("bootstrap_db").display(),
        base_url = base_url,
        download_dir = download_dir.display(),
        max_download_mb = max_download_mb
    );
    std::fs::write(path, toml).unwrap();
}

fn create_snapshot_repo(root: &Path) -> (PathBuf, PathBuf) {
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(repo_dir.join("deltas")).unwrap();

    let snapshots_cfg = fin_node::config::SnapshotsConfig {
        enabled: true,
        output_dir: repo_dir.to_string_lossy().to_string(),
        ..Default::default()
    };

    let fin = FinStore::open(root.join("fin_db").to_str().unwrap()).unwrap();
    let data = DataStore::open(root.join("data_db").to_str().unwrap()).unwrap();
    fin.set_state_version(2).unwrap();
    data.set_state_version(2).unwrap();
    let recon = None;
    let bootstrap_db = BootstrapStore::open(root.join("bootstrap_db").to_str().unwrap()).unwrap();

    let receipts_dir = root.join("receipts");
    std::fs::create_dir_all(&receipts_dir).unwrap();
    // Optional padding file to increase snapshot size for size-limit tests.
    let big = receipts_dir.join("big.bin");
    std::fs::write(&big, vec![0u8; 2 * 1024 * 1024]).unwrap();

    let base_path = repo_dir.join("base.tar");
    let base_manifest = snapshot::create_snapshot_v1_tar(
        &snapshots_cfg,
        &base_path,
        snapshot::SnapshotSources {
            fin: &fin,
            data: &data,
            recon,
            receipts_dir: &receipts_dir,
            node_id: "test-node",
        },
    )
    .unwrap();

    // Create a delta snapshot with no changes (still well-formed).
    let delta_path = repo_dir.join("deltas").join("delta-1-2.tar");
    let _ = bootstrap::create_delta_snapshot_v1_tar(
        &delta_path,
        &base_manifest.hash,
        1,
        2,
        bootstrap::DeltaSources {
            fin: &fin,
            data: &data,
            recon,
            bootstrap: &bootstrap_db,
        },
    )
    .unwrap();

    // Generate index.json
    bootstrap::publish_index_v1(&repo_dir).unwrap();
    (repo_dir, base_path)
}

fn start_file_server(
    root: PathBuf,
) -> (
    String,
    Arc<Mutex<Vec<String>>>,
    Arc<std::sync::atomic::AtomicBool>,
) {
    use tiny_http::{Header, Response, StatusCode};

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tiny_http::Server::from_listener(listener, None).unwrap();
    let seen = Arc::new(Mutex::new(Vec::<String>::new()));
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let seen_t = seen.clone();
    let stop_t = stop.clone();

    std::thread::spawn(move || {
        while !stop_t.load(std::sync::atomic::Ordering::Relaxed) {
            let req = match server.recv_timeout(Duration::from_millis(50)) {
                Ok(Some(r)) => r,
                Ok(None) => continue,
                Err(_) => continue,
            };

            let method = req.method().as_str().to_string();
            let url_path = req.url().trim_start_matches('/').to_string();
            let mut has_range = false;
            for h in req.headers() {
                if h.field.as_str().to_string().eq_ignore_ascii_case("range") {
                    has_range = true;
                }
            }
            seen_t
                .lock()
                .unwrap()
                .push(format!("{method} {url_path} range={has_range}"));

            let fs_path = root.join(&url_path);
            if !fs_path.exists() || !fs_path.is_file() {
                let _ = req.respond(Response::empty(StatusCode(404)));
                continue;
            }

            let bytes = std::fs::read(&fs_path).unwrap();
            let total_len = bytes.len() as u64;

            // HEAD: just return content-length.
            if req.method().as_str() == "HEAD" {
                let mut resp = Response::empty(StatusCode(200));
                resp.add_header(
                    Header::from_bytes(&b"Content-Length"[..], total_len.to_string().as_bytes())
                        .unwrap(),
                );
                let _ = req.respond(resp);
                continue;
            }

            // GET with optional Range support.
            let mut start = 0u64;
            let mut use_range = false;
            for h in req.headers() {
                if h.field.as_str().to_string().eq_ignore_ascii_case("range") {
                    let v = h.value.as_str();
                    if let Some(rest) = v.strip_prefix("bytes=") {
                        if let Some((s, _end)) = rest.split_once('-') {
                            if let Ok(n) = s.parse::<u64>() {
                                start = n;
                                use_range = true;
                            }
                        }
                    }
                }
            }

            if use_range && start < total_len {
                let start_usize = usize::try_from(start).unwrap_or(bytes.len());
                let slice = bytes[start_usize..].to_vec();
                let mut resp = Response::from_data(slice).with_status_code(StatusCode(206));
                resp.add_header(
                    Header::from_bytes(
                        &b"Content-Length"[..],
                        (total_len - start).to_string().as_bytes(),
                    )
                    .unwrap(),
                );
                resp.add_header(Header::from_bytes(&b"Accept-Ranges"[..], &b"bytes"[..]).unwrap());
                resp.add_header(
                    Header::from_bytes(
                        &b"Content-Range"[..],
                        format!("bytes {}-{}/{}", start, total_len - 1, total_len).as_bytes(),
                    )
                    .unwrap(),
                );
                let _ = req.respond(resp);
            } else {
                let mut resp = Response::from_data(bytes).with_status_code(StatusCode(200));
                resp.add_header(
                    Header::from_bytes(&b"Content-Length"[..], total_len.to_string().as_bytes())
                        .unwrap(),
                );
                let _ = req.respond(resp);
            }
        }
    });

    (format!("http://{}", addr), seen, stop)
}

#[test]
fn bootstrap_fetch_dry_run_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    let (repo_dir, _base_path) = create_snapshot_repo(tmp.path());
    let (base_url, _seen, stop) = start_file_server(repo_dir);

    let cfg_path = tmp.path().join("node.toml");
    let download_dir = tmp.path().join("cache");
    write_minimal_config(&cfg_path, &base_url, &download_dir, 4096);

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("fin-node"));
    cmd.args([
        "--config",
        cfg_path.to_str().unwrap(),
        "bootstrap",
        "fetch",
        "--remote",
        "default",
        "--dry-run",
    ]);
    cmd.assert().success();
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
}

#[test]
fn bootstrap_fetch_enforces_size_limit() {
    let tmp = tempfile::tempdir().unwrap();
    let (repo_dir, _base_path) = create_snapshot_repo(tmp.path());
    let (base_url, _seen, stop) = start_file_server(repo_dir);

    let cfg_path = tmp.path().join("node.toml");
    let download_dir = tmp.path().join("cache");
    // Force a tiny max size so HEAD-based planning refuses (repo contains ~2MB receipts).
    write_minimal_config(&cfg_path, &base_url, &download_dir, 1);

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("fin-node"));
    cmd.args([
        "--config",
        cfg_path.to_str().unwrap(),
        "bootstrap",
        "fetch",
        "--remote",
        "default",
    ]);
    cmd.assert().failure();
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
}

#[test]
fn bootstrap_fetch_downloads_and_verifies() {
    let tmp = tempfile::tempdir().unwrap();
    let (repo_dir, _base_path) = create_snapshot_repo(tmp.path());
    let (base_url, _seen, stop) = start_file_server(repo_dir);

    let cfg_path = tmp.path().join("node.toml");
    let download_dir = tmp.path().join("cache");
    write_minimal_config(&cfg_path, &base_url, &download_dir, 4096);

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("fin-node"));
    cmd.args([
        "--config",
        cfg_path.to_str().unwrap(),
        "bootstrap",
        "fetch",
        "--remote",
        "default",
    ]);
    cmd.assert().success();

    // Base tar should be present in the cache.
    assert!(download_dir.join("artifacts").join("base.tar").exists());
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
}

#[test]
fn bootstrap_fetch_fails_on_tampered_delta() {
    let tmp = tempfile::tempdir().unwrap();
    let (repo_dir, _base_path) = create_snapshot_repo(tmp.path());

    // Tamper a delta after index has been generated.
    let delta_path = repo_dir.join("deltas").join("delta-1-2.tar");
    let mut bytes = std::fs::read(&delta_path).unwrap();
    if !bytes.is_empty() {
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0x01;
    }
    std::fs::write(&delta_path, bytes).unwrap();

    let (base_url, _seen, stop) = start_file_server(repo_dir);
    let cfg_path = tmp.path().join("node.toml");
    let download_dir = tmp.path().join("cache");
    write_minimal_config(&cfg_path, &base_url, &download_dir, 4096);

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("fin-node"));
    cmd.args([
        "--config",
        cfg_path.to_str().unwrap(),
        "bootstrap",
        "fetch",
        "--remote",
        "default",
    ]);
    cmd.assert().failure();
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
}

#[test]
fn bootstrap_fetch_resumes_from_partial_download() {
    let tmp = tempfile::tempdir().unwrap();
    let (repo_dir, _base_path) = create_snapshot_repo(tmp.path());
    let (base_url, seen, stop) = start_file_server(repo_dir.clone());

    let cfg_path = tmp.path().join("node.toml");
    let download_dir = tmp.path().join("cache");
    write_minimal_config(&cfg_path, &base_url, &download_dir, 4096);

    // Pre-create a partial `.part` file for base.tar in the cache.
    let artifacts_dir = download_dir.join("artifacts");
    std::fs::create_dir_all(&artifacts_dir).unwrap();
    let src = std::fs::read(repo_dir.join("base.tar")).unwrap();
    let cut = (src.len() / 3).max(1);
    std::fs::write(artifacts_dir.join("base.tar.part"), &src[..cut]).unwrap();

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("fin-node"));
    cmd.args([
        "--config",
        cfg_path.to_str().unwrap(),
        "bootstrap",
        "fetch",
        "--remote",
        "default",
    ]);
    cmd.assert().success();

    // We should have seen at least one ranged GET.
    let seen = seen.lock().unwrap();
    assert!(seen
        .iter()
        .any(|s| s.contains("GET base.tar") && s.contains("range=true")));
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
}

fn rewrite_base_manifest_version(base_tar: &Path, new_version: &str) {
    let tmp = tempfile::tempdir().unwrap();
    {
        let file = std::fs::File::open(base_tar).unwrap();
        let mut archive = tar::Archive::new(file);
        archive.unpack(tmp.path()).unwrap();
    }

    let manifest_path = tmp.path().join("manifest.json");
    let mut v: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    v["ippan_l2_version"] = serde_json::Value::String(new_version.to_string());
    std::fs::write(&manifest_path, serde_json::to_vec_pretty(&v).unwrap()).unwrap();

    // Repack tar: content files first (sorted), manifest last.
    let kv_files = [
        "hub-fin.kv",
        "hub-data.kv",
        "linkage.kv",
        "receipts.kv",
        "recon.kv",
    ];
    let tmp_out = base_tar.with_extension("tar.tmp");
    let file = std::fs::File::create(&tmp_out).unwrap();
    let mut builder = tar::Builder::new(file);

    let mut names = kv_files.to_vec();
    names.sort();
    for name in names {
        let bytes = std::fs::read(tmp.path().join(name)).unwrap();
        let mut header = Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_uid(0);
        header.set_gid(0);
        header.set_cksum();
        builder
            .append_data(&mut header, name, std::io::Cursor::new(bytes))
            .unwrap();
    }

    let manifest_bytes = std::fs::read(manifest_path).unwrap();
    let mut header = Header::new_gnu();
    header.set_size(manifest_bytes.len() as u64);
    header.set_mode(0o644);
    header.set_mtime(0);
    header.set_uid(0);
    header.set_gid(0);
    header.set_cksum();
    builder
        .append_data(
            &mut header,
            "manifest.json",
            std::io::Cursor::new(manifest_bytes),
        )
        .unwrap();
    builder.finish().unwrap();

    std::fs::rename(tmp_out, base_tar).unwrap();
}

#[test]
fn bootstrap_fetch_refuses_incompatible_snapshot_version() {
    let tmp = tempfile::tempdir().unwrap();
    let (repo_dir, base_path) = create_snapshot_repo(tmp.path());

    // Rewrite manifest.json to claim an incompatible ippan_l2_version (hash remains valid).
    rewrite_base_manifest_version(&base_path, "999.0.0");

    let (base_url, _seen, stop) = start_file_server(repo_dir);
    let cfg_path = tmp.path().join("node.toml");
    let download_dir = tmp.path().join("cache");
    write_minimal_config(&cfg_path, &base_url, &download_dir, 4096);

    let mut cmd = Command::new(assert_cmd::cargo::cargo_bin!("fin-node"));
    cmd.args([
        "--config",
        cfg_path.to_str().unwrap(),
        "bootstrap",
        "fetch",
        "--remote",
        "default",
    ]);
    cmd.assert().failure();
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
}
