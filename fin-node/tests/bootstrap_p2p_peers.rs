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

fn write_minimal_config_with_p2p(
    path: &Path,
    base_url: &str,
    download_dir: &Path,
    peers: &[String],
    quorum: usize,
    max_failures: usize,
) {
    let peers_toml = peers
        .iter()
        .map(|p| format!(r#""{p}""#))
        .collect::<Vec<_>>()
        .join(", ");
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
max_download_mb = 4096
connect_timeout_ms = 200
read_timeout_ms = 2000
concurrency = 2

[bootstrap.p2p]
enabled = true
peers = [{peers_toml}]
quorum = {quorum}
max_failures = {max_failures}

[bootstrap.transfer]
max_concurrency = 2
max_mbps = 0
per_peer_timeout_ms = 2000
"#,
        receipts = download_dir.join("receipts").display(),
        fin_db = download_dir.join("fin_db").display(),
        data_db = download_dir.join("data_db").display(),
        policy_db = download_dir.join("policy_db").display(),
        recon_db = download_dir.join("recon_db").display(),
        bootstrap_db = download_dir.join("bootstrap_db").display(),
        base_url = base_url,
        download_dir = download_dir.display(),
        peers_toml = peers_toml,
        quorum = quorum,
        max_failures = max_failures
    );
    std::fs::write(path, toml).unwrap();
}

fn copy_dir_all(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap() {
        let e = e.unwrap();
        let p = e.path();
        let out = to.join(e.file_name());
        if p.is_dir() {
            copy_dir_all(&p, &out);
        } else {
            std::fs::copy(&p, &out).unwrap();
        }
    }
}

fn create_snapshot_repo_with_ca(root: &Path) -> (PathBuf, String, String) {
    let repo_dir = root.join("repo");
    std::fs::create_dir_all(repo_dir.join("deltas")).unwrap();
    std::fs::create_dir_all(repo_dir.join("artifacts").join("base")).unwrap();
    std::fs::create_dir_all(repo_dir.join("artifacts").join("delta")).unwrap();

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

    let delta_path = repo_dir.join("deltas").join("delta-1-2.tar");
    let delta_manifest = bootstrap::create_delta_snapshot_v1_tar(
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

    bootstrap::publish_index_v1(&repo_dir).unwrap();

    // Populate content-addressed paths expected by peer mode.
    std::fs::copy(
        &base_path,
        repo_dir
            .join("artifacts")
            .join("base")
            .join(format!("{}.tar", base_manifest.hash)),
    )
    .unwrap();
    std::fs::copy(
        &delta_path,
        repo_dir
            .join("artifacts")
            .join("delta")
            .join(format!("{}.tar", delta_manifest.hash)),
    )
    .unwrap();

    (repo_dir, base_manifest.hash, delta_manifest.hash)
}

fn tamper_file(path: &Path) {
    let mut bytes = std::fs::read(path).unwrap();
    if !bytes.is_empty() {
        let mid = bytes.len() / 2;
        bytes[mid] ^= 0x01;
    }
    std::fs::write(path, bytes).unwrap();
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
fn p2p_quorum_two_peers_succeeds() {
    let tmp = tempfile::tempdir().unwrap();
    let (repo_dir, base_hash, _delta_hash) = create_snapshot_repo_with_ca(tmp.path());

    let (peer1_url, peer1_seen, peer1_stop) = start_file_server(repo_dir.clone());
    let (peer2_url, peer2_seen, peer2_stop) = start_file_server(repo_dir.clone());
    let (primary_url, _primary_seen, primary_stop) = start_file_server(repo_dir);

    let cfg_path = tmp.path().join("node.toml");
    let download_dir = tmp.path().join("cache");
    write_minimal_config_with_p2p(
        &cfg_path,
        &primary_url,
        &download_dir,
        &[peer1_url.clone(), peer2_url.clone()],
        2,
        3,
    );

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

    let peer1 = peer1_seen.lock().unwrap();
    let peer2 = peer2_seen.lock().unwrap();
    assert!(peer1
        .iter()
        .any(|s| s.contains(&format!("GET artifacts/base/{base_hash}.tar"))));
    assert!(peer2
        .iter()
        .any(|s| s.contains(&format!("GET artifacts/base/{base_hash}.tar"))));

    peer1_stop.store(true, std::sync::atomic::Ordering::Relaxed);
    peer2_stop.store(true, std::sync::atomic::Ordering::Relaxed);
    primary_stop.store(true, std::sync::atomic::Ordering::Relaxed);
}

#[test]
fn p2p_quorum_two_with_one_tampered_peer_fails_if_primary_down() {
    let tmp = tempfile::tempdir().unwrap();
    let (repo_dir, _base_hash, delta_hash) = create_snapshot_repo_with_ca(tmp.path());

    let bad_repo = tmp.path().join("repo_bad");
    copy_dir_all(&repo_dir, &bad_repo);
    tamper_file(
        &bad_repo
            .join("artifacts")
            .join("delta")
            .join(format!("{delta_hash}.tar")),
    );

    let (peer_good_url, _seen_good, stop_good) = start_file_server(repo_dir);
    let (peer_bad_url, _seen_bad, stop_bad) = start_file_server(bad_repo);

    // Primary is down/unreachable.
    let primary_url = "http://127.0.0.1:1".to_string();

    let cfg_path = tmp.path().join("node.toml");
    let download_dir = tmp.path().join("cache");
    write_minimal_config_with_p2p(
        &cfg_path,
        &primary_url,
        &download_dir,
        &[peer_good_url, peer_bad_url],
        2,
        3,
    );

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

    stop_good.store(true, std::sync::atomic::Ordering::Relaxed);
    stop_bad.store(true, std::sync::atomic::Ordering::Relaxed);
}

#[test]
fn p2p_peers_down_fallback_to_primary() {
    let tmp = tempfile::tempdir().unwrap();
    let (repo_dir, _base_hash, _delta_hash) = create_snapshot_repo_with_ca(tmp.path());
    let (primary_url, primary_seen, stop_primary) = start_file_server(repo_dir);

    let cfg_path = tmp.path().join("node.toml");
    let download_dir = tmp.path().join("cache");
    write_minimal_config_with_p2p(
        &cfg_path,
        &primary_url,
        &download_dir,
        &[
            "http://127.0.0.1:2".to_string(),
            "http://127.0.0.1:3".to_string(),
        ],
        1,
        1,
    );

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

    let seen = primary_seen.lock().unwrap();
    assert!(seen.iter().any(|s| s.contains("GET base.tar")));

    stop_primary.store(true, std::sync::atomic::Ordering::Relaxed);
}

#[test]
fn p2p_quorum_one_accepts_first_valid_peer() {
    let tmp = tempfile::tempdir().unwrap();
    let (repo_dir, _base_hash, delta_hash) = create_snapshot_repo_with_ca(tmp.path());

    let bad_repo = tmp.path().join("repo_bad");
    copy_dir_all(&repo_dir, &bad_repo);
    tamper_file(
        &bad_repo
            .join("artifacts")
            .join("delta")
            .join(format!("{delta_hash}.tar")),
    );

    let (peer_bad_url, _seen_bad, stop_bad) = start_file_server(bad_repo);
    let (peer_good_url, _seen_good, stop_good) = start_file_server(repo_dir);

    // Primary is down/unreachable.
    let primary_url = "http://127.0.0.1:4".to_string();

    let cfg_path = tmp.path().join("node.toml");
    let download_dir = tmp.path().join("cache");
    write_minimal_config_with_p2p(
        &cfg_path,
        &primary_url,
        &download_dir,
        &[peer_bad_url, peer_good_url],
        1,
        3,
    );

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

    stop_bad.store(true, std::sync::atomic::Ordering::Relaxed);
    stop_good.store(true, std::sync::atomic::Ordering::Relaxed);
}
