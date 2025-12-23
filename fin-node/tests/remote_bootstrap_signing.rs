#![cfg(feature = "bootstrap-signing")]

use assert_cmd::prelude::*;
use ed25519_dalek::Signer;
use ed25519_dalek::SigningKey;
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

fn write_minimal_config(
    path: &Path,
    base_url: &str,
    download_dir: &Path,
    publisher_pubkey_hex: &str,
    required: bool,
) {
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
connect_timeout_ms = 3000
read_timeout_ms = 30000
concurrency = 1

[bootstrap.signing]
enabled = true
required = {required}
publisher_pubkeys = ["{publisher_pubkey_hex}"]
"#,
        receipts = download_dir.join("receipts").display(),
        fin_db = download_dir.join("fin_db").display(),
        data_db = download_dir.join("data_db").display(),
        policy_db = download_dir.join("policy_db").display(),
        recon_db = download_dir.join("recon_db").display(),
        bootstrap_db = download_dir.join("bootstrap_db").display(),
        base_url = base_url,
        download_dir = download_dir.display(),
        required = if required { "true" } else { "false" },
        publisher_pubkey_hex = publisher_pubkey_hex,
    );
    std::fs::write(path, toml).unwrap();
}

fn create_snapshot_repo(root: &Path) -> PathBuf {
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

    bootstrap::publish_index_v1(&repo_dir).unwrap();
    repo_dir
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
            seen_t.lock().unwrap().push(format!("{method} {url_path}"));

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

            let mut resp = Response::from_data(bytes).with_status_code(StatusCode(200));
            resp.add_header(
                Header::from_bytes(&b"Content-Length"[..], total_len.to_string().as_bytes())
                    .unwrap(),
            );
            let _ = req.respond(resp);
        }
    });

    (format!("http://{}", addr), seen, stop)
}

fn signing_message(index_bytes: &[u8]) -> Vec<u8> {
    const DOMAIN: &[u8] = b"IPPAN-L2:BOOTSTRAP_INDEX:V1\n";
    let mut out = Vec::with_capacity(DOMAIN.len() + index_bytes.len());
    out.extend_from_slice(DOMAIN);
    out.extend_from_slice(index_bytes);
    out
}

#[test]
fn bootstrap_fetch_requires_valid_signature_when_required() {
    let tmp = tempfile::tempdir().unwrap();
    let repo_dir = create_snapshot_repo(tmp.path());

    // Create a deterministic signing key.
    let sk = SigningKey::from_bytes(&[7u8; 32]);
    let pubkey_hex = hex::encode(sk.verifying_key().to_bytes());

    // Write an INVALID signature.
    std::fs::write(repo_dir.join("index.sig"), "00").unwrap();

    let (base_url, _seen, stop) = start_file_server(repo_dir);
    let cfg_path = tmp.path().join("node.toml");
    let download_dir = tmp.path().join("cache");
    write_minimal_config(&cfg_path, &base_url, &download_dir, &pubkey_hex, true);

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
    cmd.assert().failure();
    stop.store(true, std::sync::atomic::Ordering::Relaxed);
}

#[test]
fn bootstrap_fetch_accepts_valid_signature() {
    let tmp = tempfile::tempdir().unwrap();
    let repo_dir = create_snapshot_repo(tmp.path());

    let sk = SigningKey::from_bytes(&[9u8; 32]);
    let pubkey_hex = hex::encode(sk.verifying_key().to_bytes());

    let index_bytes = std::fs::read(repo_dir.join("index.json")).unwrap();
    let msg = signing_message(&index_bytes);
    let sig = sk.sign(&msg);
    std::fs::write(repo_dir.join("index.sig"), hex::encode(sig.to_bytes())).unwrap();

    let (base_url, _seen, stop) = start_file_server(repo_dir);
    let cfg_path = tmp.path().join("node.toml");
    let download_dir = tmp.path().join("cache");
    write_minimal_config(&cfg_path, &base_url, &download_dir, &pubkey_hex, true);

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
