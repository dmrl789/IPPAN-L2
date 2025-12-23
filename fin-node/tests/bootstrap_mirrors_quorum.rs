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

fn write_minimal_config_mirrors_quorum(
    path: &Path,
    primary_url: &str,
    mirrors: &[String],
    download_dir: &Path,
    quorum: usize,
) {
    let mirrors_toml = mirrors
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
base_url = "{primary_url}"
index_path = "index.json"
download_dir = "{download_dir}"
max_download_mb = 4096
connect_timeout_ms = 200
read_timeout_ms = 2000
concurrency = 2

[bootstrap.sources]
mode = "mirrors_quorum"
primary = "{primary_url}"
mirrors = [{mirrors_toml}]
quorum = {quorum}
max_sources = 5
"#,
        receipts = download_dir.join("receipts").display(),
        fin_db = download_dir.join("fin_db").display(),
        data_db = download_dir.join("data_db").display(),
        policy_db = download_dir.join("policy_db").display(),
        recon_db = download_dir.join("recon_db").display(),
        bootstrap_db = download_dir.join("bootstrap_db").display(),
        download_dir = download_dir.display(),
        primary_url = primary_url,
        mirrors_toml = mirrors_toml,
        quorum = quorum,
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
                Header::from_bytes(&b"Content-Length"[..], total_len.to_string().as_bytes()).unwrap(),
            );
            let _ = req.respond(resp);
        }
    });

    (format!("http://{}", addr), seen, stop)
}

#[test]
fn mirrors_quorum_two_sources_agree() {
    let tmp = tempfile::tempdir().unwrap();
    let repo_dir = create_snapshot_repo(tmp.path());

    let (url1, seen1, stop1) = start_file_server(repo_dir.clone());
    let (url2, seen2, stop2) = start_file_server(repo_dir);

    let cfg_path = tmp.path().join("node.toml");
    let download_dir = tmp.path().join("cache");
    write_minimal_config_mirrors_quorum(&cfg_path, &url1, &[url2.clone()], &download_dir, 2);

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

    // Both sources should have been queried for index.json.
    assert!(seen1.lock().unwrap().iter().any(|s| s == "GET index.json"));
    assert!(seen2.lock().unwrap().iter().any(|s| s == "GET index.json"));

    stop1.store(true, std::sync::atomic::Ordering::Relaxed);
    stop2.store(true, std::sync::atomic::Ordering::Relaxed);
}

#[test]
fn mirrors_quorum_majority_wins_when_one_differs() {
    let tmp = tempfile::tempdir().unwrap();
    let repo_dir = create_snapshot_repo(tmp.path());
    let good_index = std::fs::read(repo_dir.join("index.json")).unwrap();

    // Create a "bad" mirror whose index.json bytes differ but are still valid JSON
    // (trailing whitespace is valid JSON, but changes bytes -> changes hash).
    let bad_repo = tmp.path().join("repo_bad");
    copy_dir_all(&repo_dir, &bad_repo);
    let mut bad_index = std::fs::read(bad_repo.join("index.json")).unwrap();
    bad_index.extend_from_slice(b"\n");
    std::fs::write(bad_repo.join("index.json"), bad_index).unwrap();

    let (good1_url, _seen_good1, stop_good1) = start_file_server(repo_dir.clone());
    let (good2_url, _seen_good2, stop_good2) = start_file_server(repo_dir);
    let (bad_url, _seen_bad, stop_bad) = start_file_server(bad_repo);

    let cfg_path = tmp.path().join("node.toml");
    let download_dir = tmp.path().join("cache");
    write_minimal_config_mirrors_quorum(
        &cfg_path,
        &good1_url,
        &[good2_url.clone(), bad_url.clone()],
        &download_dir,
        2,
    );

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

    // fetch() persists the chosen index.json even in dry-run; it must match the majority bytes.
    let chosen = std::fs::read(download_dir.join("index.json")).unwrap();
    assert_eq!(chosen, good_index);

    stop_good1.store(true, std::sync::atomic::Ordering::Relaxed);
    stop_good2.store(true, std::sync::atomic::Ordering::Relaxed);
    stop_bad.store(true, std::sync::atomic::Ordering::Relaxed);
}

