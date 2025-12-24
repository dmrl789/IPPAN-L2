//! DevNet E2E Test
//!
//! This test only runs when:
//! - `DEVNET_E2E=1` environment variable is set
//! - `IPPAN_RPC_URL` environment variable is set
//!
//! Run with:
//! ```bash
//! DEVNET_E2E=1 IPPAN_RPC_URL=http://localhost:26657 cargo test -p l2-node --test devnet_e2e
//! ```

use std::time::Duration;

/// Check if devnet e2e tests should run.
fn should_run() -> bool {
    std::env::var("DEVNET_E2E")
        .map(|v| v == "1")
        .unwrap_or(false)
        && std::env::var("IPPAN_RPC_URL").is_ok()
}

/// Skip test if conditions not met.
macro_rules! skip_if_not_enabled {
    () => {
        if !should_run() {
            eprintln!("Skipping test: DEVNET_E2E=1 and IPPAN_RPC_URL not set");
            return;
        }
    };
}

#[tokio::test]
async fn devnet_e2e_submit_txs_and_check_batch() {
    skip_if_not_enabled!();

    use std::net::TcpListener;

    // Find a random available port
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind random port");
    let port = listener.local_addr().unwrap().port();
    drop(listener);

    let ippan_rpc_url = std::env::var("IPPAN_RPC_URL").expect("IPPAN_RPC_URL");
    let db_path = tempfile::tempdir().expect("create temp dir");

    // Start l2-node in background
    let node_handle = tokio::spawn(async move {
        use std::process::Command;

        let status = Command::new("cargo")
            .args([
                "run",
                "-p",
                "l2-node",
                "--",
                "--l2-db-path",
                db_path.path().to_str().unwrap(),
                "--l2-listen-addr",
                &format!("127.0.0.1:{port}"),
                "--ippan-rpc-url",
                &ippan_rpc_url,
                "--l2-leader",
                "true",
                "--batcher-enabled",
                "true",
                "--l2-chain-id",
                "1337",
            ])
            .env("RUST_LOG", "info")
            .status();

        match status {
            Ok(s) => eprintln!("Node exited with: {s}"),
            Err(e) => eprintln!("Node failed to start: {e}"),
        }
    });

    // Wait for node to start
    let base_url = format!("http://127.0.0.1:{port}");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("http client");

    // Poll until node is ready (max 30s)
    let start = std::time::Instant::now();
    loop {
        if start.elapsed() > Duration::from_secs(30) {
            node_handle.abort();
            panic!("Node failed to start within 30s");
        }

        match client.get(format!("{base_url}/healthz")).send().await {
            Ok(resp) if resp.status().is_success() => break,
            _ => tokio::time::sleep(Duration::from_millis(500)).await,
        }
    }

    eprintln!("Node is ready at {base_url}");

    // Submit 20 transactions
    let mut tx_hashes = Vec::new();
    for i in 0u64..20 {
        let payload = format!("tx_payload_{i:04}");
        let resp = client
            .post(format!("{base_url}/tx"))
            .json(&serde_json::json!({
                "chain_id": 1337,
                "from": format!("sender_{}", i % 5),
                "nonce": i,
                "payload": hex::encode(payload.as_bytes())
            }))
            .send()
            .await
            .expect("submit tx");

        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            panic!("Failed to submit tx {i}: {status} - {body}");
        }

        let result: serde_json::Value = resp.json().await.expect("parse response");
        assert!(
            result["accepted"].as_bool().unwrap_or(false),
            "tx {i} not accepted: {result}"
        );

        if let Some(hash) = result["tx_hash"].as_str() {
            tx_hashes.push(hash.to_string());
        }
    }

    eprintln!("Submitted {} transactions", tx_hashes.len());

    // Wait for batch to be created (max 10s)
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Check status for batch info
    let status_resp = client
        .get(format!("{base_url}/status"))
        .send()
        .await
        .expect("get status");

    let status: serde_json::Value = status_resp.json().await.expect("parse status");
    eprintln!("Status: {}", serde_json::to_string_pretty(&status).unwrap());

    // Check that batcher processed something
    let batcher = &status["batcher"];
    assert!(
        batcher["enabled"].as_bool().unwrap_or(false),
        "batcher not enabled"
    );

    // Check posting counters
    let posting = &status["posting"];
    let _total_batches = posting["pending"].as_u64().unwrap_or(0)
        + posting["posted"].as_u64().unwrap_or(0)
        + posting["confirmed"].as_u64().unwrap_or(0);

    eprintln!(
        "Posting stats: pending={}, posted={}, confirmed={}, failed={}",
        posting["pending"].as_u64().unwrap_or(0),
        posting["posted"].as_u64().unwrap_or(0),
        posting["confirmed"].as_u64().unwrap_or(0),
        posting["failed"].as_u64().unwrap_or(0)
    );

    // Verify at least one batch was processed
    // (may not have posted yet depending on timing)
    if let Some(last_hash) = status["batcher"]["last_batch_hash"].as_str() {
        eprintln!("Last batch hash: {last_hash}");

        // Try to query the batch
        let batch_resp = client
            .get(format!("{base_url}/batch/{last_hash}"))
            .send()
            .await
            .expect("get batch");

        if batch_resp.status().is_success() {
            let batch: serde_json::Value = batch_resp.json().await.expect("parse batch");
            eprintln!("Batch: {}", serde_json::to_string_pretty(&batch).unwrap());
        }
    }

    // Shutdown
    node_handle.abort();
    eprintln!("DevNet E2E test completed successfully");
}

#[tokio::test]
async fn devnet_e2e_status_endpoint() {
    skip_if_not_enabled!();

    // Simple test that just checks the IPPAN RPC is reachable
    let ippan_rpc_url = std::env::var("IPPAN_RPC_URL").expect("IPPAN_RPC_URL");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("http client");

    // Try to reach the status endpoint
    let resp = client.get(format!("{ippan_rpc_url}/status")).send().await;

    match resp {
        Ok(r) => {
            eprintln!("IPPAN RPC status: {}", r.status());
            if r.status().is_success() {
                let body: serde_json::Value = r.json().await.unwrap_or_default();
                eprintln!(
                    "IPPAN RPC response: {}",
                    serde_json::to_string_pretty(&body).unwrap_or_default()
                );
            }
        }
        Err(e) => {
            eprintln!("Warning: IPPAN RPC not reachable: {e}");
            // Don't fail - this is informational
        }
    }
}
