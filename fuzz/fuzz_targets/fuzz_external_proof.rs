#![no_main]
//! Fuzz target for external proof request parsing.
//!
//! This tests the JSON deserialization and validation of external proof
//! submission requests to ensure robust handling of malformed inputs.

use libfuzzer_sys::fuzz_target;
use serde::{Deserialize, Serialize};

/// Simplified external proof request (mirrors l2-bridge API).
#[derive(Debug, Clone, Serialize, Deserialize)]
struct FuzzProofRequest {
    proof_type: String,
    chain: String,
    tx_hash: String,
    log_index: u32,
    contract: String,
    topic0: String,
    data_hash: String,
    block_number: u64,
    block_hash: String,
    #[serde(default)]
    confirmations: Option<u32>,
    #[serde(default)]
    attestor_pubkey: Option<String>,
    #[serde(default)]
    signature: Option<String>,
    #[serde(default)]
    tx_index: Option<u32>,
    #[serde(default)]
    header_rlp: Option<String>,
    #[serde(default)]
    receipt_rlp: Option<String>,
    #[serde(default)]
    proof_nodes: Option<Vec<String>>,
}

fuzz_target!(|data: &[u8]| {
    // Try to parse as JSON
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    
    // Limit input size
    if text.len() > 512 * 1024 {
        return;
    }
    
    // Try to deserialize
    let _ = serde_json::from_str::<FuzzProofRequest>(text);
    
    // Also try as serde_json::Value for depth checking
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
        let _ = json_depth(&v);
    }
});

fn json_depth(v: &serde_json::Value) -> usize {
    match v {
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => 1,
        serde_json::Value::Array(a) => {
            // Limit array iteration
            1 + a.iter().take(100).map(json_depth).max().unwrap_or(0)
        }
        serde_json::Value::Object(m) => {
            // Limit object iteration
            1 + m.values().take(100).map(json_depth).max().unwrap_or(0)
        }
    }
}
