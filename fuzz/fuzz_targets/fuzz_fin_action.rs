#![no_main]
//! Fuzz target for FIN action request parsing.
//!
//! This tests the JSON deserialization of FIN hub action requests
//! to ensure robust handling of malformed inputs.

use libfuzzer_sys::fuzz_target;
use hub_fin::FinActionRequestV1;

fuzz_target!(|data: &[u8]| {
    // Try to parse as JSON
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    
    // Limit input size
    if text.len() > 256 * 1024 {
        return;
    }
    
    // Try to deserialize as FinActionRequestV1
    let _ = serde_json::from_str::<FinActionRequestV1>(text);
    
    // Also try parsing as generic JSON for depth analysis
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(text) {
        // Check depth doesn't exceed limits
        let depth = json_depth(&v, 0, 64);
        if depth > 64 {
            // Detected overly deep JSON
        }
    }
});

fn json_depth(v: &serde_json::Value, current: usize, max: usize) -> usize {
    if current >= max {
        return current;
    }
    
    match v {
        serde_json::Value::Null
        | serde_json::Value::Bool(_)
        | serde_json::Value::Number(_)
        | serde_json::Value::String(_) => current + 1,
        serde_json::Value::Array(a) => {
            let mut max_depth = current + 1;
            for (i, item) in a.iter().enumerate() {
                if i > 100 {
                    break; // Limit iteration
                }
                max_depth = max_depth.max(json_depth(item, current + 1, max));
            }
            max_depth
        }
        serde_json::Value::Object(m) => {
            let mut max_depth = current + 1;
            for (i, (_, val)) in m.iter().enumerate() {
                if i > 100 {
                    break; // Limit iteration
                }
                max_depth = max_depth.max(json_depth(val, current + 1, max));
            }
            max_depth
        }
    }
}
