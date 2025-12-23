#![forbid(unsafe_code)]

use serde::Serialize;

#[derive(Debug, thiserror::Error)]
pub enum CanonicalizeError {
    #[error("serde error: {0}")]
    Serde(String),
}

/// Deterministic canonical JSON bytes.
///
/// Strategy:
/// - Convert to `serde_json::Value`
/// - Recursively sort object keys (stable)
/// - Serialize to compact JSON bytes
pub fn canonical_json_bytes<T: Serialize>(v: &T) -> Result<Vec<u8>, CanonicalizeError> {
    let mut value = serde_json::to_value(v).map_err(|e| CanonicalizeError::Serde(e.to_string()))?;
    canonical_json_sort_in_place(&mut value);
    serde_json::to_vec(&value).map_err(|e| CanonicalizeError::Serde(e.to_string()))
}

fn canonical_json_sort_in_place(v: &mut serde_json::Value) {
    match v {
        serde_json::Value::Object(map) => {
            let mut entries: Vec<(String, serde_json::Value)> =
                std::mem::take(map).into_iter().collect();
            entries.sort_by(|(a, _), (b, _)| a.cmp(b));
            for (_, val) in entries.iter_mut() {
                canonical_json_sort_in_place(val);
            }
            let mut new_map = serde_json::Map::new();
            for (k, val) in entries {
                new_map.insert(k, val);
            }
            *map = new_map;
        }
        serde_json::Value::Array(arr) => {
            for x in arr.iter_mut() {
                canonical_json_sort_in_place(x);
            }
        }
        _ => {}
    }
}
