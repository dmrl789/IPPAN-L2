#![forbid(unsafe_code)]

use crate::config::{LimitsConfig, RetentionConfig};
use serde_json::Value;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct PrunePlan {
    pub now_secs: u64,
    pub cutoff_secs: u64,
    pub scanned_files: usize,
    pub deletions: Vec<PathBuf>,
    pub skipped_unknown_timestamp: usize,
    pub skipped_too_large: usize,
    pub kept_due_to_min_keep: usize,
}

pub fn plan_prune_receipts_dir(
    receipts_dir: &Path,
    retention: &RetentionConfig,
    limits: &LimitsConfig,
    now_secs: u64,
) -> Result<PrunePlan, String> {
    let days = retention.receipts_days.max(1) as u64;
    let cutoff_secs = now_secs.saturating_sub(days * 86_400);
    let failed_days = retention.recon_failed_days.max(1) as u64;
    let failed_cutoff_secs = now_secs.saturating_sub(failed_days * 86_400);

    let files = collect_json_files(receipts_dir)?;

    let mut scanned_files = 0usize;
    let mut skipped_unknown_timestamp = 0usize;
    let mut skipped_too_large = 0usize;

    let mut ts_files: Vec<(u64, bool, PathBuf)> = Vec::new();

    for p in &files {
        scanned_files += 1;
        let meta = fs::metadata(p).map_err(|e| format!("metadata failed {}: {e}", p.display()))?;
        let max_receipt_bytes_u64 = u64::try_from(limits.max_receipt_bytes).unwrap_or(u64::MAX);
        if meta.len() > max_receipt_bytes_u64 {
            skipped_too_large += 1;
            continue;
        }
        let raw = fs::read(p).map_err(|e| format!("read failed {}: {e}", p.display()))?;
        let v: Value = match serde_json::from_slice(&raw) {
            Ok(v) => v,
            Err(_) => {
                skipped_unknown_timestamp += 1;
                continue;
            }
        };
        let Some(ts) = extract_timestamp_secs(&v) else {
            skipped_unknown_timestamp += 1;
            continue;
        };
        let is_failed = receipt_is_failed(&v);
        ts_files.push((ts, is_failed, p.clone()));
    }

    // Keep newest N receipts regardless of cutoff.
    ts_files.sort_by(|a, b| b.0.cmp(&a.0));
    let mut keep: HashSet<PathBuf> = HashSet::new();
    for (_, _, p) in ts_files.iter().take(retention.min_receipts_keep) {
        keep.insert(p.clone());
    }

    let mut kept_due_to_min_keep = 0usize;
    let mut deletions = Vec::new();
    for (ts, is_failed, p) in ts_files {
        let effective_cutoff = if is_failed {
            failed_cutoff_secs
        } else {
            cutoff_secs
        };
        if keep.contains(&p) {
            if ts < effective_cutoff {
                kept_due_to_min_keep += 1;
            }
            continue;
        }
        if ts < effective_cutoff {
            deletions.push(p);
        }
    }

    Ok(PrunePlan {
        now_secs,
        cutoff_secs,
        scanned_files,
        deletions,
        skipped_unknown_timestamp,
        skipped_too_large,
        kept_due_to_min_keep,
    })
}

pub fn execute_prune(plan: &PrunePlan) -> Result<(), String> {
    for p in &plan.deletions {
        fs::remove_file(p).map_err(|e| format!("failed deleting {}: {e}", p.display()))?;
    }
    Ok(())
}

fn collect_json_files(root: &Path) -> Result<Vec<PathBuf>, String> {
    let mut out = Vec::new();
    if !root.exists() {
        return Ok(out);
    }
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        let rd = match fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(_) => continue,
        };
        for e in rd {
            let Ok(e) = e else { continue };
            let p = e.path();
            let Ok(ft) = e.file_type() else { continue };
            if ft.is_dir() {
                stack.push(p);
                continue;
            }
            if ft.is_file() && p.extension().and_then(|s| s.to_str()) == Some("json") {
                out.push(p);
            }
        }
    }
    Ok(out)
}

fn extract_timestamp_secs(v: &Value) -> Option<u64> {
    if let Some(n) = v.get("written_at_unix_secs").and_then(|x| x.as_u64()) {
        return Some(n);
    }
    if let Some(s) = v.get("written_at").and_then(|x| x.as_str()) {
        if let Ok(t) =
            time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        {
            let ts = t.unix_timestamp().max(0);
            return u64::try_from(ts).ok();
        }
    }
    if let Some(s) = v.get("submitted_at").and_then(|x| x.as_str()) {
        if let Ok(t) =
            time::OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
        {
            let ts = t.unix_timestamp().max(0);
            return u64::try_from(ts).ok();
        }
    }
    None
}

fn receipt_is_failed(v: &Value) -> bool {
    let Some(s) = v.get("submit_state") else {
        return false;
    };
    match s {
        Value::String(x) => x.eq_ignore_ascii_case("failed"),
        Value::Object(m) => m.contains_key("Failed") || m.contains_key("failed"),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_prune_keeps_min_receipts() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let dir = tmp.path();

        // Create 3 receipts with explicit unix timestamps.
        for (i, ts) in [(1, 10u64), (2, 20u64), (3, 30u64)] {
            let p = dir.join(format!("r{i}.json"));
            let v = serde_json::json!({
                "schema_version": 1,
                "written_at_unix_secs": ts
            });
            std::fs::write(&p, serde_json::to_vec(&v).unwrap()).unwrap();
        }

        let retention = RetentionConfig {
            receipts_days: 1,
            recon_failed_days: 7,
            min_receipts_keep: 2,
        };
        let limits = LimitsConfig {
            max_receipt_bytes: 1024,
            ..LimitsConfig::default()
        };

        // now=100 => cutoff=100-86400 => nothing pruned
        let plan = plan_prune_receipts_dir(dir, &retention, &limits, 100).unwrap();
        assert_eq!(plan.deletions.len(), 0);

        // now=90_000 => cutoff=3_600 (so all ts<3600 are old), but keep 2 newest => delete 1.
        let plan = plan_prune_receipts_dir(dir, &retention, &limits, 90_000).unwrap();
        assert_eq!(plan.deletions.len(), 1);
    }
}
