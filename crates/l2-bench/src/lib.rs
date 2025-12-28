//! Deterministic benchmark scenarios for IPPAN L2.
//!
//! This module provides benchmark implementations for critical L2 paths:
//! - Batcher throughput (synthetic tx → batch build)
//! - Organiser overhead (decide() per loop with varying hub stats)
//! - M2M accounting (reserve + finalise with ledger)
//! - Reconciler scan (in-flight batch state transitions)
//! - Bridge proof verification (attestation and merkle)

// Allow certain casts in benchmark code - these values are constrained
#![allow(clippy::cast_possible_truncation)]
#![allow(clippy::cast_sign_loss)]
#![allow(clippy::cast_possible_wrap)]

pub mod runner;
pub mod scenarios;

use l2_core::bench::{BenchmarkMetadata, BenchmarkOutput, ScenarioResult};
use serde::{Deserialize, Serialize};
use std::time::Instant;

/// Benchmark configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchConfig {
    /// Scenario to run.
    pub scenario: String,
    /// Number of operations/transactions.
    pub ops_count: u64,
    /// Batch size for batcher scenarios.
    pub batch_size: u32,
    /// Hubs to include (for multi-hub scenarios).
    pub hubs: Vec<String>,
    /// Number of warmup iterations.
    pub warmup_iterations: u32,
    /// Number of measurement iterations.
    pub measure_iterations: u32,
    /// Deterministic seed for synthetic data.
    pub seed: u64,
}

impl Default for BenchConfig {
    fn default() -> Self {
        Self {
            scenario: "all".to_string(),
            ops_count: 10_000,
            batch_size: 256,
            hubs: vec!["fin".to_string(), "m2m".to_string()],
            warmup_iterations: 2,
            measure_iterations: 5,
            seed: 0x42_4950_5041_4E00, // "IPPAN\0" in hex
        }
    }
}

/// Benchmark error type.
#[derive(Debug, thiserror::Error)]
pub enum BenchError {
    #[error("unknown scenario: {0}")]
    UnknownScenario(String),
    #[error("storage error: {0}")]
    Storage(String),
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

/// Run all benchmarks with the given configuration.
pub fn run_all_benchmarks(config: &BenchConfig) -> Result<BenchmarkOutput, BenchError> {
    let metadata = collect_metadata();
    let mut output = BenchmarkOutput::new(metadata);

    tracing::info!(
        ops_count = config.ops_count,
        batch_size = config.batch_size,
        seed = config.seed,
        "starting benchmark suite"
    );

    // Run each scenario
    let scenario_names = if config.scenario == "all" {
        vec![
            "batcher_throughput",
            "organiser_overhead",
            "m2m_accounting",
            "reconciler_scan",
            "bridge_attestation_verify",
            "bridge_merkle_verify",
        ]
    } else {
        vec![config.scenario.as_str()]
    };

    for name in scenario_names {
        tracing::info!(scenario = name, "running scenario");
        let result = run_scenario(name, config)?;
        output.add_scenario(result);
    }

    Ok(output)
}

/// Run a single benchmark scenario.
pub fn run_scenario(name: &str, config: &BenchConfig) -> Result<ScenarioResult, BenchError> {
    match name {
        "batcher_throughput" => scenarios::batcher::run_batcher_throughput(config),
        "organiser_overhead" => scenarios::organiser::run_organiser_overhead(config),
        "m2m_accounting" => scenarios::m2m::run_m2m_accounting(config),
        "reconciler_scan" => scenarios::reconciler::run_reconciler_scan(config),
        "bridge_attestation_verify" => scenarios::bridge::run_attestation_verify(config),
        "bridge_merkle_verify" => scenarios::bridge::run_merkle_verify(config),
        _ => Err(BenchError::UnknownScenario(name.to_string())),
    }
}

/// Collect system metadata for the benchmark output.
fn collect_metadata() -> BenchmarkMetadata {
    use sysinfo::System;

    let mut sys = System::new_all();
    sys.refresh_all();

    // Get CPU info
    let cpu_info = sys
        .cpus()
        .first()
        .map(|cpu| cpu.brand().to_string())
        .unwrap_or_else(|| "unknown".to_string());

    let cpu_cores = sys.cpus().len() as u32;
    let memory_bytes = Some(sys.total_memory());

    // Get git info from environment (set at build time or runtime)
    let git_commit = std::env::var("IPPAN_GIT_COMMIT")
        .or_else(|_| std::env::var("GIT_COMMIT"))
        .unwrap_or_else(|_| get_git_commit().unwrap_or_else(|| "unknown".to_string()));

    let git_branch = std::env::var("IPPAN_GIT_BRANCH")
        .or_else(|_| std::env::var("GIT_BRANCH"))
        .ok()
        .or_else(get_git_branch);

    // Get build timestamp
    let build_timestamp = chrono_lite_timestamp();

    // Get rustc version
    let rustc_version = get_rustc_version().unwrap_or_else(|| "unknown".to_string());

    // Determine profile
    let profile = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };

    // Collect enabled features (none currently configured for l2-bench)
    let features = Vec::new();

    BenchmarkMetadata {
        git_commit,
        git_branch,
        build_timestamp,
        features,
        cpu_info,
        cpu_cores,
        memory_bytes,
        rustc_version,
        target_triple: std::env::consts::ARCH.to_string() + "-" + std::env::consts::OS,
        profile: profile.to_string(),
        bench_version: env!("CARGO_PKG_VERSION").to_string(),
    }
}

/// Get current git commit hash.
fn get_git_commit() -> Option<String> {
    std::process::Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout)
                    .ok()
                    .map(|s| s.trim().to_string())
            } else {
                None
            }
        })
}

/// Get current git branch.
fn get_git_branch() -> Option<String> {
    std::process::Command::new("git")
        .args(["rev-parse", "--abbrev-ref", "HEAD"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout)
                    .ok()
                    .map(|s| s.trim().to_string())
            } else {
                None
            }
        })
}

/// Get rustc version.
fn get_rustc_version() -> Option<String> {
    std::process::Command::new("rustc")
        .args(["--version"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                String::from_utf8(o.stdout)
                    .ok()
                    .map(|s| s.trim().to_string())
            } else {
                None
            }
        })
}

/// Simple ISO 8601 timestamp without chrono dependency.
fn chrono_lite_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();

    let secs = duration.as_secs();

    // Convert to UTC components (simplified, doesn't handle leap seconds)
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;

    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;

    // Calculate year, month, day from days since epoch (1970-01-01)
    let mut remaining_days = days_since_epoch as i64;
    let mut year = 1970i32;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }

    let days_in_months: [i64; 12] = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };

    let mut month = 1u32;
    for &days in &days_in_months {
        if remaining_days < days {
            break;
        }
        remaining_days -= days;
        month += 1;
    }

    let day = remaining_days as u32 + 1;

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Timing helper for measuring operation latency.
pub struct LatencyCollector {
    samples: Vec<u64>,
}

impl LatencyCollector {
    /// Create a new latency collector with pre-allocated capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            samples: Vec::with_capacity(capacity),
        }
    }

    /// Record a single latency sample (in microseconds).
    pub fn record(&mut self, latency_us: u64) {
        self.samples.push(latency_us);
    }

    /// Record elapsed time from an instant.
    pub fn record_elapsed(&mut self, start: Instant) {
        let elapsed = start.elapsed();
        let us = elapsed.as_micros() as u64;
        self.samples.push(us);
    }

    /// Get the collected samples.
    pub fn samples(&self) -> &[u64] {
        &self.samples
    }

    /// Compute latency statistics.
    pub fn stats(&mut self) -> l2_core::bench::LatencyStats {
        self.samples.sort_unstable();
        l2_core::bench::LatencyStats::from_sorted_samples(&self.samples)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config() {
        let config = BenchConfig::default();
        assert_eq!(config.ops_count, 10_000);
        assert_eq!(config.batch_size, 256);
        assert!(config.hubs.contains(&"fin".to_string()));
    }

    #[test]
    fn latency_collector() {
        let mut collector = LatencyCollector::with_capacity(10);
        collector.record(100);
        collector.record(200);
        collector.record(150);

        let stats = collector.stats();
        assert_eq!(stats.sample_count, 3);
        assert_eq!(stats.min_us, 100);
        assert_eq!(stats.max_us, 200);
    }

    #[test]
    fn timestamp_format() {
        let ts = chrono_lite_timestamp();
        // Should be ISO 8601 format
        assert!(ts.contains('T'));
        assert!(ts.ends_with('Z'));
        assert_eq!(ts.len(), 20);
    }
}
