//! Benchmark output schema for deterministic performance measurement.
//!
//! This module defines standardised types for benchmark output, ensuring
//! reproducible and comparable performance metrics across runs.
//!
//! ## Design Principles
//!
//! 1. **Integer-only**: All latencies are in microseconds or nanoseconds (u64)
//! 2. **Deterministic**: Git commit, features, and environment are captured
//! 3. **Comparable**: Standardised schema allows cross-run comparisons
//! 4. **Dashboard-ready**: JSON output can be ingested by monitoring systems

use serde::{Deserialize, Serialize};

/// Complete benchmark run output.
///
/// This is the top-level structure that gets serialised to JSON.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkOutput {
    /// Metadata about the benchmark run environment.
    pub metadata: BenchmarkMetadata,
    /// Results from all scenarios run.
    pub scenarios: Vec<ScenarioResult>,
    /// Overall summary statistics.
    pub summary: BenchmarkSummary,
}

impl BenchmarkOutput {
    /// Create a new benchmark output with metadata.
    pub fn new(metadata: BenchmarkMetadata) -> Self {
        Self {
            metadata,
            scenarios: Vec::new(),
            summary: BenchmarkSummary::default(),
        }
    }

    /// Add a scenario result.
    pub fn add_scenario(&mut self, result: ScenarioResult) {
        self.scenarios.push(result);
        self.recompute_summary();
    }

    /// Recompute summary from scenarios.
    #[allow(clippy::cast_possible_truncation)]
    fn recompute_summary(&mut self) {
        let mut total_ops = 0u64;
        let mut total_duration_us = 0u64;

        for scenario in &self.scenarios {
            total_ops = total_ops.saturating_add(scenario.total_ops);
            total_duration_us = total_duration_us.saturating_add(scenario.duration_us);
        }

        // Saturate at u32::MAX for scenario count (unrealistic to have more)
        self.summary.total_scenarios = self.scenarios.len().min(u32::MAX as usize) as u32;
        self.summary.total_ops = total_ops;
        self.summary.total_duration_us = total_duration_us;

        // Compute aggregate ops/sec (avoid division by zero)
        if total_duration_us > 0 {
            // ops_per_sec = total_ops * 1_000_000 / total_duration_us
            self.summary.aggregate_ops_per_sec = total_ops
                .saturating_mul(1_000_000)
                .checked_div(total_duration_us)
                .unwrap_or(0);
        }
    }
}

/// Metadata about the benchmark run environment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkMetadata {
    /// Git commit hash (short or full).
    pub git_commit: String,
    /// Git branch name (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_branch: Option<String>,
    /// Build timestamp (ISO 8601).
    pub build_timestamp: String,
    /// Feature flags enabled during build.
    pub features: Vec<String>,
    /// CPU model/info string.
    pub cpu_info: String,
    /// Number of CPU cores.
    pub cpu_cores: u32,
    /// Total system memory in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_bytes: Option<u64>,
    /// Rust compiler version.
    pub rustc_version: String,
    /// Target triple.
    pub target_triple: String,
    /// Profile (debug/release).
    pub profile: String,
    /// Benchmark suite version.
    pub bench_version: String,
}

impl Default for BenchmarkMetadata {
    fn default() -> Self {
        Self {
            git_commit: "unknown".to_string(),
            git_branch: None,
            build_timestamp: "unknown".to_string(),
            features: Vec::new(),
            cpu_info: "unknown".to_string(),
            cpu_cores: 1,
            memory_bytes: None,
            rustc_version: "unknown".to_string(),
            target_triple: "unknown".to_string(),
            profile: "release".to_string(),
            bench_version: "0.1.0".to_string(),
        }
    }
}

/// Result from a single benchmark scenario.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScenarioResult {
    /// Scenario name (e.g., "batcher_throughput", "m2m_accounting").
    pub name: String,
    /// Scenario description.
    pub description: String,
    /// Configuration parameters used.
    pub config: ScenarioConfig,
    /// Total operations executed.
    pub total_ops: u64,
    /// Total duration in microseconds.
    pub duration_us: u64,
    /// Operations per second (integer).
    pub ops_per_sec: u64,
    /// Latency percentiles in microseconds.
    pub latency: LatencyStats,
    /// Memory statistics (if available).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<MemoryStats>,
    /// Scenario-specific metrics.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub custom_metrics: Vec<CustomMetric>,
    /// Whether the scenario completed successfully.
    pub success: bool,
    /// Error message if the scenario failed.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

impl ScenarioResult {
    /// Create a new successful scenario result.
    pub fn new(name: impl Into<String>, description: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: description.into(),
            config: ScenarioConfig::default(),
            total_ops: 0,
            duration_us: 0,
            ops_per_sec: 0,
            latency: LatencyStats::default(),
            memory: None,
            custom_metrics: Vec::new(),
            success: true,
            error: None,
        }
    }

    /// Create a failed scenario result.
    pub fn failed(name: impl Into<String>, error: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            description: String::new(),
            config: ScenarioConfig::default(),
            total_ops: 0,
            duration_us: 0,
            ops_per_sec: 0,
            latency: LatencyStats::default(),
            memory: None,
            custom_metrics: Vec::new(),
            success: false,
            error: Some(error.into()),
        }
    }

    /// Set timing results.
    pub fn with_timing(mut self, total_ops: u64, duration_us: u64) -> Self {
        self.total_ops = total_ops;
        self.duration_us = duration_us;
        // ops_per_sec = total_ops * 1_000_000 / duration_us
        self.ops_per_sec = if duration_us > 0 {
            total_ops
                .saturating_mul(1_000_000)
                .checked_div(duration_us)
                .unwrap_or(0)
        } else {
            0
        };
        self
    }

    /// Set latency statistics.
    pub fn with_latency(mut self, latency: LatencyStats) -> Self {
        self.latency = latency;
        self
    }

    /// Set memory statistics.
    pub fn with_memory(mut self, memory: MemoryStats) -> Self {
        self.memory = Some(memory);
        self
    }

    /// Add a custom metric.
    pub fn add_metric(mut self, metric: CustomMetric) -> Self {
        self.custom_metrics.push(metric);
        self
    }

    /// Set configuration.
    pub fn with_config(mut self, config: ScenarioConfig) -> Self {
        self.config = config;
        self
    }
}

/// Configuration parameters for a scenario.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ScenarioConfig {
    /// Number of operations/transactions to run.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ops_count: Option<u64>,
    /// Batch size (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub batch_size: Option<u32>,
    /// Number of iterations.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iterations: Option<u32>,
    /// Hubs involved (if applicable).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hubs: Vec<String>,
    /// Random seed (if any).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed: Option<u64>,
    /// Additional key-value parameters.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub params: Vec<(String, String)>,
}

impl ScenarioConfig {
    /// Create a new config with ops count.
    pub fn with_ops(ops_count: u64) -> Self {
        Self {
            ops_count: Some(ops_count),
            ..Default::default()
        }
    }

    /// Set batch size.
    pub fn batch_size(mut self, size: u32) -> Self {
        self.batch_size = Some(size);
        self
    }

    /// Set iterations.
    pub fn iterations(mut self, iters: u32) -> Self {
        self.iterations = Some(iters);
        self
    }

    /// Add hubs.
    pub fn hubs(mut self, hubs: Vec<String>) -> Self {
        self.hubs = hubs;
        self
    }

    /// Add a custom parameter.
    pub fn param(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.params.push((key.into(), value.into()));
        self
    }
}

/// Latency statistics in microseconds (integer-only).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LatencyStats {
    /// Minimum latency (microseconds).
    pub min_us: u64,
    /// Maximum latency (microseconds).
    pub max_us: u64,
    /// Mean latency (microseconds).
    pub mean_us: u64,
    /// Median (p50) latency (microseconds).
    pub p50_us: u64,
    /// 95th percentile latency (microseconds).
    pub p95_us: u64,
    /// 99th percentile latency (microseconds).
    pub p99_us: u64,
    /// Standard deviation (microseconds, computed from integer variance).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stddev_us: Option<u64>,
    /// Number of samples used for statistics.
    pub sample_count: u64,
}

impl LatencyStats {
    /// Create latency stats from a sorted list of samples (in microseconds).
    ///
    /// The input must be pre-sorted in ascending order.
    #[allow(clippy::cast_possible_truncation)]
    pub fn from_sorted_samples(samples: &[u64]) -> Self {
        if samples.is_empty() {
            return Self::default();
        }

        let n = samples.len();
        let min_us = samples[0];
        let max_us = samples[n - 1];

        // Compute mean using integer arithmetic
        let sum: u128 = samples.iter().map(|&x| u128::from(x)).sum();
        let mean_us = (sum / n as u128) as u64;

        // Percentiles (use nearest-rank method) - integer arithmetic
        // p50 = n * 50 / 100, p95 = n * 95 / 100, p99 = n * 99 / 100
        let p50_idx = (n * 50) / 100;
        let p95_idx = (n * 95) / 100;
        let p99_idx = (n * 99) / 100;

        let p50_us = samples[p50_idx.min(n - 1)];
        let p95_us = samples[p95_idx.min(n - 1)];
        let p99_us = samples[p99_idx.min(n - 1)];

        // Compute integer variance and stddev using abs_diff
        let variance: u128 = samples
            .iter()
            .map(|&x| {
                let diff = x.abs_diff(mean_us);
                u128::from(diff) * u128::from(diff)
            })
            .sum();
        let stddev_us = if n > 1 {
            let var = variance / (n as u128 - 1);
            Some(integer_sqrt(var) as u64)
        } else {
            None
        };

        Self {
            min_us,
            max_us,
            mean_us,
            p50_us,
            p95_us,
            p99_us,
            stddev_us,
            sample_count: n as u64,
        }
    }
}

/// Integer square root using Newton's method.
#[allow(clippy::cast_possible_truncation)]
fn integer_sqrt(n: u128) -> u128 {
    if n == 0 {
        return 0;
    }
    let mut x = n;
    let mut y = n.div_ceil(2);
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

/// Memory statistics (optional).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryStats {
    /// Peak memory usage in bytes.
    pub peak_bytes: u64,
    /// Memory allocated during the scenario in bytes.
    pub allocated_bytes: u64,
    /// Memory freed during the scenario in bytes.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub freed_bytes: Option<u64>,
}

/// Custom metric for scenario-specific measurements.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomMetric {
    /// Metric name.
    pub name: String,
    /// Metric value (integer).
    pub value: i64,
    /// Unit of measurement.
    pub unit: String,
    /// Description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl CustomMetric {
    /// Create a new custom metric.
    pub fn new(name: impl Into<String>, value: i64, unit: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value,
            unit: unit.into(),
            description: None,
        }
    }

    /// Add a description.
    pub fn with_description(mut self, desc: impl Into<String>) -> Self {
        self.description = Some(desc.into());
        self
    }
}

/// Overall benchmark summary.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BenchmarkSummary {
    /// Total number of scenarios run.
    pub total_scenarios: u32,
    /// Total operations across all scenarios.
    pub total_ops: u64,
    /// Total duration across all scenarios (microseconds).
    pub total_duration_us: u64,
    /// Aggregate operations per second.
    pub aggregate_ops_per_sec: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latency_stats_from_sorted_samples() {
        let samples = vec![10, 20, 30, 40, 50, 60, 70, 80, 90, 100];
        let stats = LatencyStats::from_sorted_samples(&samples);

        assert_eq!(stats.min_us, 10);
        assert_eq!(stats.max_us, 100);
        assert_eq!(stats.mean_us, 55); // (10+20+...+100)/10 = 550/10 = 55
        assert_eq!(stats.p50_us, 60); // 50th percentile
        assert_eq!(stats.p95_us, 100); // 95th percentile
        assert_eq!(stats.p99_us, 100); // 99th percentile
        assert_eq!(stats.sample_count, 10);
        assert!(stats.stddev_us.is_some());
    }

    #[test]
    fn latency_stats_empty() {
        let stats = LatencyStats::from_sorted_samples(&[]);
        assert_eq!(stats.sample_count, 0);
        assert_eq!(stats.min_us, 0);
        assert_eq!(stats.max_us, 0);
    }

    #[test]
    fn latency_stats_single_sample() {
        let stats = LatencyStats::from_sorted_samples(&[42]);
        assert_eq!(stats.min_us, 42);
        assert_eq!(stats.max_us, 42);
        assert_eq!(stats.mean_us, 42);
        assert_eq!(stats.p50_us, 42);
        assert_eq!(stats.sample_count, 1);
    }

    #[test]
    fn scenario_result_ops_per_sec() {
        let result = ScenarioResult::new("test", "test scenario").with_timing(1_000_000, 1_000_000); // 1M ops in 1s

        assert_eq!(result.ops_per_sec, 1_000_000);
    }

    #[test]
    fn benchmark_output_summary() {
        let mut output = BenchmarkOutput::new(BenchmarkMetadata::default());

        output
            .add_scenario(ScenarioResult::new("scenario1", "first").with_timing(100_000, 500_000));
        output
            .add_scenario(ScenarioResult::new("scenario2", "second").with_timing(200_000, 500_000));

        assert_eq!(output.summary.total_scenarios, 2);
        assert_eq!(output.summary.total_ops, 300_000);
        assert_eq!(output.summary.total_duration_us, 1_000_000);
        assert_eq!(output.summary.aggregate_ops_per_sec, 300_000);
    }

    #[test]
    fn custom_metric() {
        let metric = CustomMetric::new("batches_built", 42, "count")
            .with_description("Number of batches built");

        assert_eq!(metric.name, "batches_built");
        assert_eq!(metric.value, 42);
        assert_eq!(metric.unit, "count");
        assert!(metric.description.is_some());
    }

    #[test]
    fn scenario_config_builder() {
        let config = ScenarioConfig::with_ops(100_000)
            .batch_size(256)
            .iterations(10)
            .hubs(vec!["fin".to_string(), "m2m".to_string()])
            .param("warmup", "true");

        assert_eq!(config.ops_count, Some(100_000));
        assert_eq!(config.batch_size, Some(256));
        assert_eq!(config.iterations, Some(10));
        assert_eq!(config.hubs.len(), 2);
        assert_eq!(config.params.len(), 1);
    }

    #[test]
    fn integer_sqrt_correctness() {
        assert_eq!(integer_sqrt(0), 0);
        assert_eq!(integer_sqrt(1), 1);
        assert_eq!(integer_sqrt(4), 2);
        assert_eq!(integer_sqrt(9), 3);
        assert_eq!(integer_sqrt(100), 10);
        assert_eq!(integer_sqrt(1_000_000), 1000);
        // For non-perfect squares, should return floor
        assert_eq!(integer_sqrt(10), 3);
        assert_eq!(integer_sqrt(99), 9);
    }

    #[test]
    fn json_serialization() {
        let mut output = BenchmarkOutput::new(BenchmarkMetadata {
            git_commit: "abc123".to_string(),
            git_branch: Some("main".to_string()),
            build_timestamp: "2024-01-01T00:00:00Z".to_string(),
            features: vec!["profiling".to_string()],
            cpu_info: "Intel Core i7".to_string(),
            cpu_cores: 8,
            memory_bytes: Some(16_000_000_000),
            rustc_version: "1.75.0".to_string(),
            target_triple: "x86_64-unknown-linux-gnu".to_string(),
            profile: "release".to_string(),
            bench_version: "0.1.0".to_string(),
        });

        output.add_scenario(
            ScenarioResult::new("test", "Test scenario")
                .with_timing(1000, 1000)
                .with_latency(LatencyStats::from_sorted_samples(&[100, 200, 300]))
                .add_metric(CustomMetric::new("custom", 42, "units")),
        );

        // Should serialize without panicking
        let json = serde_json::to_string_pretty(&output).unwrap();
        assert!(json.contains("abc123"));
        assert!(json.contains("test"));

        // Should deserialize back
        let parsed: BenchmarkOutput = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.metadata.git_commit, "abc123");
        assert_eq!(parsed.scenarios.len(), 1);
    }
}
