//! Benchmark runner utilities.

use crate::BenchError;
use l2_core::bench::BenchmarkOutput;
use std::fs::File;
use std::io::Write;
use std::path::Path;

/// Write benchmark output to a JSON file.
pub fn write_output_json(output: &BenchmarkOutput, path: &Path) -> Result<(), BenchError> {
    let json = serde_json::to_string_pretty(output)?;
    let mut file = File::create(path)?;
    file.write_all(json.as_bytes())?;
    Ok(())
}

/// Print benchmark output to stdout in a human-readable format.
pub fn print_summary(output: &BenchmarkOutput) {
    println!("\n╔══════════════════════════════════════════════════════════════════╗");
    println!("║                    IPPAN L2 BENCHMARK RESULTS                    ║");
    println!("╚══════════════════════════════════════════════════════════════════╝\n");

    // Metadata
    println!("Metadata:");
    println!("  Git Commit:    {}", output.metadata.git_commit);
    if let Some(ref branch) = output.metadata.git_branch {
        println!("  Git Branch:    {}", branch);
    }
    println!("  Build Time:    {}", output.metadata.build_timestamp);
    println!("  CPU:           {}", output.metadata.cpu_info);
    println!("  CPU Cores:     {}", output.metadata.cpu_cores);
    if let Some(mem) = output.metadata.memory_bytes {
        println!("  Memory:        {} GB", mem / 1_000_000_000);
    }
    println!("  Rustc:         {}", output.metadata.rustc_version);
    println!("  Profile:       {}", output.metadata.profile);
    if !output.metadata.features.is_empty() {
        println!("  Features:      {}", output.metadata.features.join(", "));
    }
    println!();

    // Scenario results
    println!("┌──────────────────────────────────────────────────────────────────┐");
    println!("│                        SCENARIO RESULTS                          │");
    println!("├──────────────────────────────────────────────────────────────────┤");

    for scenario in &output.scenarios {
        let status = if scenario.success { "✓" } else { "✗" };
        println!(
            "│ {} {:<30}                              │",
            status, scenario.name
        );
        println!(
            "│   Description: {:<47} │",
            truncate(&scenario.description, 47)
        );
        println!(
            "│   Operations:  {:>15}                              │",
            format_number(scenario.total_ops)
        );
        println!(
            "│   Duration:    {:>12} µs                              │",
            format_number(scenario.duration_us)
        );
        println!(
            "│   Throughput:  {:>12} ops/sec                        │",
            format_number(scenario.ops_per_sec)
        );

        if scenario.latency.sample_count > 0 {
            println!("│   Latency:                                                       │");
            println!(
                "│     p50:       {:>12} µs                              │",
                format_number(scenario.latency.p50_us)
            );
            println!(
                "│     p95:       {:>12} µs                              │",
                format_number(scenario.latency.p95_us)
            );
            println!(
                "│     p99:       {:>12} µs                              │",
                format_number(scenario.latency.p99_us)
            );
        }

        // Custom metrics
        for metric in &scenario.custom_metrics {
            println!(
                "│   {:<12} {:>12} {:<20}         │",
                format!("{}:", metric.name),
                format_signed(metric.value),
                metric.unit
            );
        }

        if let Some(ref error) = scenario.error {
            println!("│   Error: {:<53} │", truncate(error, 53));
        }

        println!("├──────────────────────────────────────────────────────────────────┤");
    }

    // Summary
    println!("│                          SUMMARY                                 │");
    println!("├──────────────────────────────────────────────────────────────────┤");
    println!(
        "│   Total Scenarios:   {:>10}                                 │",
        output.summary.total_scenarios
    );
    println!(
        "│   Total Operations:  {:>10}                                 │",
        format_number(output.summary.total_ops)
    );
    println!(
        "│   Total Duration:    {:>10} µs                             │",
        format_number(output.summary.total_duration_us)
    );
    println!(
        "│   Aggregate Rate:    {:>10} ops/sec                        │",
        format_number(output.summary.aggregate_ops_per_sec)
    );
    println!("└──────────────────────────────────────────────────────────────────┘\n");
}

/// Format a u64 number with thousands separators.
fn format_number(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

/// Format a signed i64 number with thousands separators.
fn format_signed(n: i64) -> String {
    if n < 0 {
        format!("-{}", format_number((-n) as u64))
    } else {
        format_number(n as u64)
    }
}

/// Truncate a string to a maximum length.
fn truncate(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len - 3])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_number_thousands() {
        assert_eq!(format_number(0), "0");
        assert_eq!(format_number(123), "123");
        assert_eq!(format_number(1234), "1,234");
        assert_eq!(format_number(1234567), "1,234,567");
    }

    #[test]
    fn format_signed_negative() {
        assert_eq!(format_signed(-1234), "-1,234");
        assert_eq!(format_signed(1234), "1,234");
    }

    #[test]
    fn truncate_long_string() {
        assert_eq!(truncate("hello", 10), "hello");
        assert_eq!(truncate("hello world!", 8), "hello...");
    }
}
