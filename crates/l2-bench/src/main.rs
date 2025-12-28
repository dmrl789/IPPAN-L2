//! IPPAN L2 Benchmark CLI.
//!
//! Run deterministic benchmarks for critical L2 paths.
//!
//! ## Usage
//!
//! ```bash
//! # Run all benchmarks with default config
//! l2-bench run --out bench.json
//!
//! # Run specific scenario with custom parameters
//! l2-bench run --scenario m2m_accounting --txs 100000 --out bench.json
//!
//! # Run batcher benchmark with specific hubs
//! l2-bench run --scenario batcher_throughput --hubs fin,m2m --txs 50000 --out bench.json
//!
//! # Run bridge Merkle verification benchmark
//! l2-bench run --scenario bridge_merkle_verify --proofs 1000 --out bench.json
//! ```

use clap::{Parser, Subcommand};
use l2_bench::{run_all_benchmarks, runner, BenchConfig};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "l2-bench")]
#[command(author = "IPPAN Contributors")]
#[command(version)]
#[command(about = "Deterministic benchmark suite for IPPAN L2", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run benchmark scenarios
    Run {
        /// Scenario to run (or "all" for all scenarios)
        #[arg(short, long, default_value = "all")]
        scenario: String,

        /// Number of operations/transactions
        #[arg(short = 't', long = "txs", default_value = "10000")]
        txs: u64,

        /// Number of proofs (alias for --txs, for bridge scenarios)
        #[arg(short = 'p', long = "proofs")]
        proofs: Option<u64>,

        /// Hubs to include (comma-separated)
        #[arg(long, default_value = "fin,m2m")]
        hubs: String,

        /// Batch size
        #[arg(short, long, default_value = "256")]
        batch_size: u32,

        /// Output JSON file path
        #[arg(short, long)]
        out: Option<PathBuf>,

        /// Deterministic seed
        #[arg(long, default_value = "4748554636697935872")]
        seed: u64,

        /// Warmup iterations
        #[arg(long, default_value = "2")]
        warmup: u32,

        /// Measurement iterations
        #[arg(long, default_value = "5")]
        iterations: u32,

        /// Enable verbose logging
        #[arg(short, long)]
        verbose: bool,
    },

    /// List available scenarios
    List,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Run {
            scenario,
            txs,
            proofs,
            hubs,
            batch_size,
            out,
            seed,
            warmup,
            iterations,
            verbose,
        } => {
            // Setup logging
            let log_level = if verbose { "debug" } else { "info" };
            tracing_subscriber::fmt()
                .with_env_filter(
                    tracing_subscriber::EnvFilter::try_from_default_env()
                        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level)),
                )
                .init();

            // Build config
            let ops_count = proofs.unwrap_or(txs);
            let hubs: Vec<String> = hubs.split(',').map(|s| s.trim().to_string()).collect();

            let config = BenchConfig {
                scenario: scenario.clone(),
                ops_count,
                batch_size,
                hubs,
                warmup_iterations: warmup,
                measure_iterations: iterations,
                seed,
            };

            tracing::info!(
                scenario = %scenario,
                ops_count = ops_count,
                batch_size = batch_size,
                seed = seed,
                "starting benchmark"
            );

            // Run benchmarks
            let output = run_all_benchmarks(&config)?;

            // Print summary
            runner::print_summary(&output);

            // Write output if path specified
            if let Some(path) = out {
                runner::write_output_json(&output, &path)?;
                println!("Results written to: {}", path.display());
            }

            Ok(())
        }

        Commands::List => {
            println!("Available benchmark scenarios:\n");
            println!("  batcher_throughput      - Measures batch building from synthetic transactions");
            println!("  organiser_overhead      - Measures organiser decide() performance");
            println!("  m2m_accounting          - Measures M2M reserve/finalise with ledger");
            println!("  reconciler_scan         - Measures reconciler batch scanning");
            println!("  bridge_attestation_verify - Measures attestation verification");
            println!("  bridge_merkle_verify    - Measures Merkle proof verification");
            println!();
            println!("Use 'all' to run all scenarios.");
            Ok(())
        }
    }
}
