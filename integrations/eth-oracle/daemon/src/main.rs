mod config;
mod diff;
mod eth_oracle;
mod ippan_client;
mod model;

use anyhow::Result;
use clap::Parser;
use config::AppConfig;
use diff::select_changed_scores;
use eth_oracle::EthOracleClient;
use ippan_client::IppanClient;
use ethers::types::Address;
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::time::{sleep, Duration};
use tracing::{error, info, warn};

#[derive(Parser, Debug)]
struct Cli {
    #[arg(
        long,
        default_value = "integrations/eth-oracle/configs/devnet_sepolia.toml"
    )]
    config: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .init();

    let cli = Cli::parse();
    let cfg_path = PathBuf::from(cli.config);
    let cfg = AppConfig::from_toml(&cfg_path)?;

    info!(
        ippan_rpc_url = %cfg.ippan.rpc_url,
        eth_rpc_url = %cfg.ethereum.rpc_url,
        oracle = %cfg.ethereum.oracle_contract_address,
        "starting ippan -> ethereum oracle daemon"
    );

    let ippan = IppanClient::new(&cfg.ippan.rpc_url, cfg.security.score_scale);

    // Allow running without Ethereum configured yet (skeleton mode).
    let oracle_addr: Address = cfg
        .ethereum
        .oracle_contract_address
        .parse()
        .unwrap_or(Address::zero());
    let eth = if oracle_addr == Address::zero() {
        warn!("oracle_contract_address is zero; daemon will run but skip Ethereum writes");
        None
    } else {
        Some(EthOracleClient::new(&cfg.ethereum).await?)
    };

    let poll = Duration::from_millis(cfg.ippan.poll_interval_ms);
    let mut last_sent: HashMap<[u8; 32], u64> = HashMap::new();

    loop {
        let scores = match ippan.fetch_scores().await {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "IPPAN fetch failed; retrying");
                sleep(backoff(poll)).await;
                continue;
            }
        };

        let mut changed = select_changed_scores(&last_sent, scores);
        if changed.is_empty() {
            sleep(poll).await;
            continue;
        }

        if changed.len() > cfg.security.max_updates_per_round {
            changed.truncate(cfg.security.max_updates_per_round);
        }

        if let Some(eth) = &eth {
            match eth.push_scores(&changed).await {
                Ok(tx) => {
                    info!(tx_hash = %format!("0x{}", hex::encode(tx.as_bytes())), count = changed.len(), "pushed score updates");
                    for s in changed {
                        last_sent.insert(s.subject_id, s.score);
                    }
                }
                Err(e) => {
                    error!(error = %e, "ethereum push failed; will retry later");
                    sleep(backoff(poll)).await;
                }
            }
        } else {
            info!(count = changed.len(), "ethereum disabled; skipping push (mocked scores still produced)");
            for s in changed {
                last_sent.insert(s.subject_id, s.score);
            }
        }

        sleep(poll).await;
    }
}

fn backoff(poll: Duration) -> Duration {
    // simple bounded backoff
    let min = Duration::from_secs(2);
    let max = Duration::from_secs(30);
    if poll < min {
        min
    } else if poll > max {
        max
    } else {
        poll
    }
}
