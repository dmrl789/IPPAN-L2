use anyhow::Result;
use clap::Parser;
use ethers::types::Address;
use ippan_eth_oracle_daemon::config::AppConfig;
use ippan_eth_oracle_daemon::diff::diff_scores;
use ippan_eth_oracle_daemon::eth_oracle::EthOracleClient;
use ippan_eth_oracle_daemon::ippan_client::IppanClient;
use ippan_eth_oracle_daemon::model::SubjectMeta;
use std::collections::HashMap;
use std::path::PathBuf;
use tokio::time::{sleep, Duration};
use tracing::{debug, error, info, warn};

#[derive(Parser, Debug)]
#[command(name = "ippan-eth-oracle-daemon")]
struct Args {
    #[command(subcommand)]
    command: Option<Cli>,
}

#[derive(Parser, Debug)]
#[command(name = "ippan-eth-oracle-daemon")]
enum Cli {
    /// Run the oracle daemon loop (default).
    Watch {
        #[arg(
            long,
            default_value = "integrations/eth-oracle/configs/devnet_sepolia.toml"
        )]
        config: PathBuf,
    },
    /// One-shot: fetch scores from IPPAN and print subject IDs, labels, and scores.
    Dump {
        #[arg(
            long,
            default_value = "integrations/eth-oracle/configs/devnet_sepolia.toml"
        )]
        config: PathBuf,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt().with_env_filter("info").init();

    let args = Args::parse();
    let cmd = args.command.unwrap_or(Cli::Watch {
        config: PathBuf::from("integrations/eth-oracle/configs/devnet_sepolia.toml"),
    });

    match cmd {
        Cli::Watch { config } => run_watch(config).await,
        Cli::Dump { config } => run_dump(config).await,
    }
}

async fn run_dump(config_path: PathBuf) -> Result<()> {
    let cfg = AppConfig::from_toml(&config_path)?;
    let ip_client = IppanClient::new(&cfg.ippan.rpc_url, cfg.security.score_scale);

    let scores = ip_client.fetch_scores().await?;
    println!("Fetched {} subjects from IPPAN:", scores.len());

    for s in scores {
        let id_hex = hex::encode(s.subject_id);
        let eth = s.eth_address.as_deref().unwrap_or("<none>");
        println!(
            "- subject_id=0x{} label={} eth_address={} score={}",
            id_hex, s.label, eth, s.score
        );
    }

    Ok(())
}

async fn run_watch(config_path: PathBuf) -> Result<()> {
    let cfg = AppConfig::from_toml(&config_path)?;

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

    // Local cache for subject_id -> (score + human metadata).
    let mut last_scores: HashMap<[u8; 32], SubjectMeta> = HashMap::new();

    loop {
        let scores = match ippan.fetch_scores().await {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "IPPAN fetch failed; retrying");
                sleep(backoff(poll)).await;
                continue;
            }
        };

        info!(count = scores.len(), "fetched IPPAN scores");
        debug!(
            sample = ?scores
                .iter()
                .take(10)
                .map(|s| (hex::encode(s.subject_id), s.label.as_str(), s.score))
                .collect::<Vec<_>>(),
            "ippan score sample"
        );

        let changed = diff_scores(&last_scores, scores, cfg.security.max_updates_per_round);
        if changed.is_empty() {
            sleep(poll).await;
            continue;
        }

        for s in &changed {
            let id_hex = hex::encode(s.subject_id);
            let eth_addr = s.eth_address.as_deref().unwrap_or("<none>");
            info!(
                "Will update subject: label={} subject_id=0x{} eth_address={} score={}",
                s.label, id_hex, eth_addr, s.score
            );
        }

        if let Some(eth) = &eth {
            match eth.push_scores(&changed).await {
                Ok(tx) => {
                    info!(
                        tx_hash = %format!("0x{}", hex::encode(tx.as_bytes())),
                        count = changed.len(),
                        "pushed score updates"
                    );
                    for s in changed {
                        last_scores.insert(
                            s.subject_id,
                            SubjectMeta {
                                score: s.score,
                                label: s.label.clone(),
                                eth_address: s.eth_address.clone(),
                            },
                        );
                    }
                }
                Err(e) => {
                    error!(error = %e, "ethereum push failed; will retry later");
                    sleep(backoff(poll)).await;
                }
            }
        } else {
            info!(
                count = changed.len(),
                "ethereum disabled; skipping push (mocked scores still produced)"
            );
            for s in changed {
                last_scores.insert(
                    s.subject_id,
                    SubjectMeta {
                        score: s.score,
                        label: s.label.clone(),
                        eth_address: s.eth_address.clone(),
                    },
                );
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
