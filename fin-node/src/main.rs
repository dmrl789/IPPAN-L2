#![forbid(unsafe_code)]
#![deny(clippy::float_arithmetic)]
#![deny(clippy::float_cmp)]

mod config;
mod data_api;
mod fin_api;
mod ha;
mod http_server;
mod linkage;
mod metrics;
mod policy_runtime;
mod policy_store;
mod pruning;
mod rate_limit;
mod recon;
mod recon_store;

use base64::Engine as _;
use clap::{Parser, Subcommand};
use l2_core::l1_contract::http_client::HttpL1Client;
use l2_core::l1_contract::mock_client::MockL1Client;
use l2_core::l1_contract::{
    Base64Bytes, ContractVersion, FixedAmountV1, HubPayloadEnvelopeV1, IdempotencyKey, L1Client,
    L1ClientError, L1InclusionProof, L1SubmitResult, L1TxId, L2BatchEnvelopeV1,
};
use l2_core::AccountId;
use std::fs;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use time::format_description::well_known::Rfc3339;
use tracing::{info, warn};

#[derive(Parser, Debug)]
#[command(author, version, about = "IPPAN FIN Node")]
struct Args {
    /// Path to a TOML config file. If omitted, uses `IPPAN_L2_CONFIG`.
    #[arg(long)]
    config: Option<PathBuf>,

    /// L1 mode:
    /// - mock: offline deterministic mock client (default)
    /// - http: real HTTP adapter (requires config)
    #[arg(long, value_enum, default_value_t = L1Mode::Mock)]
    l1_mode: L1Mode,

    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum, PartialEq, Eq)]
enum L1Mode {
    Mock,
    Http,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Start fin-node as a long-running service (health/ready/metrics).
    Run,

    /// L1 smoke/integration helpers.
    L1 {
        #[command(subcommand)]
        cmd: L1Command,
    },

    /// Submit a batch envelope (v1) to L1 with receipts.
    SubmitBatch(SubmitBatchArgs),

    /// Generate deterministic example batch envelopes (writes valid idempotency_key).
    GenExample(GenExampleArgs),

    /// HUB-DATA operator utilities.
    Data {
        #[command(subcommand)]
        cmd: DataCommand,
    },

    /// HUB-FIN operator utilities.
    Fin {
        #[command(subcommand)]
        cmd: FinCommand,
    },

    /// Policy/compliance list management (local node).
    Policy {
        #[command(subcommand)]
        cmd: PolicyCommand,
    },

    /// Prune old receipts / state (retention).
    Prune(PruneArgs),
}

#[derive(Debug, Subcommand)]
enum DataCommand {
    /// Export a deterministic HUB-DATA state snapshot (audit-friendly).
    ExportState {
        /// Output path for the JSON snapshot.
        #[arg(long)]
        out: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum FinCommand {
    /// Delegate an operator to transfer on behalf of an account for an asset.
    Delegate {
        /// From-account granting the delegation.
        #[arg(long)]
        from: String,
        /// Operator account receiving the delegation.
        #[arg(long)]
        operator: String,
        /// Asset id (32-byte hex).
        #[arg(long)]
        asset_id: String,
    },
    /// Revoke an operator delegation.
    RevokeDelegate {
        #[arg(long)]
        from: String,
        #[arg(long)]
        operator: String,
        #[arg(long)]
        asset_id: String,
    },
}

#[derive(Debug, Subcommand)]
enum PolicyCommand {
    /// Manage the global allowlist.
    Allow {
        #[command(subcommand)]
        cmd: PolicyListCommand,
    },
    /// Manage the global denylist.
    Deny {
        #[command(subcommand)]
        cmd: PolicyListCommand,
    },
    /// Print current policy status.
    Status,
}

#[derive(Debug, Subcommand)]
enum PolicyListCommand {
    Add { account: String },
    Remove { account: String },
}

#[derive(Debug, Subcommand)]
enum L1Command {
    /// Calls `l1.endpoints.chain_status` and prints the decoded JSON.
    Status,
    /// Validates config endpoints + performs a status call (read-only).
    Check,
    /// Fetch inclusion by idempotency key (base64url).
    Inclusion {
        #[arg(long)]
        id: String,
    },
    /// Fetch finality by L1 tx id.
    Finality {
        #[arg(long)]
        tx: String,
    },
}

#[derive(Debug, clap::Args)]
struct SubmitBatchArgs {
    /// Hub selector (for guardrails only).
    #[arg(long, value_enum)]
    hub: HubArg,

    /// Read a `L2BatchEnvelopeV1` JSON from this file.
    #[arg(long, conflicts_with = "stdin")]
    file: Option<PathBuf>,

    /// Read a `L2BatchEnvelopeV1` JSON from stdin.
    #[arg(long, default_value_t = false)]
    stdin: bool,

    /// Do not submit to L1; print canonical hash + idempotency key only.
    #[arg(long, default_value_t = false)]
    dry_run: bool,
}

#[derive(Debug, clap::Args)]
struct GenExampleArgs {
    #[arg(long, value_enum)]
    hub: HubArg,

    /// Output path for the generated `L2BatchEnvelopeV1` JSON.
    #[arg(long)]
    out: PathBuf,
}

#[derive(Debug, clap::Args)]
struct PruneArgs {
    /// Execute deletion (default is dry-run).
    #[arg(long, default_value_t = false, conflicts_with = "dry_run")]
    execute: bool,
    /// Dry run only (prints what would be deleted).
    #[arg(long, default_value_t = false)]
    dry_run: bool,
}

#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum HubArg {
    Fin,
    Data,
}

impl HubArg {
    fn matches_envelope(self, env: &L2BatchEnvelopeV1) -> bool {
        matches!(
            (self, env.hub),
            (HubArg::Fin, l2_core::L2HubId::Fin) | (HubArg::Data, l2_core::L2HubId::Data)
        )
    }

    fn as_l2_hub_id(self) -> l2_core::L2HubId {
        match self {
            HubArg::Fin => l2_core::L2HubId::Fin,
            HubArg::Data => l2_core::L2HubId::Data,
        }
    }
}

#[derive(Debug, serde::Serialize)]
struct SubmitReceipt {
    submitted_at: String,
    status: String,
    contract_version: String,
    canonical_hash: String,
    idempotency_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    l1_tx_id: Option<String>,
}

fn main() {
    let args = Args::parse();

    let cfg_path = resolve_config_path(args.config.as_deref());
    let cfg = cfg_path
        .as_deref()
        .map(config::load_config)
        .transpose()
        .unwrap_or_else(|e| exit_err(&e));

    init_logging(cfg.as_ref());

    let node_label = cfg
        .as_ref()
        .map(|c| c.node.label.as_str())
        .unwrap_or("fin-node");

    info!(node = node_label, l1_mode = ?args.l1_mode, "starting fin-node");

    let inner: Arc<dyn L1Client + Send + Sync> = match args.l1_mode {
        L1Mode::Mock => Arc::new(MockL1Client::default()),
        L1Mode::Http => {
            let cfg = cfg.as_ref().unwrap_or_else(|| {
                exit_err("missing config: pass --config or set IPPAN_L2_CONFIG for --l1-mode http")
            });
            cfg.validate_for_mode_http()
                .unwrap_or_else(|e| exit_err(&e));
            Arc::new(
                HttpL1Client::new(cfg.l1.rpc.clone()).unwrap_or_else(|e| exit_err(&e.to_string())),
            )
        }
    };

    let l1 = Arc::new(InstrumentedL1Client::new(inner));

    let command = args.command.unwrap_or(Command::Run);
    match command {
        Command::Run => {
            let bind = cfg
                .as_ref()
                .map(|c| c.server.bind_address.as_str())
                .unwrap_or("0.0.0.0:3000");
            let expected = cfg.as_ref().and_then(|c| c.l1.expected_network_id.clone());
            let metrics_enabled = cfg
                .as_ref()
                .map(|c| c.server.metrics_enabled)
                .unwrap_or(true);

            let receipts_dir = cfg
                .as_ref()
                .map(|c| c.storage.receipts_dir.as_str())
                .unwrap_or("receipts");
            let fin_db_dir = cfg
                .as_ref()
                .map(|c| c.storage.fin_db_dir.as_str())
                .unwrap_or("fin_db");
            let data_db_dir = cfg
                .as_ref()
                .map(|c| c.storage.data_db_dir.as_str())
                .unwrap_or("data_db");
            let policy_db_dir = cfg
                .as_ref()
                .map(|c| c.storage.policy_db_dir.as_str())
                .unwrap_or("policy_db");
            let recon_db_dir = cfg
                .as_ref()
                .map(|c| c.storage.recon_db_dir.as_str())
                .unwrap_or("recon_db");

            let recon_cfg = cfg.as_ref().map(|c| c.recon.clone());
            let recon_store = if recon_cfg.as_ref().map(|c| c.enabled).unwrap_or(false) {
                Some(
                    recon_store::ReconStore::open(recon_db_dir)
                        .unwrap_or_else(|e| exit_err(&e.to_string())),
                )
            } else {
                None
            };

            let policy_store = policy_store::PolicyStore::open(policy_db_dir)
                .unwrap_or_else(|e| exit_err(&e.to_string()));
            let mut policy = policy_runtime::PolicyRuntime::default();
            if let Some(c) = cfg.as_ref() {
                policy.mode = c.policy.mode;
                policy.admins = c
                    .policy
                    .admins
                    .iter()
                    .cloned()
                    .map(AccountId::new)
                    .collect();
                policy.compliance.enabled = c.policy.compliance.enabled;
                policy.compliance.strategy = match c.policy.compliance.strategy {
                    config::ComplianceStrategy::None => policy_runtime::ComplianceStrategy::None,
                    config::ComplianceStrategy::GlobalAllowlist => {
                        policy_runtime::ComplianceStrategy::GlobalAllowlist
                    }
                    config::ComplianceStrategy::GlobalDenylist => {
                        policy_runtime::ComplianceStrategy::GlobalDenylist
                    }
                };
            }
            policy.store = Some(policy_store);

            let store =
                hub_fin::FinStore::open(fin_db_dir).unwrap_or_else(|e| exit_err(&e.to_string()));
            ensure_state_version_fin(&store);
            let limits_cfg = cfg.as_ref().map(|c| c.limits.clone()).unwrap_or_default();
            let fin_limits = hub_fin::validation::ValidationLimits {
                max_string_bytes: limits_cfg.max_string_bytes,
                name_max_len: limits_cfg.max_string_bytes,
                symbol_max_len: limits_cfg.max_string_bytes,
                metadata_uri_max_len: limits_cfg.max_string_bytes,
                memo_max_len: limits_cfg.max_string_bytes,
                client_tx_id_max_len: limits_cfg.max_string_bytes,
                max_account_bytes: 128,
            };
            let data_limits = hub_data::validation::ValidationLimits {
                max_string_bytes: limits_cfg.max_string_bytes,
                name_max_len: limits_cfg.max_string_bytes,
                description_max_len: limits_cfg.max_string_bytes,
                pointer_uri_max_len: limits_cfg.max_string_bytes,
                mime_type_max_len: limits_cfg.max_string_bytes,
                terms_uri_max_len: limits_cfg.max_string_bytes,
                nonce_max_len: limits_cfg.max_string_bytes,
                statement_max_len: limits_cfg.max_string_bytes,
                ref_uri_max_len: limits_cfg.max_string_bytes,
                max_tags: limits_cfg.max_tags,
                max_tag_bytes: limits_cfg.max_tag_bytes,
                max_account_bytes: 128,
            };

            let fin_api = fin_api::FinApi::new_with_policy_recon_and_limits(
                l1.clone(),
                store,
                PathBuf::from(receipts_dir),
                policy.clone(),
                recon_store.clone(),
                fin_limits,
            );

            let data_store =
                hub_data::DataStore::open(data_db_dir).unwrap_or_else(|e| exit_err(&e.to_string()));
            ensure_state_version_data(&data_store);
            let data_api = data_api::DataApi::new_with_policy_recon_and_limits(
                l1.clone(),
                data_store,
                PathBuf::from(receipts_dir),
                policy,
                recon_store.clone(),
                data_limits,
            );

            let linkage_policy = cfg
                .as_ref()
                .map(|c| c.linkage.entitlement_policy)
                .unwrap_or(config::LinkageEntitlementPolicy::Optimistic);
            let linkage_policy = match linkage_policy {
                config::LinkageEntitlementPolicy::Optimistic => {
                    l2_core::hub_linkage::EntitlementPolicy::Optimistic
                }
                config::LinkageEntitlementPolicy::FinalityRequired => {
                    l2_core::hub_linkage::EntitlementPolicy::FinalityRequired
                }
            };

            let linkage_api = linkage::LinkageApi::new_with_policy_and_recon(
                fin_api.clone(),
                data_api.clone(),
                PathBuf::from(receipts_dir),
                linkage_policy,
                recon_store.clone(),
            );

            // Graceful shutdown: SIGINT/SIGTERM sets a shared stop flag.
            let stop = Arc::new(AtomicBool::new(false));
            {
                let stop = stop.clone();
                let _ = signal_hook::flag::register(signal_hook::consts::SIGINT, stop.clone());
                let _ = signal_hook::flag::register(signal_hook::consts::SIGTERM, stop);
            }

            // Build leader-only background loops (recon + pruning), start either directly (no HA)
            // or under the HA supervisor (leader-only).
            let mut recon_loop: Option<recon::ReconLoop> = None;
            if let (Some(store), Some(rcfg)) = (recon_store.clone(), recon_cfg.clone()) {
                if rcfg.enabled {
                    let reconciler = recon::Reconciler::new(
                        l1.clone(),
                        fin_api.clone(),
                        data_api.clone(),
                        linkage_api.clone(),
                        store,
                        recon::ReconLoopConfig {
                            interval_secs: rcfg.interval_secs,
                            batch_limit: rcfg.batch_limit,
                            max_scan: rcfg.max_scan,
                            max_attempts: rcfg.max_attempts,
                            base_delay_secs: rcfg.base_delay_secs,
                            max_delay_secs: rcfg.max_delay_secs,
                        },
                    );
                    recon_loop = Some(recon::ReconLoop::new(reconciler, rcfg.interval_secs));
                }
            }

            let mut pruning_loop: Option<pruning::PruningLoop> = None;
            if cfg.as_ref().map(|c| c.pruning.enabled).unwrap_or(false) {
                let retention = cfg
                    .as_ref()
                    .map(|c| c.retention.clone())
                    .unwrap_or_default();
                let limits = cfg.as_ref().map(|c| c.limits.clone()).unwrap_or_default();
                let interval = cfg
                    .as_ref()
                    .map(|c| c.pruning.interval_secs)
                    .unwrap_or(86_400);
                pruning_loop = Some(pruning::PruningLoop {
                    receipts_dir: PathBuf::from(receipts_dir),
                    retention,
                    limits,
                    interval_secs: interval,
                });
            }

            let ha_cfg = cfg.as_ref().map(|c| c.ha.clone()).unwrap_or_default();
            let ha_state = Arc::new(ha::supervisor::HaState::new(ha_cfg.clone()));

            let mut supervisor_handle: Option<std::thread::JoinHandle<()>> = None;
            let mut direct_bg_threads: Vec<std::thread::JoinHandle<()>> = Vec::new();
            if ha_cfg.enabled {
                ha_cfg
                    .validate()
                    .unwrap_or_else(|e| exit_err(&format!("invalid [ha] config: {e}")));

                let lock = ha::build_lock_provider(&ha_cfg)
                    .unwrap_or_else(|e| exit_err(&format!("failed to init HA lock provider: {e}")));

                let supervisor =
                    ha::supervisor::HaSupervisor::new(ha_state.clone(), lock, stop.clone());

                supervisor_handle = Some(supervisor.spawn(move |leader_stop| {
                    let mut hs = Vec::new();
                    if let Some(loop_) = recon_loop.clone() {
                        hs.push(loop_.start(leader_stop.clone()));
                    }
                    if let Some(loop_) = pruning_loop.clone() {
                        hs.push(loop_.start(leader_stop));
                    }
                    hs
                }));
            } else {
                // Non-HA mode: run background loops directly on all nodes.
                if let Some(loop_) = recon_loop {
                    direct_bg_threads.push(loop_.start(stop.clone()));
                }
                if let Some(loop_) = pruning_loop {
                    direct_bg_threads.push(loop_.start(stop.clone()));
                }
            }

            // Keep clones for best-effort flush after shutdown.
            let fin_api_shutdown = fin_api.clone();
            let data_api_shutdown = data_api.clone();
            let recon_shutdown = recon_store.clone();
            let stop_main = stop.clone();

            let r = http_server::serve(
                bind,
                l1,
                expected,
                metrics_enabled,
                fin_api,
                data_api,
                linkage_api,
                recon_store,
                cfg.as_ref().map(|c| c.limits.clone()).unwrap_or_default(),
                cfg.as_ref()
                    .map(|c| c.pagination.clone())
                    .unwrap_or_default(),
                cfg.as_ref()
                    .map(|c| c.rate_limit.clone())
                    .unwrap_or_default(),
                cfg.as_ref().map(|c| c.cors.clone()).unwrap_or_default(),
                cfg.as_ref()
                    .map(|c| c.server.max_inflight_requests)
                    .unwrap_or(64),
                ha_state,
                stop,
            );

            // Ensure background threads stop, then flush stores.
            if let Err(e) = r {
                exit_err(&e);
            }
            stop_main.store(true, Ordering::Relaxed);
            if let Some(h) = supervisor_handle {
                let _ = h.join();
            }
            for h in direct_bg_threads {
                let _ = h.join();
            }
            let _ = fin_api_shutdown.flush();
            let _ = data_api_shutdown.flush();
            if let Some(r) = recon_shutdown.as_ref() {
                let _ = r.flush();
            }
        }
        Command::L1 { cmd } => match cmd {
            L1Command::Status => {
                let status = l1
                    .chain_status()
                    .unwrap_or_else(|e| exit_err(&e.to_string()));
                println!("{}", serde_json::to_string_pretty(&status).unwrap());
            }
            L1Command::Check => {
                if args.l1_mode == L1Mode::Http {
                    let cfg = cfg.as_ref().unwrap_or_else(|| {
                        exit_err("missing config: pass --config or set IPPAN_L2_CONFIG for l1 check in http mode")
                    });
                    cfg.validate_for_mode_http()
                        .unwrap_or_else(|e| exit_err(&e));
                }
                let status = l1
                    .chain_status()
                    .unwrap_or_else(|e| exit_err(&e.to_string()));
                if args.l1_mode == L1Mode::Http {
                    if let Some(expected) = cfg
                        .as_ref()
                        .and_then(|c| c.l1.expected_network_id.as_deref())
                    {
                        if status.network_id.0 != expected {
                            exit_err(&format!(
                                "L1 network_id mismatch: expected {expected}, got {}",
                                status.network_id.0
                            ));
                        }
                    }
                }
                println!("{}", serde_json::to_string_pretty(&status).unwrap());
            }
            L1Command::Inclusion { id } => {
                let key = parse_idempotency_key(&id).unwrap_or_else(|e| exit_err(&e));
                let mut proof = l1
                    .get_inclusion(&key)
                    .unwrap_or_else(|e| exit_err(&e.to_string()));
                if proof.is_none() && args.l1_mode == L1Mode::Mock {
                    let receipts_dir = cfg
                        .as_ref()
                        .map(|c| c.storage.receipts_dir.as_str())
                        .unwrap_or("receipts");
                    proof = mock_proof_from_receipt(receipts_dir, &id, false);
                }
                println!("{}", serde_json::to_string_pretty(&proof).unwrap());
            }
            L1Command::Finality { tx } => {
                let txid = L1TxId(tx);
                let mut proof = l1
                    .get_finality(&txid)
                    .unwrap_or_else(|e| exit_err(&e.to_string()));
                if proof.is_none() && args.l1_mode == L1Mode::Mock {
                    // For mock mode, allow `--tx mock:<id>` lookups by loading the receipt.
                    if let Some(id) = txid.0.strip_prefix("mock:") {
                        let receipts_dir = cfg
                            .as_ref()
                            .map(|c| c.storage.receipts_dir.as_str())
                            .unwrap_or("receipts");
                        proof = mock_proof_from_receipt(receipts_dir, id, true);
                    }
                }
                println!("{}", serde_json::to_string_pretty(&proof).unwrap());
            }
        },
        Command::SubmitBatch(cmd) => {
            let cfg_receipts_dir = cfg
                .as_ref()
                .map(|c| c.storage.receipts_dir.as_str())
                .unwrap_or("receipts");

            let env = read_batch_envelope(cmd.file.as_deref(), cmd.stdin)
                .unwrap_or_else(|e| exit_err(&e));
            env.validate().unwrap_or_else(|e| exit_err(&e.to_string()));
            if !cmd.hub.matches_envelope(&env) {
                exit_err("hub selector does not match envelope.hub");
            }
            let max_batch_items = cfg
                .as_ref()
                .map(|c| c.limits.max_batch_items)
                .unwrap_or_else(|| config::LimitsConfig::default().max_batch_items);
            let max_batch_items_u64 = u64::try_from(max_batch_items).unwrap_or(u64::MAX);
            if env.tx_count > max_batch_items_u64 {
                exit_err(&format!(
                    "batch too large: tx_count={} exceeds max_batch_items={}",
                    env.tx_count, max_batch_items
                ));
            }

            let canonical_hash = b64url32(
                &env.canonical_hash_blake3()
                    .unwrap_or_else(|e| exit_err(&e.to_string())),
            );
            let idempotency_key = b64url32(env.idempotency_key.as_bytes());

            if cmd.dry_run {
                let out = serde_json::json!({
                    "canonical_hash": canonical_hash,
                    "idempotency_key": idempotency_key,
                });
                println!("{}", serde_json::to_string_pretty(&out).unwrap());
                return;
            }

            let result = l1
                .submit_batch(&env)
                .unwrap_or_else(|e| exit_err(&e.to_string()));

            persist_receipt(cfg_receipts_dir, &env.idempotency_key, &env, &result)
                .unwrap_or_else(|e| exit_err(&e));
            println!("{}", serde_json::to_string_pretty(&result).unwrap());
        }
        Command::GenExample(cmd) => {
            let env = generate_example_envelope(cmd.hub).unwrap_or_else(|e| exit_err(&e));
            fs::write(&cmd.out, serde_json::to_vec_pretty(&env).unwrap()).unwrap_or_else(|e| {
                exit_err(&format!("failed to write {}: {e}", cmd.out.display()))
            });
            println!("{}", cmd.out.display());
        }
        Command::Data { cmd } => match cmd {
            DataCommand::ExportState { out } => {
                let data_db_dir = cfg
                    .as_ref()
                    .map(|c| c.storage.data_db_dir.as_str())
                    .unwrap_or("data_db");
                let store = hub_data::DataStore::open(data_db_dir)
                    .unwrap_or_else(|e| exit_err(&e.to_string()));
                let snapshot = store
                    .export_snapshot_v1()
                    .unwrap_or_else(|e| exit_err(&e.to_string()));
                let bytes = serde_json::to_vec_pretty(&snapshot).unwrap();
                fs::write(&out, bytes).unwrap_or_else(|e| {
                    exit_err(&format!("failed to write {}: {e}", out.display()))
                });
                println!("{}", out.display());
            }
        },
        Command::Fin { cmd } => {
            let fin_db_dir = cfg
                .as_ref()
                .map(|c| c.storage.fin_db_dir.as_str())
                .unwrap_or("fin_db");
            let store =
                hub_fin::FinStore::open(fin_db_dir).unwrap_or_else(|e| exit_err(&e.to_string()));

            match cmd {
                FinCommand::Delegate {
                    from,
                    operator,
                    asset_id,
                } => {
                    let asset_id = hub_fin::Hex32::from_hex(&asset_id)
                        .unwrap_or_else(|e| exit_err(&format!("invalid asset_id: {e}")));
                    store
                        .set_delegation(&from, &operator, asset_id)
                        .unwrap_or_else(|e| exit_err(&e.to_string()));
                    println!("ok");
                }
                FinCommand::RevokeDelegate {
                    from,
                    operator,
                    asset_id,
                } => {
                    let asset_id = hub_fin::Hex32::from_hex(&asset_id)
                        .unwrap_or_else(|e| exit_err(&format!("invalid asset_id: {e}")));
                    store
                        .revoke_delegation(&from, &operator, asset_id)
                        .unwrap_or_else(|e| exit_err(&e.to_string()));
                    println!("ok");
                }
            }
        }
        Command::Policy { cmd } => {
            let policy_db_dir = cfg
                .as_ref()
                .map(|c| c.storage.policy_db_dir.as_str())
                .unwrap_or("policy_db");
            let store = policy_store::PolicyStore::open(policy_db_dir)
                .unwrap_or_else(|e| exit_err(&e.to_string()));

            match cmd {
                PolicyCommand::Allow { cmd } => match cmd {
                    PolicyListCommand::Add { account } => {
                        store
                            .allow_add(&account)
                            .unwrap_or_else(|e| exit_err(&e.to_string()));
                        println!("ok");
                    }
                    PolicyListCommand::Remove { account } => {
                        store
                            .allow_remove(&account)
                            .unwrap_or_else(|e| exit_err(&e.to_string()));
                        println!("ok");
                    }
                },
                PolicyCommand::Deny { cmd } => match cmd {
                    PolicyListCommand::Add { account } => {
                        store
                            .deny_add(&account)
                            .unwrap_or_else(|e| exit_err(&e.to_string()));
                        println!("ok");
                    }
                    PolicyListCommand::Remove { account } => {
                        store
                            .deny_remove(&account)
                            .unwrap_or_else(|e| exit_err(&e.to_string()));
                        println!("ok");
                    }
                },
                PolicyCommand::Status => {
                    let (allow, deny) = store.counts().unwrap_or_else(|e| exit_err(&e.to_string()));
                    println!(
                        "{}",
                        serde_json::json!({
                            "schema_version": 1,
                            "allow_count": allow,
                            "deny_count": deny,
                        })
                    );
                }
            }
        }
        Command::Prune(cmd) => {
            let receipts_dir = cfg
                .as_ref()
                .map(|c| c.storage.receipts_dir.as_str())
                .unwrap_or("receipts");
            let retention = cfg
                .as_ref()
                .map(|c| c.retention.clone())
                .unwrap_or_default();
            let limits = cfg.as_ref().map(|c| c.limits.clone()).unwrap_or_default();

            let now_secs = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();

            let plan = pruning::plan_prune_receipts_dir(
                std::path::Path::new(receipts_dir),
                &retention,
                &limits,
                now_secs,
            )
            .unwrap_or_else(|e| exit_err(&e));

            let execute = cmd.execute;
            if execute {
                pruning::execute_prune(&plan).unwrap_or_else(|e| exit_err(&e));
            }

            let out = serde_json::json!({
                "schema_version": 1,
                "mode": if execute { "execute" } else { "dry_run" },
                "receipts_dir": receipts_dir,
                "now_secs": plan.now_secs,
                "cutoff_secs": plan.cutoff_secs,
                "scanned_files": plan.scanned_files,
                "deletions": plan.deletions.len(),
                "skipped_unknown_timestamp": plan.skipped_unknown_timestamp,
                "skipped_too_large": plan.skipped_too_large,
                "kept_due_to_min_keep": plan.kept_due_to_min_keep,
                "sample_delete_paths": plan
                    .deletions
                    .iter()
                    .take(10)
                    .map(|p| p.to_string_lossy().to_string())
                    .collect::<Vec<_>>(),
            });
            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        }
    }
}

const TARGET_STATE_VERSION: u32 = 2;

fn ensure_state_version_fin(store: &hub_fin::FinStore) {
    match store.get_state_version() {
        Ok(Some(v)) if v >= TARGET_STATE_VERSION => {}
        Ok(Some(v)) => {
            info!(
                hub = "fin",
                from = v,
                to = TARGET_STATE_VERSION,
                "migrating hub-fin state version"
            );
            store
                .set_state_version(TARGET_STATE_VERSION)
                .unwrap_or_else(|e| exit_err(&e.to_string()));
        }
        Ok(None) => {
            info!(
                hub = "fin",
                to = TARGET_STATE_VERSION,
                "initializing hub-fin state version (assume v1)"
            );
            store
                .set_state_version(TARGET_STATE_VERSION)
                .unwrap_or_else(|e| exit_err(&e.to_string()));
        }
        Err(e) => exit_err(&e.to_string()),
    }
}

fn ensure_state_version_data(store: &hub_data::DataStore) {
    match store.get_state_version() {
        Ok(Some(v)) if v >= TARGET_STATE_VERSION => {}
        Ok(Some(v)) => {
            info!(
                hub = "data",
                from = v,
                to = TARGET_STATE_VERSION,
                "migrating hub-data state version"
            );
            store
                .set_state_version(TARGET_STATE_VERSION)
                .unwrap_or_else(|e| exit_err(&e.to_string()));
        }
        Ok(None) => {
            info!(
                hub = "data",
                to = TARGET_STATE_VERSION,
                "initializing hub-data state version (assume v1)"
            );
            store
                .set_state_version(TARGET_STATE_VERSION)
                .unwrap_or_else(|e| exit_err(&e.to_string()));
        }
        Err(e) => exit_err(&e.to_string()),
    }
}

fn resolve_config_path(cli: Option<&Path>) -> Option<String> {
    if let Some(p) = cli {
        return Some(p.to_string_lossy().to_string());
    }
    std::env::var("IPPAN_L2_CONFIG").ok()
}

fn init_logging(cfg: Option<&config::FinNodeConfig>) {
    // Prefer explicit config logging.level unless user set RUST_LOG.
    let default_level = cfg
        .map(|c| c.logging.level.as_str())
        .unwrap_or("info")
        .to_string();
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(default_level));

    let json = cfg
        .map(|c| c.logging.format.as_str())
        .unwrap_or("json")
        .eq_ignore_ascii_case("json");

    if json {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .json()
            .with_writer(std::io::stderr)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .init();
    }
}

fn exit_err(msg: &str) -> ! {
    eprintln!("{msg}");
    std::process::exit(2);
}

fn generate_example_envelope(hub: HubArg) -> Result<L2BatchEnvelopeV1, String> {
    let hub_id = hub.as_l2_hub_id();
    let schema_version = match hub {
        HubArg::Fin => "hub-fin.payload.v1",
        HubArg::Data => "hub-data.payload.v1",
    }
    .to_string();

    let payload_json = serde_json::json!({
        "txs": [
            { "tx_id": "tx-001", "kind": "demo" }
        ]
    });
    let payload_bytes = serde_json::to_vec(&payload_json).map_err(|e| e.to_string())?;

    let payload = HubPayloadEnvelopeV1 {
        contract_version: ContractVersion::V1,
        hub: hub_id,
        schema_version,
        content_type: "application/json".to_string(),
        payload: Base64Bytes(payload_bytes),
    };

    let batch_id = match hub {
        HubArg::Fin => "batch-fin-example-v1",
        HubArg::Data => "batch-data-example-v1",
    };

    L2BatchEnvelopeV1::new(
        hub_id,
        batch_id,
        1,
        1,
        None,
        FixedAmountV1(1_000_000),
        payload,
    )
    .map_err(|e| e.to_string())
}

fn b64url32(bytes: &[u8; 32]) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn parse_idempotency_key(b64url: &str) -> Result<IdempotencyKey, String> {
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(b64url.as_bytes())
        .map_err(|e| format!("invalid idempotency key base64url: {e}"))?;
    if decoded.len() != 32 {
        return Err(format!("expected 32 bytes, got {}", decoded.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&decoded);
    Ok(IdempotencyKey(out))
}

fn read_batch_envelope(file: Option<&Path>, stdin: bool) -> Result<L2BatchEnvelopeV1, String> {
    let raw = if let Some(path) = file {
        fs::read_to_string(path)
            .map_err(|e| format!("failed to read batch file {}: {e}", path.display()))?
    } else if stdin {
        let mut buf = String::new();
        std::io::stdin()
            .read_to_string(&mut buf)
            .map_err(|e| format!("failed to read stdin: {e}"))?;
        buf
    } else {
        return Err("missing input: pass --file or --stdin".to_string());
    };

    serde_json::from_str(&raw).map_err(|e| format!("invalid L2BatchEnvelopeV1 JSON: {e}"))
}

fn persist_receipt(
    receipts_dir: &str,
    idempotency_key: &IdempotencyKey,
    env: &L2BatchEnvelopeV1,
    result: &L1SubmitResult,
) -> Result<(), String> {
    fs::create_dir_all(receipts_dir)
        .map_err(|e| format!("failed to create receipts dir {receipts_dir}: {e}"))?;

    let canonical_hash = b64url32(
        &env.canonical_hash_blake3()
            .map_err(|e| format!("canonical hash failed: {e}"))?,
    );
    let key = b64url32(idempotency_key.as_bytes());
    let submitted_at = time::OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".to_string());

    let status = if result.accepted {
        if result.already_known {
            "already_known"
        } else {
            "accepted"
        }
    } else {
        "rejected"
    };

    let receipt = SubmitReceipt {
        submitted_at,
        status: status.to_string(),
        contract_version: env.contract_version.as_str().to_string(),
        canonical_hash,
        idempotency_key: key.clone(),
        l1_tx_id: result.l1_tx_id.as_ref().map(|x| x.0.clone()),
    };

    let out_path = Path::new(receipts_dir).join(format!("{key}.json"));
    fs::write(&out_path, serde_json::to_vec_pretty(&receipt).unwrap())
        .map_err(|e| format!("failed to write receipt {}: {e}", out_path.display()))?;
    info!(receipt = %out_path.display(), "receipt written");
    Ok(())
}

fn mock_proof_from_receipt(
    receipts_dir: &str,
    id_b64url: &str,
    finalized: bool,
) -> Option<L1InclusionProof> {
    let path = Path::new(receipts_dir).join(format!("{id_b64url}.json"));
    let raw = std::fs::read_to_string(path).ok()?;
    let v: serde_json::Value = serde_json::from_str(&raw).ok()?;
    let canonical_hash_b64 = v.get("canonical_hash")?.as_str()?;

    let key_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(id_b64url.as_bytes())
        .ok()?;
    if key_bytes.len() != 32 {
        return None;
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);

    let env_hash_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(canonical_hash_b64.as_bytes())
        .ok()?;
    if env_hash_bytes.len() != 32 {
        return None;
    }
    let mut env_hash = [0u8; 32];
    env_hash.copy_from_slice(&env_hash_bytes);

    let mut h = blake3::Hasher::new();
    h.update(&key);
    h.update(&env_hash);
    let proof_bytes = h.finalize().as_bytes().to_vec();

    Some(L1InclusionProof {
        l1_tx_id: L1TxId(format!("mock:{id_b64url}")),
        height: l2_core::l1_contract::L1Height(0),
        finalized,
        proof: Base64Bytes(proof_bytes),
    })
}

struct InstrumentedL1Client {
    inner: Arc<dyn L1Client + Send + Sync>,
}

impl InstrumentedL1Client {
    fn new(inner: Arc<dyn L1Client + Send + Sync>) -> Self {
        // Ensure metrics are registered.
        let _ = &*metrics::L1_REQUESTS_TOTAL;
        let _ = &*metrics::L1_REQUEST_FAILURES_TOTAL;
        let _ = &*metrics::SUBMIT_BATCHES_TOTAL;
        let _ = &*metrics::PROCESS_UPTIME_SECONDS;
        Self { inner }
    }

    fn record_ok(&self, method: &'static str) {
        metrics::L1_REQUESTS_TOTAL
            .with_label_values(&[method, "ok"])
            .inc();
    }

    fn record_err(&self, method: &'static str, err: &L1ClientError) {
        let status = match err {
            L1ClientError::HttpStatus(code) => code.to_string(),
            L1ClientError::EndpointMissing(_) => "endpoint_missing".to_string(),
            L1ClientError::DecodeError(_) => "decode_error".to_string(),
            L1ClientError::Timeout => "timeout".to_string(),
            L1ClientError::RetryExhausted { .. } => "retry_exhausted".to_string(),
            L1ClientError::Config(_) => "config".to_string(),
            L1ClientError::Network(_) => "network".to_string(),
        };
        metrics::L1_REQUESTS_TOTAL
            .with_label_values(&[method, status.as_str()])
            .inc();

        let reason = match err {
            L1ClientError::HttpStatus(_) => "http_status",
            L1ClientError::EndpointMissing(_) => "endpoint_missing",
            L1ClientError::DecodeError(_) => "decode_error",
            L1ClientError::Timeout => "timeout",
            L1ClientError::RetryExhausted { .. } => "retry_exhausted",
            L1ClientError::Config(_) => "config",
            L1ClientError::Network(_) => "network",
        };
        metrics::L1_REQUEST_FAILURES_TOTAL
            .with_label_values(&[reason])
            .inc();
        warn!(method, error = %err, "l1 request failed");
    }
}

impl L1Client for InstrumentedL1Client {
    fn chain_status(&self) -> Result<l2_core::l1_contract::L1ChainStatus, L1ClientError> {
        let r = self.inner.chain_status();
        match &r {
            Ok(_) => self.record_ok("chain_status"),
            Err(e) => self.record_err("chain_status", e),
        }
        r
    }

    fn submit_batch(&self, batch: &L2BatchEnvelopeV1) -> Result<L1SubmitResult, L1ClientError> {
        let r = self.inner.submit_batch(batch);
        match &r {
            Ok(res) => {
                self.record_ok("submit_batch");
                let label = if res.accepted {
                    if res.already_known {
                        "already_known"
                    } else {
                        "accepted"
                    }
                } else {
                    "rejected"
                };
                metrics::SUBMIT_BATCHES_TOTAL
                    .with_label_values(&[label])
                    .inc();
            }
            Err(e) => self.record_err("submit_batch", e),
        }
        r
    }

    fn get_inclusion(
        &self,
        idempotency_key: &IdempotencyKey,
    ) -> Result<Option<L1InclusionProof>, L1ClientError> {
        let r = self.inner.get_inclusion(idempotency_key);
        match &r {
            Ok(_) => self.record_ok("get_inclusion"),
            Err(e) => self.record_err("get_inclusion", e),
        }
        r
    }

    fn get_finality(&self, l1_tx_id: &L1TxId) -> Result<Option<L1InclusionProof>, L1ClientError> {
        let r = self.inner.get_finality(l1_tx_id);
        match &r {
            Ok(_) => self.record_ok("get_finality"),
            Err(e) => self.record_err("get_finality", e),
        }
        r
    }
}
