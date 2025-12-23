use ippan_eth_oracle_daemon::config::AppConfig;
use std::io::Write;

#[test]
fn app_config_env_overrides_env_refs() {
    // Explicit env vars should override the config's env:... strings.
    std::env::set_var("ETH_RPC_URL", "https://rpc.override");
    std::env::set_var("IPPAN_RPC_URL", "http://ippan.override");

    let mut f = tempfile::NamedTempFile::new().unwrap();
    write!(
        f,
        r#"
[ippan]
rpc_url = "env:IPPAN_RPC_URL"
poll_interval_ms = 1000
subject_type = "validator"

[ethereum]
rpc_url = "env:ETH_RPC_URL"
chain_id = 11155111
oracle_contract_address = "0x0000000000000000000000000000000000000001"

[security]
score_scale = 1000000
max_updates_per_round = 10
"#
    )
    .unwrap();

    let cfg = AppConfig::from_toml(f.path()).unwrap();
    assert_eq!(cfg.ethereum.rpc_url, "https://rpc.override");
    assert_eq!(cfg.ippan.rpc_url, "http://ippan.override");
}
