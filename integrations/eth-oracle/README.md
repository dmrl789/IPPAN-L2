## IPPAN-L2 Ethereum Oracle (v1)

IPPAN-L2 Ethereum Oracle is a **read-only, testnet-first** integration that **pushes deterministic IPPAN metrics/scores into an Ethereum oracle contract**.

### Components

- **Rust daemon** (`integrations/eth-oracle/daemon`): periodically reads deterministic IPPAN metrics (v1: validator/handle-style scores) from an IPPAN DevNet/L1 HTTP endpoint and writes updates to Ethereum.
- **Solidity contract** (`integrations/eth-oracle/contracts`): stores `bytes32 subject => uint256 score`, readable by dApps.

### v1 scope

- **No token bridge** / no wrapped assets.
- **Read-only oracle**: IPPAN -> Ethereum contract storage.
- **Testnet only** (default config targets Sepolia).

### Quick start

1) Copy env template:

```bash
cp integrations/eth-oracle/.env.example integrations/eth-oracle/.env
```

2) Deploy the contract (Foundry):

```bash
cd integrations/eth-oracle/contracts

export ETH_RPC_URL=...
export ETH_PRIVATE_KEY=...
export UPDATER_ADDRESS=0xYourUpdaterEOA

forge test
forge script script/DeployIppanAiOracle.s.sol \
  --rpc-url "$ETH_RPC_URL" \
  --private-key "$ETH_PRIVATE_KEY" \
  --broadcast
```

3) Copy the deployed address into `integrations/eth-oracle/configs/devnet_sepolia.toml` (`oracle_contract_address`).

4) Run the daemon:

```bash
export ETH_PRIVATE_KEY=...
export ETH_RPC_URL=...
export IPPAN_RPC_URL=http://127.0.0.1:8080

cargo run -p ippan_eth_oracle_daemon -- \
  --config integrations/eth-oracle/configs/devnet_sepolia.toml
```

### IPPAN score source (v1 placeholder)

v1 assumes an IPPAN DevNet HTTP endpoint returning a JSON list of validators with an uptime-like metric.

- **Endpoint (placeholder)**: `GET /validators`
- **Expected JSON (placeholder)**:

```json
[
  { "validator_id": "validator-1", "uptime_percent": 99.95 },
  { "validator_id": "validator-2", "uptime_percent": 97.10 }
]
```

Mapping:

- `subject` (`bytes32`) = `sha256(validator_id)` (32 bytes)
- `score` (`uint256`) = `floor(uptime_percent * score_scale)`

If your DevNet differs, update the daemon’s IPPAN client mapping and document the actual path/shape here.
