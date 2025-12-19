# IPPAN-L2 Ethereum Oracle (v1)

This module pushes IPPAN-derived metrics/scores into an Ethereum testnet Oracle contract.

Components:
- `contracts/`: Solidity oracle (`IppanAiOracle`) using Foundry.
- `daemon/`: Rust daemon that reads scores (currently mocked) and updates the oracle contract.
- `configs/`: TOML configuration for connecting to IPPAN (DevNet) and Ethereum (Sepolia).
- `scripts/`: Utilities for local demos.

v1 is:
- Read-only (no token bridge, no custody).
- Testnet-only.
- Using mocked scores; real IPPAN metrics wiring will be added in a later order.

## Quick start

### Contracts (Foundry)

Run tests:

```bash
cd integrations/eth-oracle/contracts
forge test
```

Build and deploy:

```bash
cd integrations/eth-oracle/contracts

export ETH_RPC_URL=...
export ETH_PRIVATE_KEY=...
export UPDATER_ADDRESS=0xYourUpdaterEOA

forge build
forge script script/DeployIppanAiOracle.s.sol \
  --rpc-url "$ETH_RPC_URL" \
  --private-key "$ETH_PRIVATE_KEY" \
  --broadcast
```

Then copy the deployed address into `integrations/eth-oracle/configs/devnet_sepolia.toml` (`oracle_contract_address`).

### Daemon (mocked scores)

```bash
export IPPAN_RPC_URL=http://127.0.0.1:8080
export ETH_RPC_URL=...
export ETH_PRIVATE_KEY=...

cargo run -p ippan_eth_oracle_daemon -- \
  --config integrations/eth-oracle/configs/devnet_sepolia.toml
```

If `oracle_contract_address` is still zero, the daemon will run but skip Ethereum writes (so you can validate the loop/logging first).
