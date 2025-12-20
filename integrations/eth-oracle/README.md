# IPPAN-L2 Ethereum Oracle (v1)

This module pushes IPPAN-derived metrics/scores into an Ethereum testnet Oracle contract.

Components:
- `contracts/`: Solidity oracle (`IppanAiOracle`) using Foundry.
- `daemon/`: Rust daemon that reads IPPAN DevNet validator metrics and updates the oracle contract.
- `configs/`: TOML configuration for connecting to IPPAN (DevNet) and Ethereum (Sepolia).
- `scripts/`: Utilities for local demos.

v1 is:
- Read-only (no token bridge, no custody).
- Testnet-only.
- Uses a single public IPPAN DevNet metric and pushes it on-chain.

## Chosen IPPAN DevNet endpoint + metric (v1)

For v1, the daemon assumes the IPPAN DevNet node exposes a Tendermint/CometBFT-compatible HTTP endpoint:

- **Endpoint**: `GET {IPPAN_RPC_URL}/validators`
- **Metric**: per-validator `voting_power` (integer-like string)

Expected JSON shape (subset):

```json
{
  "result": {
    "validators": [
      { "address": "BEEF01...", "voting_power": "10" }
    ]
  }
}
```

Mapping to oracle subjects:

- **label**: a human-readable identifier such as `@alice.ipn` (if available) or a validator public key / address string.
- **subject_id**: `blake3(label)` (32 bytes)
- **score**: `voting_power * security.score_scale` (clamped to `u64::MAX`)
- **label**: the validator `address` string (v1; pushed on-chain alongside score)

Returned scores are **sorted by `subject_id`** for deterministic behaviour.

### Example subject mapping

Internally, each subject is represented by:

- `label`: a human-readable identifier such as `@alice.ipn` or a validator public key.
- `subject_id`: `blake3(label)` truncated to 32 bytes, exposed on-chain as `bytes32`.
- `score`: a scaled integer (e.g. uptime ratio × 1_000_000).

Example (from `Dump` CLI):

```text
subject_id=0xa3f7... label=@alice.ipn eth_address=<none> score=987654
```

On Ethereum, the dApp can query:

```solidity
uint256 score = oracle.getScore(0xa3f7...);
```

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

**ABI note**: the Rust daemon binds the contract ABI from:

- `integrations/eth-oracle/contracts/out/IppanAiOracle.sol/IppanAiOracle.json`

If you modify the Solidity contract, run `forge build` to regenerate this artifact before building/running the daemon.

### On-chain label API

The oracle stores both:

- `scores(subject_id) -> uint256`
- `labels(subject_id) -> string`

And provides a convenience helper:

- `getSubject(bytes32) -> (string label, uint256 score)`

Example `cast` calls:

```bash
# Get score:
cast call $ORACLE "getScore(bytes32)" 0x<subject_id_hex>

# Get label and score together:
cast call $ORACLE "getSubject(bytes32)" 0x<subject_id_hex>
```

### Daemon

```bash
export IPPAN_RPC_URL=http://127.0.0.1:8080
export ETH_RPC_URL=...
export ETH_PRIVATE_KEY=...

cargo run -p ippan_eth_oracle_daemon -- \
  watch --config integrations/eth-oracle/configs/devnet_sepolia.toml
```

To inspect the subject mapping and scores without pushing to Ethereum:

```bash
cargo run -p ippan_eth_oracle_daemon -- \
  dump --config integrations/eth-oracle/configs/devnet_sepolia.toml
```

If `oracle_contract_address` is still zero, the daemon will run but skip Ethereum writes (so you can validate the loop/logging first).

## Manual end-to-end demo (recommended)

Run:

```bash
bash integrations/eth-oracle/scripts/local_e2e_demo.sh
```
