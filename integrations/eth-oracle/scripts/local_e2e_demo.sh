#!/usr/bin/env bash
set -euo pipefail

# IPPAN-L2 Eth Oracle local e2e demo (testnet)
#
# Prereqs:
# - IPPAN DevNet HTTP endpoint reachable at $IPPAN_RPC_URL (v1 expects GET /validators)
# - Foundry installed (forge, cast)
# - Sepolia RPC + funded test key

: "${IPPAN_RPC_URL:?Set IPPAN_RPC_URL}"
: "${ETH_RPC_URL:?Set ETH_RPC_URL}"
: "${ETH_PRIVATE_KEY:?Set ETH_PRIVATE_KEY}"
: "${UPDATER_ADDRESS:?Set UPDATER_ADDRESS (EOA that will send updates)}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
CONTRACTS_DIR="$ROOT_DIR/integrations/eth-oracle/contracts"
CONFIG_FILE="$ROOT_DIR/integrations/eth-oracle/configs/devnet_sepolia.toml"

echo "==> Running forge tests"
( cd "$CONTRACTS_DIR" && forge test )

echo "==> Deploying IppanAiOracle to Sepolia"
DEPLOY_OUT=$(cd "$CONTRACTS_DIR" && forge script script/DeployIppanAiOracle.s.sol \
  --rpc-url "$ETH_RPC_URL" \
  --private-key "$ETH_PRIVATE_KEY" \
  --broadcast 2>&1)

echo "$DEPLOY_OUT"

ORACLE_ADDRESS=$(echo "$DEPLOY_OUT" | sed -n 's/.*IppanAiOracle deployed at: \(0x[0-9a-fA-F]\{40\}\).*/\1/p' | tail -n 1)
if [[ -z "$ORACLE_ADDRESS" ]]; then
  echo "Failed to parse deployed oracle address from forge output" >&2
  exit 1
fi

echo "==> Deployed oracle: $ORACLE_ADDRESS"

echo "==> Update $CONFIG_FILE with oracle_contract_address = $ORACLE_ADDRESS"
echo "(edit manually or use your preferred tool)"

echo "==> Running daemon (Ctrl+C to stop)"
export IPPAN_RPC_URL
export ETH_RPC_URL
export ETH_PRIVATE_KEY

cargo run -p ippan_eth_oracle_daemon -- --config "$CONFIG_FILE"

# Example query (subject_id must match daemon's sha256(validator_id)):
# cast call "$ORACLE_ADDRESS" "getScore(bytes32)" 0x<subject_id_hex>
