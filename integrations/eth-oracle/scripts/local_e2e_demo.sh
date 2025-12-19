#!/usr/bin/env bash
set -euo pipefail

echo "This is a placeholder script. Steps (manual for now):"
echo "1) Start IPPAN DevNet (so IPPAN_RPC_URL is valid)."
echo "2) Export ETH_RPC_URL, ETH_PRIVATE_KEY, UPDATER_ADDRESS."
echo "3) cd integrations/eth-oracle/contracts && forge test && forge build."
echo "4) Deploy oracle with:"
echo "   forge script script/DeployIppanAiOracle.s.sol --rpc-url \\$ETH_RPC_URL --private-key \\$ETH_PRIVATE_KEY --broadcast"
echo "5) Copy deployed oracle address into configs/devnet_sepolia.toml."
echo "6) From repo root, run:"
echo "   ETH_PRIVATE_KEY=\\$ETH_PRIVATE_KEY ETH_RPC_URL=\\$ETH_RPC_URL cargo run -p ippan_eth_oracle_daemon"
