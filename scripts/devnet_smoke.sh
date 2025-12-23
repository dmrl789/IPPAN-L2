#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${IPPAN_L2_CONFIG:-}" ]]; then
  echo "ERROR: IPPAN_L2_CONFIG is not set (expected ./configs/devnet.toml)" >&2
  exit 2
fi

echo "Using IPPAN_L2_CONFIG=$IPPAN_L2_CONFIG" >&2

echo "==> L1 read-only check" >&2
cargo run -p fin-node -- --l1-mode http l1 check

echo "==> Dry-run submit (no L1 writes)" >&2
cargo run -p fin-node -- --l1-mode http submit-batch --hub fin --file ./examples/batch_fin_v1.json --dry-run

echo "==> Real submit (writes receipt)" >&2
cargo run -p fin-node -- --l1-mode http submit-batch --hub fin --file ./examples/batch_fin_v1.json

echo "==> Latest receipt inclusion lookup" >&2
ID="$(ls -1 receipts/*.json | tail -n 1 | xargs -I{} jq -r .idempotency_key {})"
cargo run -p fin-node -- --l1-mode http l1 inclusion --id "$ID"

