#!/usr/bin/env bash
set -euo pipefail

# Usage (pre_restore_hook):
#   pre_restore_hook = "/path/to/prepare_restore.sh"
#
# The fin-node will append the snapshot path as the last argument.
#
# This is intentionally minimal: restore is expected to run on a stopped node.
# Typical checks you may add:
# - validate snapshot is present in local filesystem
# - verify available disk space
# - check service is stopped (systemd)

SNAPSHOT_PATH="${1:-}"
if [[ -z "${SNAPSHOT_PATH}" ]]; then
  echo "missing snapshot path argument" >&2
  exit 2
fi

if [[ ! -f "${SNAPSHOT_PATH}" ]]; then
  echo "snapshot file not found: ${SNAPSHOT_PATH}" >&2
  exit 2
fi

echo "ok: restore pre-checks passed for ${SNAPSHOT_PATH}" >&2

