#!/usr/bin/env bash
set -euo pipefail

# Usage (post_snapshot_hook):
#   post_snapshot_hook = "/path/to/upload_snapshot_scp.sh"
#
# Required environment:
#   SNAPSHOT_SCP_TARGET="backup@backup-host:/var/backups/ippan-l2/"

SNAPSHOT_PATH="${1:-}"
if [[ -z "${SNAPSHOT_PATH}" ]]; then
  echo "missing snapshot path argument" >&2
  exit 2
fi

if [[ -z "${SNAPSHOT_SCP_TARGET:-}" ]]; then
  echo "missing SNAPSHOT_SCP_TARGET (e.g. user@host:/path/)" >&2
  exit 2
fi

scp -q "${SNAPSHOT_PATH}" "${SNAPSHOT_SCP_TARGET}"

