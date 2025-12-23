#!/usr/bin/env bash
set -euo pipefail

# Usage (post_snapshot_hook):
#   post_snapshot_hook = "/path/to/upload_snapshot_s3.sh"
#
# The fin-node will append the snapshot path as the last argument.
#
# Required environment:
#   SNAPSHOT_S3_URI="s3://my-bucket/ippan-l2/snapshots/"
#
# Example:
#   SNAPSHOT_S3_URI="s3://my-bucket/ippan-l2/snapshots/" aws s3 ls

SNAPSHOT_PATH="${1:-}"
if [[ -z "${SNAPSHOT_PATH}" ]]; then
  echo "missing snapshot path argument" >&2
  exit 2
fi

if [[ -z "${SNAPSHOT_S3_URI:-}" ]]; then
  echo "missing SNAPSHOT_S3_URI (e.g. s3://bucket/prefix/)" >&2
  exit 2
fi

aws s3 cp --only-show-errors "${SNAPSHOT_PATH}" "${SNAPSHOT_S3_URI}"

