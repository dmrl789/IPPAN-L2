#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT_DIR="${ROOT_DIR}/clients/python/fin_node_client"

IMAGE="${OPENAPI_GENERATOR_IMAGE:-openapitools/openapi-generator-cli:v7.10.0}"
GEN="${OPENAPI_PY_GENERATOR:-python}"

mkdir -p "${OUT_DIR}"

docker run --rm \
  -v "${ROOT_DIR}:/local" \
  "${IMAGE}" generate \
  -i /local/docs/openapi/fin-node.openapi.json \
  -g "${GEN}" \
  -o /local/clients/python/fin_node_client \
  --additional-properties=packageName=fin_node_client,projectName=fin-node-client

echo "Generated Python client at: ${OUT_DIR}"

