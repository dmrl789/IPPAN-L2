#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
SPEC_PATH="${ROOT_DIR}/docs/openapi/fin-node.openapi.json"
OUT_DIR="${ROOT_DIR}/clients/ts/fin-node-client"

IMAGE="${OPENAPI_GENERATOR_IMAGE:-openapitools/openapi-generator-cli:v7.10.0}"
GEN="${OPENAPI_TS_GENERATOR:-typescript-fetch}"

mkdir -p "${OUT_DIR}"

docker run --rm \
  -v "${ROOT_DIR}:/local" \
  "${IMAGE}" generate \
  -i /local/docs/openapi/fin-node.openapi.json \
  -g "${GEN}" \
  -o /local/clients/ts/fin-node-client \
  --additional-properties=typescriptThreePlus=true,withInterfaces=true,enumPropertyNaming=original

echo "Generated TypeScript client at: ${OUT_DIR}"

