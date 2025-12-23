#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SPEC="${ROOT_DIR}/docs/openapi/fin-node.openapi.json"
CODE="${ROOT_DIR}/fin-node/src/http_server.rs"

python3 - "${SPEC}" "${CODE}" <<'PY'
import json
import re
import sys

spec_path = sys.argv[1]
code_path = sys.argv[2]

with open(spec_path, "r", encoding="utf-8") as f:
    spec = json.load(f)

spec_paths = set(spec.get("paths", {}).keys())

with open(code_path, "r", encoding="utf-8") as f:
    code = f.read()

# Extract explicit (method, "/path") tuples from the main request dispatch match.
# This intentionally ignores method because OpenAPI paths are keyed by path only.
literal_paths = set(re.findall(r'\("([A-Z]+)",\s*"(/[^"]*)"\)', code))
raw_paths = {p for (_m, p) in literal_paths}

# Add templated paths for prefix-based dynamic routing.
templates = set()
if 'starts_with("/data/datasets/")' in code and 'ends_with("/licenses")' in code:
    templates.add("/data/datasets/{dataset_id}/licenses")
if 'starts_with("/data/datasets/")' in code and 'ends_with("/attestations")' in code:
    templates.add("/data/datasets/{dataset_id}/attestations")
if 'starts_with("/data/datasets/")' in code:
    templates.add("/data/datasets/{dataset_id}")
if 'starts_with("/data/licenses/")' in code:
    templates.add("/data/licenses/{license_id}")
if 'starts_with("/fin/assets/")' in code:
    templates.add("/fin/assets/{asset_id}")
if 'starts_with("/fin/receipts/")' in code:
    templates.add("/fin/receipts/{action_id}")
if 'starts_with("/receipts/fin/")' in code:
    templates.add("/receipts/fin/{action_id}")
if 'starts_with("/data/receipts/")' in code:
    templates.add("/data/receipts/{action_id}")
if 'starts_with("/receipts/data/")' in code:
    templates.add("/receipts/data/{action_id}")
if 'starts_with("/linkage/purchase/")' in code:
    templates.add("/linkage/purchase/{purchase_id}")

# Build the expected versioned API paths.
expected_v1 = set()
for p in sorted(raw_paths | templates):
    if p.startswith("/api/"):
        # Should not happen in current code (dispatch uses unversioned paths).
        continue
    # OpenAPI is served only behind the versioned prefix even though dispatch matches "/openapi.json".
    if p == "/openapi.json":
        expected_v1.add("/api/v1/openapi.json")
    else:
        expected_v1.add("/api/v1" + p)

missing_in_spec = sorted(expected_v1 - spec_paths)
extra_in_spec = sorted(spec_paths - expected_v1)

ok = True
if missing_in_spec:
    ok = False
    print("ERROR: OpenAPI spec is missing paths implemented in fin-node:", file=sys.stderr)
    for p in missing_in_spec:
        print(f"  - {p}", file=sys.stderr)

if extra_in_spec:
    ok = False
    print("ERROR: OpenAPI spec contains paths not implemented by fin-node:", file=sys.stderr)
    for p in extra_in_spec:
        print(f"  - {p}", file=sys.stderr)

if not ok:
    sys.exit(2)

print(f"OK: OpenAPI spec matches fin-node routes ({len(spec_paths)} paths).")
PY

