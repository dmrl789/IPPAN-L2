# fin-node OpenAPI (v1)

This folder contains the production API contract for `fin-node`.

- **Spec file**: `docs/openapi/fin-node.openapi.json` (OpenAPI 3.1)
- **Inventory**: `docs/openapi/INVENTORY.md` (route list derived from code)

## Viewing the spec (running node)

Start the server:

```bash
cargo run -p fin-node -- run
```

Fetch the spec:

```bash
curl -sS http://localhost:3000/api/v1/openapi.json
```

## Bounds / limits

The spec uses bounds that match `fin-node` defaults (see `fin-node/src/config.rs`):

- **max request body**: `limits.max_body_bytes` (default `256 KiB`)
- **max string bytes**: `limits.max_string_bytes` (default `1024`)
- **max tags**: `limits.max_tags` (default `32`)
- **max tag bytes**: `limits.max_tag_bytes` (default `48`)
- **cursor paging**: `pagination.default_limit` (default `50`), `pagination.max_limit` (default `200`)

If you tune these limits in config for a deployment, the runtime behavior changes, but the wire-format remains compatible.

## Generating SDK stubs

This repo ships generator scripts (docker-based) under `tools/openapi/`.

### TypeScript

```bash
./tools/openapi/generate_ts.sh
```

### Python (optional)

```bash
./tools/openapi/generate_py.sh
```

Generated code is **not committed** by default; it is written under `clients/` (see scripts for exact output paths).

