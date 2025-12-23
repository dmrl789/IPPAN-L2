# fin-node HUB-FIN API (MVP v1)

This API is served by `fin-node` on the configured bind address (default `0.0.0.0:3000`).

## Endpoints

- `POST /fin/actions`
- `GET /fin/assets/:asset_id_hex`
- `GET /fin/balances?asset_id=...&account=...`
- `GET /fin/receipts/:action_id_hex`

All responses include a `schema_version` field.

## Run (local, mock L1)

```bash
export IPPAN_L2_CONFIG=./configs/local.toml

# mock L1 is the default; HTTP server binds to config.server.bind_address
cargo run -p fin-node -- run
```

By default:
- FIN state DB path: `fin_db` (config: `storage.fin_db_dir`)
- Receipts dir: `receipts` (config: `storage.receipts_dir`)

## Examples

### 1) CREATE_ASSET

```bash
curl -sS -X POST "http://127.0.0.1:3000/fin/actions" \
  -H "Content-Type: application/json" \
  -d '{
    "type": "create_asset_v1",
    "actor": "issuer-001",
    "name": "Example Euro Stablecoin",
    "symbol": "EURX",
    "issuer": "issuer-001",
    "decimals": 6,
    "metadata_uri": "https://example.com/eurx",
    "mint_policy": "issuer_only",
    "transfer_policy": "free"
  }'
```

This returns (fields may include more):
- `action_id` (hex)
- `asset_id` (hex, derived deterministically)
- `idempotency_key` (base64url, for the batch submission)
- `receipt_path`

### 2) MINT_UNITS

```bash
ASSET_ID="<asset_id_hex_from_previous_response>"

curl -sS -X POST "http://127.0.0.1:3000/fin/actions" \
  -H "Content-Type: application/json" \
  -d "{
    \"type\": \"mint_units_v1\",
    \"asset_id\": \"${ASSET_ID}\",
    \"to_account\": \"acc-alice\",
    \"amount\": \"20000000\",
    \"actor\": \"issuer-001\",
    \"client_tx_id\": \"mint-001\",
    \"memo\": \"genesis allocation\"
  }"
```

### 3) TRANSFER_UNITS (payments)

```bash
ASSET_ID="<asset_id_hex>"

curl -sS -X POST "http://127.0.0.1:3000/fin/actions" \
  -H "Content-Type: application/json" \
  -d "{
    \"type\": \"transfer_units_v1\",
    \"asset_id\": \"${ASSET_ID}\",
    \"from_account\": \"acc-buyer\",
    \"to_account\": \"acc-seller\",
    \"amount\": \"1000000\",
    \"actor\": \"acc-buyer\",
    \"client_tx_id\": \"<64_hex_chars_or_other_id>\",
    \"memo\": \"dataset license purchase\",
    \"purchase_id\": \"<purchase_id_hex_optional>\"
  }"
```

## Delegation (operator transfers)

To allow an operator account to transfer on behalf of a `from_account` for a specific asset:

```bash
fin-node fin delegate --from acc-alice --operator acc-operator --asset-id "<ASSET_ID_HEX>"
fin-node fin revoke-delegate --from acc-alice --operator acc-operator --asset-id "<ASSET_ID_HEX>"
```

In **strict** policy mode, operator transfers require an explicit delegation entry.

### 3) Query asset

```bash
curl -sS "http://127.0.0.1:3000/fin/assets/${ASSET_ID}"
```

### 4) Query balance

```bash
curl -sS "http://127.0.0.1:3000/fin/balances?asset_id=${ASSET_ID}&account=acc-alice"
```

### 5) Fetch receipt by action_id

```bash
ACTION_ID="<action_id_hex_from_submit_response>"
curl -sS "http://127.0.0.1:3000/fin/receipts/${ACTION_ID}"
```

