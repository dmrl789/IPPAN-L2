# Buy a Dataset License — Cross-Hub Workflow (MVP v1)

This is the minimal “payments + entitlements” workflow linking HUB-FIN and HUB-DATA.

## Endpoint

`POST /linkage/buy-license`

Request body:

```json
{
  "dataset_id": "<DATASET_ID_HEX>",
  "listing_id": "<LISTING_ID_HEX>",
  "buyer_account": "acc-buyer",
  "nonce": "optional-string",
  "memo": "optional-string"
}
```

Response:
- `receipt.purchase_id`
- `receipt.status`: `created | paid | entitled | failed_recoverable`
- `receipt.payment_ref` (FIN action id + canonical hash)
- `receipt.entitlement_ref` (DATA action id + entitlement license id)

## What fin-node does (resume-safe)

1. **Load listing** from HUB-DATA state (price/currency/seller/terms).
2. **Derive** `purchase_id` deterministically (see `docs/hubs/LINKAGE.md`).
3. **Create or load** linkage receipt at `receipts/linkage/<purchase_id>.json`.
4. **Execute FIN payment**: `TRANSFER_UNITS_V1` (buyer → licensor), embedding `purchase_id`.
5. **Execute DATA entitlement**: `GRANT_ENTITLEMENT_V1` for `(purchase_id, listing_id, licensee)`.
6. If a step fails: status becomes `failed_recoverable`. **Rerun the same request** to continue.

## Query

Get linkage receipt by purchase id:

`GET /linkage/purchase/:purchase_id`

```bash
curl -sS "http://127.0.0.1:3000/linkage/purchase/<PURCHASE_ID_HEX>"
```

List entitlements (who has access):

```bash
curl -sS "http://127.0.0.1:3000/data/entitlements?dataset_id=<DATASET_ID_HEX>"
curl -sS "http://127.0.0.1:3000/data/entitlements?licensee=acc-buyer"
```

## Example (end-to-end)

```bash
curl -sS -X POST "http://127.0.0.1:3000/linkage/buy-license" \
  -H "Content-Type: application/json" \
  -d '{
    "dataset_id": "<DATASET_ID_HEX>",
    "listing_id": "<LISTING_ID_HEX>",
    "buyer_account": "acc-buyer",
    "nonce": "nonce-001",
    "memo": "dataset license purchase"
  }'
```

