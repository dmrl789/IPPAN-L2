# Finality & Reconciliation (fin-node)

This repo supports two operator-selectable linkage settlement modes:

- **`optimistic`**: preserve MVP behaviour. Payment and entitlement are granted immediately after local apply + L1 submission.
- **`finality_required`**: **do not** grant DATA entitlements until the FIN payment is **finalized on L1**.

`fin-node` never assumes finality at submit time: all L1 submits start as `Submitted` and must be advanced by explicit inclusion/finality queries.

## Shared submit state

All submitted items carry a `submit_state` (or `*_submit_state`) field:

- `not_submitted`
- `submitted { idempotency_key, l1_tx_id? }`
- `included { proof_hash, l1_tx_id? }`
- `finalized { proof_hash, l1_tx_id? }`
- `failed { error_code }`

`proof_hash` is an opaque, deterministic hash of the L1 proof bytes (implementation-defined).

## Linkage state machine (text diagram)

### Policy = `optimistic`

```
Created
  └─(submit FIN payment)─────────────────────────────┐
                                                     ├─(submit DATA entitlement)→ EntitledFinal
                                                     └─(error)→ FailedRecoverable
```

### Policy = `finality_required`

```
Created
  └─(submit FIN payment)→ PaymentPendingFinality
        ├─(L1 inclusion)→ PaymentPendingFinality (payment_submit_state=included)
        ├─(L1 finality) → PaidFinal (payment_submit_state=finalized)
        │                   └─(submit DATA entitlement)→ EntitlementPendingFinality
        │                         ├─(L1 inclusion)→ EntitlementPendingFinality (entitlement_submit_state=included)
        │                         ├─(L1 finality) → EntitledFinal (entitlement_submit_state=finalized)
        │                         └─(error)→ FailedRecoverable
        └─(error)→ FailedRecoverable
```

### Resume safety

Both the linkage receipt and the reconciliation queue are persisted, so recovery is deterministic:

- The **linkage receipt** is the source of truth for “what has already happened” (payment_ref, entitlement_ref, submit states).
- The **recon DB** is the source of truth for “what still needs to be checked/continued”.

## Persistent reconciliation queue

`fin-node` persists a Sled-backed queue:

- Keys: `recon:pending:<kind>:<id>`
- Kinds:
  - `fin_action` (FIN action receipt)
  - `data_action` (DATA action receipt)
  - `linkage_purchase` (linkage purchase receipt)

Metadata:

- `next_check_at` (unix seconds)
- `attempts`
- `last_error`

The loop:

1) Pulls a bounded due batch (`batch_limit`).
2) Advances each item using configured L1 endpoints:
   - `get_inclusion(idempotency_key)`
   - `get_finality(l1_tx_id)`
3) Applies bounded exponential backoff on transient failures.

