# L1 Settlement API (High-Level Draft)

This document defines a high-level request/response shape for FIN (and other hubs) to settle L2 batches on IPPAN CORE (L1). Real RPC transport and cryptographic commitments are intentionally deferred.

## Settlement Request

Fields:

- **hub**: hub identifier (`L2HubId`)
- **batch_id**: unique batch identifier (string)
- **tx_count**: number of transactions in the batch (integer)
- **commitment**: optional commitment placeholder (string, optional)
- **fee**: protocol fee (`FixedAmount`, deterministic integer)

Example (shape only):

```json
{
  "hub": "Fin",
  "batch_id": "batch-001",
  "tx_count": 3,
  "commitment": null,
  "fee": 1000000
}
```

## Settlement Response

Fields:

- **l1_reference**: opaque L1 identifier for the settlement (string)
- **finalised**: whether the settlement is final (boolean)

Example (shape only):

```json
{
  "l1_reference": "0xabc123...",
  "finalised": true
}
```

## Notes

- Amounts must be represented using deterministic integers (no floats).
- Commitment / proof validation is a future milestone.

