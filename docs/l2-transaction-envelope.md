# L2 Transaction Envelope (Deterministic Pattern)

IPPAN L2 hubs should model transactions using a simple, deterministic envelope pattern:

```text
L2TransactionEnvelope<T> = { hub, tx_id, payload }
```

- **hub**: Which hub the transaction belongs to (`L2HubId`), e.g. `Fin`.
- **tx_id**: An opaque transaction identifier (string).
- **payload**: The hub-specific transaction payload `T` (e.g. a FIN operation enum).

## Goals

- Deterministic encoding and processing
- Integer-only numeric model (no floats)
- Easy auditing and replay across architectures

The envelope lives in `l2-core` as `L2TransactionEnvelope<T>`. Hubs can either use it directly or keep a hub-specific transaction type that is trivially mappable to this envelope.

