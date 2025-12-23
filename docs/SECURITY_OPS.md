# Security Ops (IPPAN-L2)

## Secrets and key material

- **Never commit secrets**: API keys, private keys, seed phrases, `.env` files.
- Prefer **environment variables** (`env:VAR` in TOML) or a secrets manager.
- Restrict filesystem permissions for config/env files:

```bash
chmod 600 /etc/ippan-l2/config.toml
chown root:root /etc/ippan-l2/config.toml
```

## Logging

- `fin-node` uses structured logs.
- **Secrets must not appear in logs** (e.g. `l1.api_key`).
- For production, prefer JSON logs and an explicit `RUST_LOG` filter.

## Network exposure

- `/metrics` should be treated as internal-only (Prometheus scrape).
- If exposing outside a private network, put a reverse proxy in front and restrict access.

## Safe defaults

- `fin-node` does not require private keys by default.
- Any signing behavior must remain **explicitly enabled** (feature-gated) and must load keys from a path or secrets manager.

