# IPPAN-L2 Configuration Guide

This document describes the configuration options for IPPAN-L2 components.

## Configuration Loading

Configuration is loaded from multiple sources in this priority order (highest first):

1. **Environment Variables** - Override any TOML value
2. **Config File** - Specified by `--config` flag or `IPPAN_L2_CONFIG` env var
3. **Default Values** - Built-in defaults

### Specifying Config File

```bash
# Via command line flag
cargo run -p fin-node -- --config configs/local.toml

# Via environment variable
export IPPAN_L2_CONFIG=configs/local.toml
cargo run -p fin-node
```

## Configuration Reference

### L1 Settlement (`[l1]`)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `base_url` | String | Yes | IPPAN CORE settlement endpoint URL |
| `api_key` | String | No | API key for authentication |

**Example:**
```toml
[l1]
base_url = "http://127.0.0.1:8080"
api_key = "env:L1_API_KEY"  # Load from environment
```

### Server (`[server]`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `bind_address` | String | `127.0.0.1:3000` | HTTP server bind address |
| `metrics_enabled` | Boolean | `true` | Enable Prometheus metrics endpoint |

**Example:**
```toml
[server]
bind_address = "0.0.0.0:3000"
metrics_enabled = true
```

### Hubs (`[hubs]`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `fin_enabled` | Boolean | `true` | Enable FIN Hub |
| `data_enabled` | Boolean | `true` | Enable DATA Hub |

**Example:**
```toml
[hubs]
fin_enabled = true
data_enabled = true
```

### Storage (`[storage]`)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `path` | String | Yes | Directory path for persistent storage |

**Example:**
```toml
[storage]
path = "./data/local"
```

### Logging (`[logging]`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `level` | String | `info` | Log level: `trace`, `debug`, `info`, `warn`, `error` |
| `format` | String | `pretty` | Output format: `json`, `pretty` |

**Example:**
```toml
[logging]
level = "debug"
format = "json"
```

### Oracle (`[oracle]`)

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | Boolean | `false` | Enable oracle daemon |
| `poll_interval_ms` | Integer | `10000` | Poll interval in milliseconds |

**Example:**
```toml
[oracle]
enabled = true
poll_interval_ms = 30000
```

## Environment Variable References

Configuration values can reference environment variables using the `env:` prefix:

```toml
[l1]
base_url = "env:L1_BASE_URL"
api_key = "env:L1_API_KEY"
```

This syntax loads the value from the specified environment variable at startup.

## Environment Variable Overrides

Any configuration value can be overridden by setting an environment variable:

| Config Path | Environment Variable |
|-------------|---------------------|
| `l1.base_url` | `L1_BASE_URL` |
| `l1.api_key` | `L1_API_KEY` |
| `server.bind_address` | `SERVER_BIND_ADDRESS` |
| `logging.level` | `RUST_LOG` or `LOG_LEVEL` |

## Oracle Daemon Configuration

The Ethereum oracle daemon uses a separate configuration file. See the
[eth-oracle README](../integrations/eth-oracle/README.md) for details.

**Oracle config example:**
```toml
[ippan]
rpc_url = "env:IPPAN_RPC_URL"
poll_interval_ms = 10000
subject_type = "validator"

[ethereum]
rpc_url = "env:ETH_RPC_URL"
chain_id = 11155111
oracle_contract_address = "0x..."

[security]
score_scale = 1000000
max_updates_per_round = 100
```

## Security Recommendations

### Production Deployments

1. **Never commit secrets** - Use environment variables for API keys and private keys
2. **Use `env:` references** - Load sensitive values from environment
3. **Restrict file permissions** - Config files should be readable only by the service user
4. **Use secrets management** - Consider HashiCorp Vault, AWS Secrets Manager, etc.

### Example Secure Setup

```bash
# Store secrets in environment (e.g., from secrets manager)
export L1_API_KEY=$(vault read -field=value secret/ippan/l1-api-key)
export ETH_PRIVATE_KEY=$(vault read -field=value secret/ippan/eth-key)

# Config file references environment variables
cat > /etc/ippan-l2/config.toml << EOF
[l1]
base_url = "https://core.ippan.io"
api_key = "env:L1_API_KEY"
EOF

# Run with explicit config
./fin-node --config /etc/ippan-l2/config.toml
```

## Validation

Configuration is validated at startup. The application will fail fast with a
clear error message if:

- Required fields are missing
- Environment variable references cannot be resolved
- Values are out of valid range
- Paths are inaccessible

**Example error:**
```
Error: Configuration validation failed

Caused by:
    Missing required environment variable: L1_API_KEY
    Referenced in: l1.api_key = "env:L1_API_KEY"
```

## Sample Configurations

- `configs/local.toml` - Local development
- `configs/dev.toml` - Development/staging environment
- `configs/prod.toml` - Production template

See these files for complete examples.
