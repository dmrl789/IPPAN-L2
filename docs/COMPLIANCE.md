# Compliance hooks (optional, fin-node only)

Compliance hooks are **orchestration-layer** checks enforced by `fin-node` **before** it builds hub envelopes and applies hub state.

## Design

- **Optional**: disabled by default.
- **Deterministic**: uses local `fin-node` storage only (no network calls, no time).
- **Non-consensus**: not part of hub state; different operators can choose different compliance postures.

## Config

In your fin-node TOML:

```toml
[policy]
mode = "permissive" # or "strict"
admins = ["acc-admin-001"] # optional

[policy.compliance]
enabled = true
strategy = "global_denylist" # none | global_allowlist | global_denylist

[storage]
policy_db_dir = "policy_db"
```

## Lists (local storage keys)

- Allowlist: `compliance_allow:<account> -> 1`
- Denylist: `compliance_deny:<account> -> 1`

## CLI

```bash
# add/remove allowlist
fin-node policy allow add acc-alice
fin-node policy allow remove acc-alice

# add/remove denylist
fin-node policy deny add acc-mallory
fin-node policy deny remove acc-mallory

# show counts
fin-node policy status
```

## Semantics

- **global_denylist**: an action is denied if **any relevant account** in the request is denylisted.
- **global_allowlist**: an action is denied unless **all relevant accounts** are allowlisted.

“Relevant accounts” include the actor (if present/required) and obvious subjects (e.g. `from_account`, `to_account`, `licensee`, etc.).

