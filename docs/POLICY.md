# Policy & Permissions (v1)

This repo implements **minimal, explicit** policy controls for HUB-FIN and HUB-DATA.

## Goals

- **Deterministic**: decisions depend only on stored state + request fields.
- **Auditable**: rejections return stable error codes and sanitized messages.
- **Minimal**: not a full IAM system; explicit rules only.

## Roles

Defined in `l2-core/src/policy/mod.rs`:

- **Owner**: owns a dataset, asset, or account-controlled balance.
- **Issuer**: issues an asset and may be allowed to mint.
- **Operator**: acts on behalf of an owner when explicitly delegated.
- **Admin**: optional operational override in strict mode (node-configured).

## Policy modes

- **permissive**: local/dev friendly; allows some legacy/missing fields.
- **strict**: production posture; requires explicit actor identity and delegation.

## Stable deny codes

`PolicyDenyCode` values are stable and must not be renamed:

- **missing_actor**: actor identity missing where strict requires it.
- **unauthorized**: actor is not allowed to perform the action.
- **delegation_required**: operator action requires an explicit delegation grant.
- **not_found**: referenced subject (asset/dataset/listing) missing.
- **compliance_denied**: blocked by optional orchestration-layer compliance lists.
- **invalid_policy_input**: policy precondition failed (distinct from schema validation).

## Notes

- Policy is intentionally **small and explicit** to stay reviewable.
- No external calls or wall-clock time are permitted in policy evaluation.

## fin-node error shape

When a request is denied by policy, `fin-node` returns HTTP **403** with:

- `error: "policy_denied"`
- `policy.code` (stable deny code)
- `policy.message` (sanitized)
- `policy.context_id` (deterministic correlation id; usually the action id)

