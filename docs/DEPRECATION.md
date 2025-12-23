# API Deprecation Policy

This repo aims to provide a stable integration surface for `fin-node`.

## Principles

- **No surprise breaks**: existing clients must keep working through a deprecation window.
- **Versioned contracts**: breaking changes require a new API version (`/api/v2/...`).
- **Schema evolution**: prefer additive changes (new optional fields) over breaking changes.

## Deprecating an endpoint or field

1) Mark it deprecated:
- In OpenAPI: add `"deprecated": true` on the operation (or field docs).
- In docs: add a note to `docs/API_VERSIONING.md` if it’s widely used.

2) Provide an alternative:
- New endpoint path (prefer `/api/v1/...`).
- Or new field while keeping the old field for compatibility.

3) Announce and keep it working for a window:
- **Minimum**: 2 releases or 30 days (whichever is longer) unless it’s a security emergency.

4) Remove:
- Only after the window, and only if CI + OpenAPI spec is updated together.

## Adding new versions

Use a new path prefix:
- `/api/v2/...`

Rules:
- `/api/v1/...` remains supported for the full deprecation window.
- The OpenAPI spec should be split or versioned by filename (e.g. `fin-node.openapi.v2.json`) if v1 and v2 diverge meaningfully.

