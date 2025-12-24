# Contributing to IPPAN-L2

1. Run `make check` before opening a PR (`fmt`, `clippy`, `test`).
2. Keep deterministic code paths: no floating point usage or non-canonical serialization for hashes.
3. Add documentation alongside code (new modules require a doc entry under `docs/`).
4. Ensure `/healthz`, `/readyz`, `/status`, and `/metrics` continue to work when touching node code.
5. Describe repo baseline and changes clearly in PR bodies; include how to run (`make run`).
6. Security issues: follow `SECURITY.md` for responsible disclosure.
