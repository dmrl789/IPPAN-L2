# IPPAN-L2 Release Checklist

This document outlines the pre-release verification steps for IPPAN-L2 FIN Node releases.

## Version: ___.___.___ (fill in before release)

**Release Date:** _______________  
**Release Manager:** _______________

---

## Pre-Release Checks

### 1. Code Quality

- [ ] All CI checks pass (fmt, clippy, test, build)
- [ ] `cargo test --workspace --all-features` passes locally
- [ ] `cargo clippy --workspace --all-features -- -D warnings` passes
- [ ] No new compiler warnings introduced

### 2. Security

- [ ] `cargo deny check` passes (no new vulnerabilities)
- [ ] `cargo audit` passes (no unaddressed advisories)
- [ ] Security mode tested in all configurations:
  - [ ] `devnet` mode works as expected
  - [ ] `staging` mode enforces partial auth
  - [ ] `prod` mode enforces full restrictions
- [ ] Rate limiting tested under load
- [ ] Payload limits tested (oversized requests rejected)
- [ ] Admin endpoints require auth in staging/prod

### 3. Feature Flags

Verify behavior with each feature combination:

| Feature Combination | Status |
|---------------------|--------|
| Default (no features) | [ ] Tested |
| `contract-posting` | [ ] Tested |
| `signed-envelopes` | [ ] Tested |
| `contract-posting,signed-envelopes` | [ ] Tested |
| `eth-headers` | [ ] Tested |
| `eth-lightclient` | [ ] Tested |
| All features | [ ] Tested |

### 4. Configuration

- [ ] Default config works out-of-box for devnet
- [ ] `configs/prod.toml` template is current
- [ ] Environment variable substitution works (`env:VAR_NAME`)
- [ ] Config validation catches invalid settings
- [ ] Documentation matches actual config options

### 5. API Compatibility

- [ ] OpenAPI spec (`docs/openapi/fin-node.openapi.json`) is current
- [ ] `scripts/check_openapi_drift.sh` passes
- [ ] No breaking changes to stable endpoints (or documented if intentional)
- [ ] API versioning follows `docs/API_VERSIONING.md`
- [ ] Deprecation notices issued for removed/changed endpoints

### 6. Database & State

- [ ] Sled DB opens cleanly from fresh state
- [ ] State migration tested (if applicable)
- [ ] State version incremented if schema changed
- [ ] Pruning works correctly
- [ ] Snapshots can be created and restored

### 7. Settlement & Reconciliation

- [ ] Settlement state machine transitions correctly
- [ ] Reconciler recovers from crash
- [ ] Pending batches resume after restart
- [ ] Final settlement detected from L1

### 8. Bridge & External Proofs

- [ ] Attestation proofs verify correctly
- [ ] Merkle proofs verify correctly
- [ ] Proof deduplication works (no double-credit)
- [ ] Invalid proofs rejected with clear errors

### 9. High Availability (if applicable)

- [ ] Leader election works
- [ ] Leader failover tested
- [ ] Follower catches up from leader
- [ ] Split-brain prevented

---

## Build & Packaging

### 10. Build Artifacts

- [ ] `cargo build --release` produces binary
- [ ] Binary size reasonable (< 50MB compressed)
- [ ] No debug symbols in release build
- [ ] LTO enabled for production builds

### 11. Docker

- [ ] `docker build` succeeds
- [ ] Image size reasonable (< 100MB)
- [ ] Container runs as non-root user
- [ ] Health check passes
- [ ] OCI labels present (version, commit, etc.)

### 12. Documentation

- [ ] CHANGELOG.md updated with release notes
- [ ] README installation instructions current
- [ ] `docs/ops/prod-config.md` current
- [ ] New features documented
- [ ] Breaking changes highlighted

---

## Deployment Verification

### 13. Systemd

- [ ] Unit file installs correctly
- [ ] Service starts successfully
- [ ] Service stops gracefully
- [ ] Auto-restart works
- [ ] Logs go to journald

### 14. Monitoring

- [ ] `/metrics` endpoint exposes Prometheus metrics
- [ ] `/healthz` returns 200 when healthy
- [ ] `/readyz` returns 200 when ready
- [ ] Key metrics present:
  - [ ] `http_requests_total`
  - [ ] `http_request_duration_seconds`
  - [ ] `http_rate_limited_total`
  - [ ] `recon_pending_total`
  - [ ] `receipts_total`
- [ ] Grafana dashboard imports correctly (if provided)

### 15. Backup & Recovery

- [ ] Snapshot creation works
- [ ] Snapshot restore works
- [ ] Point-in-time recovery possible
- [ ] Backup documentation current

---

## Release Process

### 16. Version Bump

```bash
# Update version in workspace Cargo.toml
[workspace.package]
version = "X.Y.Z"

# Verify all crates inherit workspace version
grep -r "workspace = true" --include="Cargo.toml"
```

### 17. Changelog

Update `CHANGELOG.md`:

```markdown
## [X.Y.Z] - YYYY-MM-DD

### Added
- Feature X
- Feature Y

### Changed
- Change A
- Change B

### Fixed
- Bug fix 1
- Bug fix 2

### Security
- Security fix (if applicable)

### Deprecated
- Deprecated feature (if applicable)

### Removed
- Removed feature (if applicable)
```

### 18. Git Tag

```bash
# Create signed tag
git tag -s vX.Y.Z -m "Release vX.Y.Z"

# Push tag
git push origin vX.Y.Z
```

### 19. GitHub Release

- [ ] Create GitHub release from tag
- [ ] Attach release binaries (if applicable)
- [ ] Copy changelog to release notes
- [ ] Mark as pre-release if not stable

---

## Post-Release

### 20. Verification

- [ ] Docker image available on registry
- [ ] Binary downloadable from release
- [ ] Documentation site updated (if applicable)

### 21. Communication

- [ ] Announce release (if public)
- [ ] Notify dependent projects
- [ ] Update integration examples

### 22. Monitoring

- [ ] Monitor error rates after deployment
- [ ] Check for unexpected metrics changes
- [ ] Review logs for new warnings/errors

---

## Emergency Procedures

### Rollback Plan

If issues discovered post-release:

1. **Identify scope:** Is it data corruption? Performance? Security?
2. **Communicate:** Alert stakeholders
3. **Rollback:** Deploy previous version
4. **Investigate:** Root cause analysis
5. **Fix forward:** Patch and re-release

### Known Issues

Document any known issues for this release:

| Issue | Severity | Workaround |
|-------|----------|------------|
| (none) | | |

---

## Sign-Off

| Role | Name | Date | Signature |
|------|------|------|-----------|
| Release Manager | | | |
| QA Lead | | | |
| Security Review | | | |

---

## Appendix: Version History

| Version | Date | Notes |
|---------|------|-------|
| 0.1.0 | TBD | Initial production release |
