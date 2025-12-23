## Dashboard baseline (Prometheus/Grafana)

This is a minimal baseline dashboard for operating `fin-node` under load.

### Recommended panels

- **HTTP request rate**: `sum(rate(http_requests_total[5m])) by (route)`
- **HTTP error rate (4xx/5xx)**: `sum(rate(http_requests_total{status=~"4..|5.."}[5m])) by (route,status)`
- **HTTP latency p95**:
  - `histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket[5m])) by (le,route))`
- **Rate limiting**: `sum(rate(rate_limited_total[5m])) by (scope)`
- **Payload rejections**: `sum(rate(payload_rejected_total[5m])) by (reason)`
- **Reconciliation pending**: `recon_pending_total`
- **Reconciliation failures**: `sum(rate(recon_failures_total[5m])) by (kind,reason)`
- **Pruning deletes**: `sum(rate(pruning_deleted_total[1h])) by (kind)`
- **L1 RPC failures**: `sum(rate(l1_request_failures_total[5m])) by (reason)`
- **Uptime**: `process_uptime_seconds`

### Alert suggestions (starter set)

- **Sustained 5xx**:
  - `sum(rate(http_requests_total{status=~"5.."}[5m])) / sum(rate(http_requests_total[5m])) > 0.01`
- **Recon backlog growing**:
  - `sum(recon_pending_total) > 0` for > 15m and `rate(recon_checks_total[15m]) == 0`
- **Rate limit spikes** (potential abuse):
  - `sum(rate(rate_limited_total[5m])) by (scope) > 10`
- **Pruning not running** (if enabled):
  - `increase(pruning_deleted_total[7d]) == 0` (tune based on expected churn)

