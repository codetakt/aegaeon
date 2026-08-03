# Monitoring & Alerts (Prometheus/Alertmanager)

Last updated: 2026-07-07

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

## Scope

- Prometheus metric names and alerting examples
- Alertmanager and Grafana sample configuration pointers
- JWKS, DCR, token-lifecycle, and step-up monitoring guidance

## Canonical Documents

- `[runbook]` [Prometheus rules sample](prometheus-rules.md)
- `[runbook]` [Alertmanager sample](alertmanager.md)
- `[runbook]` [Grafana dashboard sample](grafana-dashboard.md)

## Reading Rule of Thumb

1. Start here to understand supported metric families and alert intent.
2. Use the sample files as starting points, not production-ready thresholds.
3. Keep live dashboards and raw alert history outside `docs/`.

## Overview

- This document proposes thresholds and example alerting rules (**sample config**) for the Aegaeon server.
- Metrics are exposed through the authenticated management API at `/api/v1/operations/metrics`.
  Configure Prometheus with a management human session or an API key that has audit-read
  capability; the main protocol server intentionally does not expose `/metrics`.

## Key Metrics

### JWKS

- `jwks_http_events_total{outcome,uri_hash}`
- `jwks_http_latency_seconds{outcome,uri_hash}` (histogram; buckets via `AEGAEON_JWKS_HISTOGRAM_BUCKETS`)
- `jwks_http_latency_quantiles_seconds{outcome,uri_hash}` (summary; objectives via `AEGAEON_JWKS_SUMMARY_OBJECTIVES`)
- `jwks_http_failures_reason_total{reason,uri_hash}`
  - `reason`: `size`, `pin`, `dup_kid`, `reuse`, `http_<status>`, `error`, `min_interval`, `circuit`
- `jwks_cache_hit_memory_total`
- `jwks_circuit_state{state,uri_hash}` (gauge)
  - `state`: `open`, `half_open`, `closed` (current phase = 1; others = 0)
- `jwks_shared_runtime_state_failures_total{operation,uri_hash}`
  - `operation`: `circuit_success`, `circuit_failure`, `circuit_phase`, `circuit_allow_fetch`,
    `kid_fingerprints`

When `AEGAEON_JWKS_REDIS_URL` is configured, JWKS circuit phase, half-open probe coordination,
and `kid` fingerprint history are shared across server nodes. Metric labels remain per node and
per `uri_hash`, but state transitions are backed by the shared Redis runtime state rather than by
process-local memory. Any increment of
`jwks_shared_runtime_state_failures_total` means the server had to fail closed or degrade a
non-critical shared-state write because the Redis-backed runtime contract was unavailable.

### BCP Noncompliance

- `dcr_bcp_noncompliant_total{reason}` (DCR-time)
  - `reason`: `redirect_invalid`, `alg_not_allowed`, `kid_missing`, `dup_kid`
- `runtime_bcp_noncompliant_total{reason}` (runtime client assertion)
  - `reason`: `alg_not_allowed`, `kid_missing`

### Token Lifecycle / Refresh Rotation

- `oauth_refresh_token_bindings_total` (counter)
  - Incremented whenever an access token is bound to a refresh token (initial issuance or refresh).
- `oauth_refresh_token_rotation_conflicts_total` (counter)
  - Counts attempts to reuse an already-rotated refresh token (suspicious; RFC 9700 rotation hardening).
- `oauth_refresh_cascade_revoked_total` (counter)
  - Total number of access tokens revoked via refresh-token cascade.
- `oauth_refresh_cascade_size` (histogram)
  - Distribution of cascade sizes (number of child access tokens revoked per refresh token).

### Step-Up (RFC 9470)

- `oauth_stepup_events_total{event}`
  - `event`: `required_acr_mismatch`, `required_max_age`, `required_acr_and_max_age`,
    `prompt_none_login_required`, `challenge_issued`, `challenge_consumed`, `challenge_completed`,
    `challenge_missing_session`

## Suggested Thresholds (Starting Points)

Notes:
- All rules below are samples. Tune thresholds and windows to your SLOs and traffic profile.
- The `uri_hash` label anonymizes URIs. Avoid high-cardinality labels in dashboards.

### JWKS HTTP errors

- Alert if:
  - `sum(rate(jwks_http_failures_reason_total{reason=~"http_.*|error|circuit"}[5m])) > 0`

### JWKS shared runtime state

- Page in multi-node deployments if:
  - `sum(rate(jwks_shared_runtime_state_failures_total[5m])) > 0`

### JWKS 304 effectiveness

- Warn if:
  - `sum(rate(jwks_http_events_total{outcome="304"}[15m])) == 0`
  - and `sum(rate(jwks_http_events_total{outcome="200"}[15m])) > 0`

### JWKS latency (P99)

- Alert if:
  - `histogram_quantile(0.99, sum(rate(jwks_http_latency_seconds_bucket[5m])) by (le)) > 0.5`
- Alternative (summary-based):
  - `jwks_http_latency_quantiles_seconds{outcome="200"} > 0.5`

### DCR noncompliance

- Warn if:
  - `sum(rate(dcr_bcp_noncompliant_total[15m])) > 0`
- Alert if:
  - `sum(rate(dcr_bcp_noncompliant_total{reason=~"kid_missing|dup_kid|alg_not_allowed"}[5m])) > 0`

### Runtime noncompliance

- Warn if:
  - `sum(rate(runtime_bcp_noncompliant_total[15m])) > 0`

### Refresh token rotation conflicts

- Alert if:
  - `sum(rate(oauth_refresh_token_rotation_conflicts_total[5m])) > 0`

## Grafana Panels (Examples)

### Circuit state (per `uri_hash`)

- Stat: `max(jwks_circuit_state{state="open", uri_hash="$uri"})`
- Stat: `max(jwks_circuit_state{state="half_open", uri_hash="$uri"})`
- Stat: `max(jwks_circuit_state{state="closed", uri_hash="$uri"})`

### Circuit events

- Time series: `sum by (uri_hash)(rate(jwks_http_events_total{outcome="circuit"}[5m]))`

### JWKS success/304/error mix

- Stacked time series: `sum by (outcome)(rate(jwks_http_events_total[5m]))`

### JWKS latency (P99)

- `histogram_quantile(0.99, sum(rate(jwks_http_latency_seconds_bucket{outcome="200"}[5m])) by (le))`

## Fail-Closed Integrity Audit (JWKS)

JWKS circuit and integrity policy is managed by the active PostgreSQL policy snapshot. The retired
file-backed stale path is removed from the policy document and database schema. Stale JWKS serving
has been removed from the production runtime; if the circuit is open or shared runtime state is
unavailable, the fetch path fails closed instead of returning expired key material. The old
`AEGAEON_JWKS_*` startup policy variables are rejected by `aegaeon-server`.

- `AEGAEON_JWKS_REDIS_URL`: Shared runtime state for multi-node circuit state, half-open probes,
  and `kid` fingerprint history. The legacy `AEGAEON_JWKS_SHARED_CACHE_PATH` on-disk JWKS
  response-body cache is removed.

## Sample Alerts

Extend `prometheus.rules.sample.yaml`:

```yaml
- alert: JWKS_CircuitOpen
  expr: sum(jwks_circuit_state{state="open"}) > 0
  for: 2m
  labels:
    severity: warning
  annotations:
    summary: "JWKS circuit(s) open"
    description: "One or more JWKS URIs are in OPEN state; fetches fail closed until the circuit allows a probe."

- alert: JWKSSharedRuntimeStateFailures
  expr: sum(rate(jwks_shared_runtime_state_failures_total[5m])) > 0
  for: 2m
  labels:
    severity: critical
  annotations:
    summary: "JWKS shared runtime state failures observed"
    description: "Redis-backed JWKS runtime coordination failed; multi-node circuit/kid state is fail-closing."

- alert: RefreshTokenRotationConflicts
  expr: sum(rate(oauth_refresh_token_rotation_conflicts_total[5m])) > 0
  for: 5m
  labels:
    severity: warning
  annotations:
    summary: "Refresh token rotation conflicts observed"
    description: "One or more refresh tokens were reused after rotation in the last 5m (suspicious)."
```

## Structured Logs

### Event sampling (JWKS)

- Global: `AEGAEON_JWKS_LOG_SAMPLE_PERCENT` (default `5`)
- Per-outcome overrides:
  - `AEGAEON_JWKS_LOG_SAMPLE_PERCENT_200`
  - `AEGAEON_JWKS_LOG_SAMPLE_PERCENT_304`
  - `AEGAEON_JWKS_LOG_SAMPLE_PERCENT_FAILURE`
  - `AEGAEON_JWKS_LOG_SAMPLE_PERCENT_ERROR`

### Token lifecycle logs

- `target`: `tokens`
  - INFO: `refresh token bound to access token`, `refresh token rotated`, `cascade revocation triggered`
  - WARN: `refresh token reuse detected; cascading revoke`

### Step-up logs

- `event`: `stepup_required`, `stepup_prompt_none_rejected`, `stepup_challenge_issued`,
  `stepup_challenge_consumed`, `stepup_challenge_completed`, `stepup_challenge_issue_overflow`
  - Fields: `client_id`, `reason`, `prompt`, `request_id`

## Files

- `README.md`: monitoring overview and guidance
- `prometheus-rules.md`: Prometheus rules (Markdown copy)
- `alertmanager.md`: Alertmanager config (Markdown copy)
- `grafana-dashboard.md`: Grafana dashboard import notes
- `prometheus.rules.sample.yaml`: sample PrometheusRule(s)
- `alertmanager.sample.yaml`: sample Alertmanager routing/receivers
- `grafana.dashboards.sample.json`: sample Grafana dashboard panels (import into Grafana)

## Metrics Endpoint

- Metrics are exposed through the authenticated management API at `/api/v1/operations/metrics`.
- `AEGAEON_EXPOSE_METRICS_ON_MAIN` was removed; the main protocol server no longer exposes `/metrics`.
- Use a management human session or an API key with audit-read capability when scraping this endpoint.
