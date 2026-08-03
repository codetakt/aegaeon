# Prometheus Rules (Sample)

Last updated: 2026-07-07

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

This page documents the recommended alert rules and recording rules for Aegaeon.

Canonical sample file:
- `docs/operations/monitoring/prometheus.rules.sample.yaml`

## How to use

- For a Prometheus server that supports rule files directly: include the YAML file as-is.
- For Kubernetes (Prometheus Operator): translate the rule groups into a `PrometheusRule` CRD.

## Sample rules

```yaml
groups:
  - name: aegaeon-jwks
    interval: 30s
    rules:
      - record: job:aegaeon:jwks_http_errors:rate5m
        expr: sum(rate(jwks_http_failures_reason_total{reason=~"http_.*|error|circuit"}[5m]))
      - alert: JWKSHttpErrors
        expr: sum(rate(jwks_http_failures_reason_total{reason=~"http_.*|error|circuit"}[5m])) > 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "JWKS HTTP errors detected"
          description: "JWKS fetch errors or circuit open observed in the last 5m."

      - alert: JWKSNo304sBut200s
        expr: sum(rate(jwks_http_events_total{outcome="304"}[15m])) == 0 and sum(rate(jwks_http_events_total{outcome="200"}[15m])) > 0
        for: 15m
        labels:
          severity: info
        annotations:
          summary: "JWKS 304 not observed while 200s present"
          description: "ETag/Last-Modified may be missing or caching ineffective."

      - alert: JWKSP99LatencyHigh
        expr: histogram_quantile(0.99, sum(rate(jwks_http_latency_seconds_bucket[5m])) by (le)) > 0.5
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "JWKS P99 latency > 500ms"
          description: "Investigate upstream JWKS server or network."

      - alert: JWKS_CircuitOpen
        expr: sum(jwks_circuit_state{state="open"}) > 0
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "JWKS circuit(s) open"
          description: "Circuits opened for one or more JWKS URIs. Serving stale if configured."

      - alert: JWKSSharedRuntimeStateFailures
        expr: sum(rate(jwks_shared_runtime_state_failures_total[5m])) > 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "JWKS shared runtime state failures observed"
          description: "Redis-backed JWKS runtime coordination failed; multi-node fetch/stale/kid state is fail-closing."

  - name: aegaeon-bcp
    interval: 30s
    rules:
      - alert: DCRBCPViolations
        expr: sum(rate(dcr_bcp_noncompliant_total[15m])) > 0
        for: 10m
        labels:
          severity: info
        annotations:
          summary: "DCR BCP noncompliance observed"
          description: "One or more noncompliant client registrations detected."

      - alert: RuntimeBCPViolations
        expr: sum(rate(runtime_bcp_noncompliant_total[15m])) > 0
        for: 10m
        labels:
          severity: warning
        annotations:
          summary: "Runtime BCP noncompliance observed"
          description: "Client assertions with disallowed alg or missing kid detected."

  - name: aegaeon-tokens
    interval: 30s
    rules:
      - alert: RefreshTokenRotationConflicts
        expr: sum(rate(oauth_refresh_token_rotation_conflicts_total[5m])) > 0
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Refresh token rotation conflicts observed"
          description: "One or more refresh tokens were reused after rotation in the last 5m (suspicious)."
```
