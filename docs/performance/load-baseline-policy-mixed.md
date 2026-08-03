# Load Test Baseline: Policy-Mixed (OIDC-backed policy rejection mix)

Last updated: 2026-07-07

Status: snapshot

Owner: Performance

Audience: performance reviewers, maintainers

> **Status note (2026-05-16):** This is the current checked-in smoke baseline
> for the `policy-mixed` scenario. For newer measurements, re-run the load
> workflow and store raw outputs under `artifacts/perf/`.

_Run timestamp: 2026-05-16T03:31:27Z (UTC)_

This document records a load smoke baseline for the `policy-mixed` scenario in
`aegaeon-loadtest`. The scenario intentionally rotates both successful and
expected policy-rejection requests across `/introspect`, `/revoke`, and
`/userinfo`.

The current scenario treats the following outcomes as success:

- successful authenticated `/introspect`
- successful authenticated `/revoke`
- successful sender-constrained `/userinfo`
- `401 invalid_client` for unauthenticated `/introspect`
- `401 invalid_client` for unauthenticated `/revoke`
- `401` for `/userinfo` without an `Authorization` header

Because the `/userinfo` success leg is included, the server must run with OIDC
enabled and an active `OIDC_ID_TOKEN_SIGNING` runtime key in the PostgreSQL-backed
management runtime. Results are sourced from
`artifacts/perf/policy-mixed-smoke-20260516/report.json`.

## Execution Summary

- **Historical entry point**: this baseline predates the PostgreSQL-only management-runtime
  boundary. Do not use startup `AEGAEON_OIDC_*` policy or signing-key environment variables for new
  runs. Re-run the scenario against a seeded management database selected by
  `AEGAEON_RUNTIME_ISSUER_HOST`, with OIDC/userinfo policy and runtime keys supplied from the active
  database snapshot.
  ```bash
  AEGAEON_RUNTIME_ISSUER_HOST=127.0.0.1:18096 \
  AEG_LOADTEST_PROOF_ORIGIN=https://127.0.0.1:18096 \
  ARTIFACT_DIR=artifacts/perf/policy-mixed-smoke-20260516 \
  PERF_SERVER_PORT=18096 \
  nix run .#perf-load -- \
    --scenario policy-mixed \
    --workers 2 \
    --run-time 4s \
    --warmup 1 \
    --rps 4 \
    --server-port 18096 \
    --report-file artifacts/perf/policy-mixed-smoke-20260516/report.json
  ```
- **Server build**: `cargo build --release --locked --bin aegaeon-server`
- **Server launch**: `target/release/aegaeon-server --host 127.0.0.1 --port 18096`
  - Output logged in `artifacts/perf/policy-mixed-smoke-20260516/server.log`
- **Client logs**: `artifacts/perf/policy-mixed-smoke-20260516/loadtest.log`
- **Legacy copy**: `artifacts/load-test-report.json`

We bound the server to port `18096` to keep the public proof origin stable
across re-runs. The scenario uses a deliberately low target RPS because it
mixes success-path sender-constrained traffic with intentional policy failures;
this smoke should be interpreted as correctness/regression coverage rather than
as a throughput ceiling for the runtime.

## Key Metrics

| Metric | Value | Notes |
| --- | --- | --- |
| Total requests | 16 | All scenario legs completed within the 4-second smoke window |
| Successful requests | 16 | Includes both success-path responses and expected `401` policy rejections |
| Successful throughput | 3.89 req/s | Derived from `throughput` in the report JSON |
| Attempted throughput | 3.89 req/s | Derived from `attempted_throughput` in the report JSON |
| Latency p50 | 0 ms | Loopback execution stays below 1 ms resolution |
| Latency p99 | 1 ms | Includes the mixed `/userinfo` and rejection legs |
| Peak RSS | 87.32 MB | From memory monitor samples |
| Warmup duration | 1 s | As configured |
| Test duration | 4.11 s | Excluding warmup; derived from the report JSON duration |

The `aegaeon-loadtest` tool enforces SLO thresholds (p50 <= 50 ms, p99 <=
200 ms, throughput >= 1000 req/s, peak memory <= 500 MB). For this smoke run,
all tracked SLOs passed using the scenario-local target RPS of `4`, so the
effective throughput gate remained `0.9 * 4 req/s`. Error rate stayed at `0%`
because the expected policy failures were classified as success by the
scenario itself.

## Notes

- This document complements [Load baseline: DPoP](load-baseline-dpop.md), which
  measures pure success-path sender-constrained issuance. `policy-mixed`
  intentionally exercises the operational boundary between accepted requests and
  fail-closed policy rejection.
- The `AEG_LOADTEST_PROOF_ORIGIN` override is required whenever the server
  validates `DPoP` proofs against a public HTTPS origin that differs from the
  local HTTP request URL.
- The same scenario is now wired into `performance.yml` for scheduled/manual
  heavy runs, alongside the public `smoke` load lane.
- For new baselines, use a descriptive artefact directory via
  `ARTIFACT_DIR=artifacts/perf/<run-id>` and keep large logs under
  `artifacts/perf/`.
