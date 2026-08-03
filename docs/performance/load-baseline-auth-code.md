# Load Test Baseline: Authorization Code (auth-code)

Last updated: 2026-07-07

Status: snapshot

Owner: Performance

Audience: performance reviewers, maintainers

> **Status note (2026-05-15):** This is the current checked-in success-path
> baseline summary for the pure auth-code scenario. For newer measurements,
> re-run the load workflow and store raw outputs under `artifacts/perf/`.

_Run timestamp: 2026-05-15T08:58:30Z (UTC)_

This document records a load smoke baseline for the pure authorization-code
scenario. The test exercises the end-to-end flow (authorize → token) using the
`aegaeon-loadtest` utility while explicitly disabling the default sender
constraint requirement so the measurement stays scoped to the auth-code path.

Results are sourced from `artifacts/perf/load-baseline-auth-code-20260515/report.json`.

## Execution Summary

- **Canonical entry point**:
  ```bash
  AEGAEON_POLICY_SENDER_CONSTRAINT=none \
  ARTIFACT_DIR=artifacts/perf/load-baseline-auth-code-20260515 \
  PERF_SERVER_PORT=18084 \
  nix run .#perf-load -- \
    --scenario auth-code \
    --workers 15 \
    --run-time 20s \
    --warmup 3 \
    --rps 40 \
    --server-port 18084 \
    --report-file artifacts/perf/load-baseline-auth-code-20260515/report.json
  ```
- **Server build**: `cargo build --release --locked --bin aegaeon-server`
- **Server launch**: `target/release/aegaeon-server --host 127.0.0.1 --port 18084`
  - Output logged in `artifacts/perf/load-baseline-auth-code-20260515/server.log`
- **Client logs**: `artifacts/perf/load-baseline-auth-code-20260515/loadtest.log`
- **Legacy copy**: `artifacts/load-test-report.json`

We bound the server to port `18084` to avoid conflicts with other local
processes. For new runs, prefer `nix run .#perf-load` (or
`scripts/perf/run_load_tests.sh`) and set `PERF_SERVER_HOST` / `PERF_SERVER_PORT`
to avoid port collisions. The bare server defaults to `DPoP`, so the
`AEGAEON_POLICY_SENDER_CONSTRAINT=none` override is required when you want the
baseline to measure pure auth-code latency/throughput rather than the separate
sender-constrained path.

## Key Metrics

| Metric | Value | Notes |
| --- | --- | --- |
| Total requests | 777 | All completed successfully under the pure auth-code posture |
| Successful requests | 777 | `authorize → token` success path with PKCE S256 |
| Successful throughput | 38.17 req/s | Derived from `throughput` in the report JSON |
| Attempted throughput | 38.17 req/s | Derived from `attempted_throughput` in the report JSON |
| Latency p50 | 0 ms | Loopback execution stays below 1 ms resolution |
| Latency p99 | 0 ms | Same sub-millisecond resolution limit as p50 |
| Peak RSS | 91.91 MB | From memory monitor samples |
| Warmup duration | 3 s | As configured |
| Test duration | 20.36 s | Excluding warmup; derived from the report JSON duration |

The `aegaeon-loadtest` tool enforces SLO thresholds (p50 ≤ 50 ms, p99 ≤ 200 ms,
throughput ≥ 1000 req/s, peak memory ≤ 500 MB). For this run, all tracked SLOs
passed: p50/p99 stayed below the threshold, throughput cleared the
`0.9 * target_rps` gate, and error rate remained at `0%`. The wrapper writes
the JSON report and refreshes the legacy copy even for non-zero exits, but this
calibrated success-path run completed with exit status `0`.

## Notes

- The bare server already seeds `test-client` / `test-secret`; the default local failure mode was the stronger `DPoP` sender-constraint posture, not missing client metadata.
- See [Load baseline: DPoP](load-baseline-dpop.md) for the default sender-constrained posture. This document intentionally holds the pure auth-code baseline.
- For new baselines, use a descriptive artefact directory via `ARTIFACT_DIR=artifacts/perf/<run-id>` and keep large logs under `artifacts/perf/`.
