# Load Test Baseline: DPoP (default sender-constrained posture)

Last updated: 2026-07-07

Status: snapshot

Owner: Performance

Audience: performance reviewers, maintainers

> **Status note (2026-05-15):** This is the current checked-in success-path
> baseline summary for the default hardened `DPoP` posture. For newer
> measurements, re-run the load workflow and store raw outputs under
> `artifacts/perf/`.

_Run timestamp: 2026-05-15T09:19:37Z (UTC)_

This document records a load smoke baseline for the default sender-constrained
server posture. The test exercises the end-to-end authorization-code flow
(`authorize` -> `token`) via the `dpop` scenario in `aegaeon-loadtest`,
including the required `DPoP` proof on the token request.

The current loadtest scenario matches the server's RFC 9449 posture by:

- constructing the `htu` claim from the absolute token endpoint URL
- retrying the token request once when the server replies with
  `use_dpop_nonce` plus a fresh `DPoP-Nonce` header

Results are sourced from
`artifacts/perf/load-baseline-dpop-20260515/report.json`.

## Execution Summary

- **Canonical entry point**:
  ```bash
  ARTIFACT_DIR=artifacts/perf/load-baseline-dpop-20260515 \
  PERF_SERVER_PORT=18087 \
  nix run .#perf-load -- \
    --scenario dpop \
    --workers 15 \
    --run-time 20s \
    --warmup 3 \
    --rps 40 \
    --server-port 18087 \
    --report-file artifacts/perf/load-baseline-dpop-20260515/report.json
  ```
- **Server build**: `cargo build --release --locked --bin aegaeon-server`
- **Server launch**: `target/release/aegaeon-server --host 127.0.0.1 --port 18087`
  - Output logged in `artifacts/perf/load-baseline-dpop-20260515/server.log`
- **Client logs**: `artifacts/perf/load-baseline-dpop-20260515/loadtest.log`
- **Legacy copy**: `artifacts/load-test-report.json`

We bound the server to port `18087` to avoid conflicts with other local
processes. This baseline intentionally keeps the default sender-constrained
posture enabled, so no `AEGAEON_POLICY_SENDER_CONSTRAINT` override is applied.

## Key Metrics

| Metric | Value | Notes |
| --- | --- | --- |
| Total requests | 777 | All completed successfully under the default `DPoP` posture |
| Successful requests | 777 | `authorize -> token` success path with PKCE S256 plus `DPoP` sender binding |
| Successful throughput | 38.16 req/s | Derived from `throughput` in the report JSON |
| Attempted throughput | 38.16 req/s | Derived from `attempted_throughput` in the report JSON |
| Latency p50 | 0 ms | Loopback execution stays below 1 ms resolution |
| Latency p99 | 0 ms | Same sub-millisecond resolution limit as p50 |
| Peak RSS | 91.80 MB | From memory monitor samples |
| Warmup duration | 3 s | As configured |
| Test duration | 20.36 s | Excluding warmup; derived from the report JSON duration |

The `aegaeon-loadtest` tool enforces SLO thresholds (p50 <= 50 ms, p99 <=
200 ms, throughput >= 1000 req/s, peak memory <= 500 MB). For this run, all
tracked SLOs passed: p50/p99 stayed below the threshold, throughput cleared the
`0.9 * target_rps` gate, and error rate remained at `0%`. The wrapper writes
the JSON report and refreshes the legacy copy even for non-zero exits, but this
calibrated default-posture run completed with exit status `0`.

## Notes

- This document complements [Load baseline: Authorization Code (auth-code)](load-baseline-auth-code.md), which keeps `AEGAEON_POLICY_SENDER_CONSTRAINT=none` so the pure auth-code path can be measured separately.
- The default server posture requires both a `DPoP` proof and a server-issued nonce on the token request. The loadtest scenario now performs that nonce roundtrip automatically during the token exchange.
- The same sender-constrained token acquisition path is now reused by the `introspection`, `revocation`, `par`, and `mixed` scenarios so their default-posture smokes no longer depend on `AEGAEON_POLICY_SENDER_CONSTRAINT=none`.
- OIDC `userinfo` smoke also uses the same nonce-aware DPoP path, but it additionally needs OIDC signing-key env and, when the public issuer differs from the local HTTP URL, `AEG_LOADTEST_PROOF_ORIGIN=<public-origin>`.
- For new baselines, use a descriptive artefact directory via `ARTIFACT_DIR=artifacts/perf/<run-id>` and keep large logs under `artifacts/perf/`.
