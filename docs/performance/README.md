# Performance Overview

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Performance

Audience: performance reviewers, maintainers

This directory contains long-lived performance documentation: baseline snapshots,
how to reproduce them locally, and how to interpret results.

Baseline documents remain point-in-time snapshots. Current raw evidence belongs
under `artifacts/perf/`; checked-in Markdown should stay as methodology plus
stable summary.

## Scope

- stable performance methodology
- checked-in baseline summaries
- pointers to raw performance artefacts under `artifacts/perf/`

## Canonical Documents

- `[snapshot]` [Load baseline (auth-code scenario)](load-baseline-auth-code.md)
- `[snapshot]` [Load baseline (DPoP scenario)](load-baseline-dpop.md)
- `[snapshot]` [Load baseline (policy-mixed scenario)](load-baseline-policy-mixed.md)
- `[reference]` [Enterprise SLO baselines](enterprise-slo-baselines.md)
- `[snapshot]` [JOSE JSON parsing baseline](jose-json-parsing-baseline.md)
- `[runbook]` [AWS performance environment](aws-perf-env.md)

## Entry Points

- Benchmarks (Criterion): `nix run .#perf-bench`
- Load tests (manual Layer 2 smoke/regression): `nix run .#perf-load`
- Coverage (llvm-cov HTML): `nix run .#perf-coverage`

When `PERF_MANAGE_SERVER=1`, `perf-load` starts `aegaeon-server` itself and
therefore requires PostgreSQL runtime authority:

- `AEGAEON_DATABASE_URL`
- `AEGAEON_RUNTIME_ISSUER_HOST` or `PERF_RUNTIME_ISSUER_HOST`

For local/CI smoke runs, set `PERF_APPLY_DATABASE_MIGRATIONS=1` for a fresh
database, then bootstrap the active management environment/configuration and
required runtime keys through the management API or `aegaeon-hosted-bootstrap`
before starting `perf-load`.

## Scenario Notes

- The default hardened posture is `DPoP`, so `dpop`, `introspection`,
  `revocation`, `par`, and `mixed` now use sender-constrained token acquisition
  in `aegaeon-loadtest`.
- `policy-mixed` rotates successful and intentionally rejected requests across
  `/introspect`, `/revoke`, and `/userinfo`; the expected `401` policy responses
  count as success for this scenario, and the `userinfo` legs require the OIDC
  startup prerequisites listed below.
- Supporting endpoints now have dedicated smoke scenarios:
  - `discovery` validates `/.well-known/oauth-authorization-server`
  - `jwks` validates `/.well-known/jwks.json` response shape; the bare server
    may legitimately return an empty `keys` array before explicit key rotation
- OIDC `userinfo` smoke requires the active management-database runtime snapshot to enable OIDC
  and provide an ACTIVE `OIDC_ID_TOKEN_SIGNING` runtime key for the issuer selected by
  `AEGAEON_RUNTIME_ISSUER_HOST`.
  Process environment OIDC policy/key-material toggles are rejected; configure these values through
  the management database before running load tests.
- When the server validates `DPoP` proofs against a public issuer/origin that
  differs from the local HTTP request URL, set
  `AEG_LOADTEST_PROOF_ORIGIN=<public-origin>` so the generated `htu` matches
  server-side validation while requests still target the local test server.

## Performance Tiers

1. Layer 2 CI smoke/regression uses the built-in `smoke` scenario against
  public health/version endpoints.
2. Layer 3 throughput benchmarking remains deferred to dedicated self-hosted
  infrastructure and should not be inferred from GitHub-hosted smoke runs.

## Reading Rule of Thumb

1. Start here when you need methodology or baseline context.
2. Treat `artifacts/perf/` as the authoritative home for current raw outputs.
3. Update checked-in Markdown only with stable summary and reproducibility guidance.
