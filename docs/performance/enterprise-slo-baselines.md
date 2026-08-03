# Enterprise SLO Baselines

Last updated: 2026-07-08

Status: snapshot

Owner: Performance

Audience: performance reviewers, maintainers

> **Status note (2026-07-08):** Point-in-time performance baseline; rerun the documented command before using numbers for a new release decision.

## Scope

This document defines the baseline evidence required by the
`enterprise-slo-baselines` gate in
`spec/enterprise-readiness-claim.current.json`.

The machine-readable manifest schema is
`spec/enterprise-slo-baseline.schema.json`; validate manifests with
`nix develop .#default --command bash -c 'python3 scripts/validation/validate_enterprise_slo_baseline.py <manifest.json>'`.

It does not activate the enterprise-readiness claim by itself. The gate remains
in progress until fresh issuer and management-surface evidence is collected,
archived, and linked from the claim gate.

## Included surfaces

Enterprise SLO evidence must cover the externally operated surfaces included in
the enterprise-readiness claim:

- issuer availability and health endpoints
- OAuth/OIDC token issuance and authorization-code exchange
- PAR, JWKS, discovery, introspection, revocation, and userinfo endpoints when
  enabled for the deployment
- management API read/write paths that are part of the supported control plane
- observability, alerting, and audit-log delivery paths used by operators

Admin-console browser evidence can support the control-plane story, but it must
not be used as a substitute for management API or issuer SLO evidence.

## Required metrics

Every baseline bundle must record:

- release identifier and source revision
- deployment shape, database backend, signer backend, and enabled feature flags
- HTTPS target URL and network placement
- scenario, workers, target RPS, warmup, and duration
- total requests, success count, failure count, and error rate
- p50, p95, p99, and max latency where available
- attempted throughput and achieved throughput
- CPU, memory, database, and signer/KMS saturation indicators where available
- alerting and dashboard links or exported Prometheus snapshots

Expected policy rejections may count as scenario success only when the scenario
is explicitly designed for mixed policy outcomes, such as `policy-mixed`.

## Minimum scenario set

Before marking the gate complete, collect fresh evidence for:

- `smoke`
- `auth-code`
- `dpop`
- `introspection`
- `revocation`
- `par`
- `discovery`
- `jwks`
- `policy-mixed` with OIDC userinfo prerequisites enabled
- management API control-plane scenarios, once the load harness includes those
  paths

If a deployment disables a surface, record the reason and scope reduction in the
baseline manifest rather than silently omitting the scenario.

## Evidence layout

Store baseline bundles under:

```text
artifacts/perf/enterprise/<baseline-id>/
```

Each bundle should contain:

- `manifest.json`
- `reports/` with load-test JSON outputs
- `logs/` with server and load-generator logs
- `observability/` with dashboard exports, Prometheus snapshots, or links to
  immutable hosted evidence
- `review.json` with reviewer, decision, exceptions, and follow-up actions

`manifest.json` must use `spec/enterprise-slo-baseline.schema.json` and include
the minimum scenario set below. A scenario may be `not_applicable` only when the
manifest includes an explicit scope-reduction note.

Scenario `report_uri` values and observability URIs must be either local
relative paths that stay inside the baseline directory, or immutable external
`https://`, `s3://`, or `gs://` references. `http://`, absolute local paths, and
`../` escapes are rejected by the validator.
The deployment `target_url` must also use `https://`; local HTTP smoke runs are
useful for development but do not satisfy the enterprise SLO baseline gate.

## Local reproduction

The local smoke path remains useful for regression, but it is not sufficient for
enterprise-readiness activation by itself.

Run individual scenarios through the flake app:

```bash
PERF_SCENARIO=smoke ARTIFACT_DIR=artifacts/perf/enterprise/local-smoke \
  nix run .#perf-load

PERF_SCENARIO=dpop ARTIFACT_DIR=artifacts/perf/enterprise/local-dpop \
  nix run .#perf-load
```

For hosted or self-hosted baselines, run against the target deployment and keep
server management outside the local helper:

```bash
PERF_MANAGE_SERVER=0 PERF_BASE_URL=https://issuer.example.test \
PERF_SCENARIO=policy-mixed ARTIFACT_DIR=artifacts/perf/enterprise/hosted-policy-mixed \
  nix run .#perf-load
```

## Completion criteria

Before marking `enterprise-slo-baselines` complete:

1. Collect issuer scenario evidence for the target deployment.
2. Collect management API control-plane evidence or record that the management
   API is outside the claimed deployment scope.
3. Archive observability snapshots or durable links for the same test window.
4. Record feature flags, signer backend, database backend, and deployment shape.
5. Review error rates and latency outliers, with follow-up owners for accepted
   exceptions.
6. Link the baseline bundle from
   `spec/enterprise-readiness-claim.current.json`.

## Related documents

- `docs/performance/README.md`
- `docs/performance/load-baseline-auth-code.md`
- `docs/performance/load-baseline-dpop.md`
- `docs/performance/load-baseline-policy-mixed.md`
- `docs/operations/monitoring/README.md`
- `spec/enterprise-readiness-claim.current.json`
