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

## Load consumer inputs and reporting

Public `smoke`, `discovery`, and `jwks` selections use the supplied target. OAuth
selections require an actual activated confidential client and a genuine issuer
session produced by public login. The target must equal the exact HTTPS issuer;
use ordinary DNS/TLS routing and a trusted fixture CA. The HTTP client disables
redirect following and never contacts a registered callback.

Set these inputs privately before selecting `auth-code`, `dpop`, `introspection`,
`revocation`, `userinfo`, `par`, `mixed`, or `policy-mixed`:

- `AEG_LOADTEST_PROFILE_MANIFEST`: a frozen JSON receipt from management readback,
  containing `issuer`, `environment_id`, `configuration_version_id`,
  `oauth_profile_id`, `activation` (`ACTIVE`), `client_id`, `redirect_uri`,
  `client_auth` (`client_secret_basic` or `client_secret_post`), `scope`,
  `oidc_scope`, `subject`, `sender_policy` (`none` or `dpop`), `par_policy`
  (`optional` or `required`), `resource`, and `id_token_alg`. Nullable fields are
  `oidc_scope`, `resource`, and `id_token_alg`; every selected OIDC transaction
  requires explicitly approved `RS256`. Unsupported algorithms fail setup.
- `AEG_LOADTEST_CLIENT_SECRET`: the actual secret of that registered OAuth client.
- `AEG_LOADTEST_SESSION_FILE`: a protected file containing only
  `aegaeon_auth_session=<actual session value>` and an optional final newline.
- `AEG_LOADTEST_SESSION_PROVENANCE`: a protected JSON receipt with `issuer`,
  `subject`, `method` (`public-login`), `producer` (the actual producer reference),
  `profile_sha256` (digest of exact profile-manifest bytes), and `session_sha256`
  (digest of the cookie line without its newline). The producer must establish
  genuine current login, profile activation, and subject correspondence; the
  receipt is an input, not an independent assertion of authentication.

Every run requires `AEG_LOADTEST_SOURCE_SHA256`, the SHA256 of its frozen source
manifest, and a new `--report-file` path. The producer must bind that source to the
built artifact. The report records the digest of the actual running executable,
configuration, profile and session provenance, observed JWKS digests, and a
unique report identifier. `AEG_LOADTEST_CA_CERT` may supply an additional trusted
PEM CA. Legacy credential and proof-origin overrides are rejected; there are no
default OAuth credentials, management-owner substitution, or forged forwarding
headers. See the [environment reference](../configurations/environment/federation-observability-and-test.md#load-testing).

`--warmup` accepts numeric seconds and the same `s`, `m`, or `h` duration syntax as
`--run-time` (for example `--warmup 10s`); invalid values preserve a failed report.

Authorization retains state, issuer, nonce, scope/resource and PKCE through the
entire transaction. It requests `prompt=none` and query response mode. Required
PAR holds all transaction parameters; only client ID and request URI remain on
authorize. Positive authorization requires exactly one HTTP 302 Location to the
registered HTTPS destination, including its static query. Login pages, OAuth
errors, JSON responses, changed state/issuer, and duplicate parameters fail.
Current consent semantics remove `offline_access` under `prompt=none`; no refresh
token is expected. This does not simulate persisted offline consent.

Auth-code uses declared sender/PAR policy. DPoP and mixed selections require a
DPoP profile; PAR selection always pushes the request. AS HTTP 400 and RS HTTP
401 nonce challenges receive at most one retry with the same key and a fresh
JTI; UserInfo proofs include the access-token hash. UserInfo selects the issuer's
UserInfo resource, verifies the RS256 ID Token signature against issuer JWKS and
its issuer/audience/authorized-party/nonce/time/subject bindings, then requires
UserInfo subject correspondence. Introspection checks active client/scope/sender
and any selected resource; revocation verifies subsequent inactivity.

All 12 selections remain available. `mixed` must consume all four positive legs
(DPoP, introspection, revocation, PAR). `policy-mixed` must consume its six legs:
positive introspection/revocation/UserInfo and each corresponding missing-auth
rejection. Expected rejections are reported separately from positive successes.
`key-rotation` fails explicitly because supported HUMAN management, NEXT key
replenishment and issuer restart supervision require a separate lifecycle.

Report schema 2 retains `total_requests` and throughput as **scenario invocations**,
with `request_unit=scenario_invocations`. HTTP attempts, responses, method/endpoint
and status partitions, transport/body failures, AS/RS challenges and retries are
independent counters. Per-leg positive successes, expected rejections and failures
are recorded. Warmup has separate counters and never enters main invocation totals.
Worker/setup/join errors, missing selected legs, failed invocations, absent HTTP or
positive traffic, inconsistent counts, nonfinite measurements and missing
source/artifact/report identities cause nonzero exit. Failed reports are preserved;
existing reports are never overwritten. Keep private receipts, sessions, secrets
and raw configuration outside published evidence.

The existing SLO thresholds remain: p50 <= 50 ms, p99 <= 200 ms, successful
invocation throughput >= max(target * 0.9, 1), error rate <= 0.01, and peak memory
<= 500 MB. Memory describes the **load generator process**, not server/KMS memory.
A finite normal development fixture can establish source behavior; it does not
establish release/OCI artifact readiness, cloud performance or product assurance.

## Performance Tiers

1. Layer 2 CI smoke/regression uses the built-in `smoke` scenario against
  public health/version endpoints.
2. Layer 3 throughput benchmarking remains deferred to dedicated self-hosted
  infrastructure and should not be inferred from GitHub-hosted smoke runs.

## Reading Rule of Thumb

1. Start here when you need methodology or baseline context.
2. Treat `artifacts/perf/` as the authoritative home for current raw outputs.
3. Update checked-in Markdown only with stable summary and reproducibility guidance.

The report identity includes `config_json`, the exact UTF-8 JSON string produced
by the load generator for its configuration, and `config_sha256`, the SHA256 of
those same bytes. An artifact consumer must hash that string without
reserializing it, reject missing, duplicate or unknown configuration fields,
and compare the decoded values with the actual invocation. The separate driver
configuration has its own digest. Its serialization does not define the load
generator's digest.
