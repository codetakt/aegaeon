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

`perf-load` prepares one pinned Nix build containing the workload and its
synchronous URL-only validator. The generated application executes immutable
runner/helper code and fixes the supplier identities; it does not select a
validator from the caller's environment, `PATH`, or mutable `target/`. The
tracked shell entrypoints forward to `nix run .#perf-load`.

Preparation may fetch dependencies or write Nix store, cache and build outputs
before the application rejects an input. Once prepared, explicit URL/issuer
rejection creates no runner output, status, retained source, server setup or
port probe. The application first compares every tracked worktree member with
the complete supplier snapshot, including prose, modes and literal links,
using two read-only rounds. Index membership defines the domain; current
worktree bytes are checked independently of staged blob IDs. Untracked inputs,
conflicts and snapshot mismatches fail closed. Dirty and staged changes are
usable only when that exact content and mode were captured by the Git flake.
Preparation and observed admission are separate from runtime acceptance.

When `PERF_MANAGE_SERVER=1`, `perf-load` starts `aegaeon-server` itself and
therefore requires PostgreSQL runtime authority:

- `AEGAEON_DATABASE_URL`
- `AEGAEON_RUNTIME_ISSUER_HOST` or `PERF_RUNTIME_ISSUER_HOST`

For local/CI smoke runs, set `PERF_APPLY_DATABASE_MIGRATIONS=1` for a fresh
database, then bootstrap the active management environment/configuration and
required runtime keys through the management API or `aegaeon-hosted-bootstrap`
before starting `perf-load`.

## Load consumer inputs and reporting

Public `smoke`, `discovery`, and `jwks` selections use the supplied transport target.
For `discovery`, `--discovery-expected-issuer` (or
`PERF_DISCOVERY_EXPECTED_ISSUER` in `perf-load`) independently selects the exact
canonical HTTPS issuer expected in metadata, including its `/token` and `/jwks`
URLs. This supports public metadata over an HTTP loopback transport while
checking an HTTPS issuer. Without the option, discovery retains the target-based
expectation; smoke and JWKS defaults are unchanged. OAuth
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
manifest, and a new `--report-file` path. `perf-load` produces that digest from
its complete tracked source before managed setup or workload launch and rejects any inherited value,
including an empty one. Invoke it in a source-only Git worktree with canonical
0644/0755 regular-file modes; tracked dirty bytes and literal symlinks are recorded.
Unknown untracked or ignored files are rejected. Keep protected runtime inputs
outside the checkout. Only the conventional `target/`, reserved `artifacts/perf/`
outputs and the two legacy report files are excluded; no tracked path is excluded.
Custom build/evidence outputs can be outside the source. The driver passes the
selected Cargo output directory with an explicit `--target-dir`, overriding
Cargo build settings. The driver retains the manifest and observations on
failure, checks source again before each build and launch, and binds the report to the actual supplied executable selected by
Cargo and reread after installation. The workload binding uses schema version
2 and retains the independent supplier binding plus its actual build/graph
observations; the managed server retains its separate build binding. No local
workload rebuild substitutes a different parser. The same paired Rust
configuration validator governs early admission, invocation configuration and report
configuration: valid HTTP(S) transport spelling can normalize, while the
discovery issuer must already equal its canonical HTTPS spelling. Before
launching the consumer, it freezes `source/INVOCATION.json` containing the exact
selected command, source and executable hashes, full normalized configuration,
an independently generated UUIDv4 passed as `--report-id`, and the exact new
report path. Target and issuer URLs reject embedded credentials, queries,
fragments and control characters before this nonsecret record is written.
Admission checks all configuration fields, selected scenario, UUID
and destination against that retained record, as well as the SHA256 of the
report's exact `config_json` string. Raw source
preimages and dirty patches remain private outside upload roots. These checks
establish observed source identity; native/OCI/supplier and performance acceptance
remain separate. Direct binary invocations still require a real independently
frozen source digest and source-to-artifact producer evidence.

For a managed server, the already parsed and validated host is passed directly
to port selection and used in the final target URL. The final URL is checked
again after port selection, before output/source setup, server construction,
migrations or launch; this later check may follow a socket probe.
The report records the digest of the actual running executable,
configuration, profile and session provenance, observed JWKS digests, and a
unique report identifier. `AEG_LOADTEST_CA_CERT` may supply an additional trusted
PEM CA; the shared runner uses the same CA for readiness and retains certificate
and hostname verification. Report, log, build and evidence destinations must be
disjoint. Only the declared report and legacy-report roles may share a normalized
leaf. Every report, log, evidence and status destination must also remain outside
both the default and configured Cargo target trees, including their parents.
Private retention paths reject traversal and stay outside upload roots.
Legacy credential and proof-origin overrides are rejected; there are no
default OAuth credentials, management-owner substitution, or forged forwarding
headers. See the [environment reference](../configurations/environment/federation-observability-and-test.md#load-testing).

`--warmup` accepts numeric seconds and the same `s`, `m`, or `h` duration syntax as
`--run-time` (for example `--warmup 10s`); invalid direct-binary values preserve a
failed report. The runner rejects invalid effective configuration before creating
outputs, freezing source, migrations, builds, launch or readiness probes.
Managed arguments use the
documented long options and existing long aliases before `--`; arguments after
`--` support only one `--debug`. Other trailing options, including aliases and
report/configuration overrides, are rejected. `--debug` and
`--discovery-expected-issuer` can also be supplied before `--`. Numeric duration
counts and worker counts use ASCII decimal digits in managed runs.

Execution and report acceptance use the same configuration validation. Worker
count and target invocation rate must produce a finite, bounded interval that
Rust can represent as a positive `Duration`; a rate that rounds the interval to
zero is rejected before worker startup.

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
The scheduled workflow currently reports `policy-mixed` as pending and skips both
its execution and SLO acceptance under the same prerequisite gate. Activated HTTPS,
a declared client profile, a public-login session and supplier acceptance remain
required. A separate bounded runtime acceptance must supply and accept these
prerequisites before changing that gate; the pending lane is not execution or
performance evidence. The public smoke caller continues through the shared runner.

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
