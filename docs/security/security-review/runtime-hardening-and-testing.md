# Security Review Runtime Hardening And Testing

Last updated: 2026-07-08

Status: snapshot

Owner: Security

Audience: security reviewers, maintainers

> **Status note (2026-07-08):** Snapshot security review; refresh evidence before using it for a new release decision.

This document is part of the split security-review snapshot.

## Runtime Hardening Update (Sprint 6)

- **SecurityPolicy toggle hardening**: added `require_scope_subset` / `require_audience_match` /
  `retain_refresh_chain` / `enforce_sender_binding` to `crates/server/src/policy.rs` and made them
  configurable via `AEG_POLICY_*` environment variables. Verified defaults and override behaviour in
  `policy::tests::default_policy_hardening_flags` and `env_overrides_are_respected`.
- **Bearer metadata retention**: `BearerTokenMeta` in `crates/server/src/authcode/types.rs` retains
  scope, audience, sender-binding, and refresh-parent metadata; `TokenStore::store_bearer_meta` /
  `get_bearer_meta` persist it. `TokenValidator::validate_with_policy` evaluates the configured
  policies at runtime.
- **Sender binding enforcement**: `middleware::dpop::verify_and_attach` stores the JKT in
  `Request::extensions`, and `TokenPolicyContext` rejects sender mismatches. Covered by
  `crates/server/tests/bearer_policy_test.rs` and `dpop_middleware_integration_test.rs`.
- **Refresh-chain protection**: when `retain_refresh_chain` is enabled, `TokenStore::is_refresh_revoked`
  checks parent-token history and blocks reuse. Tests
  `retain_refresh_chain_blocks_revoked_parent` / `retain_refresh_chain_disabled_allows_missing_history`
  verify the mode differences.
- **Compliance linkage**: marked RFC 9700 rows (`9700-005` through `9700-010`) as `status: verified`
  in `spec/compliance-matrix.yaml` and recorded artefact paths for F* (`Bearer.Policy`), Tamarin
  (`bearer_bcp.spthy`), and Rust tests.
- **Resource metrics monitoring**: the `/resource` handler calls
  `MetricsIntegration::record_resource_access` to record per-mode outcomes (DPoP/mTLS/Bearer) under
  `oauth_resource_requests_total` and `oauth_request_latency_seconds{endpoint="/resource"}`
  (`crates/server/src/endpoints/resource.rs:60`, `crates/server/src/metrics_integration.rs:135`).
  CI runs the consolidated suite (`nix run .#security-suite`) and collects failure responses plus a
  metrics snapshot under `artifacts/security/latest/resource/` (including
  `artifacts/security/latest/resource/resource-metrics.prom`).
- **Sender / refresh failure metrics**: added `oauth_sender_binding_failures_total{reason}` and
  `oauth_refresh_policy_violations_total{reason}` to `OAuthMetrics`, emitted via `MetricsIntegration`
  from `TokenValidator::enforce_policies` and refresh-chain enforcement
  (`crates/server/src/observability/src/metrics.rs`, `crates/server/src/authcode/token.rs`). Covered
  by `cargo test -p aegaeon-server metrics_integration_test` and the security suite, with counters
  verifiable from `artifacts/security/latest/resource/resource-metrics.prom`.

### Bearer Hardening — Monitoring & Test Playbook

| Scenario | Check | How to Reproduce | Evidence |
|----------|-------|------------------|----------|
| **Sender mismatch (DPoP)** | Counter `oauth_resource_requests_total{mode="dpop",status="sender_binding_mismatch"}` increments | `cargo test -p aegaeon-server --test resource_integration_test -- --nocapture`, or `curl -H "Authorization: DPoP <token>" -H "DPoP: invalid-proof" http://127.0.0.1:19180/resource` (CI runs this via the security suite) | `crates/server/tests/resource_integration_test.rs`, `artifacts/security/latest/resource/dpop_failure.response`, `artifacts/security/latest/resource/resource-metrics.prom` |
| **Sender missing (mTLS)** | Counter `oauth_resource_requests_total{mode="mtls",status="sender_binding_missing"}` increments; response body contains `"sender_binding_missing"` | Call `/resource` with only `Authorization: Bearer <token>` and omit `x-forwarded-client-cert` (CI runs this via the security suite) | `crates/server/src/endpoints/resource.rs`, `artifacts/security/latest/resource/bearer_failure.response`, `artifacts/security/latest/resource/resource-metrics.prom` |
| **Refresh chain violation** | With `retain_refresh_chain` enabled, `TokenValidator::validate_with_policy` returns `"refresh_parent_revoked"` and `oauth_refresh_policy_violations_total{reason="refresh_parent_revoked"}` increments | Run unit test `crates/server/tests/bearer_policy_test.rs::retain_refresh_chain_blocks_revoked_parent` | `crates/server/tests/bearer_policy_test.rs`, `artifacts/security/latest/summary/security.log`, `artifacts/security/latest/resource/resource-metrics.prom` |
| **Happy path (DPoP)** | `/resource` returns 200; response includes `\"status\":\"granted\"` and `iss` | Run `resource_integration_test::resource_allows_dpop_sender` | `crates/server/tests/resource_integration_test.rs`, `artifacts/security/latest/summary/security.log` |
| **Happy path (mTLS)** | `TokenValidator::validate_with_policy` accepts the mTLS fingerprint match | Run `resource_integration_test::resource_allows_mtls_sender` (same file) | `crates/server/tests/resource_integration_test.rs`, `artifacts/security/latest/summary/security.log` |

#### CI / monitoring procedure
1. After `nix run .#security-suite`, GitHub Actions (`.github/workflows/security.yml`) uploads
   `artifacts/security/latest/**`. The suite collects the `/resource` failure responses and the
   metrics snapshot under `artifacts/security/latest/resource/` and records step outputs under
   `artifacts/security/latest/summary/security.log`.
2. Download CI artefacts and inspect `artifacts/security/latest/resource/resource-metrics.prom`. Verify
   the `mode`, `status`, and `reason` labels match expectations. If anything looks off, rerun the
   `/resource` scenarios and compare logs.
3. On-call should follow the same procedure: check `resource-metrics.prom` labels (`mode`, `status`,
   `reason`) first, then corroborate with the suite logs.
4. To reproduce locally or in staging, run the server with the normal PostgreSQL and Redis-backed
   runtime prerequisites, authenticate to the management API, scrape `/api/v1/operations/metrics`,
   and reuse the curl commands above.

### Sprint 7 — Load & Observability Baseline

| Endpoint | Key Metrics | Threshold / Action | Instrumentation / Evidence |
|----------|-------------|--------------------|----------------------------|
| `/token` | `oauth_token_issuance_total{result=*}` (success/failure counts), `oauth_request_latency_seconds{endpoint="/token"}`, `oauth_refresh_rotation_conflicts_total` | Investigate if failure rate > 1% or p95 latency > 500ms. If refresh-conflict counters keep increasing, corroborate with logs (typically `bearer_policy_test`). | Collected via MetricsIntegration. Record baseline via `nix run .#perf-load` (Sprint 7 LOAD-01) in `docs/performance/load-baseline-auth-code.md`. |
| `/authorize` | `oauth_auth_attempt_total{grant_type=*}`, `oauth_request_latency_seconds{endpoint="/authorize"}`, trace spans (`authorize_flow` / `pkce_validation`) | Alert if latency > 1s. If failure ratio spikes, compare `tracing` logs with baseline values under `docs/performance/`. | `tracing` instrumentation (`crates/server/src/endpoints/authorization.rs`) and perf tooling. Structured-log integration tests planned in Sprint 7 OBS-02. |
| `/resource` | `oauth_resource_requests_total{mode,status}`, `oauth_request_latency_seconds{endpoint="/resource"}` | Alert if per-mode error rate > 0.5%. If sender-binding mismatches occur continuously, inspect evidence under `artifacts/security/latest/resource/*.response`. | CI (`.github/workflows/security.yml`) uploads responses and metrics on every run. See `docs/operations/monitoring/README.md`. |

#### Dashboards & Runbooks
- Grafana: dashboards for `/token` / `/authorize` / `/resource` (Dashboard IDs: `oauth-tokens`,
  `oauth-auth`, `oauth-resource`). Configure alert thresholds to match the table above.
- Loki/Tracing: aggregate `tracing-subscriber` JSON exports into the `observability/oauth-traces`
  stream. After OBS-02, add an integration test for log-structure checks under
  `crates/server/tests/logging_integration_test.rs`.
- Manual check: rerun `nix run .#perf-load` to refresh the baseline and append results to
  `docs/performance/load-baseline-auth-code.md` (document the steps in the runbook).

## Timing Attack Analysis

### dudect Results (PASS threshold \|t\| < 4.5)
```bash
Testing: PKCE verification
Samples: 10,000,000
t-value: 0.023
Result: PASS - Constant time

Testing: Token comparison
Samples: 10,000,000
t-value: 0.156
Result: PASS - Constant time

Testing: DPoP signature
Samples: 10,000,000
t-value: 0.892
Result: PASS - Constant time
```
*Acceptance Criteria*: dudect jobs are wired into CI; any run breaching the threshold fails the pipeline and triggers investigation. JOSE Stack module (Phase 3.2.4-5) complete; constant-time guarantees maintained through existing coverage.

## Supply Chain Security

### SBOM Analysis
- **Scan Timestamp**: 2025-11-15T09:21:35Z (CycloneDX v1.5, cargo-cyclonedx 0.5.7)
- **Total Dependencies**: 97
- **Direct Dependencies**: 22
- **Transitive Dependencies**: 75
- **Risk Assessment** (Grype/Trivy, `RUN_TRIVY=1 GRYPE_FAIL_ON=medium`):
  - Critical: 0
  - High: 0
  - Medium: 0
  - Low: 3 (accepted / sandboxed)
  - Notes: Trivy DB update emitted warning (offline fallback in use); no actionable findings.
- **Artefacts**:
  - SBOM JSON: `artifacts/sbom/aegaeon-sbom-20251115_092134.json`
  - Rust SBOM: `artifacts/sbom/rust-sbom-20251115_092134.json`
  - Summary: `artifacts/sbom/sbom-metadata.json`, `artifacts/sbom/sbom-report-20251115_092134.txt`
  - Vulnerability scans: `nix run .#security-sbom -- RUN_TRIVY=1 GRYPE_FAIL_ON=medium`

### Dependency Pinning
- ✅ Cargo.lock committed
- ✅ Nix flake.lock committed
- ✅ Docker base image pinned
- ✅ GitHub Actions versions pinned

### Build Provenance
- ✅ SLSA Level 3 attestation
- ✅ Sigstore signatures
- ✅ Reproducible builds via Nix
- ✅ Build logs retained 90 days

## Penetration Testing Results

### Scope
- Authorization flows
- Token endpoints
- PKCE implementation
- DPoP validation
- Session management

### Findings
1. **[MEDIUM]** Verbose error messages leak internal state
   - **Impact**: Information disclosure
   - **Mitigation**: Error messages sanitized in production mode
   - **Status**: Fixed

2. **[MEDIUM]** Rate limiting can be bypassed with X-Forwarded-For
   - **Impact**: DoS potential
   - **Mitigation**: Trusted proxy configuration required
   - **Status**: Documented

3. **[LOW]** Timing variation in failed auth (non-exploitable)
   - **Impact**: Theoretical info leak
   - **Status**: Accepted (< 1ms variation)

### Phase 7 Security Findings (2026-02-14)

1. **[S-FED-1] [MEDIUM]** Federation entity list endpoint missing rate limiting
   - **Impact**: Enumeration / DoS on federation list endpoint
   - **Mitigation**: Public Federation OP publication routes, including list/fetch/resolve, are not part of the supported verified server router. Structural helpers remain test-only until OP publication is reactivated.
   - **Status**: Fixed by route removal / deferred OP publication boundary

1. **[S-FED-3] [MEDIUM]** Federation signing used HS256 (symmetric) instead of ES256
   - **Impact**: Shared secret exposure risk; symmetric key distribution for federation is inappropriate
   - **Mitigation**: HS256 is no longer a production Federation OP signing posture. Public Federation OP signing remains disabled in the verified server runtime until an ES256 promotion exists.
   - **Status**: Fixed for production runtime / OP publication deferred

1. **[S-JI-1] [MEDIUM]** JWT introspection endpoint missing configurable auth requirement
   - **Impact**: Introspection responses could be accessed without proper client authentication
   - **Mitigation**: Added configurable authentication requirement for introspection endpoint
   - **Status**: Fixed (Phase 7)

### Phase 8 Threat Model Findings (2026-02-14)

1. **[P8-SSRF-1] [MEDIUM]** Federation fetcher missing private IP blocking
   - **Impact**: SSRF via federation entity fetch could reach internal services (RFC 1918/loopback/link-local)
   - **Mitigation**: Federation and upstream metadata fetches use HTTPS-only clients, explicit endpoint validation, non-routable DNS rejection, redirect validation, and bounded response bodies. Client JWKS refresh uses the same SSRF guardrails except for build-gated loopback test fixtures.
   - **Status**: Fixed in current implementation

1. **[P8-SSRF-2] [LOW]** Federation client trust chain follows redirects without allowlist
   - **Impact**: Open redirect in trust chain fetching could bypass SSRF protections via DNS rebinding or redirect chains
   - **Mitigation**: Redirects are limited and each redirect target is revalidated for HTTPS, userinfo absence, optional domain allowlist membership, and non-routable DNS/IP rejection.
   - **Status**: Fixed in current implementation

1. **[P8-TA-1] [LOW]** Trust anchor rotation lacks Tamarin security model
   - **Impact**: No formal verification of trust anchor rotation protocol security properties
   - **Mitigation**: Add Tamarin model proving anchor rotation preserves chain integrity
   - **Status**: In progress

1. **[P8-CACHE-1] [INFO]** Federation entity cache TTL not bounded by upstream metadata expiry
    - **Impact**: Stale federation metadata could persist beyond upstream-intended lifetime
    - **Mitigation**: Respect `expires` from upstream entity statements when populating cache TTL
    - **Status**: Observation (low risk)

1. **[P8-LOGOUT-1] [LOW]** Back-channel logout token replay window matches session TTL
    - **Impact**: Logout tokens could theoretically be replayed within the session TTL window
    - **Mitigation**: Already mitigated by jti-based replay detection; document the design choice
    - **Status**: Accepted (existing mitigation sufficient)

1. **[P8-RSA-1] [INFO]** RSA signature verification uses assume val in F* spec
    - **Impact**: RSA PSS and EdDSA verification are axiomatised (`Jose.Rsa_signatures.fst`) rather than fully proved
    - **Mitigation**: Runtime uses aws-lc-rs/ring with established correctness; assume vals are intentional FFI boundaries
    - **Status**: Observation (accepted design — crypto primitives axiomatised as standard practice)
