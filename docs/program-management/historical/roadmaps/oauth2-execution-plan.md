# OAuth 2.x Execution Plan

Last updated: 2026-07-07

Status: historical record

Owner: Program Management

Audience: maintainers, planning contributors

This document is a **historical sprint record** derived from planning notes and reformatted for AI
agent collaboration. It captures how the project delivered a formally verified, security-first OAuth
2.x core that serves as the foundation for OpenID Connect.

For the current (post-sprint) execution plan, see `docs/program-management/roadmaps/active/current-execution-plan.md`.
For a consolidated historical delivery + DoD summary, see `docs/program-management/historical/oauth-oidc-delivery.md`.

## 0. Program Goals
There are two goals for OAuth 2.x.

1. **Complete coverage of the OAuth 2.x compliance profile**
   1. The open-census asset is `spec/compliance-matrix.yaml`.
   2. This matrix covers RFC 6749, 6750, 7009, 7662, 7636, 7515, 7517, 7518, 7519,
      7591, 8414, 9126, 9449, 9700.
   3. The OAuth 2.1 delta requirements (draft) are deferred to a follow-on project.
2. **Create a reusable verified platform for OIDC work**
   1. Every OAuth feature must expose its verification details, metrics, and defensive posture.
   2. This makes it possible to extend into OIDC without reworking core features.

All contributors must read the canonical policy document `AGENTS.md` before working on tasks.

## 1. Reference Artefacts
Use these assets when working on planned items.

- `AGENTS.md`: canonical repository policies and remediation priorities.
- `docs/program-management/README.md`: high-level program context.
- `spec/compliance-matrix.yaml`: mapping from RFC requirements to proofs/tests.
- `scripts/validation/validate_compliance_matrix.py`: compliance validation tool.
- Verification runbooks and status index: `docs/verification/README.md`.

## 2. Sprint Roadmap
Each sprint spans roughly two weeks. Execution is staged so that early sprints build comfortable scaffolding for later work.

| Sprint | Theme | Key RFCs | Primary Workstreams |
|--------|-------|----------|----------------------|
| 0 | Foundation & CI bring-up | RFC 6749, 6750 (baseline) | Compliance matrix, CI scaffolding, toolchain pinning, policy defaults |
| 1 | JOSE core & FFI safety | RFC 7515–7519 | F*/Tamarin proofs for JOSE, Low*/KaRaMeL extraction, Rust FFI, dudect |
| 2 | PKCE & DPoP guarantees | RFC 7636, 9449, 9700 | F* refinement proofs, EverParse, Tamarin lemmas, Rust middleware |
| 3 | Pushed Authorization Requests | RFC 9126, 8414 | F* PAR state machine, Tamarin mix-up, metadata adjustments |
| 4 | Authorization Code & storage | RFC 6749, 6750, 9700 | F*/Tamarin invariants, Token storage, Kani harnesses |
| 5 | Revocation / Introspection / DCR | RFC 7009, 7662, 7591, 8414 | F* proofs, Tamarin extensions, DCR/EverParse, metadata coverage |
| 6 | Bearer hardening | RFC 6750, 9700 | F* scope/audience checks, Tamarin regressions, policy CI |
| 7 | Fuzzing/Observability | Cross-cutting | Fuzz targets, metrics instrumentation, load/SLO baseline |
| 8 | External conformance & Beta | External suites | Conformance integration, SBOM & security review, beta release |

## 3. Sprint Details
Each sprint lists prerequisites, tracks, deliverables, and exit gates. Subtasks can be assigned to agents using the IDs below.

### Sprint 0 — Foundation & CI Bring-up *(Status: Complete — compliance scaffolding in place)*
- **Prerequisites**: Repository layout per `AGENTS.md`; tool versions selected.
- **Tracks**:
  1. Build compliance matrix for all OAuth 2.x RFCs. Missing artefacts should have TODO placeholders.
  2. Bring up CI skeleton: jobs for `fstar`, KaRaMeL extraction, `cargo build`, `tamarin`, `kani`, `dudect`, storing artefacts under `artifacts/`.
  3. Pin toolchains (F*, KaRaMeL, EverParse, Tamarin, Kani, dudect) in `ci/README.md`.
  4. Enable policy defaults (disable implicit & ROPC, require PKCE, enable sender constraints).
- **Exit Criteria**:
  - Compliance matrix enumerates all OAuth requirements.
  - CI runs skeleton jobs and publishes artefacts.
  - Toolchain pins recorded in `ci/README.md`.
  - Policy gates implemented in `crates/server/src/bcp_policy.rs`.
- **Evidence**:
  - `spec/compliance-matrix.yaml`
  - GitHub workflows: `.github/workflows/ci.yml`, `verification.yml`, `security.yml`
  - `ci/README.md`
  - Policy defaults in `crates/server/src/bcp_policy.rs`

### Sprint 1 — JOSE Core & FFI Safety *(Status: Complete — all exit criteria satisfied)*
- **Prerequisites**: Sprint 0 jobs green; JOSE test vectors available.
- **Tracks**:
  1. F* specification for JOSE (JWS/JWE, DPoP proofing).
  2. Low*/KaRaMeL extraction to C.
  3. Rust FFI wrappers using safe abstractions.
  4. dudect runs on cryptographic hot paths.
  5. Kani harnesses ensure FFI boundary safety.
- **Exit Criteria**: ≥95% JOSE vector pass rate; dudect p-values < 0.01; Kani harnesses verified.
- **Evidence**:
  - F* modules: `fstar/jose/Jose.*`
  - Extraction outputs: `generated/lowstar/jose/*.c/h`
  - Rust FFI: `crates/ffi/src/lib.rs`
  - RFC 7520 vectors in `verification.yml` (job `jose-vectors`)
  - Kani harnesses: `crates/ffi/src/kani_tests.rs`

### Sprint 2 — PKCE & DPoP Guarantees *(Status: Complete — DPoP/JAR conformance vectors landed; additional E2E scenarios scheduled)*
- **Tracks**:
  1. F* refinements for PKCE and DPoP (linear `jti`, proof freshness).
  2. Rust middleware enforcement for DPoP proofs (signature, `htm`/`htu`, `iat`, `jti`).
  3. Tamarin lemmas `dpop_replay`, `pkce_security`.
  4. Property and integration tests covering replay protection and proof validation.
  5. Conformance tests for DPoP (vectors under `tests/vectors/dpop_vectors.yaml`).
- **Exit Criteria**: Tamarin proofs pass, F* verification green, property tests detect `jti` reuse; Rust middleware rejects malformed proofs.
- **Evidence**:
  - F* modules: `fstar/dpop/Dpop.*`, `fstar/pkce/Pkce.*`
  - Tamarin proofs: `proofs/tamarin/**/*.spthy` (sources), `artifacts/tamarin/manual/*.log` (evidence)
  - Rust middleware: `crates/server/src/middleware/dpop.rs`
  - Tests: `crates/server/tests/dpop_middleware_integration_test.rs`, `crates/server/tests/dpop_jti_replay_test.rs`, property tests in `tests/fstar/property/TestDpopJtiReuse.fst`
  - Conformance vectors: `tests/conformance/jose_vector_test.py`, `tests/vectors/dpop_vectors.yaml`

### Sprint 3 — Pushed Authorization Requests *(Status: Complete — PAR state machine verified and integrated)*
- **Tracks**:
  1. F* state machine for PAR (`fstar/par/Par.fst`, `fstar/par/Par_Internal.fst`, `fstar/par/Par_Ticket.fst`).
  2. Tamarin mix-up protection (`proofs/tamarin/par/par_security.spthy`).
  3. Metadata updates exposing PAR endpoints.
  4. Integration tests for PAR flows.
- **Exit Criteria**: Tamarin proofs pass; metadata endpoints advertise PAR (`/par`).
- **Evidence**:
  - F* modules: `fstar/par/Par*`
  - Tamarin proofs: `proofs/tamarin/**/*.spthy` (sources), `artifacts/tamarin/manual/*.log` (evidence)
  - Rust implementation: `crates/server/src/par.rs`
  - Tests: `crates/server/tests/par_http_lifecycle_test.rs`, `par_http_test.rs`
  - Metadata exposure: `crates/server/src/metadata.rs`

### Sprint 4 — Authorization Code & Storage *(Status: Complete — single-use storage verified end-to-end)*
- **Tracks**:
  1. F* invariants for authorization code lifecycle, state/nonce uniqueness.
  2. Tamarin lemmas for code replay and session integrity.
  3. Token store implementation with refresh rotation.
  4. Kani harnesses (AuthCodeStore, TokenStore).
- **Exit Criteria**: Tamarin proofs green; tests detect code reuse and rotation issues.
- **Evidence**:
  - F* modules: `fstar/authcode/AuthCode.*`
  - Tamarin proofs: `proofs/tamarin/**/*.spthy` (sources), `artifacts/tamarin/manual/*.log` (evidence)
  - Token store: `crates/server/src/authcode/store.rs`
  - Tests: `crates/server/tests/refresh_rotation_test.rs`, `authcode_snapshot_test.rs`
  - Kani harnesses: `crates/server/tests/kani_authcode_verification.rs`

### Sprint 5 — Revocation / Introspection / DCR *(Status: Complete — evidence in `spec/compliance-matrix.yaml`)*
- **Tracks**:
  1. F* semantics for revocation/introspection with totality proofs.
  2. EverParse schema generation for DCR payloads.
  3. Rust runtime endpoints (`revocation.rs`, `introspection.rs`, `registration.rs`).
  4. Compliance matrix updates for RFC 7009/7662/7591/8414.
- **Evidence & notes**: Cross-cutting verification status is indexed in `docs/verification/README.md`.
  Sprint 5 artefacts remain referenced from `spec/compliance-matrix.yaml` and the verification logs under `artifacts/`.

### Sprint 6 — Bearer Hardening & BCP *(Status: Complete — scope/audience/sender/refresh hardening + observability)*
- **Prerequisites**: Sprint 5 artefacts merged; RFC 7009/7662/7591/8414 compliance rows verified per
  the 2025-11-15 validation log.
- **Tracks**:
  1. **F* hardening** — add scope/audience containment, refresh-token replay prevention, and
     sender-constrained binding (DPoP/mTLS) under `fstar/token/` (or existing modules). Introduce
     lemmas such as `lemma_bearer_scope_contains`, `lemma_refresh_revocation`, `lemma_sender_binding`.
  2. **Tamarin model** — create `proofs/tamarin/bearer/` and prove scope/audience deviations, no
     access after revocation, and sender mismatches. Store evidence logs under
     `artifacts/tamarin/manual/*.log`.
  3. **Rust runtime enforcement** — implement BCP checks under `crates/server/src/policy/` and
     `middleware/` (scope/audience guards, refresh revocation after rotation, DPoP/mTLS binding) and
     cover them with tests (e.g. `bearer_scope_test.rs`, `token_after_revocation_test.rs`,
     `dpop_mtls_binding_test.rs`).
  4. **Observability & security suite** — add new rejection metrics to `aegaeon-observability` and
     run bearer tests via `nix run .#security-suite`. Ensure artifact collection and
     `AEG_SECURITY_OFFLINE` controls are in place.
  5. **Documentation & compliance** — update
     `docs/security/security-review/runtime-hardening-and-testing.md` and add RFC 9700 /
     Bearer BCP rows to `spec/compliance-matrix.yaml` (linking F*/Tamarin/Rust/CI evidence).
  6. **CI integration** — ensure `security.yml` / `ci.yml` always run `nix run .#security-suite` and
     the bearer tests, uploading `artifacts/security/**` on failure.
- **Exit Criteria**:
  - Bearer-related F*/Tamarin lemmas complete; evidence logs refreshed under `artifacts/tamarin/manual/*.log`.
  - `crates/server/tests/bearer_*` automatically validate scope/audience enforcement, revocation, and sender mismatches.
  - Security suite collects the new metrics and tests and preserves them as CI artefacts.
  - RFC 9700 / Bearer BCP rows are `status: verified` in `spec/compliance-matrix.yaml`.
- **Current Status (2025-11-14)**:
  - F*: `fstar/token/Bearer.Policy.fst` constructively proves scope containment, audience binding,
    refresh history, sender binding, and policy-ok invariants. It passes cleanly with
    `fstar.exe --include fstar --include fstar/token fstar/token/Bearer.Policy.fst`.
  - Tamarin: `proofs/tamarin/bearer/bearer_bcp.spthy` is integrated via `proofs/tamarin/run_tamarin.sh`,
    with evidence saved to `artifacts/tamarin/manual/bearer_bearer_bcp.log`.
  - Rust runtime: `TokenValidator::validate_with_policy` evaluates `require_scope_subset` /
    `require_audience_match` / `enforce_sender_binding` / `retain_refresh_chain` consistently.
    `TokenStore::is_refresh_revoked` and `bearer_policy_test.rs` cover refresh-parent history protection.
  - Observability: `OAuthMetrics` includes sender-binding and refresh-policy failure counters emitted
    from `TokenValidator::enforce_policies`. `nix run .#security-suite` collects
    `metrics_integration_test` plus a `/resource` metrics snapshot, and CI uploads
    `artifacts/security/latest/resource/resource-metrics.prom`.
  - Docs: `docs/security/security-review.md` and `docs/automation/ci-cd-guide.md` document the
    monitoring and CI procedures.
  - Compliance: RFC 9700 scope/audience/sender-binding/refresh rows (`9700-005`…`9700-010`) are
    `status: verified` with linked F*/Tamarin/Rust artefacts plus security-suite evidence. Compliance
    validator log: `artifacts/compliance/validate.log`.

### Sprint 7 — Fuzzing, Load, Observability *(Status: Complete — see `docs/performance/load-baseline-auth-code.md`, `docs/operations/monitoring/README.md`, `docs/automation/ci-cd-guide.md`)*
- **Highlights**:
  - Stabilised longer fuzz runs via `scripts/security/run_security_suite.sh --fuzz-long`, and
    `scripts/manage_fuzz_corpus.py` automatically persists corpus and crash history.
  - Built a load-testing harness via `cargo run -p aegaeon-loadtest` and recorded baseline metrics
    in `docs/performance/load-baseline-auth-code.md`.
  - Improved structured tracing for `/authorize` and `/token`, plus CI summaries
    (`crates/server/tests/logging_integration_test.rs`, `security.yml` step summary).
- **Artefact Links**:
  - Fuzz: `artifacts/security/latest/fuzz/run_summary.json`, `fuzz/corpus_meta/latest_run.json`.
  - Load: `artifacts/perf/baseline-sprint7/`, `docs/performance/load-baseline-auth-code.md`.
  - Observability: `docs/security/security-review.md` (runtime hardening + monitoring section),
    `docs/operations/monitoring/README.md`.

### Sprint 8 — External Conformance & Release Readiness *(Status: Deferred — tracked in future backlog)*
- **Status note**: This sprint is the OSS publication workstream (external suites + release collateral).
  It is intentionally deferred; track priorities and sequencing in `docs/program-management/roadmaps/future/future-projects.md`.
- **Prerequisites**: All internal verification gates green; security telemetry stable.
- **Planning Doc**: `docs/program-management/roadmaps/future/external-conformance-and-beta-plan.md` (runbook/evidence layout)
- **Tracks**:
  1. Integrate external conformance suites (OAuth/JAR/DPoP, OIDF ready-set) and capture artefacts.
  2. Produce release collateral: SBOM + vulnerability scans (`scripts/security/run_sbom_scan.sh`), security review updates, CHANGELOG entries.
  3. Package beta artifacts (Nix flake, Docker image, documentation) for OSS consumers.
  4. Finalise compliance matrix with “verified” status and link to artefacts produced by suites.
- **Exit Criteria**:
  - At least one representative OIDF/OIDC conformance plan is executed end-to-end and archived under `artifacts/conformance/`
    (OIDCC Basic is treated as the baseline for OSS readiness; broader OAuth plan coverage is tracked as follow-up).
  - Release notes and runbooks updated; CHANGELOG records beta milestone.
  - Compliance matrix validated (`scripts/validation/validate_compliance_matrix.py`) with all Sprint 0-8 rows green.
- **Evidence Targets**:
  - Conformance logs: `artifacts/conformance/`.
  - Release docs: `docs/releases/`, `CHANGELOG.md`.
  - Compliance: `spec/compliance-matrix.yaml`, validation outputs.

## 4. Risk / Future Tracking
- **Kani known limitations**: start with `docs/verification/kani/README.md` (runbook) and
  `docs/verification/kani/troubleshooting.md` (HashMap state-space limitation). Historical ICE repro notes:
  `docs/verification/kani/hashmap-ice-repro.md`.
- **Future Program**: OAuth 2.1 & Operational hardening tracked in `docs/program-management/roadmaps/future/future-projects.md`.
