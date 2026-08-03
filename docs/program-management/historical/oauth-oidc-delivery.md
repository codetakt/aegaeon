# OAuth + OIDC Delivery Record (Historical)

Last updated: 2025-12-29

Status: historical record

Owner: Program Management

Audience: maintainers, planning contributors

This document is a historical record of delivered OAuth/OIDC functionality and the Definition of
Done (DoD) criteria used to accept work. It is intentionally high-level: the single source of truth
for requirement status is `spec/compliance-matrix.yaml`.

## 1) Definition of Done (DoD) used for past sprints

For OAuth Sprints 0–7 and OIDC Sprints OIDC-1…OIDC-5, work was considered “done” when:

1. **Standards posture remains fail-closed**
   - Implicit/ROPC flows are disabled by default.
   - PKCE (S256) and sender-constrained token policies remain standards-first and operator-gated.
2. **Compliance matrix is updated and validates**
   - All relevant rows are present in `spec/compliance-matrix.yaml` and are marked `verified` only
     when evidence exists.
   - `python3 scripts/validation/validate_compliance_matrix.py --check` succeeds.
3. **Verification gates are green (reproducible)**
   - Merge guard: `nix flake check --print-build-logs` is green.
   - Tool gates are reproducible locally: see `docs/verification/README.md`.
4. **Evidence is linkable**
   - Proofs/tests live in-tree (F*, Tamarin specs, Rust tests).
   - Machine-readable artefacts are written under `artifacts/` (gitignored by default) and indexed
     by runbooks under `docs/verification/` and `docs/releases/`.

Notes:
- Kani is treated as best-effort on HashMap-heavy state spaces; known limitations are documented in
  `docs/verification/kani/troubleshooting.md`.
- OIDF conformance gating and OSS release readiness are **deferred** and tracked under the future
  backlog (`docs/program-management/roadmaps/future/future-projects.md`).

## 2) OAuth delivery (Sprints 0–7)

Delivered core capabilities:
- Authorization Code + PKCE (S256), with strict policy defaults (no implicit/ROPC).
- PAR (RFC 9126), DPoP (RFC 9449), and sender-constrained token hardening per OAuth Security BCP.
- Dynamic Client Registration (RFC 7591) with operator-controlled policy gates.
- Revocation (RFC 7009) and Introspection (RFC 7662).
- RFC 8414 metadata and a verification-backed defensive posture (F*, Tamarin, Kani, dudect).
- Fuzzing + observability harnesses and a baseline load-testing harness.

Canonical tracking and evidence entrypoints:
- Requirement status: `spec/compliance-matrix.yaml`
- CI/verification runbooks: `docs/automation/ci-cd-guide.md`, `docs/verification/README.md`
- Proof and extraction roadmap (JOSE/TLV): `docs/program-management/roadmaps/active/proofs-roadmap.md`
- Performance baseline artefacts (operator-facing): `docs/performance/`

Sprint roadmaps (historical detail; not the authoritative compliance tracker):
- `docs/program-management/historical/roadmaps/oauth2-execution-plan.md`

## 3) OIDC delivery (OIDC-1…OIDC-5)

Delivered OIDC capabilities behind `AEGAEON_OIDC_ENABLED=1`:
- ID Token issuance and validation, including `nonce`, `at_hash`, `c_hash` invariants.
- Discovery (`/.well-known/openid-configuration`) and `/userinfo` routing behind feature flags.
- Logout (RP-initiated and back-channel) with session state handling.
- `response_mode=form_post` with injection-safe HTML generation and CSP constraints.
- JAR (Request Object) integrated with PAR, including strict precedence rules.

Canonical tracking and evidence entrypoints:
- Requirement status: `spec/compliance-matrix.yaml`
- OIDC verification notes: `docs/verification/oidc/oidc-1-formal-verification-dod.md`
- OIDC sprint details (historical): `docs/program-management/historical/roadmaps/oidc-execution-plan.md`

## 4) Deferred work (not part of the completed sprints)

The following are intentionally tracked as future workstreams (see
`docs/program-management/roadmaps/future/future-projects.md`):

- OSS publication & release readiness (Deferred OIDC-6 / OAuth Sprint 8):
  - Community/security policy files, quickstart + sample RPs, conformance baseline selection, CI posture.
- OAuth 2.1 compatibility and operational hardening (per-client policy profiles + auditability).
- Broader external conformance coverage and FAPI/JARM enablement.
