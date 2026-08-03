# OIDC Execution Plan

Last updated: 2026-07-07

Status: historical record

Owner: Program Management

Audience: maintainers, planning contributors

This document captures the OpenID Connect implementation roadmap described in
historical planning notes, reorganised so AI agents can collaborate without ambiguity. It
complements `docs/program-management/historical/roadmaps/oauth2-execution-plan.md`.

Status note: this is a **historical sprint record** (OIDC-1…OIDC-5). OSS publication and external
conformance gating are tracked as future workstreams; see
`docs/program-management/roadmaps/active/current-execution-plan.md` and
`docs/program-management/roadmaps/future/future-projects.md`.

Program posture update (2026-03-08): the general verification claim remains
modern-crypto-first, broad RSA support stays in the compat boundary by default,
and OIDC now tracks two narrow follow-on slices: `RS256 Required Slice`
(mandatory ID Token signing / verification for the OIDC Core claim) and
`RS256 Interop Slice` (signed Request Objects / `request_uri` and related
interop surfaces). This does not retroactively change the historical sprint
Definition of Done; it records the next assurance gap to close.

## 0. Common Principles

- Default flow: Authorization Code + PKCE. Implicit/Hybrid flows remain disabled
  unless explicitly re-enabled via policy switches documented in `AGENTS.md`.
- Dual assurance on every feature:
  - Computational safety: F*/Low* → KaRaMeL → C (with EverCrypt/HACL* and
    EverParse), dudect for constant-time validation, Kani for FFI safety.
  - Symbolic safety: Tamarin proofs for session integrity, mix-up resistance,
    replay protection.
- Definition of Done (applies to every sprint):
  1. F\* verification (`--verify_all`) succeeds; Low\* constraints hold; KaRaMeL
     extraction succeeds.
  2. Tamarin lemmas for the sprint scope are discharged.
  3. dudect passes (no leakage on hot paths); Kani harnesses verify FFI/runtime
     expectations.
  4. Relevant interoperability tests are green (unit/integration + RP harnesses).
     OIDF Conformance Suite runs and OSS release readiness are tracked as a
     future workstream (see `docs/program-management/roadmaps/future/future-projects.md`).
  5. Artifacts recorded under `artifacts/`; compliance matrix entries updated.
  6. Public API/metadata documentation refreshed.

## 1. Sprint Overview

| Sprint | Theme | Key Outputs |
|--------|-------|-------------|
| OIDC-1 | Core foundations | ID Token issuance/validation, `userinfo`, nonce safety |
| OIDC-2 | Discovery, JWKS, OIDC DCR | Self-describing metadata, JWKS rotation, OIDC-specific DCR policies |
| OIDC-3 | Logout (RP-initiated & Back-channel) | Reliable session termination across RPs |
| OIDC-4 | Form Post response mode | Secure form delivery with CSP and injection protections |
| OIDC-5 | JAR (Request Object) | Request parameter integrity when combined with PAR |

## 2. Detailed Sprint Playbooks

### Sprint OIDC-1 — OpenID Connect Core 1.0

- **Objective**: Deliver ID Token and `userinfo` endpoints with formal guarantees.
- **Tracks**:
  1. *F* Models*: capture ID Token claims (`iss`, `aud`, `sub`, `exp`, `iat`,
     `nbf`, `auth_time`, `nonce`, `azp`, `acr`, `amr`) with type-level contracts.
  2. *Hash Proofs*: specify `at_hash`/`c_hash` computations per JWA, including
     bit-truncation rules.
  3. *max_age Enforcement*: model `auth_time` requirements and clock handling.
  4. *EverParse*: define unambiguous schemas for ID Token payload and `userinfo`
     responses.
  5. *JOSE Integration*: leverage F* + EverCrypt for JWS (optionally JWE) with
     allow-listed algorithms; reject `none` explicitly.
  6. *Tamarin*: prove OIDC session integrity and nonce-based replay prevention.
  7. *Rust*: expose `/authorize` (code + PKCE), `/token`, `/userinfo` via FFI.
  8. *Testing*: run RP samples (Node/Go/Java) end-to-end with code + PKCE.
- **Exit Criteria**: Nonce uniqueness enforced; `at_hash`/`c_hash` vectors pass;
  Tamarin sessions proofs green; Kani harnesses accept nonce store semantics.
- **Current Status (2025-12-01)**:
  - ✅ Runtime feature flags (`AEG_OIDC_*`) guard ID Token issuance, discovery,
    and `/userinfo`; warp integration tests cover enabled/disabled behaviours.
  - ✅ `crates/server/tests/oidc_e2e_test.rs::test_token_issuer_id_token_validates_end_to_end`
    validates nonce + `at_hash`/`c_hash` end-to-end from the RP's perspective.
  - ✅ `nix run .#oidc-rp-flow` runs `crates/server/tests/oidc_rp_flow_test.rs`,
    which launches the server binary and drives `/authorize → /token → /userinfo`
    with PKCE + nonce + DPoP sender-binding to provide RP evidence for Track 8.
  - ✅ `crates/server/tests/userinfo_route_test.rs` exercises discovery + `/userinfo`
    filters (401/404/200) and compliance matrix entry `OIDC-2-001` now marked verified.
  - ✅ OIDC-1 formal verification scope/DoD is recorded in
    `docs/verification/oidc/oidc-1-formal-verification-dod.md` and tracked via
    `spec/compliance-matrix.yaml` (`OIDC-1-002`…`OIDC-1-008`).
  - ✅ F* semantics (claims invariants, hash semantics, max_age/auth_time) are
    verified by `nix build .#verify-fstar` and recorded in the compliance matrix.
  - ✅ EverParse `IdTokenSchema.3d` artefacts are checked in under
    `generated/everparse/IdTokenSchema*` and fail-close on missing artefacts via
    `crates/ffi/build.rs`.
  - ✅ Tamarin proofs for nonce integrity and issuer mix-up resistance are
    included under `proofs/tamarin/oidc/` and verified by `nix build .#verify-tamarin`.
  - ✅ OIDC-1 Kani coverage for the JWT canonicaliser is verified and tracked as
    `OIDC-1-007`.
  - 📝 Follow-on assurance gap (post-sprint): close the `RS256 Required Slice`
    so the mandatory OIDC Core ID Token `RS256` path moves from compat runtime
    support into the formal verification boundary without promoting generic RSA
    as a whole.
  - ⏳ Additional non-Rust RP samples (Track 8) remain on the backlog for OSS
    launch; Rust harness coverage is in place today.

### Sprint OIDC-2 — Discovery, JWKS, OIDC DCR

- **Objective**: Provide self-describing metadata and automated onboarding.
- **Tracks**:
  1. *Discovery*: extend OAuth 8414 metadata with OIDC-specific parameters;
     verify completeness via F* contracts.
  2. *JWKS*: manage kid assignment, rotation, duplication avoidance; verify via
     EverParse schema.
  3. *OIDC DCR*: specify policies for `redirect_uris` exact match, allowed
     `response_types`, `grant_types`, `id_token_signed_response_alg`, etc.
  4. *Rust Implementation*: publish metadata and DCR endpoints; publish OIDC
     signing JWKS with safe rotation overlap and strict `kid` uniqueness.
  5. *Testing*: schema validation and property tests covering rejection paths.
- **Exit Criteria**: Discovery JSON and JWKS pass schema checks; DCR rejection
  cases exhaustively tested; compliance matrix updated.
- **Deferred**: KMS/HSM integration for OIDC signing keys is tracked as an
  operational hardening item in `docs/program-management/roadmaps/future/future-projects.md`.
- **Current Status (2025-12-22)**:
  - ✅ OIDC discovery advertises `registration_endpoint` and uses the configured issuer as the base for public endpoints (`crates/server/src/main.rs`, `crates/server/src/oidc/discovery.rs`).
  - ✅ OAuth 8414 metadata uses the OIDC issuer when OIDC is enabled (integration test: `crates/server/tests/as_metadata_oidc_issuer_test.rs`).
  - ✅ OIDC signing JWKS supports rotation overlap via `AEGAEON_OIDC_JWKS_ADDITIONAL(_FILE)` and rejects duplicate `kid` values (unit tests: `crates/server/src/oidc/config.rs`).
  - ✅ DCR enforces `id_token_signed_response_alg=RS256` when provided (unit tests: `crates/server/src/endpoints/registration.rs`, enforcement in `crates/server/src/dcr.rs`).
  - ✅ Compliance matrix entries `OIDC-2-001`…`OIDC-2-003` are marked verified and validated via `python3 scripts/validation/validate_compliance_matrix.py --check`.

### Sprint OIDC-3 — Logout (RP-initiated & Back-channel)

- **Objective**: Deliver robust logout across relying parties.
- **Tracks**:
  1. *RP-initiated*: implement `end_session_endpoint`; F* proofs for
     `id_token_hint` issuer/audience/expiry validation; whitelist redirect URIs.
  2. *Back-channel*: model logout token claims (`iss`, `sub`/`sid`, `aud`, `iat`,
     `events`) via F* and EverParse; design state machine guaranteeing idempotent
     retries.
  3. *Tamarin*: prove session integrity after logout (dead sessions cannot
     authorize).
  4. *Rust*: implement OP↔RP session store keyed by `sid`; Kani harnesses for
     TTL, uniqueness, idempotency.
- **Exit Criteria**: Back-channel retry semantics proven safe; session integrity
  lemmas green; end-to-end logout tests pass.
- **Current Status (2025-12-22)**:
  - ✅ RP-initiated logout route `/logout` is implemented and fail-closes when disabled (gated by `AEGAEON_OIDC_ENABLED=1` + `AEGAEON_OIDC_ENABLE_LOGOUT=1`).
  - ✅ `id_token_hint` validation and `post_logout_redirect_uri` exact-match whitelisting are covered by `crates/server/tests/oidc_rp_logout_test.rs`.
  - ✅ Back-channel logout fan-out and retry idempotency (`jti` reuse) are covered by `crates/server/tests/oidc_backchannel_logout_test.rs`.
  - ✅ F* model `fstar/oidc/Logout.fst` is verified by `nix build .#verify-fstar`.
  - ✅ Tamarin lemmas for logout session termination and retry stability live in `proofs/tamarin/oidc/logout_session_termination.spthy` and are verified by `nix build .#verify-tamarin`.
  - ✅ Kani harness coverage for the OIDC session store (TTL/uniqueness/idempotency) is implemented in `crates/server/src/kani_test.rs` and verified by `nix build .#verify-kani`.

### Sprint OIDC-4 — OAuth 2.0 Form Post Response Mode

- **Objective**: Ensure `response_mode=form_post` is secure and interoperable.
- **Tracks**:
  1. *F* Contracts*: define template invariants (field completeness, no extra
     fields, escaping rules, CSP requirements).
  2. *Template Control*: restrict Rust-side templates to vetted generators with
     enforced HTML escaping and CSP.
  3. *Tamarin*: cover parameter integrity with PAR/JAR combinations.
  4. *Testing*: interoperability with major RP libraries; boundary testing for
     payload size and encoding.
- **Exit Criteria**: Static analysis and property tests confirm injection
  resistance; integration tests green.
- **Current Status (2025-12-23)**:
  - ✅ `/authorize` supports `response_mode=form_post` for both success and error responses (HTML POST with hidden inputs) via `crates/server/src/form_post.rs`.
  - ✅ HTML template is injection-safe (attribute escaping + field allowlist/uniqueness checks) and emits a strict nonce CSP (integration: `crates/server/tests/oidc_form_post_test.rs`).
  - ✅ Discovery metadata advertises `form_post` under `response_modes_supported` when OIDC discovery is enabled (`crates/server/src/oidc/discovery.rs`).
  - ✅ F* invariants for the encoder and CSP are implemented in `fstar/oidc/FormPost.fst` and verified by `nix build .#verify-fstar` (tests: `tests/fstar/property/TestFormPostEncoder.fst`, `tests/fstar/unit/TestFormPostCsp.fst`).

### Sprint OIDC-5 — JAR (Request Object)

- **Objective**: Harden authorization requests using signed/ encrypted JWTs.
- **Tracks**:
  1. *F* Validators*: ensure Request Objects bind `aud`, `exp`/`nbf`,
     `client_id`, `response_type`, `scope`, `redirect_uri`; enforce
     safe precedence rules vs query parameters.
  2. *PAR Binding*: prove unique linkage between `request_uri` and stored PAR
     entries (single-use, TTL) via state machine.
  3. *EverParse*: generate schemas for Request Object payload.
  4. *Tamarin*: prove mix-up resistance and parameter fixation under JAR.
  5. *Rust*: implement Request Object intake, policy to prefer JAR + PAR flows.
- **Exit Criteria**: Tamarin proofs show no tampering path; conflicting
  parameters resolved safely; tests for signed/encrypted variants pass.
- **Current Status (2025-12-23)**:
  - ✅ `/par` validates signed Request Objects (RFC 9101) and applies strict precedence (Request Object claims win for bound fields) before issuing a `request_uri`.
  - ✅ Encrypted Request Objects are supported when configured: `/par` accepts compact JWE (`alg=RSA-OAEP`, `enc=A256GCM`) and decrypts to a nested signed JWT before applying RFC 9101 validation (`crates/server/src/request_object.rs`, `crates/server/src/main.rs`).
  - ✅ Discovery + JWKS: `/.well-known/openid-configuration` advertises `request_object_signing_alg_values_supported` and, when an encryption key is configured, advertises `request_object_encryption_*` and publishes a `use=enc` key in JWKS (`crates/server/src/main.rs`, `crates/server/src/oidc/discovery.rs`).
  - ✅ EverParse schema for Request Object payload is generated via `fstar/lowparse/RequestObjectSchema.3d` and checked in under `generated/everparse/RequestObjectSchema*` (fail-close build via `crates/ffi/build.rs`).
  - ✅ Tamarin fixation proof for PAR+JAR is implemented in `proofs/tamarin/par/jar_par_fixation.spthy` and verified by `nix build .#verify-tamarin`.
  - ✅ End-to-end coverage includes both signed and encrypted Request Objects (`crates/server/tests/jar_par_binding_test.rs`).
  - 📝 Follow-on assurance gap (post-sprint): close the `RS256 Interop Slice`
    for signed Request Objects / `request_uri` validation while keeping the
    remainder of broad RSA interoperability in compat unless separately
    promoted.

### Deferred Program — FAPI & JARM Enablement

- **Status**: Starts only after OIDC Sprints OIDC-1…OIDC-5 reach Definition of
  Done and the operational platform workstream is scheduled.
- **Intended Scope**:
  1. Implement FAPI Baseline/Advanced and JARM profiles, reusing the verified
     OAuth/OIDC primitives.
  2. Extend proofs and conformance suites to cover financial-grade requirements
     (PAR-only, signed responses, MTLS/DPoP policies).
  3. Produce interoperability artefacts for the applicable FAPI/JARM self-cert
     programs.
- **Tracking**: Captured in `docs/program-management/roadmaps/future/future-projects.md` and
  scheduled once the core OIDC stack is in beta.

## 3. Risk Management

- *`at_hash`/`c_hash` Variability*: maintain test vectors per JWA and specify
  truncation rules in F*.
- *Logout Delivery Reliability*: idempotent, retry-friendly state machine with
  monitoring metrics.
- *JAR Parameter Conflicts*: documented precedence (Request Object wins), proven
  tamper resistance via Tamarin.
- *Discovery/DCR Bloat*: EverParse schemas reject unknown fields unless opt-in.

## 4. Governance

- Keep this plan synchronized with the compliance matrix, security policies, and OIDC-specific ADRs.
- Use sprint identifiers (e.g., `OIDC3-Track2`) when coordinating agent tasks to
  avoid collisions.
