# JOSE / JWT Implementation Plan

Last updated: 2026-07-07

Status: active plan

Owner: Program Management

Audience: maintainers, planning contributors

**Last updated:** 2026-05-18

This roadmap tracks the JOSE workstream and the remaining steps required to
graduate more surfaces to extracted/verified components. It breaks the work into
manageable phases so each Sprint can graduate a concrete slice of functionality
to `status: verified` in `spec/compliance-matrix.yaml`.

## Guiding Goals

1. **Standards Coverage** – Implement the normative requirements from RFC 7515–7519
   (JWS/JWE/JWK/JWA/JWT) that appear in the compliance matrix for Sprint 1.
2. **Provable Behaviour** – Maintain the F*/Low*/KaRaMeL pipeline so each finished
   algorithm has complementary proofs or constant-time guarantees where required.
3. **Testability** – Provide Rust APIs that can be unit-tested directly, plus FFI
   shims suitable for Kani and integration tests.
4. **Incremental Delivery** – Ship in phases (JWS first, then JWT validation,
   followed by JWE/JWK extras) so that Sprint 1 exit criteria can be unblocked
   even if advanced features (e.g. JWE compact decrypt) land later.

## Program Posture Update (2026-03-08)

- The strong verification claim remains modern-crypto-first and follows the
  verified allowlist in `docs/verification/claims/crypto-allowlist.md`.
- Broad RSA / JOSE interoperability remains in the compat boundary unless a
  specific slice is promoted.
- OIDC introduces two explicit RS256 promotions: `RS256 Required Slice`
  (mandatory ID Token signing / verification for the OIDC Core claim) and
  `RS256 Interop Slice` (signed Request Objects / `request_uri`, plus
  `private_key_jwt` when supported for interoperability).
- This roadmap therefore treats `RS256` promotion as a narrow OIDC-driven slice
  closure, not as a commitment to verify generic RSA end to end.

## Current Baseline

- `crates/jose/src/jws.rs` verifies HS256/RS256/ES256/PS256 at runtime and routes protected-header policy enforcement through the extracted Low*/C JSON bridge first. The default compatibility build retains a local fallback on `JsonError::ParserUnavailable`; `--features verified-claim` disables that fallback and fails closed. RFC 7520 vectors cover positive/negative paths. Only algorithms on the verified allowlist participate in the current strong-constraint claim; `RS256` remains compat except for the promoted OIDC slices. Compliance rows 7515-002/7515-004 are `verified`.
- `crates/jose/src/jwe.rs` implements RSA-OAEP + A256GCM decryption with the same Low*/C-first protected-header path as JWS. The default compatibility build retains a local fallback on `JsonError::ParserUnavailable`; `--features verified-claim` disables that fallback and fails closed. The RFC 7520 suite exercises success and tamper scenarios (7516-001/7516-002 are `verified`).
- `crates/jose/src/jwt.rs` exposes the claim validation API with unit coverage for expiry, nbf, audience, etc. Compliance entries 7519-001…7519-004 are `verified`.
- `crates/jose/src/jwk.rs` and server-side DCR modules handle JWK ingestion and registration policies; the corresponding compliance rows (7517-001…7517-004, 7591-001…7591-004) are `verified`.
- `crates/ffi/src/lib.rs` continues to export deterministic HMAC/RSA/JWE helpers for Kani/dudect. JOSE header Low*/EverParse integration is now partially wired in Phase 7 via the extracted JSON bridge, the native EverParse entry-validator bridge, and the opt-in `ffi_jose_header_tlv` path; broader JOSE extraction work remains tracked under `lowstar/lowstar-extraction-plan.md`.
- The raw JSON structural-parser Phase 1 landing is complete for the scoped
  `jose-header` path: `verified-structural-v1` is opt-in for that surface only,
  remains non-claim-bearing, rejects unsupported surfaces fail-closed, and now
  passes `cargo test -p aegaeon-jose --lib`, `nix build .#server`, and
  `nix build .#verifyJose`. The next increment is the typed `jose-header`
  decoder / promotion step rather than more Phase 1 backend plumbing.

## Phase Plan

### Phase 0 — Foundations (Shared prerequisites)

- **API sketch**: define the key Rust traits/structs for JWS signing input,
  header parsing, JWT claim validation, JWK representation, and error handling.
- **Error taxonomy**: agree on `JoseError` variants so FFI and server layers can
  propagate actionable messages (e.g. `UnsupportedAlg`, `InvalidSignature`,
  `MissingClaim`).
- **Crypto crate choices**: document whether we lean on `ring`, `p256`,
  `rsa`, etc., and confirm license compatibility.
- **FFI boundary**: design the functions exported from `crates/ffi` so later F*
  extraction can hook into them (even if the first revision uses Rust-only
  implementations behind those signatures).

#### Phase 0 Status — ✅ Completed (2025-10-18)

| Track | Decisions / Artefacts |
|-------|------------------------|
| API sketch | `crates/jose/src/lib.rs` re-exports stable modules; `crates/jose/src/jws.rs` now exposes `VerificationKey`, `verify_compact`, and `JwsError`. Follow-on modules (`jwt`, `jwk`, `jwe`) are implemented; the remaining work is chiefly extraction/FFI hardening and keeping policy parity. |
| Error taxonomy | `JwsError` in `crates/jose/src/jws.rs` enumerates algorithm/format/verification failures. A repo-wide `JoseError` remains an optional follow-up to unify mapping across JWS/JWE/JWT surfaces. |
| Crypto crates | HMAC via `hmac` + `sha2`; RSA/ECDSA via `aws-lc-rs`; P-256 via `p256`. No extra `openssl` dependency required. Recorded in `crates/jose/Cargo.toml` and referenced here so auditors know the footprint. |
| FFI boundary | `scripts/run_kani.sh` / `crates/ffi/src/lib.rs` retain C ABI for HMAC/RSA/JWE helpers; Phase 0 notes capture which externs must be kept stable (`jws_hmac_verify`, `jws_rsa_verify`, `Jose_Jwe_chacha20poly1305_{encrypt,decrypt}`). Future Low*/EverParse extraction will slot into these signatures. |

Supporting notes live in `docs/program-management/initiatives/jose/phase0-foundations.md` (API diagram, crate choices, FFI contract summary). With the foundations locked, Phase 1 can focus purely on JWS behaviour and test coverage.

### Phase 1 — JWS (RFC 7515)

#### Scope

- Implement JWS header parsing (reject `alg=none` unless explicitly whitelisted).
- Support HS256, RS256, and ES256 signature verification at runtime.
- Keep the verified-vs-compat posture explicit in code, docs, and compliance evidence when algorithms are promoted.
- Produce canonical signing input and constant-time comparison wrappers.

#### Tasks

1. Implement `jws::Header` and `jws::verify` in `crates/jose`.
2. Extend `crates/ffi` with stable extern functions (e.g. `aeg_jws_verify`).
3. Replace the placeholder tests with RFC 7520 vector verification (positive & negative).
4. Update compliance matrix rows 7515-002, 7515-004, 7518-002 to `status: verified`.

#### Artefacts

- Unit tests: RFC 7520 fixtures in `crates/jose/tests/rfc7520_vectors.rs` cover HS/RS/ES/PS positive and negative cases.
- Integration tests: server end-to-end JWS flows remain TODO (defer to Phase 2 once FFI wiring is in place).
- Optional fuzz target: compact JWS parser.

#### Phase 1 Status — 🚧 In Progress (2026-05-16)

| Track | Notes |
|-------|-------|
| Header parsing | JWS and JWE protected headers both use `json_lowstar::parse_json_header_lowstar` first. The default build retains a local fallback on `ParserUnavailable`; `verified-claim` disables that fallback and fails closed. TLV parsing remains an internal parity / hardening path, with the native `everparse_jose_header_entry` validator and the opt-in `ffi_jose_header_tlv` route both available as separate evidence-bearing profiles. |
| Algorithm coverage | HS256/RS256/ES256/PS256 verification shipped; RFC 7520 vectors (positive/negative) execute in `crates/jose/tests/rfc7520_vectors.rs`. `RS256` is still a compat-path algorithm today except for the planned OIDC slice-closure work. |
| FFI surface | `jws_hmac_verify` / `jws_rsa_verify` wrappers remain stable; consolidated `aeg_jws_verify` entry point deferred to Phase 7 alongside extraction work. |
| Compliance | Compliance rows 7515-002 / 7515-004 are `verified`. CI now covers RFC 7520 vectors and TLV parity across the default, `everparse_jose_header_entry`, `ffi_jose_header_tlv`, `verified-claim`, and `ffi_jose_header_tlv,verified-claim` profiles; the security-suite `jose-boundaries` stage mirrors the TLV parity profile set for artifact collection. |

### Phase 2 — JWT Claim Validation (RFC 7519)

#### Scope

- Validate registered claims (`iss`, `sub`, `aud`, `exp`, `nbf`, `iat`, `jti`).
- Support audience matching rules (single string vs array of strings).
- Provide clock-skew configuration for `exp`/`nbf` evaluation.

#### Tasks

1. Add `jwt::Claims` validation API that accepts `ValidationContext` (contains leeway, expected audience, etc.).
2. Write unit tests covering valid/invalid expiry, audience mismatch, missing issuer.
3. Hook into server components that depend on JWT evaluation (e.g. DCR SSA, future OIDC tokens).
4. Update compliance rows 7519-001…7519-004 to `status: verified` once tests exist.

#### Artefacts

- Unit tests: `crates/jose/tests/jwt_validate.rs`.
- Property tests: QuickCheck-style harness for time-window checks (optional).

#### Phase 2 Status — ✅ Completed (2025-10-30)

| Track | Deliverables |
|-------|-------------|
| Validation API | `JwtClaims::validate` implements expiry/nbf/audience/issuer checks with configurable `ValidationContext`. |
| Test coverage | `crates/jose/tests/jwt_validate.rs` exercises success and error paths (expired, not-yet-valid, audience mismatch, malformed arrays, issued-at in future). |
| Compliance | Matrix rows 7519-001…7519-004 updated to `verified`; CI invokes `cargo test -p aegaeon-jose --test jwt_validate`. |

### Phase 3 — JWK Handling (RFC 7517)

#### Scope

- Parse JWK/JWKS (focus on RSA and EC keys used by Phases 1 & 2).
- Enforce `kty` presence and duplicate `kid` detection.
- Allow usage metadata (`use`, `key_ops`) to drive policy decisions.

#### Tasks

1. Implement `jwk::Key` enum and `jwks::Set` collection with validation helpers.
2. Ensure DCR endpoint can validate JWKS payloads according to BCP requirements.
3. Write tests (Rust + API-level) verifying `kty` existence, unique `kid`, metadata checks.

#### Artefacts

- Unit tests: `crates/jose/tests/jwk_parse.rs`.
- Integration tests: DCR registration tests hitting JWKS handling to satisfy 7591-003, 7517-003.

#### Phase 3 Status — ✅ Completed (2025-10-19)

| Track | Deliverables |
|-------|--------------|
| Parser & validation | `crates/jose/src/jwk.rs` parses RSA/EC JWKs, enforces `kty`, `use`, `kid`, and signature capability. |
| Tests | `crates/jose/tests/jwk_parse.rs` covers success/negative cases (missing `kty`, duplicate `kid`, `use=enc`). |
| DCR integration | Inline JWKS validation now uses the shared parser (`crates/server/src/endpoints/registration.rs`). |

### Phase 4 — DCR Policy Tests (RFC 7591)

Although DCR logic lives in `crates/server`, several Sprint 1 matrix rows stay `planned` until automated tests cover them.

#### Tasks

1. Factor `validate_registration` into a testable module (e.g. `crates/server/src/dcr` plus dedicated unit tests).
2. Write API tests verifying:
   - POST JSON acceptance and correct `client_id` issuance (7591-001, 7591-002).
   - Redirect URI validation respecting HTTPS/loopback rules (7591-003).
   - Unauthorized attempts return `401` (7591-004).
3. Ensure JOSE components from Phases 1–3 integrate (e.g., JWKS `kid` uniqueness feeding into DCR response validation).

#### Phase 4 Status — ✅ Completed (2025-10-19)

| Track | Deliverables |
|-------|--------------|
| Module factoring | DCR validation logic extracted to `crates/server/src/dcr.rs`, reused across endpoints. |
| API tests | `registration_returns_client_id` / `registration_rejects_invalid_metadata` in `crates/server/src/endpoints/registration.rs` cover JSON POST & error paths. |
| Behavioural tests | JWK handling + redirect URI checks live in `dcr::tests`, ensuring compliance for 7591-003. |
| Compliance | `spec/compliance-matrix.yaml` rows 7591-001..003 updated to `verified`. |

### Phase 5 — JWE Essentials (RFC 7516)

#### Scope

- Enforce `enc` header presence and AAD calculation semantics.
- Provide decrypt helper for supported algorithms (start with RSA-OAEP + A256GCM as per RFC 7520).

#### Tasks

1. Implement header parser that rejects missing `enc` (7516-001) and ensures AAD matches (7516-002).
2. Back the decrypt logic with `ring`/`aes-gcm` or FFI stubs, depending on crypto policy.
3. Extend RFC 7520 test harness to decrypt example payloads.

#### Phase 5 Status — ✅ Completed (2025-10-20)

| Track | Deliverables |
|-------|--------------|
| Decrypt helper | `crates/jose/src/jwe.rs` implements RSA-OAEP + A256GCM decryptor with strict header validation and zeroised CEK handling. |
| Positive coverage | `test_jwe_rsa_oaep_a256gcm_vector` in `crates/jose/tests/rfc7520_vectors.rs` exercises the RFC 7520 happy-path vector. |
| Negative coverage | Additional tests in `rfc7520_vectors.rs` reject missing/unsupported `enc`, unsupported `alg`, truncated tag, tampered tag, and mutated protected headers (AAD mismatch). |
| Compliance | `spec/compliance-matrix.yaml` rows 7516-001/7516-002 now reference these tests and are marked `verified`. |

### Phase 6 — Documentation & Proof Integration

- Update `docs/security/security-review/threat-vulnerability-and-formal-review.md` with new coverage.
- Wire constant-time guarantees via dudect (already enforced by CI) and record p-value thresholds when verifying JOSE primitives.
- Capture F\* proof duties (if applicable) so later sprints can move functionality from Rust to verified Low\*/C modules.

#### Phase 6 Status — ✅ Completed (2025-10-20)

| Track | Deliverables |
|-------|--------------|
| Security review updates | `docs/security/security-review/threat-vulnerability-and-formal-review.md` documents JOSE Phase 5 coverage, F* modules (`Jose.Jwe_header`, `Jose.Jwe_aad`), and dudect acceptance thresholds wired into CI. |
| Constant-time criteria | Timing analysis section now records the `t-statistic < 4.5` gate and investigation workflow; compliance matrix references `cargo test -p aegaeon-jose --test rfc7520_vectors`. |
| Verification follow-up | Remaining F*/Kani extraction work captured under **Next Steps** in the security review (JOSE FFI harness extension) for future sprints. |

### Phase 7 — Low*/C Extraction Foundations

See `docs/program-management/initiatives/jose/lowstar/lowstar-extraction-plan.md` for the
workstream breakdown.

#### Phase 7 Status — 🚧 In Progress (2026-05-16)

| Track | Recorded Update |
|-------|---------------|
| Toolchain pinning | ✅ Toolchain pins live in `flake.nix` and are indexed in `docs/verification/README.md`; ready for extraction pipeline work. |
| Repo layout | ✅ Created `generated/lowstar/jose/` scaffolding for Low\*/C artefacts. `include/` hosts the C headers consumed by the Rust FFI build. Existing `c/` tree will host the static lib build. |
| Verification shell | ✅ `nix develop` default shell already exposes F\*, KaRaMeL, Z3 through `verificationTools`; no additional wiring required. |
| Module prep | ✅ `Jose.LowStar` wrappers plus property lemmas landed; JWE/JWS modules expose `*_spec` bodies, include AAD length lemma, enforce a 4096-char limit, and prove successful parses respect the bound. Context infrastructure (`Jose.Context`, `Jose.Arith.Bounds`) completed with all F* verification conditions discharged. |
| Policy docs | ✅ `docs/policies/jose-header-policy.md` documents the enforcement policy; server runtime uses active database policy field `policy.joseHeaderMaxLen`. |
| Extraction pipeline | ✅ Low*/EverParse regeneration and KaRaMeL extraction are enforced in CI via `scripts/extraction/run_jose_lowstar.sh` (see `.github/workflows/ci.yml`); CI fails on uncommitted diffs. JSON header parsing flows through the Low*/C pipeline (`Jose_LowStar_Json.c`). |
| Raw JSON structural Phase 1 | ✅ **COMPLETE** (2026-05-18) — `verified-structural-v1` is wired as an opt-in backend for the `jose-header` `raw_json` surface only, keeps the released claim posture unchanged, and remains fail-closed for unsupported surfaces. The scoped landing passes `cargo test -p aegaeon-jose --lib`, `nix build .#server`, and `nix build .#verifyJose`; the next parser increment is Phase 2 typed decoding/promotion. |
| Phase 3.2.4 (Stack) | ✅ **COMPLETE** (2025-11-09) — bytes_block-based Stack module implementation (`Jose.LowStar.Json.Stack`) extracted and integrated. Eliminated intermediate allocations (~93% reduction). All 83 JOSE integration tests pass. Early header length validation added for DoS mitigation. |
| Phase 4 (Verification) | ✅ **COMPLETE** (2026-05-16) — Added 8 Kani FFI boundary harnesses, established performance baseline (criterion benchmarks: 782ns-2.85µs), confirmed existing dudect coverage sufficient, and expanded hosted JOSE evidence so `verify-jose`, `verification.yml`, and the security-suite `jose-boundaries` stage cover TLV parity / RFC 7520 across the default, `everparse_jose_header_entry`, `ffi_jose_header_tlv`, and strict `verified-claim` profile matrix. See `docs/verification/jose/phase4-verification-summary.md` and `docs/verification/claims/verification-maturity-status/README.md`. |

## Deliverables & Success Criteria

For each phase, mark the corresponding compliance matrix rows `verified` and
link the new test paths. Additionally:

- `crates/jose` exposes stable APIs consumed by server code and tests.
- `crates/ffi` offers deterministic behaviour for Kani/dudect harnesses.
- RFC 7520 test suite passes end-to-end signatures/decryption.
- DCR tests in `crates/server` pass with JOSE-backed validation.

## Open Questions / Follow-ups

- **FFI alignment**: converge on the final `aeg_jws_verify` surface and plan the Low*/EverParse substitution (see Phase 7).
- **Performance**: measure impact of JWT validation in hot paths and add benchmarks if needed.
- **Error ergonomics**: align with API consumers (server, DCR) on error codes/messages for client-facing endpoints.

---

This document is intentionally implementation-focused. Once each phase is complete,
update `spec/compliance-matrix.yaml`, the sprint status in
`docs/program-management/historical/roadmaps/oauth2-execution-plan.md`, and any relevant README sections.

## JOSE Roadmap Dependencies (Updated 2025-10-31)

1. ### Phase 7 (Low*/C extraction) prerequisites
   - Complete the F*/Rust prep work by following the remaining tasks in
     `docs/program-management/initiatives/jose/lowstar/lowstar-extraction-plan.md` and
     `docs/program-management/initiatives/jose/json-tlv/json-tlv-proof-plan.md` (Low* API design,
     extraction script updates, and FFI integration). Any future raw-byte parser promotion work is
     tracked separately from the current released `top-level-object-members` claim boundary.
   - Ensure Phase 1–6 outputs are up to date and CI is green (especially Phase 1 compliance 7515-*
     and Phase 2 compliance 7519-*).

2. ### Phase 5 completion gates Phase 6
   - Confirm the JWE decrypt implementation and tests (Phase 5) are `verified` in
     `spec/compliance-matrix.yaml`.
   - Phase 6 security-review updates assume JWE/JWS/JWK are all `verified`.

3. ### Phase 3 → 4 ordering
   - DCR tests (Phase 4) require the JWK parser work (Phase 3) to be complete.

4. ### Phase 1 → 2 ordering
   - JWT validation (Phase 2) assumes JWS signature verification (Phase 1) is complete.

5. ### JSON/TLV hybrid operation
   - Per the JWS/JWE specs, external input is JSON. TLV remains an internal verification/extraction
     helper format.
   - CI runs `rfc7520_vectors` / `tlv_parity` across the default,
     `everparse_jose_header_entry`, `ffi_jose_header_tlv`, `verified-claim`,
     and `ffi_jose_header_tlv,verified-claim` profiles; the security-suite
     `jose-boundaries` stage mirrors the TLV parity profile set to
     regression-detect drift in the JSON↔TLV policy contract.

6. ### Future work
   - Keep the claim-bearing JOSE boundary aligned with the released posture:
     `top-level-object-members`, not raw JSON bytes.
   - Optional enhancement track: replace the raw-byte `serde_json` front-end
     with a verified parser if the program later chooses to promote the boundary
     beyond `top-level-object-members`; until then, keep that front-end outside
     the stronger claim and document the boundary consistently (see
     `docs/program-management/initiatives/jose/json-tlv/json-tlv-proof-plan.md`).

This dependency list is appended to the end of this document and kept consistent with the other
plans (e.g. `json-tlv/json-tlv-proof-plan.md`).
