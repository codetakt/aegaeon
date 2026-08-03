# Verified Core Claims Runtime — Implementation Plan

Last updated: 2026-07-07

Status: future plan

Owner: Engineering

Audience: implementation contributors, maintainers

> **Status note (2026-07-07):** The backend Phase 1 claims-runtime baseline is implemented.
> This document now tracks deferred SDK/runtime follow-up work only. The
> current verified signature path remains narrower (`EdDSA` in the WASM verified path;
> `HS*` via the verified bridge at Rust level). `RS256` remains a compat/runtime
> surface unless a separate OIDC slice-closure step promotes it. As of 2026-03-09,
> `VerifiedCore_jwt_verify_claims_v1` performs optional expected `iss` / `aud`
> checks, `ath` binding is handled in the C exports layer, and the default fixture
> import table is down to 7 imports (replay store, handle registration/release,
> compact parsing, and handle resolution).

## 1. Objective

Record the completed DPoP/JWT claims-based verification path in the Verified Core
WASM artefact and track the remaining SDK/runtime follow-up work. The implemented
exports, `VerifiedCore_dpop_verify_claims_v1` and
`VerifiedCore_jwt_verify_claims_v1`, operate on host-supplied, fully normalised
inputs without reintroducing Base64/JSON parsing inside the core.

## 2. Scope & Non-Goals

- **In scope**
  - New F\*/Low★ module (`VerifiedCore.Api.Claims.Runtime`) that bridges claims inputs to
    existing DPoP/JWT validation logic.
    - DPoP: method/URL equality, iat window, signature verification, replay prevention.
    - JWT: signature verification (ES256/RS256), optional exp/nbf/iat checks.
  - Additive ABI updates (`DpopClaimsInputV1`, `JwtClaimsInputV1`, claim exports).
  - KaRaMeL extraction/compilation flow restricted to the new runtime module.
  - C exports forwarding (`verified_core_exports.c/h`).
  - Minimal host integration smoke tests (Node runtime + Redis stub/fake).
- **Out of scope** (tracked elsewhere)
  - Compact-input verification (`*_verify_v1`) rework.
  - Base64/JSON parsing inside Verified Core.
  - Web runtime parity, management SDK wiring (handled in separate sprint items).

## 3. Preconditions

- ABI JSON updated with the additive claims structs/exports
  (see `scripts/sdk/generate_verified_core_abi.js`).
- Runtime adapters should support `vc_host_register_bytes` /
  `vc_host_release_handle`, `Host_handle_data_ptr/len`, and ReplayStore imports.
- Redis-backed replay store contract agreed (`SET key 1 NX PX ttl`).

## 4. Work Breakdown (To‑Do)

### 4.1 F\*/Low★ layer

- [ ] Create module skeleton `VerifiedCore.Api.Claims.Runtime.fst` under `fstar/verifiedcore/api/`.
  - [ ] Define record projections to read `DpopClaimsInputV1`/`JwtClaimsInputV1`
    (bytes handle wrappers).
  - [ ] Implement helper predicates: `bytes_len_eq`, `bytes_len_le`, `read32`, etc.
  - [ ] DPoP path: validate HTM/HTU equality, iat window, jti presence/length,
    signature verify, replay call.
  - [ ] JWT path: signature verify, optional exp/nbf/iat flags, issuer/audience
    compare (if enabled).
  - [ ] Map host results to `VerifiedCoreStatusCode`.
- [ ] Provide Low★/Stack binding declarations for host callbacks:
  - `HostCrypto_verify_signature`
  - `ReplayStore_check_and_store`
  - `FStar_Bytes_len`, `FStar_Bytes_read`
- [ ] Ensure no Base64/JSON modules are referenced (add `noextract` where needed).

### 4.2 KaRaMeL extraction

- [ ] Update extraction script (likely `scripts/extraction/package_verified_core.sh`):
  - Restrict module list to include `VerifiedCore.Api.Claims.Runtime` and existing dependencies.
  - Exclude unrelated generated C files from the claims artefact bundle.
- [ ] Regenerate `generated/lowstar/verified-core/` artefacts.
  - [ ] Validate `verified_core.exports.c` now links against the new runtime function symbols.
  - [ ] Confirm no unresolved references to Base64/JSON helpers remain.

### 4.3 C bridge & build system

- [x] Implement `VerifiedCore_dpop_verify_claims_v1` / `VerifiedCore_jwt_verify_claims_v1` in
      `c/verified-core/verified_core_exports.c`.
  - [x] Zero/initialise outputs, call runtime functions, translate status codes.
- [x] Update build scripts (CMake/Make/Nix) so the current minimal claims-capable
  WASM artefact is produced.
  - [x] ABI JSON regenerated via `scripts/sdk/generate_verified_core_abi.js`.

### 4.4 Runtime adapter integration & tests

- [x] Add a backend-repo Node reference adapter
  (`scripts/sdk/runtime_node_reference.mjs`) that consumes the current claims/full
  exports and the 7-import host boundary.
- [x] Add a backend-repo browser-facing reference adapter
  (`scripts/sdk/runtime_web_reference.mjs`) with SecureContext enforcement and
  WebCrypto artefact verification.
- [x] Create focused adapter tests in this repository:
  - [x] Node smoke tests (`tests/verified_core_wasm/runtime_node_reference_test.mjs`)
    for happy-path DPoP/JWT plus replay / mismatch failures.
  - [x] Browser-facing adapter tests on Node WebCrypto
    (`tests/verified_core_wasm/runtime_web_reference_test.mjs`).
  - [x] Static browser smoke harness
    (`tests/verified_core_wasm/runtime_web_reference.html`) served by
    `runtime_web_reference_server.mjs`.
- [ ] Port the same runtime surface into publishable
  `aegaeon-sdk/packages/runtime-node` / `runtime-web` tests.
- [ ] Add ES256 + RS256 compatibility-path coverage once those algorithms are
  intentionally promoted or wrapped outside the current verified WASM path.
- [ ] Document invocation examples in `../../../aegaeon-sdk/README.md` (claims path).

### 4.5 Documentation updates

- [x] Update `docs/specs/verified-core-abi.md` with claims struct/export description.
- [x] Add section to `docs/design/verified-core-api-plan.md` describing Phase 1
  claims execution model.
- [x] Reference this plan from `docs/specs/verified-core-wasm.md` (implementation roadmap).

## 5. Acceptance Criteria

- Verified Core WASM exports `VerifiedCore_dpop_verify_claims_v1` and
  `VerifiedCore_jwt_verify_claims_v1` that return meaningful status codes.
- Node and browser-facing adapter tests pass locally (including replay store
  scenarios and secure-context loader checks on the browser-facing path).
- ABI JSON and docs updated and committed.
- No unresolved references to Base64/JSON helper symbols in generated artefacts.

## 6. Follow-up / Deferred items

- Compact verification path (`*_verify_v1`) rework.
- Dedicated browser CI / Playwright automation for the runtime-web harness.
- Expanded JWT claim validation (iss/aud semantics, audience arrays) if required.
- Rust runtime adapters consuming the claims path.
