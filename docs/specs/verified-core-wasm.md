# Verified Core WASM Extraction

Last updated: 2026-09-07

Status: current implementation baseline

Owner: Product / Engineering

Audience: implementers, reviewers

## Current raw ABI trust boundary

As of 2026-09-07, `SIGNATURE_PREVERIFIED` is a raw ABI assertion by an admitted
trusted runtime adapter. It is not a verification capability available to an
untrusted public SDK caller. Before setting it, the adapter must have verified
the exact signed bytes, signature, key, algorithm and policy for that operation;
the subsequently checked claims must come from the same signed bytes. Mutable
objects, handles, asynchronous execution and restored state must preserve that
binding or cause rejection.

The current F* runtime selects `CRYPTO_VALID` when the bit is set instead of
calling `try_verify_signature`; it does not authenticate the assertion's origin.
The C shim preserves raw ABI flags. Thus the trust boundary described here is
an obligation on the adapter and its callers, not an enforced property supplied
by the flag or a newly proved precondition of the runtime.

Under [SDK C-06/C-15](../verification/claims/sdk-assurance/assurance-contract.md),
public SDK options must reject or remove reserved authority bits; verified-result
provenance and any admitted raw ABI use must be isolated and proved across the
declared host/caller boundary. This is an internal trust restriction, not a claim
that WASM exports are inaccessible. A low-level component contract must identify
its trusted-caller preconditions rather than advertise unconditional authentication.

Reference SDK adapter isolation and high-level authenticated-session admission
remain unfulfilled obligations. Completing them requires implementation changes,
source/output correspondence and negative tests on packed/installed outputs.
The comments clarified with this section change no executable behavior and do
not attest the historical WASM outputs or a released SDK. The snapshot below
records earlier extraction work under its stated scope and date.

> **Status (2026-03-10)**
> Running `scripts/extraction/package_verified_core.sh` generates `verified_core.wasm`, which exports the **claims-input variants** (`VerifiedCore_dpop_verify_claims_v1`, `VerifiedCore_jwt_verify_claims_v1`) alongside `VerifiedCore_dpop_verify_v1` / `VerifiedCore_jwt_verify_v1`. The claims exports are no longer uniformly stubs: they return meaningful status values for **EdDSA** in the verified WASM path, and `jwt_verify_claims_v1` also handles optional expected `iss` / `aud` constraints. `ES256` / `RS256` remain unsupported for **signature verification inside WASM**, but the `SIGNATURE_PREVERIFIED` flags now allow Node/Web reference adapters to preverify signatures with host crypto and delegate subsequent claims / time / replay enforcement to the Verified Core claims exports. `tests/verified_core_wasm/test_instantiate.mjs` verifies both acceptance of preverified `RS256` and rejection without preverification, while `runtime_{node,web}_reference_test.mjs` provides adapter-side `RS256` / `ES256` coverage.
> As of 2026-03-09, `aud` membership checks have been brought into `c/verified-core/verified_core_exports.c`, and `Dpop.Htm_validation` no longer requires `FStar_String_uppercase`. Adding a minimal runtime shim and a build without HMAC dependencies further reduced the default fixture's import table from 67 → 64 → 7. The remaining host/runtime imports are limited to the replay store, `vc_host_register_bytes` / `vc_host_release_handle`, compact parsers, and handle resolution. `scripts/sdk/runtime_node_reference.mjs` is the reference Node adapter that consumes this 7-import boundary directly, and `tests/verified_core_wasm/runtime_node_reference_test.mjs` provides Node smoke coverage for both compact and claims paths.
> `WASI_CLANG` / `WASI_SYSROOT` now support automatic detection; if detection fails, override them through environment variables as before.
> Low* Warning 15 (GC types / integers) remains an extraction concern, but `Prims_*` / `__multi3` / allocator shims are no longer host imports in the default fixture.
> `scripts/sdk/package_verified_core_dist.js` and `scripts/sdk/sign_core_artifact.js` can now generate a packaged distribution containing an Ed25519 signature for dev/test use, a CycloneDX SBOM, hash helper files, and TypeScript bindings. `tests/verified_core_wasm/package_dist_test.mjs` passes sign → package → fetch verification. `scripts/sdk/runtime_web_reference.mjs` and `tests/verified_core_wasm/runtime_web_reference_test.mjs` verify the browser-facing runtime adapter surface on Node/WebCrypto, while `tests/verified_core_wasm/runtime_web_reference.html` / `runtime_web_reference_server.mjs` provide a secure-context browser smoke harness. Remaining work includes production key custody, CI attestations, finalizing operations for public releases, and dedicated browser CI.
> **Positioning note (2026-03-09)**
> This plan supports the future client / SDK distribution track. It does **not** by itself create a claimable "formally verified client" product statement. Use `../product-positioning.md` for current outward-facing wording and `../verification/claims/assurance-case/claim-definition.md` for the formal boundary.

## 1. Purpose

Provide a reproducible pipeline that extracts the Verified Core (F*/Low*/KaRaMeL) into a `wasm32-wasi`
artifact, signs it, and exposes a minimal C ABI for higher-level adapters. The **same extracted C**
is also built as a **native library** for the server; the WASM artifact is for **client distribution**.
Verified Core artefacts stay in this repository; the Runtime Adapter / Domain SDK layers are managed in a separate repository
(`aegaeon-sdk`).
This work supports the TypeScript/Rust SDK publication track captured in
`docs/program-management/roadmaps/active/management-platform-follow-on-plan.md`.

## 2. Scope

- **Input modules (initial set)**
  - Phase 1 (prototype): PKCE core (`Pkce`, `Pkce.Challenge`, `Pkce.Verifier`, `Pkce.Method_selection`, `Pkce.Verification`) and DPoP core (`Dpop.*`).
  - AuthCode/Token store modules are temporarily excluded because KaRaMeL conversion raises `Failure("nth")`. The cause is a known bug in KaRaMeL's `Simplify.remove_unused_parameters`, which also recurs in a minimal reproduction (`AuthCode.Flow` + `AuthCode.Store` + `AuthCode.Types`). Track the fix and reintroduce the modules once a workaround is established.
  - Reconnect shared utilities (`ConstTime` / `EverCrypt.*`, etc.) when incorporating the corresponding modules.
- **Outputs**
  - `artifacts/verified-core/verified_core.wasm` (wasm32-wasi, stripped).
  - `artifacts/verified-core/verified_core.wasm.sha256` / `.sri` / `manifest.json` (hash & metadata).
  - **Native server library** (built from the same extracted C and linked via `crates/ffi`).
- `artifacts/verified-core/verified_core.wasm.sig` (Ed25519 signature; future work).
- `artifacts/verified-core/sbom.json` (CycloneDX; future work).
- `include/verified_core.h` (generated C ABI header; future work).
- `../program-management/initiatives/sdk/client-sdk-architecture.md` updated with build + trust notes and repository split.
- `crates/aegaeon-core` (Rust helper crate) embeds the artefact to provide integrity checks; `aegaeon-sdk/packages/verified-core` supplies the matching pnpm test harness.
- **Out of scope (Sprint A)**
  - TypeScript/Rust runtime adapters (handled in Sprint B).
  - Browser packaging, bundler integration, CDN decisions.
  - FIPS 140 evaluation (recorded as future work in
    `../program-management/initiatives/sdk/client-sdk-architecture.md` §8.1).

## 3. Build Pipeline (proposed)

1. **F-star verification**
   - `nix develop .#verification --command make -C fstar verify-core` (new target).
   - Uses cached `.checked` files (`fstar/.cache`) for deterministic runs.
2. **KaRaMeL extraction**
   - `nix develop .#verification --command scripts/extraction/run_verified_core_lowstar.sh` (new script).
   - Outputs C sources under `generated/lowstar/verified-core/`.
3. **WASM compilation / staging**
   - `scripts/extraction/package_verified_core.sh` (running inside `nix develop .#verification` is recommended).
     - Updated to automatically detect `wasm32-unknown-wasi-clang` and `*-wasi-sysroot` in `/nix/store` even when `WASI_CLANG` / `WASI_SYSROOT` are unspecified.
     - Set the environment variables explicitly if automatic detection fails.
   - Internally calls `run_verified_core_lowstar.sh` with `WITH_WASM_BUILD=1` and copies `verified_core.wasm` and hash artefacts into `artifacts/verified-core/`.
   - Compilation uses the `wasm32-unknown-wasi` clang wrapper, KaRaMeL headers (`lib/krml/{c,dist}`), and stubs for missing `assert.h` (`c/wasi-stubs/`).
   - Exported functions follow naming convention `vc_*`.
4. **Signing & SBOM**
   - Signing key managed via `./keys/verified-core-dev.key` (dev) and Secrets Manager in CI.
   - `cosign sign-blob verified_core.wasm --key ... > verified_core.wasm.sig`.
   - `nix run .#security-sbom -- verified_core.wasm`.
5. **Smoke tests**
   - `tests/verified_core_wasm/` with `wasmtime` harness verifying PKCE round-trip, DPoP proof validation, JWT signature check using known vectors.

## 4. C ABI (initial sketch)

```c
typedef struct {
    const uint8_t *ptr;
    size_t len;
} vc_slice;

typedef struct {
    uint32_t code;      // 0 = success, non-zero = error
    vc_slice output;    // caller-owned buffer on success
} vc_result;

// PKCE
vc_result vc_pkce_challenge_generate(vc_slice verifier);
vc_result vc_pkce_verify(vc_slice verifier, vc_slice challenge);

// DPoP
vc_result vc_dpop_verify(vc_slice jwt, vc_slice jwk, uint64_t now_seconds);

// JWT/JWS
vc_result vc_jwt_verify(vc_slice jwt, vc_slice jwks_json, vc_slice expected_claims_json);

void vc_free_slice(vc_slice slice);
```

> Note: exact signatures will depend on KaRaMeL extraction; the above guides the shim implementation.

## 5. Definition of Done (Sprint A)

1. `scripts/extraction/package_verified_core.sh` succeeds (CI + local `nix develop`).
2. `cargo test -p aegaeon-core` and `pnpm test --filter @aegaeon/verified-core` pass, invoking the WASM artifact through host shims (future work).
3. Artefacts (`verified_core.wasm`, `*.sha256`, `*.sri`, `manifest.json`) are stored under `artifacts/verified-core/` with regeneration instructions.
4. Documentation updated:
   - `docs/program-management/initiatives/sdk/client-sdk-architecture.md` (build + trust model).
   - `docs/program-management/roadmaps/active/management-platform-follow-on-plan.md` (publication and
     hosted-evidence status).
   - This file reflects final module list and command reference.
5. No new fail-open paths; secrets (signing keys) are managed outside git (CI secrets/SSM).

## 6. Open Questions

- Exact list of modules to include in initial WASM (state/nonce helpers may live in `fstar/auth` or `fstar/authcode`; survey in progress).
- Whether to expose streaming APIs (for large payloads) or keep slice-based API.
- Integration with existing EverCrypt C stubs—some routines may already exist as native C; duplication must be avoided.

### 6.1 Candidate module inventory (WIP)

| Capability | Primary modules | Notes |
|------------|-----------------|-------|
| PKCE | `fstar/pkce/Pkce.fst`, `Pkce.Challenge.fst`, `Pkce.Verifier.fst`, `Pkce.Method_selection.fst` | Requires `ConstTime`, `Result`. |
| DPoP | `fstar/dpop/Dpop.fst`, `Dpop.Validation.fst`, `Dpop.Signature.fst`, `Dpop.Replay.fst`, `Dpop.Claims.fst` | Depends on JOSE signature helpers + replay store lemmas. |
| JWT/JWS | `fstar/jose/Jose.Jwt_validation.fst`, `Jose.Jws_signature.fst`, `Jose.Jwk_structure.fst`, `Jose.Alg_policy.fst` | Relies on EverCrypt HMAC/Ed25519 wrappers and TLV parsers. |
| Nonce/State | _(Deferred)_ `fstar/authcode/AuthCode.Store.fst`, `AuthCode.Types.fst` | Currently excluded because of KaRaMeL `Failure("nth")`. Reassess once a workaround is established. |
| Utilities | `fstar/ConstTime.fst`, `fstar/result/Result.fst`, `fstar/EverCrypt.HMAC.fst`, `fstar/EverCrypt.Chacha20Poly1305.fst` | Provide constant-time primitives and crypto facades. |

> Action: confirm `authcode` module structure and extend the table before extraction scripting.

## 7. Next Steps

1. Review Low* warnings: enumerate the functions causing Warning 15 (GC types / integers) and decide whether to resolve them by adding `compat.h` or refactoring store implementations, or adopt a `noextract`/`bundle` approach.
2. Reintegrate Token/PkJWT: retry KaRaMeL extraction after turning `empty_store` into a function and check whether `Failure("nth")` is resolved. Follow upstream fixes as needed.
3. ABI + Shim: implement `c/verified_core.c` and `include/verified_core.h` and define the `vc_*` entry points.
4. Smoke tests: implement `cargo test -p aegaeon-core` (wasmtime) and `pnpm test --filter @aegaeon/verified-core` (Node/Web).
5. Signatures/SBOM: generate `verified_core.wasm.sig` with `cosign` and CycloneDX with `nix run .#security-sbom`, and integrate them into CI.
6. Artefact delivery: establish GitHub Release/S3 distribution and versioning so the SDK repository can fetch artefacts through `pnpm run fetch-core`.

---

_This document will be updated as Sprint A progresses._
