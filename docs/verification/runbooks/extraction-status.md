# KaRaMeL Extraction and Verified Core Status

Last updated: 2026-07-07

Status: current implementation baseline

Owner: Verification

Audience: verification contributors, maintainers

Assessment date: 2026-02-26

> **Status note (2026-03-08):** This is the canonical extraction / EverParse / Verified Core status page. Rerun the verification gates before using it for release evidence.

## 1. Overview

KaRaMeL extracts F\* modules to C code, which is then built into **two outputs from the same sources**:
1) **Native library** linked directly into the Rust server, and
2) **WASM Verified Core** (`verified_core.wasm`) for portable client distribution.

This module implements cryptographic claim verification (PKCE, DPoP, JWT) as a formally
verified core (modulo 1 remaining WASM host `assume val` contract — see [Assumption Register](../claims/assumptions/current-register.md)).

The project provides **two deployment paths** for verified code:
1. **Native C FFI** (server path, primary runtime): KaRaMeL-extracted C linked via `crates/ffi`
2. **WASM Verified Core** (client distribution): the same extracted C compiled to wasm32-wasi

Both artifacts are built from the same extracted C and are expected to be behaviorally
equivalent. Shared test vectors should be run against both outputs to detect drift.

## 2. Extraction Coverage Map

### 2.1 F\* Modules Extracted to WASM

The Nix derivation `nix/verified-core-wasm.nix` extracts 18 F\* modules:

| F\* Module | Extracted C File | WASM Export(s) | Status |
|---|---|---|---|
| `Pkce.Challenge.fst` | `Pkce_Challenge.h` | — (types only) | Extracted |
| `Pkce.fst` | `Pkce.c`/`.h` | `Pkce_verifier_ok`, `Pkce_verify_pkce`, `Pkce_verify_pkce_s256` | Extracted + Tested |
| `Pkce.Method_selection.fst` | `Pkce_Method_selection.c`/`.h` | method selection helpers | Extracted |
| `Pkce.Verification.fst` | `Pkce_Verification.c`/`.h` | SHA256/base64url stubs (host) | Extracted |
| `Pkce.Verifier.fst` | `Pkce_Verifier.h` | — (types only) | Extracted |
| `Dpop.Ath_validation.fst` | `Dpop_Ath_validation.c`/`.h` | `Dpop_Ath_validation_validate_ath` | Extracted + Tested |
| `Dpop.Claims.fst` | `Dpop_Claims.h` | — (types only) | Extracted |
| `Dpop.fst` | `Dpop.c`/`.h` | — (re-exports) | Extracted |
| `Dpop.Header.fst` | — | — (types only) | Extracted |
| `Dpop.Htm_validation.fst` | `Dpop_Htm_validation.c`/`.h` | `Dpop_Htm_validation_validate_htm` | Extracted + Tested |
| `Dpop.Htu_validation.fst` | `Dpop_Htu_validation.c`/`.h` | `Dpop_Htu_validation_validate_htu` | Extracted + Tested |
| `Dpop.Iat_validation.fst` | `Dpop_Iat_validation.c`/`.h` | `Dpop_Iat_validation_validate_iat` | Extracted + Tested |
| `Dpop.Replay.fst` | `Dpop_Replay.c`/`.h` | replay helpers (host) | Extracted |
| `Dpop.Signature.fst` | `Dpop_Signature.h` | — (host callback decl) | Extracted |
| `Dpop.Token_binding.fst` | — | — | Extracted |
| `Dpop.Validation.fst` | `Dpop_Validation.c`/`.h` | `Dpop_Validation_verify_dpop` | Extracted + Tested |
| `VerifiedCore.Api.Claims.Runtime.fst` | `VerifiedCore_Api_Claims_Runtime.c`/`.h` | `*_dpop_verify_claims_impl`, `*_jwt_verify_claims_impl`, `*_status_to_u32`, `*_iat_in_window`, `*_not_expired`, `*_is_active`, `*_try_verify_signature_multi` | Extracted + Tested |
| `ConstTime.fst` | `ConstTime.c`/`.h` | `ConstTime_ct_bytes_eq` | Extracted + Tested |

### 2.2 C ABI Shim Layer

In addition to KaRaMeL-extracted code, two hand-written C files provide the public ABI:

| File | Purpose |
|---|---|
| `c/verified_core.c` | Public `vc_*` ABI (PKCE generate/verify, DPoP verify, JWT verify, version/ABI introspection) |
| `c/verified-core/verified_core_exports.c` | Internal `VerifiedCore_*_v1` struct-based API wrapping extracted F\* claims verification |
| `include/verified_core.h` | Public header with `vc_slice`, `vc_result`, `vc_error_code`, host callback declarations |
| `c/verified-core/verified_core_exports.h` | Internal header with `DpopVerificationInputV1`, `JwtVerificationInputV1`, host callback types |

### 2.3 WASM Artifact

Location: `generated/lowstar/verified-core/wasm/verified_core.wasm`

**Exported functions** (tested in `tests/verified_core_wasm/`):
- `vc_pkce_challenge_generate`, `vc_pkce_challenge_verify`
- `vc_dpop_verify`, `vc_jwt_verify`
- `vc_free_slice`, `vc_version`, `vc_abi_version`
- `VerifiedCore_dpop_verify_v1`, `VerifiedCore_jwt_verify_v1`
- `VerifiedCore_dpop_verify_claims_v1`, `VerifiedCore_jwt_verify_claims_v1`
- `VerifiedCore_Api_Claims_Runtime_*` (8+ pure helper functions)
- `Pkce_verifier_ok`, `Pkce_verify_pkce`, `Pkce_verify_pkce_s256`
- `Dpop_Validation_verify_dpop`, `Dpop_*_validation_validate_*`
- `ConstTime_ct_bytes_eq`
- `memory` (WASM linear memory)

**Host imports required** (provided by WASM runtime adapter):
- `vc_host_register_bytes`, `vc_host_release_handle` (memory management)
- `VerifiedCore_Api_Claims_Runtime_host_*` (SHA-256, signature verify, replay store, bytes equality)
- `Host_parse_dpop_compact`, `Host_parse_jwt_compact` (JWS parsing)
- `Host_verify_ath_binding`, `Host_check_audience_membership` (claim validation)
- `Pkce_strlen`, `Pkce_s256`, `Pkce_Verification_*` (PKCE host callbacks)
- `Dpop_Ath_validation_sha256`, `Dpop_Signature_verify_signature` (DPoP host callbacks)
- FStar runtime stubs (`FStar_Bytes_get`, `FStar_UInt32_*`, `Prims_*`, `FStar_String_uppercase`)

## 3. FFI Boundary Diagram

```text
┌──────────────────────────────────────────────────────────────┐
│                    Rust Server (axum)                         │
│  crates/server/src/{authcode,dpop,dcr,federation,...}         │
└──────────┬────────────────────────────┬──────────────────────┘
           │                            │
           │ Boundary 1: Native C FFI   │ Boundary 2: WASM Module
           │ (linked into process)      │ (sandboxed runtime)
           ▼                            ▼
┌─────────────────────────┐  ┌─────────────────────────────────┐
│   crates/ffi/src/       │  │   verified_core.wasm            │
│                         │  │                                 │
│ ┌─────────────────────┐ │  │ ┌───────────────────────────┐   │
│ │ EverParse Validators│ │  │ │ KaRaMeL-extracted F*      │   │
│ │ • JoseHeader.c      │ │  │ │ • PKCE (5 modules)       │   │
│ │ • DCR.c             │ │  │ │ • DPoP (11 modules)      │   │
│ │ • Dpop.c            │ │  │ │ • VerifiedCore Claims    │   │
│ │ • IdTokenSchema.c   │ │  │ │ • ConstTime              │   │
│ │ • LogoutTokenSchema.c│ │  │ └───────────┬───────────────┘   │
│ │ • RequestObject     │ │  │             │                   │
│ │   Schema.c          │ │  │             │                   │
│ │ • DcrRegistration.c │ │  │ ┌───────────▼───────────────┐   │
│ └─────────────────────┘ │  │ │ C ABI Shim               │   │
│                         │  │ │ • verified_core.c         │   │
│ ┌─────────────────────┐ │  │ │ • verified_core_exports.c │   │
│ │ Crypto Shims        │ │  │ └───────────────────────────┘   │
│ │ • jws.c (HMAC/RSA)  │ │  │                                 │
│ │ • jwe.c (ChaCha20)  │ │  │ Host Callbacks ←──── Runtime    │
│ │ • rsa_signatures.c  │ │  │ (SHA-256, sig verify, replay)   │
│ └─────────────────────┘ │  └─────────────────────────────────┘
│                         │
│ ┌─────────────────────┐ │
│ │ Low* Extracted      │ │
│ │ • Jose_Dcr.c        │ │
│ │ • Jose_LowStar_    │ │
│ │   Json_Stack.c      │ │
│ └─────────────────────┘ │
└─────────────────────────┘
```

## 4. Known Blockers

### 4.1 KaRaMeL Warning 15 (Mathematical Integer Leakage)

Documented in `docs/verification/workplans/analysis/karamel-warning15-analysis.md`. Affects:

| Module | Issue | Impact |
|---|---|---|
| `Dpop.Validation.verify_dpop` | `int`-based time calculations | KaRaMeL emits FStar runtime calls for math ops |
| `Dpop.Htm_validation.validate_htm` | `FStar_String_uppercase` (GC type) | Requires host stub |
| `Dpop.Iat_validation.validate_iat` | `int`-based `now - iat` | Same as above |
| `Dpop.Claims.claims` | `iat : int` field | Struct uses math int |
| `Pkce.verifier_ok`, `Pkce.strlen` | `nat`/`int` length checks | Same as above |
| `ConstTime.ct_bytes_eq` | `FStar.Seq`-based comparison | Seq operations not Low\* |
| `Prims.*` operators | Chained from above | GC-managed integer arithmetic |

**Mitigation**: The WASM module works because host stubs provide FStar runtime functions (`FStar_UInt32_uint_to_t`, `Prims_op_Addition`, etc.) as WASM imports. This is functional but **not optimal** — the extracted code relies on host-provided math rather than native WASM i32/i64 instructions.

**Resolution path**: Refactor F\* modules to use `UInt32`/`UInt64` instead of `int`/`nat`, eliminating Warning 15 sources. Priority order: DPoP iat/time → PKCE lengths → ConstTime.

### 4.2 FStar.String Dependency

`Dpop.Htm_validation` uses `FStar.String.uppercase` which is a GC-managed type. The WASM module handles this via a host stub (`FStar_String_uppercase`) but this is a design smell. Should be replaced with case-insensitive comparison using fixed method names.

### 4.3 EverParse Schema F\* Verification (RESOLVED)

All 7 EverParse schemas are now verified in `verify_fstar.sh` Pass 2. The source
schemas are `JoseHeader`, `DCR`, `DcrRegistration`, `Dpop`, `IdTokenSchema`,
`LogoutTokenSchema`, and `RequestObjectSchema`. For F\* verification, `Dpop`
is checked as `DpopSchema` to avoid a module-name conflict with the hand-written
`dpop/Dpop.fst`; the original generated `Dpop` files remain the C build input.
Runtime invocation is narrower than verification coverage: `JoseHeader`, `DCR`,
`Dpop`, and `RequestObjectSchema` are wired into server paths, `IdTokenSchema`
is used for hash helper linkage only, and `DcrRegistration` /
`LogoutTokenSchema` are compiled but not called from Rust.

## 5. Extraction Coverage Gap Analysis

### 5.1 F\* Modules with Concrete Implementations NOT Extracted

| F\* Module | Concrete Proofs? | Could Extract? | Priority | Blocker |
|---|---|---|---|---|
| `authcode/AuthCode.Store.fst` | Yes (5/5 proved) | Possible | Medium | Seq-based API → needs Low\* buffer refactor |
| `authcode/AuthCode.Flow.fst` | Yes (4/5 proved) | Possible | Medium | Depends on Store; `generate_secure_random` is permanent assume |
| `token/Token.fst` | Yes | Low effort for types | Low | Mostly type definitions |
| `token/JwtAccessToken.fst` | Yes (5 lemmas) | Possible | Medium | Spec-level, needs Low\* impl |
| `token/Bearer.fst` / `Bearer.Policy.fst` | Yes | Possible | Low | Policy checks |
| `token/Bearer_validation.fst` | Yes | Possible | Low | Validation predicates |
| `par/Par.fst` (and sub-modules) | Yes | Possible | Medium | Large module family, Steel effect |
| `introspection/Introspection.fst` | Yes | Possible | Low | Spec-level |
| `introspection/JwtIntrospection.fst` | Yes | Possible | Low | Spec-level |
| `dcr/DcrManagement.fst` | Yes (5 lemmas) | Possible | Low | Spec-level |
| `dpop/Dpop.Nonce.fst` | Yes (4 lemmas) | Possible | Medium | Time-based store, needs Low\* |
| `federation/Jose.Federation.fst` | Yes (many lemmas) | Possible | Low | Complex; `as` pattern issue with F\* 2025.10 |
| `jose/Jose.Federation.Policy.*.fst` | Yes (16 proof sections) | Possible | Low | List-based algebra, not performance-critical |
| `resource/ResourceIndicators.fst` | Yes | Low effort | Low | Simple predicates |
| `resource/ProtectedResourceMetadata.fst` | Yes | Low effort | Low | Simple predicates |

### 5.2 Prioritized Extraction Candidates

**Tier 1 — High Value** (directly impacts token verification correctness):
1. **Token.fst + JwtAccessToken.fst**: JWT access token issuance and validation
2. **AuthCode.Store.fst + AuthCode.Flow.fst**: Authorization code lifecycle
3. **Dpop.Nonce.fst**: DPoP nonce freshness enforcement

**Tier 2 — Medium Value** (defense-in-depth):
4. **Bearer_validation.fst**: Bearer token format enforcement
5. **DcrManagement.fst**: Client registration lifecycle
6. **Par.fst family**: PAR request binding verification

**Tier 3 — Low Value** (spec-level, not performance-critical):
7. Federation policy algebra modules
8. Resource indicator predicates
9. Introspection/revocation spec modules

### 5.3 Practical Constraints

Most Tier 1/2 modules use:
- `FStar.Seq` (not Low\*-compatible without buffer refactoring)
- `FStar.List.Tot` (GC-managed, Warning 15)
- `int`/`nat` mathematical integers (Warning 15)
- Ghost/spec-level predicates that can't be extracted

Extraction would require a **Low\* porting effort** for each module: replacing `Seq` with `LowStar.Buffer`, `list` with arrays, and `int`/`nat` with `UInt32`/`UInt64`.

## 6. Direct C FFI (Boundary 1) — Current State

### 6.1 What's Linked

`crates/ffi/build.rs` compiles and links:

| Source Category | Files | Purpose |
|---|---|---|
| Crypto shims | `jws.c`, `jwe.c`, `rsa_signatures.c` | HMAC-SHA256, ChaCha20-Poly1305, RSA-PSS |
| EverParse validators (7) | `DCR.c`, `JoseHeader.c`, `Dpop.c`, `IdTokenSchema.c`, `LogoutTokenSchema.c`, `RequestObjectSchema.c`, `DcrRegistration.c` + wrappers | Binary format validation |
| Error handlers (5) | `dcr_error.c`, `dpop_error.c`, `jose_header_error.c`, `logout_token_error.c`, `request_object_error.c` | EverParse error callbacks |
| Low\* JSON | `json_lowstar_runtime.c`, `Jose_LowStar_Json_Stack.c` | Verified JSON parsing |
| Low\* DCR | `Jose_Dcr.c` | DCR policy checks (token/sender method) |
| KaRaMeL runtime | `fstar_uint32.c`, `fstar_bytes.c` | FStar integer/bytes runtime |

### 6.2 Rust Safe Wrappers

| Rust Module | C Symbol(s) Called | Safe Wrapper |
|---|---|---|
| `ffi::lib::verify_hmac` | `jws_hmac_verify` | `verify_hmac(alg, key, msg, sig) -> bool` |
| `ffi::lib::verify_rsa` | `jws_rsa_verify` | `verify_rsa(alg, key, msg, sig) -> bool` |
| `ffi::lib::verify_ed25519` | (pure Rust) | `verify_ed25519(alg, key, msg, sig) -> bool` |
| `ffi::lib::encrypt_chacha20poly1305` | `Jose_Jwe_chacha20poly1305_encrypt` | encrypt/decrypt wrappers |
| `ffi::lib::verify_dpop` | `DpopCheckDpopClaims` | `verify_dpop(proof, method, uri, now, ath) -> Option<String>` |
| `ffi::jose_header` | `JoseHeaderCheckJoseHeaderEntry` | `check_jose_header_entry(bytes) -> ParseResult` |
| `ffi::dcr_parser` | `DcrCheck*` (4 functions) | `check_registration_request/response/update_request/error_response` |
| `ffi::id_token` | `IdTokenSchemaCheck*` (3 functions) | `check_id_token_claims/userinfo_response/id_token_jwt` |
| `ffi::request_object_parser` | `RequestObjectSchemaCheckRequestObjectClaimsEntry` | `check_request_object_claims` |
| `ffi::lib::parse_json_entries` | `Jose_LowStar_Json_json_parse_entries_to_c` | `parse_json_entries_safe(members) -> Result<Vec<(String, String)>>` |

## 7. WASM Tests

### 7.1 Test Inventory

| Test File | Tests | Type | What's Tested |
|---|---|---|---|
| `tests/verified_core_wasm/smoke_test.sh` | 31 | Structural | Magic header, version, exports/imports present, manifest hash |
| `tests/verified_core_wasm/test_instantiate.mjs` | 28 | Functional | Module compilation, instantiation with mock host, pure function correctness |
| `tests/verified_core_wasm/run_all.sh` | — | Runner | Orchestrates both test suites |

### 7.2 Functional Tests Coverage

The `test_instantiate.mjs` exercises:
- `status_to_u32` (3 status code mappings)
- `iat_in_window` (valid + expired cases)
- `not_expired` (valid + expired cases)
- `is_active` (active + not-yet-active cases)
- `bytes_handle_is_present` (0=absent, non-zero=present)
- `algorithm_from_bitmask` (ES256/RS256/EdDSA filtering)
- `vc_*` public ABI export presence

### 7.3 Test Limitations

- Tests use **mock host callbacks** — crypto verification always returns fixed values
- No end-to-end test with real signatures
- Tests depend on a pre-built WASM fixture at `tests/fixtures/verified-core/verified_core.wasm`
- The fixture may not be rebuilt on every CI run (depends on Nix build)

## 8. Recommended Next Steps

### Priority 1: Eliminate Warning 15 Sources (High impact, medium effort)
1. Refactor `Dpop.Iat_validation.fst` and `Dpop.Claims.fst` to use `UInt64.t` for timestamps
2. Replace `FStar_String_uppercase` in `Dpop.Htm_validation.fst` with enumerated method comparison
3. Refactor `Pkce.verifier_ok`/`Pkce.strlen` to use `UInt32` for lengths
4. Re-run extraction and verify no Warning 15 remains

### Priority 2: ~~Add Missing EverParse F\* Verification~~ (DONE)
All 7 EverParse schemas are now in `verify_fstar.sh` Pass 2 (including `DpopSchema.fst/fsti` renamed to avoid module conflict).

### Priority 3: WASM Integration Tests with Real Crypto (Medium effort)
Extend `test_instantiate.mjs` or create a new test file that:
1. Provides a real SHA-256 implementation as a host callback
2. Creates valid PKCE challenge/verify round-trip
3. Tests DPoP and JWT verification with pre-computed test vectors

### Priority 4: Low\* Porting for Token Verification (High effort)
Port `token/Token.fst` and `token/JwtAccessToken.fst` to Low\* compatible style (Buffer-based) and add to KaRaMeL extraction list. This would extend verified core coverage from "claim verification" to "token issuance validation".

### Priority 5: CI Integration for WASM Build (Medium effort)
Ensure `nix build .#verified-core-wasm` runs in CI and the resulting artifact is:
1. Tested with both smoke and functional test suites
2. Hash-verified against the committed manifest
3. Published as a CI artifact for downstream consumption
