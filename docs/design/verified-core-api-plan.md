# Verified Core API Export Plan

Last updated: 2026-07-07

Status: future plan

Owner: Engineering

Audience: implementation contributors, maintainers

> **Status note (2026-07-07):** The Phase 1 claims runtime baseline described below is implemented in this repository. Read this document as a follow-up plan for deferred compact-path, SDK-packaging, and compat-algorithm work; it does not widen the current verified allowlist.

## Background

TypeScript/Node runtimes expect exports such as `VerifiedCore_dpop_verify_v1` / `VerifiedCore_jwt_verify_v1`,
but the current Low*/KaRaMeL extraction exposes only internal functions
such as `Dpop_Validation_verify_dpop` and `Pkce_verify_pkce`.
Direct use from the host requires the following:

1. DPoP/JWT parsing (JOSE Header, Payload, Signature)
2. Algorithm selection for signature verification and claim validation
3. Conversion to Low* types such as `FStar_Bytes_bytes` / `Prims_string`

These operations must be reimplemented on the host. This diminishes the value of Verified Core as the
single source of protocol implementation, so Verified Core will provide an ABI suitable for host use.

## Current Implementation Status

### Compact Path (`*_verify_v1`)
- `VerifiedCore_dpop_verify_v1` / `VerifiedCore_jwt_verify_v1` have been introduced in `c/verified-core/verified_core_exports.c`.
- The current compact path works through `Host_parse_dpop_compact` / `Host_parse_jwt_compact` and can return **EdDSA** DPoP/JWT verification results in the current verified WASM path.
- `ES256` / `RS256` remain `UNSUPPORTED` in the verified WASM path and are treated as a separate promotion task.

### Claims Path (`*_verify_claims_v1`) — **Phase 1 Complete**
- Implemented in F* in `fstar/verifiedcore/api/VerifiedCore.Api.Claims.Runtime.fst`.
- C code generated through KaRaMeL extraction: `generated/lowstar/verified-core/c/VerifiedCore_Api_Claims_Runtime.{c,h}`
- The bridge code that calls the F* implementation from `c/verified-core/verified_core_exports.c` is complete.
- This repository contains a reference Node adapter (`scripts/sdk/runtime_node_reference.mjs`) and a reference browser adapter (`scripts/sdk/runtime_web_reference.mjs`), providing `dpopVerify` / `dpopVerifyClaims` / `jwtVerify` / `jwtVerifyClaims`.
- Verified with Node smoke tests in `tests/verified_core_wasm/runtime_node_reference_test.mjs` and browser-facing adapter tests in `tests/verified_core_wasm/runtime_web_reference_test.mjs`.

The claims path delegates Base64/JSON parsing to the host; Verified Core receives only previously parsed byte sequences.
This reduces the TCB (Trusted Computing Base) while providing full verification functionality.

## Goal

Export the following C symbols directly from `verified_core.wasm`.

```c
uint32_t VerifiedCore_dpop_verify_v1(
  const struct DpopVerificationInputV1 *input,
  struct DpopVerificationOutputV1 *output);

uint32_t VerifiedCore_jwt_verify_v1(
  const struct JwtVerificationInputV1 *input,
  struct JwtVerificationOutputV1 *output);
```

Align the ABI structure definitions with `scripts/sdk/generate_verified_core_abi.js`.
The return value is `VerifiedCoreStatusCode` (0: OK; all other values are error codes).

## Implementation Approach

### 1. F*/Low* module (`fstar/verifiedcore/VerifiedCore.Api.fst`)

- `val dpop_verify_v1 : input -> ST output (requires ...) (ensures ...)`
- `val jwt_verify_v1  : input -> ST output (requires ...) (ensures ...)`
- Reuse the underlying logic by calling the existing `Dpop_Validation.verify_dpop` and `Jose.*` modules.
- Define input types as tuples of `bytes` / `string` / `uint32` / `uint64` aligned with the ABI,
  and attach the `[@@@extract]` attribute so they become `struct` types during Low* extraction.
- Normalize errors to integers corresponding to `VerifiedCoreStatusCode` (fix the representation with `C_Enums` rather than `Prims_native`).
- Define an abstract interface, `module type ReplayStore`, for the DPoP replay store,
  and generate keys (hashes) through the existing `Dpop.Replay`.

### 2. KaRaMeL bundle

- Add `verifiedcore` (a new directory) to `MODULE_DIRS` in `run_verified_core_lowstar.sh`.
- Extraction order: place `verifiedcore/VerifiedCore.Api.fst` last and `--bundle` its `Dpop`/`Jose` dependencies beforehand.
- Use KaRaMeL's `-bundle` option to bundle `VerifiedCore.Api=Prims,FStar,...`, preventing unnecessary symbols from appearing in C.
- To suppress Warning 15 for functions such as `FStar.UInt32.*`, explicitly include `compat.h` or refactor the Low* code to use `UInt32.t`.

### 3. C Shim (`c/verified_core/verified_core.c`)

- To export the modules extracted from F* directly, supplement the KaRaMeL output
  with a handwritten C file responsible for the following:
  - ABI structure definitions (such as `DpopVerificationInputV1`) and size checks using `static_assert`.
  - Conversion of UTF-8 strings to `Prims_string` (`char *`).
  - Wrapping binary sequences with `FStar_Bytes_of_buffer(len, ptr)`.
  - Implementing `VerifiedCore_dpop_verify_v1` / `VerifiedCore_jwt_verify_v1`, calling F*/Low* functions, and packing return values into structures.
- Copy this C file into the KaRaMeL output using `run_verified_core_lowstar.sh` and include it in the build.

### 4. Tests

- Add `wasmtime`-based smoke tests to `tests/verified_core_wasm`.
  - Success cases: confirm `status=0` for valid DPoP/JWT vectors.
  - Error cases: confirm codes such as replay detection (`REPLAY`) and signature mismatch (`INVALID_SIGNATURE`).
- Implement Node/Web integration tests through `pnpm test` from the SDK runtimes.

## Remaining Work

1. Reorganize the compact path (`*_verify_v1`) using the same error categories as the claims path ABI.
2. Incorporate the claims path into runtime-node / runtime-web examples and tests in the publishable SDK packages.
3. Treat `ES256` / `RS256` as compat/runtime targets until a separate boundary-promotion record is closed.

## Phase 1: Claims Execution Model

### Architecture

```text
┌─────────────────┐     ┌─────────────────────────────────────────┐
│  Application    │     │              Host Runtime               │
│                 │     │  (Node.js / Browser)                    │
│  - DPoP proof   │────▶│                                         │
│  - JWT token    │     │  1. Parse JWS (split by '.')            │
└─────────────────┘     │  2. Decode Base64url segments           │
                        │  3. Extract claims from payload JSON    │
                        │  4. Create bytes handles                │
                        │                                         │
                        │     ┌─────────────────────────────┐     │
                        │     │     Verified Core WASM      │     │
                        │     │                             │     │
                        │     │  dpop_verify_claims_impl    │     │
                        │     │  jwt_verify_claims_impl     │     │
                        │     │                             │     │
                        │     │  - Validate claims          │     │
                        │     │  - Check iat window         │     │
                        │     │  - Verify Ed25519 in-WASM   │     │
                        │     │  - Call replay store        │     │
                        │     └─────────────────────────────┘     │
                        │                                         │
                        │  Host callbacks (current 7 imports):   │
                        │  - replay store check-and-store         │
                        │  - register/release byte handles        │
                        │  - parse compact DPoP/JWT               │
                        │  - resolve handle -> (ptr, len)         │
                        └─────────────────────────────────────────┘
```

### Implementation Files

| File | Role |
|---------|------|
| `fstar/verifiedcore/api/VerifiedCore.Api.Claims.Runtime.fst` | F* verification logic |
| `generated/lowstar/verified-core/c/VerifiedCore_Api_Claims_Runtime.{c,h}` | C code extracted by KaRaMeL |
| `c/verified-core/verified_core_exports.{c,h}` | C bridge (including ABI structure definitions) |
| `scripts/sdk/runtime_node_reference.mjs` | Reference Node adapter / host imports / packaging-aware loader |
| `scripts/sdk/runtime_web_reference.mjs` | Reference browser adapter / secure-context loader / WebCrypto-based artefact verification |
| `tests/verified_core_wasm/runtime_node_reference_test.mjs` | Node smoke tests |
| `tests/verified_core_wasm/runtime_web_reference_test.mjs` | Web-facing adapter tests on Node WebCrypto |
| `tests/verified_core_wasm/runtime_web_reference.html` | Browser smoke harness for the reference web adapter |
| `tests/verified_core_wasm/package_dist_test.mjs` | sign → package → fetch verification smoke |

### Verified Items

- DPoP iat window validation (max age / future skew)
- current verified-signature path: EdDSA (`ES256` / `RS256` remain unsupported in the verified WASM path)
- Replay detection (store with TTL)
- Status code mapping (F* → C → TypeScript)

## References

- `fstar/dpop/Dpop.Validation.fst` – Current signature verification and claim checks.
- `fstar/jose/Jose.Jwt_validation.fst` – JWT claim validation logic.
- `scripts/sdk/generate_verified_core_abi.js` – Authoritative ABI JSON source.
- `docs/design/runtime-adapter-design.md` – API specification on which the runtimes depend.
- `docs/design/verified-core-claims-runtime-plan.md` – Phase 1 implementation plan.
