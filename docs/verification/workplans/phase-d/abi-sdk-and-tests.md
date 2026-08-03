# Phase D ABI, SDK, And Test Strategy

Last updated: 2026-07-08

Status: active plan

Owner: Verification

Audience: verification contributors, maintainers

This document is part of the split Phase D workplan.

## §3 ABI Impact

### Phase D (Minimal ABI Change)

Phase D adds one new WASM host import:

```c
/* New host import: copy handle data into WASM linear memory */
uint32_t vc_host_copy_bytes_to_linear(
    uint32_t handle,           /* bytes_handle to read from */
    uint8_t *dest,             /* destination in WASM linear memory */
    uint32_t dest_len          /* capacity of destination buffer */
);
/* Returns: number of bytes copied, or 0 on error */
```

This is *additive* — existing host imports remain unchanged. The WASM module
continues to accept `bytes_handle` values and merely copies them into linear
memory before processing.

**Existing host imports preserved:**
- `vc_host_register_bytes` — still needed for vc_pkce_challenge_generate
- `vc_host_release_handle` — still needed for handle lifecycle
- `Host_parse_dpop_compact` — still needed for JWS parsing
- `Host_parse_jwt_compact` — still needed for JWT parsing
- `Host_verify_ath_binding` — still needed (could be internalized later)
- `Host_check_audience_membership` — still needed (requires JSON parsing)
- `host_bytes_len` — still needed (handle→length query)
- `host_bytes_eq` — still needed (retained in Phase D)
- `host_replay_store_check_and_store` — permanent

**Removed host imports:**
- `host_crypto_sha256` — replaced by internal HACL\* call
- `host_crypto_verify_signature` — replaced by internal dispatch with fallback

**Net: −2 imports removed, +1 import added = −1 net host import change.**

### Phase E (Future — Full ABI Migration)

Phase E would replace the entire handle-based ABI with a pointer-based ABI:
- `bytes_handle` becomes `struct { uint8_t *ptr; uint32_t len; }` in WASM
  linear memory.
- Host writes input data directly into WASM linear memory before calling
  exported functions.
- All handle management functions (`vc_host_register_bytes`,
  `vc_host_release_handle`) are eliminated.
- `vc_host_copy_bytes_to_linear` is eliminated (data already in linear memory).

This is a **breaking ABI change** and requires a new `VC_ABI_VERSION`.

---

## §4 SDK Impact

### Rust Host Runtime Changes

**Phase D changes (non-breaking):**

1. **New host import implementation:** Add `vc_host_copy_bytes_to_linear` to
   the Rust WASM host adapter. Implementation is straightforward:
   ```rust
   fn vc_host_copy_bytes_to_linear(handle: u32, dest_ptr: u32, dest_len: u32) -> u32 {
       let data = handle_table.get(handle)?;
       let len = std::cmp::min(data.len(), dest_len as usize);
       // Write data into WASM linear memory at dest_ptr
       memory.write(dest_ptr, &data[..len])?;
       len as u32
   }
   ```

2. **Remove host crypto implementations:** The Rust host no longer needs to
   implement `host_crypto_sha256` or `host_crypto_verify_signature` for the
   algorithms handled internally. The host-side crypto code for EdDSA and
   HMAC can be removed from the WASM adapter (though it remains in the native
   server for non-WASM paths).

3. **Retain fallback crypto:** The host must still implement
   `host_crypto_verify_signature_fallback` for ES256 (ECDSA P-256) and RS256
   (RSA-PSS) until these are added to the WASM binary (if ever).

**TypeScript/Node.js host adapter:** Same pattern — implement
`vc_host_copy_bytes_to_linear`, remove crypto host callbacks except fallback.

### CryptoProfile Integration

The `CryptoProfile::Verified` allowlist (`HS256, HS384, HS512, EdDSA`) already
aligns with the algorithms that Phase D internalizes. RS256 and ES256 are
in `CryptoProfile::Compat` and correctly remain as host-delegated paths.

No CryptoProfile changes needed.

---

## §5 Test Strategy

### 5.1 F\* Verification

- All new concrete implementations must type-check under `nix build .#verify-fstar`.
- The constant-time comparison function (`ct_bytes_eq` or equivalent) must be
  extracted from an existing verified module (e.g., `fstar/ConstTime.fst`).
- The HACL\* call sites must have correct preconditions (buffer liveness,
  length bounds).

### 5.2 WASM Functional Tests

Extend `tests/verified_core_wasm/` with:

1. **SHA-256 correctness:** Hash known test vectors (RFC 6234 §8) and compare
   outputs. Verifies that the WASM-internal HACL\* path produces identical
   results to the previous host-delegated path.

2. **Ed25519 verification:** Verify known Ed25519 signatures (RFC 8032 §7.1
   test vectors). Covers the WASM-internal path.

3. **HMAC verification:** Verify HMAC-SHA256 against RFC 4231 test vectors.

4. **Algorithm fallback:** Verify that ES256/RS256 still work via the host
   fallback path. Ensure the dispatch logic correctly routes unsupported
   algorithms to the host.

5. **Edge cases:** Empty input (0-length handle), maximum-length input (64 KB
   cap), invalid handles.

### 5.3 Native/WASM Equivalence

Extend the T3 (Native/WASM equivalence tests) framework to compare:
- SHA-256 output for identical inputs via native Rust (aws-lc-rs) vs WASM
  (HACL\* internal).
- Ed25519 verify results for identical (msg, key, sig) triples.
- HMAC results for identical (key, data) pairs.

This provides defense-in-depth: even if the HACL\* WASM implementation has
a subtle bug, the equivalence test catches it against the production crypto
library.

### 5.4 Regression Tests

- All 1091+ existing Rust tests must continue to pass (the native server
  does not use the WASM module for crypto).
- All 59 existing WASM smoke tests must continue to pass.
- DPoP and JWT verification end-to-end tests must produce identical results.

---
