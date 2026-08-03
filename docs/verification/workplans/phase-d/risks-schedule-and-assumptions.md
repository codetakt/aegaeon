# Phase D Risks, Schedule, And Assumption Projection

Last updated: 2026-07-08

Status: active plan

Owner: Verification

Audience: verification contributors, maintainers

This document is part of the split Phase D workplan.

## §6 Risk Assessment

### 6.1 Stack Overflow from Large Inputs

**Risk:** `B.alloca` for input copy uses WASM stack memory. If a signing input
exceeds the stack size, the WASM module traps.

**Mitigation:** Cap input size at 64 KB (covers all OAuth/OIDC use cases —
JWTs are typically <4 KB, DPoP proofs <2 KB). Return error code for
oversized inputs. The cap is enforced in F\* via a precondition check before
`B.alloca`.

**Severity:** Low. OAuth/OIDC payloads are small by design.

### 6.2 Binary Size Increase

**Risk:** Adding P-256 ECDSA (if attempted) would increase the WASM binary by
~30–50 KB.

**Mitigation:** Phase D does NOT add P-256. EdDSA and HMAC are already compiled
into the binary (0 KB increase). P-256 is deferred to a future phase with a
separate cost/benefit analysis.

**Severity:** N/A for Phase D.

### 6.3 ABI Compatibility

**Risk:** Adding `vc_host_copy_bytes_to_linear` as a new host import means
existing host adapters must be updated to provide this import, or the WASM
module will fail to instantiate.

**Mitigation:**
- Bump `VC_ABI_VERSION` from 1 to 2.
- Document the new import in `include/verified_core.h`.
- Provide fallback: if the host does not provide `vc_host_copy_bytes_to_linear`,
  the WASM module falls back to the old `host_crypto_sha256` and
  `host_crypto_verify_signature` imports. This requires conditional linking or
  a feature flag at build time.

**Severity:** Medium. Breaking for existing host adapters unless fallback is
provided.

### 6.4 Constant-Time Guarantee

**Risk:** The WASM-internal `host_bytes_eq` replacement (Phase E) must be
constant-time. WASM compilers (LLVM → wasm32) may optimize away constant-time
patterns.

**Mitigation:**
- Use `volatile` or compiler barriers in the C implementation.
- The existing `ConstTime.fst` module is already verified and extracted.
- Dudect testing (T1) will cover the WASM binary.

**Severity:** Low for Phase D (bytes_eq deferred to Phase E). Medium for Phase E.

### 6.5 HACL\* Spec vs Implementation Divergence

**Risk:** The F\* spec uses `Spec.Agile.Hash.hash` while the WASM binary uses
`Hacl_Hash_SHA2_hash_256` (the C extraction). If there is a divergence between
spec and implementation, the verification claim is weakened.

**Mitigation:** HACL\* guarantees spec/implementation correspondence as part of
its own verification. This is the same trust boundary used by Phase A and is
well-established.

**Severity:** Very Low. This is the core reason for using HACL\*.

---

## §7 Phased Schedule

### Phase D-1: Infrastructure (Prerequisite)

1. Add `host_copy_bytes_to_linear` host import to F\* (`assume val`),
   C header, and WASM build.
2. Implement `host_copy_bytes_to_linear` in the C test shim
   (`c/verified_core.c`) and document in `include/verified_core.h`.
3. Update Nix `verified-core-wasm.nix` if any new C files are needed.
4. Add WASM smoke test for the new host import.

### Phase D-2: SHA-256 Internalization

1. Replace `host_crypto_sha256` calls with:
   - `host_bytes_len` to get input length.
   - `host_copy_bytes_to_linear` to copy input into stack buffer.
   - `Hacl_Hash_SHA2_hash_256` to compute hash locally.
2. Update `VerifiedCore.Api.Claims.Runtime.fst`:
   - Remove `assume val host_crypto_sha256`.
   - Add concrete `let wasm_crypto_sha256` implementation.
3. Verify with `nix build .#verify-fstar`.
4. Add SHA-256 test vectors to WASM tests.

### Phase D-3: EdDSA + HMAC Signature Verification

1. Implement WASM-internal Ed25519 verification:
   - Copy public key (32 bytes), message, signature (64 bytes) via
     `host_copy_bytes_to_linear`.
   - Call `Hacl_Ed25519_verify`.
2. Implement WASM-internal HMAC verification:
   - Copy key and message via `host_copy_bytes_to_linear`.
   - Compute `Hacl_HMAC_compute_sha2_*`.
   - Constant-time compare with provided signature.
3. Replace `host_crypto_verify_signature` with dispatch function:
   - EdDSA → internal.
   - HS256/HS384/HS512 → internal.
   - ES256/RS256 → `host_crypto_verify_signature_fallback`.
4. Update `VerifiedCore.Api.Claims.Runtime.fst`:
   - Remove `assume val host_crypto_verify_signature`.
   - Add `assume val host_crypto_verify_signature_fallback` (narrower scope).
   - Add concrete `let wasm_crypto_verify_signature` dispatch.
5. Verify with `nix build .#verify-fstar`.
6. Add Ed25519 and HMAC test vectors to WASM tests.

### Phase D-4: Documentation and CI

1. Update `docs/verification/claims/assumptions/current-register.md`:
   - Mark #10 as ELIMINATED (replaced with data-copy + HACL\*).
   - Mark #11 as NARROWED (EdDSA/HMAC internalized; ES256/RS256 remain).
   - Add new assume vals for `host_copy_bytes_to_linear` and
     `host_crypto_verify_signature_fallback`.
2. Update `docs/verification/runbooks/ffi-contracts/README.md` with new contracts.
3. Update compliance matrix if any entries reference host crypto.
4. Run full CI: `nix build .#verify-fstar`, `cargo test`, WASM smoke tests.

### Phase E (Future — Separate Plan)

1. ABI migration: handle → pointer.
2. Eliminate `host_bytes_len`, `host_bytes_eq`, `host_copy_bytes_to_linear`.
3. Eliminate `vc_host_register_bytes`, `vc_host_release_handle`.
4. Bump `VC_ABI_VERSION` to 3.

---

## §8 Assume Val Projection

> **Updated 2026-03-08:** The approach changed from "copy-in + fallback"
> to "raw buffer + HACL\* direct." The C exports layer now resolves
> `bytes_handle` values to `(B.buffer U8.t, U32.t)` pairs *before* calling
> F\* verification functions. This eliminates the need for
> `host_copy_bytes_to_linear` and `host_crypto_verify_signature_fallback`
> entirely. HACL\* functions (`Hacl_Hash_SHA2_hash_256`, `Hacl_Ed25519_verify`)
> are declared as `-library` module interfaces — not assume vals.

### After Phase D

| # | Function | Status | Category |
|---|---|---|---|
| 1 | `jws_verify_unforgeable` | Unchanged | A (crypto) |
| 2 | `lemma_sha256_collision_resistant` | Unchanged | A (crypto) |
| 3 | `lemma_sha256_of_string_collision_resistant` | Unchanged | A (crypto) |
| 4 | `lemma_ed25519_unforgeable` | Unchanged | A (crypto) |
| 5 | `disclosure_digest_collision_resistant` | Unchanged | A (crypto) |
| 6 | `assumption_collision_resistance` | Unchanged | A (crypto) |
| ~~8~~ | ~~`host_bytes_len`~~ | **ELIMINATED** — never called from F\*; used only in C `verified_core_exports.c` | — |
| ~~9~~ | ~~`host_bytes_eq`~~ | **ELIMINATED** — never called from F\*; used only in C `verified_core_exports.c` | — |
| ~~10~~ | ~~`host_crypto_sha256`~~ | **ELIMINATED** — replaced by `hacl_sha256` (HACL\* linkage) | — |
| ~~11~~ | ~~`host_crypto_verify_signature`~~ | **ELIMINATED** — replaced by `hacl_ed25519_verify` (HACL\* linkage, EdDSA only) | — |
| 12 | `host_replay_store_check_and_store` | Unchanged (permanent) — signature updated to `(B.buffer U8.t, U32.t)` pair | C (host) |
| NEW-1 | `hacl_sha256` | New (Phase D) — HACL\* `-library` linkage stub | B' (verified foreign code) |
| NEW-2 | `hacl_ed25519_verify` | New (Phase D) — HACL\* `-library` linkage stub | B' (verified foreign code) |

**Count: 11 → 9 assume vals** (6 crypto (A) + 2 HACL\* linkage (B') + 1 WASM host (C)).
Effective count excluding verified foreign code: **7** (6 A + 1 C).

**Key design changes from original plan:**
- **No `host_copy_bytes_to_linear`:** The C exports layer resolves handles to raw
  pointers and passes `(ptr, len)` pairs directly to the F\* functions. No new
  host callback needed.
- **No `host_crypto_verify_signature_fallback`:** The verified path supports
  **EdDSA only** for signature verification (via HACL\* `Hacl_Ed25519_verify`).
  ES256/RS256 are `CryptoProfile::Compat` algorithms and are handled entirely
  at the Rust `jose` crate level, outside the WASM verified module.
- **HACL\* declarations are `-library` modules**, not assume vals. They are
  interface declarations for C functions already compiled into the WASM binary.
- **`bytes_handle` removal from F\*:** The opaque `U32.t` handle type is no
  longer used in F\* verification functions. The C exports layer is the boundary
  between the handle-based WASM ABI and the raw-buffer F\* API.

### Verified Allowlist Scope (D-1)

The WASM verified path supports the following algorithms:

| Algorithm | Verification status | Implementation |
|---|---|---|
| **EdDSA (Ed25519)** | Verified in WASM | HACL\* `Hacl_Ed25519_verify` (direct call from F\*) |
| HS256/HS384/HS512 | Verified at Rust level | HACL\* via `Verified.Crypto.Bridge` (server-side); handled by `jose` crate at runtime |
| ES256 (ECDSA P-256) | `CryptoProfile::Compat` only | **Not in WASM verified path** — ring/aws-lc-rs at Rust level |
| RS256 (RSA-PSS) | `CryptoProfile::Compat` only | **Not in WASM verified path** — ring/aws-lc-rs at Rust level |

This is intentional: the verified core proves EdDSA properties via HACL\*. Other
algorithms are out of scope for the WASM verification boundary.

### Phase E (Obsoleted)

The original Phase E (full ABI migration from handle→pointer) is **no longer
necessary** for assume val reduction. Phase D achieves 11→7 directly by moving
the handle→pointer resolution into the C exports layer. A future ABI
simplification may still be desirable for SDK ergonomics but carries no
verification benefit.

### Phase D-Local Theoretical Minimum

The Phase D-local theoretical minimum was **9 assume vals**: 6 crypto hardness,
2 HACL\* linkage, and 1 replay store. This was achieved at the Phase D
checkpoint. Later JOSE/OIDC runtime-linkage work intentionally added explicit
linkage contracts; use `../../claims/assumptions/README.md` as the authority for the current
repository-wide count.
The HACL\* linkage stubs are permanent (they represent verified foreign code,
not proof gaps). The `host_replay_store_check_and_store` assume val is
irreducible — it requires persistent, concurrent state that cannot exist inside
a stateless WASM module (see §2.4).

Excluding the 2 HACL\* linkage stubs (which are backed by verified
implementations), the effective minimum is **7** (6 A + 1 C).

---

## Appendix A: Host Import Inventory

Complete list of WASM host imports (functions the host must provide):

### Current (ABI v1)

| Import | F\* assume val? | Purpose |
|---|---|---|
| `vc_host_register_bytes` | No (C-level) | Register bytes as handle |
| `vc_host_release_handle` | No (C-level) | Release handle |
| `host_bytes_len` | Yes (#8) | Query handle length |
| `host_bytes_eq` | Yes (#9) | Compare handle contents |
| `host_crypto_sha256` | Yes (#10) | SHA-256 hash |
| `host_crypto_verify_signature` | Yes (#11) | Signature verification |
| `host_replay_store_check_and_store` | Yes (#12) | Replay detection |
| `Host_parse_dpop_compact` | No (C-level) | DPoP JWS parsing |
| `Host_parse_jwt_compact` | No (C-level) | JWT JWS parsing |
| `Host_verify_ath_binding` | No (C-level) | ATH claim verification |
| `Host_check_audience_membership` | No (C-level) | Audience array check |

### After Phase D

> **Note:** The approach changed to "raw buffer + HACL\* direct." Handle
> resolution is now done in the C exports layer, so WASM host imports for
> `host_bytes_len`, `host_bytes_eq`, `host_crypto_sha256`, and
> `host_crypto_verify_signature` are no longer referenced from F\*. The C
> exports layer still uses some host callbacks for handle management, but
> these are outside the F\* verification boundary.

| Import | F\* assume val? | Change |
|---|---|---|
| `vc_host_register_bytes` | No (C-level) | Unchanged (C exports layer) |
| `vc_host_release_handle` | No (C-level) | Unchanged (C exports layer) |
| ~~`host_bytes_len`~~ | ~~Yes (#8)~~ | **Removed from F\*** — C exports resolves handles to `(ptr, len)` |
| ~~`host_bytes_eq`~~ | ~~Yes (#9)~~ | **Removed from F\*** — comparison done with raw buffers |
| ~~`host_crypto_sha256`~~ | ~~Yes (#10)~~ | **Removed** — replaced by inline HACL\* call |
| ~~`host_crypto_verify_signature`~~ | ~~Yes (#11)~~ | **Removed** — replaced by HACL\* dispatch (EdDSA only) |
| `host_replay_store_check_and_store` | Yes (#12) | Retained — signature updated to `(B.buffer U8.t, U32.t)` |
| `Host_parse_dpop_compact` | No (C-level) | Unchanged |
| `Host_parse_jwt_compact` | No (C-level) | Unchanged |
| `Host_verify_ath_binding` | No (C-level) | Unchanged |
| `Host_check_audience_membership` | No (C-level) | Unchanged |

**F\* assume val count in `VerifiedCore.Api.Claims.Runtime.fst`: 5 → 1.**
**New assume vals in `VerifiedCore.Crypto.Hacl.fst`: 2 (HACL\* linkage stubs).**
