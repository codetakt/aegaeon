# F* Assumption Historical Reductions

Last updated: 2026-07-08

Status: historical record

Owner: Verification

Audience: verification reviewers, maintainers

This document is part of the split F* assumption register.

## 7. Historical — Proved and Removed

The following assume vals were present in earlier versions of the codebase but
have been proved as concrete `let` lemmas. They are no longer trust assumptions.

### TCB Hardening Round (2026-03-01)

| Former # | File | Function | Description | Proof technique |
|---|---|---|---|---|
| 2 | `Jose.Jws.Verify.fst` | `jws_verify_correct` | Bool excluded middle for jws\_verify results. SMTPat trigger for Z3 case-splitting. | Tautology — `()` suffices; F\* discharges reflexively. Now a `let` lemma at line 28. |
| 6 | `Jose.SdJwt.fst` | `disclosure_digest_deterministic` | Same encoded input always yields the same digest. SMTPat trigger. | Tautology — `()` suffices; reflexivity of `==`. Now a `let` lemma at line 278. |
| 11 | `Dpop.Signature.fst` | `lemma_verify_signature_true` | A valid signature implies the verifier returns true. SMTPat trigger. | Tautology — premise equals conclusion. Now a `let` lemma at line 22. |

These three were all **Negligible risk, Category A** tautologies used purely as
SMTPat triggers for Z3 proof automation. Their elimination reduced the assume
val count from 28 to 25 and removed all Negligible-risk entries from the
register.

### Phase A Completion (2026-03-07)

| Former # | File | Function | Description | Proof technique |
|---|---|---|---|---|
| 7 | `Drbg.HmacSha256.fst` | `hmac_sha256` | HMAC-SHA256 primitive for DRBG. Was the only crypto function `assume val` (not a Lemma). | Delegation to `Verified.Crypto.Bridge.hmac_sha256` (HACL\* `Spec.Agile.HMAC`). DRBG-specific preconditions (key=32, data≤65) trivially satisfy Bridge preconditions. |

This elimination completes the Phase A goal: **0 Category A crypto `assume val`
functions on the verified path**. All 6 remaining Category A assume vals are
Lemma properties (computational hardness: collision resistance, EUF-CMA) that
cannot be proved from first principles.

### Base64 Concrete Proofs (2026-03-07)

| Former # | File | Function | Description | Proof technique |
|---|---|---|---|---|
| 13 | `FStar.Base64.fst` | `base64url_roundtrip` | Roundtrip: `base64url_decode (base64url_encode b) = Some b` for `length b > 0`. | Concrete encode/decode implementations with proved `let` lemma `base64url_decode_encode_roundtrip`. |
| 14 | `FStar.Base64.fst` | `base64url_encode_injective` | Injectivity: `base64url_encode a = base64url_encode b ==> a = b`. | Proved via decode roundtrip: if `encode a = encode b` then `decode(encode a) = decode(encode b)`, hence `a = b`. |
| 15 | `FStar.Base64.fst` | `base64_roundtrip` | Standard Base64 roundtrip (same property as #13 for standard encoding). | Same technique as #13 applied to standard Base64 codec. |
| 16 | `FStar.Base64.fst` | `base64_encode_injective` | Standard Base64 injectivity (same property as #14 for standard encoding). | Same technique as #14 applied to standard Base64 codec. |

These four were **Low risk, Category E** encoding axioms modeled with
`irreducible` placeholder bodies. Their elimination replaced all `irreducible`
placeholders with concrete implementations and reduced the assume val count
from 15 to 11, completely eliminating Category E.

---

## 8. Phase A — Strong-Constraint HACL\* Integration (2026-03-05)

Phase A replaced all `irreducible` identity/false/constant crypto models with
genuine HACL\* spec-level implementations. This section documents the transition
and its impact on the assumption register.

### 8.1 Pre-Phase A State (Historical)

Before Phase A, crypto functions used identity/false/constant models that enabled
tautological proofs via `reveal_opaque`:
- `jws_verify _ _ = false` → `jws_verify_unforgeable` proved vacuously
- `disclosure_digest e = e` (identity) → collision resistance tautological
- `compute_hash alg input = input` (identity) → collision resistance tautological
- Similar patterns for `verify_rsa_pss`, `verify_ed25519`, `verify_signature`,
  `jwk_thumbprint`, `sha256`, `base64url_encode`, `s256`

These proofs were formally valid but tautological — they demonstrated protocol
correctness under idealized models, not under real cryptographic implementations.

### 8.2 Phase A Changes

Phase A created `Verified.Crypto.Bridge.fst` (10 HACL\* wrapper functions) and
replaced 9 F\* crypto models with genuine HACL\* spec calls:

| Function | Old model | New implementation |
|---|---|---|
| `jws_verify` | `false` (deny-by-default) | HACL\* HMAC + Ed25519 dispatch |
| `disclosure_digest` | identity | `Verified.Crypto.Bridge.sha256_of_string` |
| `compute_hash` | identity | `Verified.Crypto.Bridge.sha256_hash` |
| `verify_ed25519` | `false` | `Verified.Crypto.Bridge.ed25519_verify` |
| `verify_signature` | `false` | `Verified.Crypto.Bridge.ed25519_verify` |
| `jwk_thumbprint` | identity | `Verified.Crypto.Bridge.sha256_of_string` |
| `s256` / `sha256` | identity/constant | `Verified.Crypto.Bridge.sha256_hash` |
| `base64url_encode` | 43-char constant | spec model (irreducible, encoding only) |

### 8.3 Impact on Assume Vals

Phase A converted 3 formerly tautological proofs back into honest assume vals:
- `jws_verify_unforgeable` — no longer vacuously true (jws\_verify ≠ false)
- `disclosure_digest_collision_resistant` — no longer tautological (digest ≠ identity)
- `assumption_collision_resistance` — no longer tautological (hash ≠ identity)

Phase A added 3 new assume vals in `Verified.Crypto.Bridge.fst`:
- `lemma_sha256_collision_resistant`
- `lemma_sha256_of_string_collision_resistant`
- `lemma_ed25519_unforgeable`

Net: +6 assume vals, but these are **honest** computational hardness assumptions
on real HACL\* specs, replacing tautological proofs on toy models. The formal
claim is now substantially stronger.

### 8.4 Cross-Validation

The security properties modeled by Category A assume vals are independently
verified at the protocol level by **Tamarin** (248 lemmas, symbolic Dolev-Yao
model). At runtime, these properties are provided by:
- **aws-lc-rs** — FIPS 140-3 validated (signatures, hashing, RNG)
- **ring** — extensively audited (ECDSA, Ed25519, CSPRNG)
- **HACL\*/EverCrypt** — formally verified implementations (spec-level used by F\*)

---

## 9. Phase D — WASM Host Boundary Internalization (2026-03-08)

Phase D eliminates 4 of the 5 WASM host import assume vals (#8–#11) by
replacing the handle-based host callback pattern with direct HACL\* calls on
raw buffers.

### 9.1 Approach: Raw Buffer + HACL\* Direct

The original Phase D workplan proposed a "copy-in + fallback" approach using
`host_copy_bytes_to_linear`. The actual implementation uses a cleaner approach:

1. The **C exports layer** (`verified_core_exports.c`) resolves `bytes_handle`
   values to `(ptr, len)` pairs *before* calling F\* verification functions.
2. F\* functions receive `(B.buffer U8.t, U32.t)` pairs directly — no opaque
   handles.
3. HACL\* functions (`Hacl_Hash_SHA2_hash_256`, `Hacl_Ed25519_verify`) are
   declared as **`-library` module interfaces** in
   `VerifiedCore.Crypto.Hacl.fsti` — these are NOT assume vals because KaRaMeL
   does not extract them; the HACL\* C code already compiled into the WASM
   binary provides implementations.
4. `B.alloca` is NOT needed — data is already in WASM linear memory when the
   C exports layer calls the F\* functions.

### 9.2 Eliminated Assume Vals

| Former # | File | Function | Elimination technique |
|---|---|---|---|
| 8 | `VerifiedCore.Api.Claims.Runtime.fst` | `host_bytes_len` | Never called from F\*; used only in C `verified_core_exports.c`. Removed from F\* module. |
| 9 | `VerifiedCore.Api.Claims.Runtime.fst` | `host_bytes_eq` | Never called from F\*; used only in C `verified_core_exports.c`. Removed from F\* module. |
| 10 | `VerifiedCore.Api.Claims.Runtime.fst` | `host_crypto_sha256` | Replaced by inline call to `Hacl_Hash_SHA2_hash_256` (HACL\* `-library` module). |
| 11 | `VerifiedCore.Api.Claims.Runtime.fst` | `host_crypto_verify_signature` | Replaced by direct `Hacl_Ed25519_verify` dispatch. Verified path supports EdDSA only; ES256/RS256 are `CryptoProfile::Compat`. Planned OIDC `RS256` slice closure does not currently add RSA back into this WASM path. |

### 9.3 Verified Allowlist Scope

The WASM verified path supports **EdDSA (Ed25519) only** for signature
verification. This is intentional:

- **EdDSA:** Verified via HACL\* `Hacl_Ed25519_verify` (direct F\* call)
- **HS256/HS384/HS512:** Verified at Rust level via `Verified.Crypto.Bridge`;
  handled by `jose` crate at runtime, not in WASM module
- **ES256/RS256:** `CryptoProfile::Compat` only — out of scope for WASM
  verification. Handled entirely by ring/aws-lc-rs at the Rust level.

Planned OIDC `RS256` slice closure, if adopted, is currently expected to close
claim scope at the JOSE / OIDC boundary above the WASM signature path rather
than broadening the WASM verified allowlist to generic RSA.

### 9.4 Signing RNG Boundary (C-1)

The Rust `kms` module uses `ring::SystemRandom` for ES256 signing (federation
entity configuration). This is outside the F\* verified path and is a
**permanent signing boundary** — ECDSA signing requires access to a CSPRNG,
which is provided by the OS via ring. This is documented but not F\*-verified.

### 9.5 Impact

At the Phase D checkpoint, the count moved **11 → 9 assume vals**
(6 crypto hardness (A) + 2 HACL\* linkage (B') + 1 WASM host (C)).
Later JOSE / OIDC runtime-linkage work brings the current count to 12; see
§3 and §4 for the current register.

The net count change is −2 (4 eliminated, 2 new HACL\* linkage added). However,
the trust boundary quality improves significantly:
- **Eliminated (4):** Host callbacks that trusted arbitrary host code for crypto
  and data access (#8–#11).
- **Added (2):** Linkage stubs to HACL\*-verified C code — implementations are
  themselves formally verified, not arbitrary host code.
- **Retained (1):** `host_replay_store_check_and_store` (#12) — irreducible by
  design; requires persistent, concurrent state. See
  [Phase D risks and assumptions](../../workplans/phase-d/risks-schedule-and-assumptions.md).

Alternatively, if the 2 HACL\* linkage stubs (B') are excluded from the headline
count (since they represent verified foreign code, not unverified host boundaries),
the effective count is **7** (6 A + 1 C).
