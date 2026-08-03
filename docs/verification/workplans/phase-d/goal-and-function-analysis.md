# Phase D Goal And Function Analysis

Last updated: 2026-07-08

Status: active plan

Owner: Verification

Audience: verification contributors, maintainers

This document is part of the split Phase D workplan.

## §1 Goal

Reduce the 5 WASM host import `assume val` declarations in
`fstar/verifiedcore/api/VerifiedCore.Api.Claims.Runtime.fst` (Category C,
assumptions #8–#12 in the Assumption Register) by internalizing their
implementations into the WASM module itself.

**Formal boundary note:** In realistic von Neumann systems with I/O, the project
cannot formally prove computational hardness (EUF‑CMA/collision resistance)
except as theorem premises, OS/device entropy sources (modeled as external
contracts), or external host/storage behaviour (modeled as explicit interface
contracts or TCB boundaries). These remain outside the formal claim.

### Current State

| # | Assume Val | F\* Signature | Category |
|---|---|---|---|
| 8 | `host_bytes_len` | `bytes_handle -> Stack U32.t` | C (host boundary) |
| 9 | `host_bytes_eq` | `bytes_handle -> bytes_handle -> Stack bool` | C (host boundary) |
| 10 | `host_crypto_sha256` | `bytes_handle -> B.buffer U8.t -> Stack U32.t` | C (host boundary) |
| 11 | `host_crypto_verify_signature` | `U32.t -> U32.t -> bytes_handle -> bytes_handle -> bytes_handle -> Stack U32.t` | C (host boundary) |
| 12 | `host_replay_store_check_and_store` | `bytes_handle -> B.buffer U8.t -> U32.t -> Stack U32.t` | C (host boundary) |

### Target State

Eliminate assume vals #8, #9, #10, and #11 by implementing them inside the
WASM module using HACL\* C code already compiled into the binary and
LowStar buffer operations. Retain #12 (replay store) as a permanent host
boundary — it requires persistent, concurrent state that cannot exist inside
a stateless WASM module.

**Projection: 11 → 9 assume vals after Phase D** (6 crypto (A) + 2 HACL\*
linkage (B') + 1 WASM host (C)). Effective count excluding verified foreign
code: **7** (6 A + 1 C).

> **Program posture note (2026-03-08):** Phase D narrows the WASM verified
> signature path to `EdDSA`. The planned OIDC `RS256` slice closure is currently
> expected above this WASM layer unless a future architecture decision reopens
> generic RSA inside Verified Core.
>
> **Update (2026-03-08):** The approach changed from "copy-in + fallback"
> (original §2) to "raw buffer + HACL\* direct" — the C exports layer resolves
> `bytes_handle` → `(B.buffer U8.t, U32.t)` pairs before calling F\* functions,
> so no new `host_copy_bytes_to_linear` import is needed. Assumptions #8–#11
> are eliminated outright; only #12 (`host_replay_store_check_and_store`)
> remains. Two new HACL\* linkage assume vals (B') were added for SHA-256 and
> Ed25519 — these are `-library` stubs backed by verified HACL\* C code.
> See §8 for the updated projection.

---

## §2 Per-Function Analysis

### 2.1 `host_bytes_len` and `host_bytes_eq` (Assumptions #8, #9)

**Current design:** `bytes_handle` is `U32.t` — an opaque 32-bit handle
referencing host-managed byte arrays. The WASM module never sees the actual
bytes; it passes handles back to the host for length queries and comparisons.
The host (Rust runtime) maintains a handle table mapping handle IDs to
`Vec<u8>` values.

**Architecture:** These two functions are *intrinsically tied to the handle-based
ABI*. The WASM module receives `bytes_handle` values from the host callbacks
`vc_host_register_bytes` / `Host_parse_dpop_compact` / `Host_parse_jwt_compact`.
The handles reference data owned by the host, not by the WASM linear memory.

**Internalization path:** Replace the handle-based ABI with a *pointer-based ABI*
where the host writes input data directly into WASM linear memory and passes
`(ptr, len)` pairs instead of opaque handles. Then:

- `host_bytes_len` becomes a trivial read of the length field (or direct
  `Buffer.len` call).
- `host_bytes_eq` becomes a verified constant-time `memcmp` using
  `LowStar.Buffer` — similar to the existing `vc_ct_eq` in `c/verified_core.c`
  but extracted from F\* with a verified constant-time guarantee.

**F\* implementation sketch:**

```fstar
(* Replace assume val with concrete implementation *)
let host_bytes_len (h: bytes_handle) : Stack U32.t
  (requires fun mem -> True)
  (ensures fun h0 r h1 -> h0 == h1)
= (* bytes_handle would become a struct { ptr: B.buffer U8.t; len: U32.t } *)
  h.len

let host_bytes_eq (a b: bytes_handle) : Stack bool
  (requires fun mem -> B.live mem a.ptr /\ B.live mem b.ptr)
  (ensures fun h0 r h1 -> h0 == h1)
= if a.len <> b.len then false
  else ConstTime.ct_bytes_eq a.ptr b.ptr a.len  (* verified constant-time *)
```

**Blocker:** This requires a **breaking ABI change** — `bytes_handle` must change
from an opaque `U32.t` to a `(ptr, len)` pair, and all host callbacks
(`Host_parse_dpop_compact`, `Host_parse_jwt_compact`, `vc_host_register_bytes`,
etc.) must be redesigned to write into WASM linear memory instead of managing
external handle tables. This is a major refactor affecting:

- `c/verified-core/verified_core_exports.c` (all struct definitions use u32 handles)
- `c/verified_core.c` (register/release handle pattern)
- `include/verified_core.h` (public ABI)
- The Rust host runtime adapter
- All WASM smoke tests

**Verdict: DEFER to Phase E.** The handle→pointer ABI migration is a
prerequisite but carries substantial risk and SDK-breaking impact. Phase D
should focus on the crypto functions (#10, #11) which can be internalized
*within the current handle-based ABI* (see §2.2, §2.3).

### 2.2 `host_crypto_sha256` (Assumption #10)

**Current design:** The F\* code calls `host_crypto_sha256(input_handle,
output_ptr)` where `input_handle` is a `bytes_handle` (opaque u32 referencing
host-managed data) and `output_ptr` is a `B.buffer U8.t` in WASM linear
memory. The host reads the input data from its handle table, computes SHA-256,
and writes 32 bytes to `output_ptr`.

**HACL\* availability:** `Hacl_Hash_SHA2_hash_256` is already compiled into the
WASM binary via `crypto_bridge.c` → `Hacl_Hash_SHA2.c`. The C function
signature is:

```c
void Hacl_Hash_SHA2_hash_256(uint8_t *output, uint8_t *input, uint32_t input_len);
```

**Internalization path:** Replace the host callback with a direct call to
`Hacl_Hash_SHA2_hash_256` inside the WASM module.

**Challenge:** The current signature takes a `bytes_handle` (opaque u32) for
input, but `Hacl_Hash_SHA2_hash_256` needs a raw pointer. Two sub-approaches:

**Approach A (within current ABI):** Add a new host callback
`vc_host_copy_bytes_to_linear(handle, dest_ptr, dest_len)` that copies the
handle's data into WASM linear memory. Then the WASM module:
1. Queries `host_bytes_len(handle)` to get the length.
2. Allocates a stack buffer via `B.alloca`.
3. Calls `vc_host_copy_bytes_to_linear(handle, buf, len)` to copy data in.
4. Calls `Hacl_Hash_SHA2_hash_256(output, buf, len)` locally.

This *replaces* the crypto host callback with a simpler data-copy host
callback — a net improvement because the trust boundary narrows from
"host computes SHA-256 correctly" to "host copies bytes faithfully" (a much
weaker assumption).

**Approach B (pointer-based ABI, deferred):** Same as §2.1 — after the
handle→pointer migration, the WASM module has direct access to input bytes
and calls `Hacl_Hash_SHA2_hash_256` directly. No host callback needed at all.

**F\* implementation sketch (Approach A):**

```fstar
(* New minimal host callback — copies handle data into WASM linear memory *)
assume val host_copy_bytes_to_linear:
  handle: bytes_handle ->
  dest: B.buffer U8.t ->
  dest_len: U32.t{B.length dest >= U32.v dest_len} ->
  Stack U32.t  (* returns bytes copied, or 0 on error *)
  (requires fun h -> B.live h dest)
  (ensures fun h0 r h1 -> B.modifies (B.loc_buffer dest) h0 h1)

(* Replace host_crypto_sha256 with concrete HACL* call *)
let wasm_crypto_sha256
  (input_handle: bytes_handle)
  (output_ptr: B.buffer U8.t{B.length output_ptr >= 32})
: Stack U32.t
  (requires fun h -> B.live h output_ptr)
  (ensures fun h0 r h1 -> B.modifies (B.loc_buffer output_ptr) h0 h1)
= let input_len = host_bytes_len input_handle in
  if input_len = 0ul || U32.(input_len >^ 65536ul) then 1ul  (* error *)
  else
    let input_buf = B.alloca 0uy input_len in
    let copied = host_copy_bytes_to_linear input_handle input_buf input_len in
    if copied <> input_len then 1ul
    else begin
      Hacl_Hash_SHA2_hash_256 output_ptr input_buf input_len;
      0ul
    end
```

**Memory constraint:** `B.alloca` uses WASM stack memory. For DPoP/JWT signing
inputs, typical sizes are <8 KB. The WASM stack is typically 64 KB–1 MB.
A 64 KB cap on single-hash inputs is safe and covers all OAuth/OIDC use cases.

**Assume val impact:** Eliminates #10 (`host_crypto_sha256`). Adds one new
assume val (`host_copy_bytes_to_linear`) with a *strictly weaker* trust
requirement (data copy, not cryptographic computation).

**Net: −1 assume val, +1 simpler assume val → 0 count change but significant
trust boundary improvement.** The new assumption is "host copies bytes
faithfully" (trivially verifiable via test) vs "host computes SHA-256 correctly"
(requires trusting the entire crypto stack).

**Alternative — zero-new-assume-val path:** If combined with the ABI migration
(��2.1), no new assume val is needed at all. The WASM module already has the
input bytes in linear memory and calls HACL\* directly. This is the preferred
long-term path but requires Phase E (ABI migration) first.

### 2.3 `host_crypto_verify_signature` (Assumption #11)

**Current design:** The F\* code calls `host_crypto_verify_signature(algorithm,
public_key_format, public_key_handle, signing_input_handle, signature_handle)`
which dispatches to ES256/RS256/EdDSA signature verification in the host.

**HACL\* availability:**
- **EdDSA (Ed25519):** `Hacl_Ed25519_verify` is compiled into the WASM binary
  via `crypto_bridge.c`. Fully verified by HACL\*.
- **HMAC-SHA256/384/512:** `Hacl_HMAC_compute_sha2_{256,384,512}` are compiled
  into the WASM binary. Used for HS256/HS384/HS512 MAC-based "signature"
  verification.
- **ES256 (ECDSA P-256):** **NOT available** in the current WASM binary.
  HACL\* has `Hacl_P256.c` but it is not included in the build. P-256 ECDSA
  verification is algorithmically complex (~5 KLOC of verified C).
- **RS256 (RSA-PSS):** **NOT available** in HACL\*/EverCrypt WASM build.
  RSA requires arbitrary-precision integer arithmetic — HACL\* does not provide
  a WASM-compatible RSA implementation.

**Internalization path — partial:**

For EdDSA: Replace the host callback with a direct call to
`Hacl_Ed25519_verify` inside the WASM module. Same copy-in pattern as §2.2:
1. Copy public key (32 bytes), message, and signature (64 bytes) into linear
   memory via `host_copy_bytes_to_linear`.
2. Call `Hacl_Ed25519_verify(public_key, msg_len, msg, signature)`.

For HMAC (HS256/HS384/HS512): Replace with `Hacl_HMAC_compute_sha2_*` +
constant-time comparison. Copy key and message into linear memory, compute
HMAC, compare with provided signature.

For ES256 and RS256: **Cannot internalize** without adding P-256 and RSA to
the WASM binary. Options:
- **ES256:** Add `Hacl_P256.c` + dependencies to the WASM build (~30–50 KB
  binary size increase). Feasible but adds build complexity.
- **RS256:** No HACL\* implementation available. Must remain a host callback.

**Recommended approach:** Internalize EdDSA + HMAC verification. For ES256 and
RS256, retain the host callback but restructure it into algorithm-specific
host callbacks with a fallback pattern:

```c
// WASM-internal (verified):
if (alg == EdDSA) return wasm_ed25519_verify(...);
if (alg == HS256) return wasm_hmac_sha256_verify(...);
if (alg == HS384) return wasm_hmac_sha384_verify(...);
if (alg == HS512) return wasm_hmac_sha512_verify(...);
// Host fallback (for ES256, RS256):
return host_crypto_verify_signature_fallback(alg, ...);
```

**F\* modeling:** The `assume val` for `host_crypto_verify_signature` is
replaced with a concrete `let` that dispatches EdDSA/HMAC internally and
defers to a *narrower* host callback for ES256/RS256 only:

```fstar
(* Narrower host callback — only for algorithms not available in WASM *)
assume val host_crypto_verify_signature_fallback:
  algorithm: U32.t ->
  public_key_format: U32.t ->
  public_key_handle: bytes_handle ->
  signing_input_handle: bytes_handle ->
  signature_handle: bytes_handle ->
  Stack U32.t
  (requires fun h -> True)
  (ensures fun h0 r h1 -> h0 == h1)

(* Concrete dispatch — EdDSA/HMAC verified, ES256/RS256 host-delegated *)
let wasm_crypto_verify_signature
  (algorithm: U32.t)
  (public_key_format: U32.t)
  (public_key_handle: bytes_handle)
  (signing_input_handle: bytes_handle)
  (signature_handle: bytes_handle)
: Stack U32.t
  (requires fun h -> True)
  (ensures fun h0 r h1 -> h0 == h1)
= if algorithm = 3ul (* EdDSA *)
  then wasm_ed25519_verify public_key_handle signing_input_handle signature_handle
  else if algorithm = 4ul (* HS256 *) || algorithm = 5ul (* HS384 *) || ...
  then wasm_hmac_verify algorithm ...
  else host_crypto_verify_signature_fallback algorithm ...
```

**Assume val impact:** Replaces #11 (broad: any algorithm) with a narrower
assume val (ES256/RS256 only). EdDSA and HMAC verification paths become fully
verified within the WASM module. This is a *qualitative* trust boundary
improvement even if the assume val count stays at 1 for this slot.

**Binary size impact:**
- HMAC: already compiled in (0 KB additional).
- Ed25519: already compiled in (0 KB additional).
- P-256 (optional): ~30–50 KB additional. Requires `Hacl_P256.c`,
  `Hacl_EC_K256.c`, and field arithmetic dependencies.

### 2.4 `host_replay_store_check_and_store` (Assumption #12)

**Current design:** Atomic check-and-store for DPoP replay detection. The host
maintains a time-bounded key-value store (hash → insertion timestamp) with
TTL-based expiry.

**Why this CANNOT be internalized:**

1. **Persistence:** The replay store must survive across individual WASM
   invocations. WASM linear memory is ephemeral — it is allocated fresh for
   each module instantiation (or at best shared within a single instance
   lifetime). DPoP replay detection requires state that persists across HTTP
   requests.

2. **Concurrency:** The host contract requires *atomic* check-and-store. WASM
   is single-threaded within a module instance, but the server handles
   concurrent requests across multiple WASM instances (or uses a shared
   Rust-side store). An in-WASM store would be per-instance and miss replays
   across concurrent requests.

3. **Memory limits:** A bounded hash set or bloom filter in WASM linear memory
   would work for a single instance but:
   - Bloom filters have false positives (unacceptable for security — would
     reject valid DPoP proofs).
   - Hash sets require unbounded growth or eviction, consuming linear memory
     that competes with other WASM allocations.
   - Neither provides cross-instance coordination.

4. **Time source:** WASM has no reliable time source (no `clock_gettime`
   equivalent in WASI-core for production use). The TTL-based expiry requires
   a monotonic clock, which must come from the host.

**Verdict: PERMANENT host boundary.** This assume val is irreducible by design.
The replay store is a distributed systems primitive (comparable to a database
or cache), not a pure computation that can be internalized.

**Mitigation:** The existing FFI contract documentation and WASM smoke tests
provide adequate coverage. The trust requirement is "atomic check-and-store
with TTL" — a well-understood primitive implemented by standard data structures
(Redis, DashMap, etc.).

### 2.5 Summary (Updated 2026-03-08)

> **Approach change:** The original plan used "copy-in + fallback" requiring a
> new `host_copy_bytes_to_linear` import. The actual implementation uses "raw
> buffer + HACL\* direct" — the C exports layer resolves handles to pointers,
> and F\* functions receive `(B.buffer U8.t, U32.t)` pairs directly.

| # | Function | Action | Net assume val Δ |
|---|---|---|---|
| 8 | `host_bytes_len` | **ELIMINATED** — not called from F\*; C exports layer resolves handles | −1 |
| 9 | `host_bytes_eq` | **ELIMINATED** — not called from F\*; C exports layer resolves handles | −1 |
| 10 | `host_crypto_sha256` | **ELIMINATED** — replaced by inline HACL\* `Hacl_Hash_SHA2_hash_256` | −1 |
| 11 | `host_crypto_verify_signature` | **ELIMINATED** — replaced by HACL\* dispatch (EdDSA only in verified path) | −1 |
| 12 | `host_replay_store_check_and_store` | Retained (permanent) — signature updated to raw buffer pair | 0 |

**Phase D: 11 → 9 assume vals** (−4 eliminated, +2 HACL\* linkage = −2 net).

The improvement is both quantitative and qualitative:
- **Before Phase D:** 5 Category C assume vals including 2 crypto operations
  (SHA-256, multi-algo signature verification) trusting arbitrary host code.
- **After Phase D:** 1 Category C assume val (replay store only) + 2 Category B'
  assume vals (HACL\* linkage — implementations are themselves formally verified).
  All crypto operations are verified within the WASM module via HACL\*.

---
