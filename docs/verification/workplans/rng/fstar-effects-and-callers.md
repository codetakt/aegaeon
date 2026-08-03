# RNG F* Effects And Caller Impact

Last updated: 2026-07-08

Status: active plan

Owner: Verification

Audience: verification contributors, maintainers

This document is part of the split DRBG and entropy-input workplan.

## 3. F\* Type Signatures (Proposed)

### 3.1 Module: `Drbg.HmacSha256`

> **Note (2026-03-07):** The `assume val hmac_sha256` shown below has been
> **eliminated** by delegating to `Verified.Crypto.Bridge.hmac_sha256`
> (HACL\* `Spec.Agile.HMAC`). The code below is the original design; see
> `fstar/crypto/Drbg.HmacSha256.fst` for the current implementation.

```fstar
module Drbg.HmacSha256

open FStar.Bytes

(** HMAC-SHA256 — crypto trust boundary.
    Honest assume val (strong-constraint compliant: no constant model).
    Runtime: delegates to `hmac` + `sha2` crates via crates/crypto/src/mac.rs.
    This is the ONLY assume val in the DRBG module — the DRBG construction
    itself is fully verified. *)
assume val hmac_sha256:
  key:bytes{Bytes.length key = 32} ->
  data:bytes ->
  Tot (r:bytes{Bytes.length r = 32})

(** DRBG state *)
type drbg_state = {
  key: k:bytes{Bytes.length k = 32};
  v:   v:bytes{Bytes.length v = 32};
  reseed_counter: nat;
}

(** Internal: HMAC_DRBG Update per SP 800-90A Section 10.1.2.2 *)
val drbg_update:
  key:bytes{Bytes.length key = 32} ->
  v:bytes{Bytes.length v = 32} ->
  provided_data:bytes ->
  Tot (k:bytes{Bytes.length k = 32} * v:bytes{Bytes.length v = 32})

(** Instantiate: create DRBG state from 32-byte entropy seed.
    SP 800-90A Section 10.1.2.3 *)
val drbg_instantiate:
  seed:bytes{Bytes.length seed = 32} ->
  Tot drbg_state

(** Generate: produce n bytes of pseudorandom output.
    Returns updated state and output bytes.
    SP 800-90A Section 10.1.2.5 *)
val drbg_generate:
  st:drbg_state{st.reseed_counter <= reseed_limit} ->
  n:nat{n > 0 /\ n <= 65536} ->
  Tot (drbg_state * r:bytes{Bytes.length r = n})

(** Reseed: re-key DRBG state with fresh entropy.
    SP 800-90A Section 10.1.2.4 *)
val drbg_reseed:
  st:drbg_state ->
  entropy:bytes{Bytes.length entropy = 32} ->
  Tot drbg_state
```

### 3.2 Module: `Random` (refactored)

The existing `Random.fst` module is refactored to take explicit entropy:

```fstar
module Random

open FStar.Bytes
open FStar.String
open Drbg.HmacSha256

type challenge_id = string

(** Generate a random string of the specified length.
    Takes explicit 32-byte entropy seed.
    No irreducible — fully verified through DRBG construction. *)
val generate_secure_random:
  entropy:bytes{Bytes.length entropy = 32} ->
  len:nat{len > 0} ->
  Tot (r:string{String.length r = len})

(** Generate a fresh challenge ID.
    Takes explicit 32-byte entropy seed.
    No irreducible — fully verified through DRBG construction. *)
val fresh_challenge_id:
  entropy:bytes{Bytes.length entropy = 32} ->
  Tot challenge_id
```

**Key changes from current signatures:**
1. Both functions gain an `entropy: bytes{Bytes.length entropy = 32}` parameter.
2. Both become `Tot` (pure). The ST effect in `generate_secure_random` was only
   needed because the former implementation nominally accessed "CSPRNG state."
   With explicit entropy, the function is deterministic and pure.
3. No `irreducible` — the implementations delegate to the verified DRBG, which
   delegates to `assume val hmac_sha256` (the single crypto trust boundary).

---

## 4. Effect Handling

### 4.1 Pre-Phase C Effect Map (historical)

| Function | Module | Effect | Callers |
|---|---|---|---|
| `generate_secure_random` | `Random` | **ST** (was) | `AuthCode.Flow.generate_auth_code`, `AuthCode.Flow.generate_access_token` |
| `fresh_challenge_id` | `Random` | **Tot** (was) | `StepUp.issue_challenge` |

### 4.2 Post-Phase C Effect Map (implemented)

| Function | Module | Effect | Change |
|---|---|---|---|
| `hmac_sha256` | `Drbg.HmacSha256` | **Tot** | New (assume val crypto boundary) |
| `drbg_instantiate` | `Drbg.HmacSha256` | **Tot** | New |
| `drbg_generate` | `Drbg.HmacSha256` | **Tot** | New |
| `drbg_reseed` | `Drbg.HmacSha256` | **Tot** | New |
| `generate_secure_random` | `Random` | **Tot** | ST -> Tot (entropy param replaces CSPRNG state) |
| `fresh_challenge_id` | `Random` | **Tot** | Unchanged effect, new entropy param |

### 4.3 Design Decision

All DRBG and wrapper functions are **Tot** (pure). The entropy is passed as an
explicit argument, pushing the ST effect (OS RNG access) entirely to the Rust
caller.

**Rationale:**
- Tot functions compose freely in specifications and lemmas.
- The DRBG is a pure mathematical construction — given the same seed and
  request, it always produces the same output. This is exactly what Tot models.
- The only non-determinism (entropy acquisition) is at the system boundary
  (Rust `getrandom`), which is outside the F\* verification scope.

### 4.4 ST-to-Tot Migration for AuthCode.Flow

`AuthCode.Flow.fst` currently uses ST for `authorize` and `issue_tokens_helper`
because they call `generate_secure_random` (ST). With the refactored signatures:

**Option A (recommended): Make authorize/issue_tokens_helper Tot with entropy param.**
- `authorize` gains `entropy: bytes{Bytes.length entropy = 32}` param.
- `issue_tokens_helper` gains `entropy` param.
- `token_exchange` gains `entropy` param.
- The ST effect in these functions was solely due to `generate_secure_random`.
  All other operations (Seq.snoc, Seq.upd, etc.) are already Tot.
- This makes the entire authorization code flow a pure function from
  (store, request, entropy) -> (store', response), which is ideal for
  verification.

**Option B: Keep ST wrappers that call OS RNG internally.**
- Less disruption to callers but perpetuates the ST effect unnecessarily.
- Rejected: the whole point is to make entropy explicit.

---

## 5. Caller Impact Analysis

### 5.1 `AuthCode.Flow.fst` (fstar/authcode/AuthCode.Flow.fst)

**Functions affected:**

| Function | Current Signature | Proposed Signature |
|---|---|---|
| `generate_auth_code` | `unit -> ST string` | `entropy:bytes{...} -> Tot string` |
| `generate_access_token` | `unit -> ST string` | `entropy:bytes{...} -> Tot string` |
| `authorize` | `store -> req -> user -> ST (store * ...)` | `store -> req -> user -> entropy:bytes{...} -> Tot (store * ...)` |
| `issue_tokens_helper` | `store -> code -> ST (store * token_response)` | `store -> code -> entropy:bytes{...} -> Tot (store * token_response)` |
| `token_exchange` | `store -> req -> ST (store * token_response)` | `store -> req -> entropy:bytes{...} -> Tot (store * token_response)` |

**Downstream lemma impact:** None. The existing lemmas in AuthCode.Flow.fst are
all about store invariants (Seq.length, code.state, code.nonce, etc.) and do not
depend on the randomness properties of generated codes. Adding an entropy
parameter does not affect these proofs — the lemmas will require a minor
signature update but the proof bodies (`()`) remain unchanged.

**`modifies_none` postcondition:** Currently, the ST functions assert
`modifies_none h0 h1`. With Tot, there is no heap and this postcondition
is dropped entirely. The functional property (e.g., `Seq.length store'.codes =
Seq.length store.codes + 1`) is preserved as a Tot postcondition on the return
value.

### 5.2 `StepUp.fst` (fstar/stepup/StepUp.fst)

**Functions affected:**

| Function | Current Signature | Proposed Signature |
|---|---|---|
| `issue_challenge` | `client -> session -> request -> now -> ttl -> Tot stepup_challenge` | `client -> session -> request -> now -> ttl -> entropy:bytes{...} -> Tot stepup_challenge` |

**Downstream lemma impact:**

- `lemma_issue_binds_inputs`: Gains entropy param. Proof body (`()`) unchanged
  — the lemma asserts field equality (client, session, request, timestamps),
  which does not depend on the challenge ID value.
- `lemma_issue_bounds`: Gains entropy param. Proof body (`()`) unchanged —
  asserts `issued_at <= expires_at`.
- `lemma_complete_rejects_replay`: No change (does not call `issue_challenge`).
- `lemma_stepup_enforced`: No change (does not call `issue_challenge`).

### 5.3 Other Callers

A grep for `open Random` and direct calls to `generate_secure_random` / `fresh_challenge_id`:

- `fstar/authcode/AuthCode.Flow.fst` — covered above
- `fstar/stepup/StepUp.fst` — covered above
- No other F\* modules import `Random` directly.

### 5.4 Rust-Side Callers

The Rust FFI boundary in `crates/ffi/src/lib.rs` (line 1243) uses
`rand::rngs::OsRng` directly. The DRBG integration at the Rust level
(task C-3) will:

1. Add a `drbg_generate` FFI function that accepts a 32-byte entropy seed.
2. Modify the existing token generation paths to call `fill_random` from
   `crates/crypto/src/rand.rs` to obtain entropy, then pass it to the
   verified DRBG.
3. The `crates/crypto/src/rand.rs` module already centralizes all RNG usage
   and provides `random_bytes(32)` for seed acquisition.

---
