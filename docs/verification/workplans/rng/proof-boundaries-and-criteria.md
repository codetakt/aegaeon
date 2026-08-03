# RNG Proof Boundaries And Completion Criteria

Last updated: 2026-07-08

Status: active plan

Owner: Verification

Audience: verification contributors, maintainers

This document is part of the split DRBG and entropy-input workplan.

## 6. Modeling Limitation Resolution

### 6.1 Former Limitation (pre-Phase C)

```fstar
(* Former: fresh_challenge_id was Tot with irreducible constant model *)
irreducible  (* historical — now replaced with assume val DRBG *)
let fresh_challenge_id (_:unit) : Tot challenge_id = "challenge_placeholder"

(* Problem: this is provable *)
assert (fresh_challenge_id () == fresh_challenge_id ())
```

Since `fresh_challenge_id` takes `unit` and is `Tot`, calling it twice with
the same argument always returns the same result. The `irreducible` attribute
hid the constant value from SMT, but it could not prevent SMT from deducing
`f x == f x` for any pure function `f`.

**Impact:** Proofs cannot rely on uniqueness, freshness, or unpredictability
of challenge IDs. The existing code documents this limitation explicitly
(Random.fst lines 27-31).

### 6.2 Resolution with Explicit Entropy

```fstar
(* Proposed: fresh_challenge_id takes entropy *)
val fresh_challenge_id:
  entropy:bytes{Bytes.length entropy = 32} -> Tot challenge_id

(* Now: determinism is explicit — same entropy implies same output *)
(* fresh_challenge_id e1 == fresh_challenge_id e2  when  e1 == e2 *)
(* The converse (e1 <> e2 ==> output differs) is NOT provable; see §7 *)
```

With explicit entropy:
- **Provable (determinism):** `fresh_challenge_id e1 == fresh_challenge_id e2`
  when `e1 == e2` (same seed → same output, since DRBG is a pure function).
- **NOT provable (injectivity):** `e1 <> e2 ==> fresh_challenge_id e1 <> fresh_challenge_id e2`
  is NOT provable from the `assume val` HMAC model alone, because SMT has no
  injectivity axiom for `hmac_sha256`. This is an **assumed property** that
  holds at runtime (HMAC-SHA256 is a PRF) but is not modeled in F\*.
- **Improvement over status quo:** The current `fresh_challenge_id ()` allows
  SMT to prove `f () == f ()` unconditionally. The new signature prevents this
  unless the caller can prove `e1 == e2`, which is a strictly better model.

### 6.3 What Can Be Proved

With the DRBG-based design, the following properties are provable in F\*:

1. **Determinism:** Same entropy → same output.
   `drbg_generate (drbg_instantiate s) n == drbg_generate (drbg_instantiate s) n`

2. **Output length:** Generated output has exactly the requested length.
   `let (_, r) = drbg_generate st n in Bytes.length r = n`

3. **State monotonicity:** Each generate increments the reseed counter.
   `let (st', _) = drbg_generate st n in st'.reseed_counter = st.reseed_counter + 1`

4. **Reseed resets counter:**
   `(drbg_reseed st e).reseed_counter = 1`

5. **Distinctness (NOT provable, runtime assumption):** If `e1 <> e2` then
   `fresh_challenge_id e1 <> fresh_challenge_id e2` — requires HMAC injectivity,
   which the `assume val` model does NOT provide. This is a runtime property
   of HMAC-SHA256, not a verified specification property. See Section 7.

### 6.4 What Cannot Be Proved (Acceptable Limitations)

- **Unpredictability:** That an adversary cannot predict output without knowing
  the entropy. This is a computational security property, not a symbolic one.
  Tamarin models this at the protocol level (Dolev-Yao).
- **Entropy quality:** That the OS RNG provides high-quality entropy. This is
  outside the F\* model (runtime property of `getrandom`).

---

## 7. HMAC-SHA256 Modeling

> **Update (2026-07):** the `hmac_sha256` `assume val` described in this
> section was **eliminated** in Phase A completion by delegating to
> `Verified.Crypto.Bridge.hmac_sha256` (HACL\* `Spec.Agile.HMAC`). §7.1–§7.5
> are retained as historical design rationale; the current axiom set is
> defined solely by
> `docs/verification/claims/assumptions/current-register.md`, and the runtime
> HMAC contract is RC-3 in
> `docs/verification/claims/assumptions/runtime-contract-register.md`.

### 7.1 Trust Boundary

The HMAC-SHA256 primitive is modeled as an honest `assume val` in F\*:

```fstar
assume val hmac_sha256:
  key:bytes{Bytes.length key = 32} ->
  data:bytes ->
  Tot (r:bytes{Bytes.length r = 32})
```

This is a **permanent crypto trust boundary**. Unlike the `irreducible`
constant models used for signature verification and hash computation
(see `docs/verification/claims/assumptions/current-register.md` Section 3), this `assume val`
contains **no identity/false/constant implementation** and is therefore
**strong-constraint compliant** per `../crypto-extraction-roadmap.md` §1.2.

### 7.2 Properties Available to DRBG Proofs

Since `hmac_sha256` is an `assume val`, the SMT solver knows only:
- **Input type:** key is 32 bytes, data is arbitrary bytes.
- **Output type:** result is exactly 32 bytes.
- **Purity:** It is Tot, so `hmac_sha256 k d == hmac_sha256 k d` (determinism).

The DRBG proofs use only these three facts. They do NOT require:
- PRF/MAC security of HMAC
- Collision resistance of SHA-256
- Any relationship between input and output values

### 7.3 Why This Is Sufficient

The DRBG proofs verify the **construction** — that the state update, generate,
and reseed operations correctly compose HMAC calls per SP 800-90A. The
**security** of the DRBG (unpredictability, backtracking resistance) depends on
HMAC being a PRF, which is the runtime implementation's responsibility
(`hmac` + `sha2` crates via `crates/crypto/src/mac.rs` at runtime).

This separation is standard practice:
- The F\* model verifies the construction is correct.
- The Tamarin model verifies the protocol uses randomness correctly (247 lemmas).
- The runtime provides actual cryptographic strength.

### 7.4 Relationship to Existing HMAC Infrastructure

The new `Drbg.HmacSha256.hmac_sha256` is **separate** from
`HACL_Wrapper.hmac_sha256` (`fstar/HACL_Wrapper.fst:42`). Rationale:

- `HACL_Wrapper.hmac_sha256` has no length refinement on output (returns
  `bytes` not `bytes{length = 32}`). The DRBG needs the 32-byte guarantee.
- `Drbg.HmacSha256.hmac_sha256` requires `key` to be exactly 32 bytes. The
  HACL wrapper accepts arbitrary key lengths (per RFC 2104 key padding).
- At extraction time, both can delegate to the same underlying HMAC
  implementation. The F\* modules are separate for type safety.

### 7.5 Assume Val Impact

This design introduces **one new assume val** (`hmac_sha256` in
`Drbg.HmacSha256.fst`) but **eliminates two former irreducible stubs**
(`generate_secure_random` and `fresh_challenge_id` in `Random.fst`).

The assume val count is **5 → 6** (1 crypto `hmac_sha256` + 5 WASM host).
Unlike the former `irreducible` constant model (`Bytes.create 32ul 0uy`),
the new `assume val` is **strong-constraint compliant** — it contains no
identity/false/constant implementation.

---

## 8. Completion Criteria

| Criterion | Metric | Owner |
|---|---|---|
| `generate_secure_random` no longer irreducible | Grep for `irreducible.*generate_secure_random` returns 0 | C-2 |
| `fresh_challenge_id` no longer irreducible | Grep for `irreducible.*fresh_challenge_id` returns 0 | C-2 |
| Both take explicit entropy parameter | Signature includes `entropy:bytes{Bytes.length entropy = 32}` | C-2 |
| DRBG construction fully verified | `Drbg.HmacSha256.fst` in verify_fstar.sh, 0 admit, 0 assume val (former `hmac_sha256` eliminated via Bridge delegation) | C-1 |
| Output length correctness | `drbg_generate` postcondition: `Bytes.length r = n` | C-1 |
| State monotonicity | `drbg_generate` postcondition: reseed_counter increments | C-1 |
| Determinism | Lemma: same seed + same request → same output | C-1 |
| HMAC-SHA256 is honest assume val | `assume val hmac_sha256` (no constant model) — strong-constraint compliant | C-1 |
| Callers updated | AuthCode.Flow + StepUp compile with new signatures | C-2 |
| Existing lemmas preserved | All existing lemma proofs pass with `()` | C-2 |
| Rust FFI wired | `crates/crypto` rand.rs routes ALL public API through DRBG | C-3 |
| `nix build .#verify-fstar` green | Full F\* verification passes | C-4 |
| No regression in Rust tests | `cargo test --workspace` passes | C-4 |

---

## 9. File Map

| File | Status | Description |
|---|---|---|
| `fstar/drbg/Drbg.HmacSha256.fst` | **New** | DRBG state, instantiate, generate, reseed, update |
| `fstar/crypto/Random.fst` | **Modified** | Remove irreducible, add entropy param, delegate to DRBG |
| `fstar/authcode/AuthCode.Flow.fst` | **Modified** | Add entropy param to authorize/issue/token_exchange, ST→Tot |
| `fstar/stepup/StepUp.fst` | **Modified** | Add entropy param to issue_challenge |
| `scripts/verify_fstar.sh` | **Modified** | Add Drbg.HmacSha256 to MODULES |
| `crates/crypto/src/drbg.rs` | **New** | Rust DRBG (mirrors F* spec), `drbg_random_bytes(n)` entry point |
| `crates/crypto/src/rand.rs` | **Modified** | All public API routes through DRBG (0 direct getrandom) |
| `crates/jose/src/algorithms/mod.rs` | **Modified** | Removed unused `is_verified()` |
| `docs/verification/claims/assumptions/current-register.md` | **Modified** | assume val count 5→6 (+ hmac_sha256) |
| `docs/verification/workplans/crypto-extraction-roadmap.md` | **Modified** | Update Phase 3 / Section 5.5 status |

### Commits

| Hash | Description |
|---|---|
| `f9a0a5c` | Phase C initial delivery (C-0 through C-5) |
| `0510efb` | Strong-constraint fix (H1 assume val, H2 DRBG wiring, M1 full-byte model, L1 cleanup) |

---

## 10. Risk Assessment

| Risk | Severity | Mitigation |
|---|---|---|
| HMAC-SHA256 trust boundary | Low | F\* spec delegates to `Verified.Crypto.Bridge` (HACL\* spec); runtime executes via RustCrypto `hmac`/`sha2` crates (RC-3); Tamarin cross-validates |
| Per-request DRBG instantiation overhead | Negligible | 2 HMAC calls for instantiate + 1 per 32 bytes; < 1 microsecond at runtime |
| ST→Tot migration breaks downstream code | Low | Only 2 caller files (AuthCode.Flow, StepUp); no external dependents |
| Entropy quality depends on OS RNG | Low | `getrandom` is the standard Rust primitive; backed by kernel CSPRNG; documented as runtime contract |
| Z3 performance with DRBG generate loop | Medium | Use `--fuel` / `--z3rlimit` tuning; DRBG generate loop is bounded (n ≤ 65536, output per iteration = 32) |
