# Crypto Extraction Roadmap (指示書1)

Last updated: 2026-07-24

Status: active plan

Owner: Verification

Audience: verification contributors, maintainers

*Created: 2026-03-01*
*Last updated: 2026-07-24*

This document defines the strategy for reducing Aegaeon's `assume val` count
toward zero by replacing trust boundaries with verified implementations.

---

## 1. Goal

Systematically eliminate all non-permanent `assume val` declarations in the F\*
verification suite. Each assume val is either:
- **Proved** — replaced by a concrete implementation with a machine-checked proof
- **Documented** — classified as a permanent trust boundary with explicit
  justification and risk assessment

The long-term target is to have every remaining assume val be a deliberate,
well-justified trust boundary — not an artifact of incomplete proof engineering.

---

## 1.1 Crypto Profile Boundary (per instance)

The strong-constraint verification claim applies **only** to IdP/RP/trust-chain
instances configured with the **verified allowlist** (HACL*/EverCrypt-backed).
Instances using the broader compat allowlist (ring/aws-lc/mbedtls/p256) remain
operationally supported but are **out of scope** for the formal claim.

See `docs/verification/claims/crypto-allowlist.md` for the canonical allowlist and
profile definition.

---

### 1.1.1 OIDC `RS256` slice note

The crypto-extraction roadmap continues to treat **broad RSA** as compat by
default. The promoted `RS256 Required Slice` / `RS256 Interop Slice` were
closed as **narrow boundary promotions**, not by silently expanding the general
verified allowlist.

## 1.2 Strong-Constraint Rule for Crypto / RNG

For strong-constraint verification claims, **crypto and RNG proofs must not
use identity/false/constant models** (including `irreducible` + `reveal_opaque`
shortcuts). These techniques are acceptable for internal proof engineering,
but they do **not** qualify for the formal claim boundary.

Therefore, the plan below **re-opens** the crypto and RNG boundary work and
requires HACL*/EverCrypt-backed implementations plus extraction and runtime
wiring for any algorithm that remains inside the verified allowlist.

**Fixed policy:** strong-constraint claims require **zero crypto-function
`assume val`** entries. Within Category A, the only crypto `assume val` entries
permitted are **hardness lemmas** (collision resistance / EUF‑CMA), which are
explicitly documented as permanent boundaries. Function-shaped runtime
assumptions must be documented as linkage contracts outside Category A.

**Impossibility note:** In realistic von Neumann systems with I/O, the project
cannot formally prove computational hardness (EUF‑CMA/collision resistance)
except as theorem premises, OS/device entropy sources (modeled as external
contracts), or external host/storage behaviour (modeled as explicit interface
contracts or TCB boundaries). These remain outside the formal claim.

---

## 2. Current State

| Metric | Value |
|---|---|
| Total assume vals | **12** (across 8 files) |
| Category A: Crypto trust boundaries | **6** (honest computational hardness Lemmas — all permanent) |
| Category B: FFI / C runtime stubs | **0** (all 9 eliminated via Low\* concrete) |
| Category B': HACL\* linkage stubs | **2** (`hacl_sha256`, `hacl_ed25519_verify` — verified foreign code) |
| Category B'': EverParse linkage stubs | **1** (`jose_header_entry_error_code` — generated parser bridge) |
| Category B''': OIDC hash runtime linkage stubs | **2** (`HashComputation.Low` C bridge contracts) |
| Category C: WASM host imports | **1** (Phase D eliminated 4 of 5 via raw buffer + HACL\* direct) |
| Category E: Encoding model boundaries | **0** (all 4 proved with concrete implementations) |
| ~~Category D: Mathematical axioms~~ | Merged into A |
| Reducible | **0** |
| Permanent (crypto hardness) | 6 |
| Permanent (HACL\* linkage) | 2 |
| Permanent (EverParse linkage) | 1 |
| Permanent (OIDC hash runtime linkage) | 2 |
| Permanent (WASM host) | 1 |
| Eliminated via Low\* concrete | 9 (FFI → `LowStar.Buffer`, incl. 1 bridge + 1 noextract pipeline) |
| Eliminated via HACL\* internalization (Phase D) | 4 (#8–#11: host\_bytes\_len, host\_bytes\_eq, host\_crypto\_sha256, host\_crypto\_verify\_signature) |

**Total proved/eliminated to date:** 76 assume vals eliminated across 19 proof campaigns.
Effective count excluding verified foreign code (B' and B''): **9**
(6 A + 2 B''' + 1 C).

**Strong-constraint status:** RNG boundary **CLOSED** (Phase C, 2026-03-05) —
`generate_secure_random` / `fresh_challenge_id` verified via HMAC-SHA256 DRBG
with explicit entropy. Remaining crypto `irreducible` models (signature
verification, hash, JWK thumbprint) are **open** until HACL*/EverCrypt-backed.

---

## 3. Phase 1 — Tautologies (COMPLETED)

**Status:** All 3 tautology assume vals proved on 2026-03-01.

| Function | File | Proof |
|---|---|---|
| `jws_verify_correct` | `Jose.Jws.Verify.fst` | `let` lemma; `()` suffices (bool excluded middle) |
| `disclosure_digest_deterministic` | `Jose.SdJwt.fst` | `let` lemma; `()` suffices (reflexivity of `==`) |
| `lemma_verify_signature_true` | `Dpop.Signature.fst` | `let` lemma; `()` suffices (premise = conclusion) |

**Impact:** 28 → 25 assume vals. All Negligible-risk entries eliminated.

---

## 4. Phase 2 — LowStar JSON FFI (ALL ELIMINATED)

**Status:** COMPLETED. All 8 assume vals eliminated + 1 bridge. Category B = 0.

### Assume vals targeted

| # | File | Function |
|---|---|---|
| 13 | `Jose.BytesBlock.fst` | `malloc_bytes` |
| 14 | `Jose.BytesBlock.fst` | `free_bytes` |
| 15 | `Jose.LowStar.Json.Stack.fst` | `malloc_bytes` (duplicate for KaRaMeL extraction) |
| 16 | `Jose.LowStar.Json.Stack.fst` | `collect_members_u32_stack_aux` |
| 17 | `Jose.LowStar.Json.Runtime.fst` | `malloc_entry_array` |
| 18 | `Jose.LowStar.Json.Runtime.fst` | `free_entry_array` |
| 19 | `Jose.LowStar.Json.Runtime.fst` | `free_entry_array_contents` |
| ~~20~~ | ~~`Jose.LowStar.Json.fst`~~ | ~~`json_parse_entries_to_c`~~ — **ELIMINATED** (concrete `noextract`) |

### Approach

Replace the C runtime implementations in `c/json_lowstar_runtime.c`
with extractable Low\* code. The existing C functions would become the
KaRaMeL extraction output rather than hand-written stubs.

**Key technique:** The `members_nested_live` ghost predicate (proved for
`index_member_with_liveness` in the Maximum Reduction round) establishes the
pattern for making nested buffer liveness invariants explicit. This same pattern
can be applied to `collect_members_u32_stack_aux`.

### Blockers

1. **Separation logic complexity** — The `free_entry_array_contents` function
   requires proving that nested key/value buffers within an entry array are
   mutually disjoint and individually live. This involves `entries_buffers_live`,
   `entries_buffers_disjoint`, and `entries_buffer_disjoint_from_nested`
   preconditions.
2. ~~**Spec/extractable bridge**~~ — **RESOLVED.** `json_parse_entries_to_c`
   replaced with concrete `noextract` implementation using `validate_members_utf8`
   (Low\* UTF-8) + spec-level pipeline. C runtime remains for KaRaMeL extraction.
3. **malloc\_bytes duplication** — Two copies exist (BytesBlock and Stack) to
   avoid Jose.\* dependencies in the KaRaMeL extraction path. Both must be
   addressed together.

### Success criteria

- All 8 assume vals replaced with concrete implementations
- KaRaMeL extraction produces equivalent C code
- `nix build .#verify-fstar` passes
- No regression in runtime behavior

---

## 5. Phase 3 — Crypto Boundaries (HACL*/EverCrypt Required)

**Status:** REOPENED under strong-constraint requirements

The prior `irreducible`/`reveal_opaque` shortcuts are **not acceptable** for
formal claims. We must replace them with **real, verified crypto** backed by
HACL*/EverCrypt and extracted into the runtime path.

### 5.1 Scope and Algorithm Policy

1. **Verified allowlist** includes only algorithms with HACL*/EverCrypt-backed
   implementations. RSA-based algorithms are **compat only** unless verified
   implementations land.
2. **Compat allowlist** remains for interoperability, but is **out of scope**
   for strong-constraint claims.
3. All compliance entries that depend on JWS/JWT/JWE must specify which profile
   applies and default to verified for formal claims.

### 5.2 Design (Recommended)

**A. F\* primitives (spec + executable):**
- Use EverCrypt/HACL modules for SHA-256 and HMAC.
- Add verified signature verification for Ed25519 and P-256 (EverCrypt).
- Remove `irreducible` placeholders in:
  - `Jose.Rsa_signatures.fst` (Ed25519 path)
  - `Jose.Jws.Verify.fst` (JWS verification)
  - `Dpop.Signature.fst` (DPoP signature)
  - `Jose.SdJwt.fst` (digest / disclosure)
  - `Jose.Jwk_thumbprint_uri.fst` (thumbprint hash)

**B. Extraction + FFI wiring:**
- Extract verified primitives via KaRaMeL.
- Provide a thin, total FFI layer in `crates/ffi` that exposes only verified
  operations.
- Rust crypto paths must select verified FFI when a verified profile is active.

**C. Constant-time enforcement:**
- Add dudect coverage for extracted primitives (HMAC, signature verify, hash).
- Keep `check_crypto_calls.py` and `check_runtime_drift.py` as fail-close gates.

### 5.3 Deliverables

1. Verified allowlist shrinks to HACL*/EverCrypt-backed algorithms only.
2. All crypto checks in verified profile use extracted primitives exclusively.
3. No `irreducible` or identity/false model remains for crypto or RNG.

### 5.4 Exit Criteria

- `nix build .#verify-fstar` passes.
- Verified profile path uses only extracted HACL*/EverCrypt primitives.
- dudect passes for all verified primitives.
- CI fails if Rust bypasses verified crypto (crypto call detection).

### 5.5 RNG Boundary (Strong-Constraint Requirement) — **COMPLETED** (2026-03-05)

**Phase C delivery:**
- `fstar/crypto/Drbg.HmacSha256.fst`: HMAC-SHA256 DRBG per NIST SP 800-90A
  §10.1.2. 0 assume val, 0 admit, 5 verified lemmas. `hmac_sha256` delegates
  to `Verified.Crypto.Bridge.hmac_sha256` (HACL\* `Spec.Agile.HMAC`).
- `fstar/crypto/Random.fst`: refactored — `generate_secure_random` and
  `fresh_challenge_id` take explicit 32-byte entropy, delegate to DRBG. No
  `irreducible`. All DRBG output bytes used via `bytes_to_char_list` +
  `string_of_list`. All functions Tot (ST eliminated).
- `fstar/authcode/AuthCode.Flow.fst` and `fstar/stepup/StepUp.fst`: updated
  to pass entropy explicitly. ST→Tot migration complete. All lemmas preserved.
- `crates/crypto/src/drbg.rs`: Rust DRBG implementation (same algorithm as
  F* spec). 10 tests. `drbg_random_bytes(n)` combines `getrandom` + DRBG.
- `crates/crypto/src/rand.rs`: token/nonce/identifier generation functions
  (`random_bytes`, `fill_random`, `random_base64url`, `ring_random_nonce_32`)
  route through DRBG. No direct `getrandom` calls remain in the `rand` module.
  **Scope note:** Signing key generation and ECDSA/RSA-PSS nonce generation
  (`crates/crypto/src/signing.rs`) remain on `ring::rand::SystemRandom` /
  `aws_lc_rs::rand::SystemRandom` — these are outside Phase C scope (signature
  primitives are Phase 3B/HACL\* work, not RNG boundary).

Exit criteria met:
- No RNG-related `irreducible` in any crypto module (0 occurrences).
- `hmac_sha256` in DRBG module now delegates to HACL\* Bridge (0 assume vals).
- DRBG construction fully verified. Rust token/nonce/identifier generation
  routes through the verified DRBG construction. Signing key generation
  remains on `ring`/`aws-lc-rs` SystemRandom (Phase 3B scope).
- Design: `docs/verification/workplans/rng/README.md`.
- Commits: `f9a0a5c` (initial), `0510efb` (strong-constraint fix).

---

## 6. Phase 4 — WASM Host Imports (1 assume val)

**Priority:** Long-term (6+ months)
**Effort:** Requires architecture change

### Remaining assume vals

| # | File | Function |
|---|---|---|
| 25 | `VerifiedCore.Api.Claims.Runtime.fst` | `host_replay_store_check_and_store` |

### Approach

Phase D eliminated `host_bytes_len`, `host_bytes_eq`, `host_crypto_sha256`,
and `host_crypto_verify_signature` by internalizing HACL\* SHA-256 and Ed25519
and using raw buffer pairs in the C exports layer. The replay store remains a
permanent host boundary because it requires persistent, concurrent state.

### Blockers

1. **WASM crypto**: The WebAssembly execution model does not natively support
   cryptographic operations. Embedding HACL\* C output into WASM via
   wasm32-unknown-unknown or Emscripten is possible but significantly increases
   module size and complexity.
2. **Replay store**: `host_replay_store_check_and_store` requires persistent
   state across invocations. A pure WASM module cannot maintain persistent state
   without host cooperation.
3. **Constant-time guarantees**: `host_bytes_eq` has a security contract
   requiring constant-time comparison. Verified constant-time code in WASM
   depends on the runtime not optimizing away the constant-time property.

### Assessment

These assume vals are **permanent for the WASM compilation target**. The host
boundary is an inherent architectural property of the WASM deployment model.
The mitigation strategy (host contract documentation + C ABI reference
implementation + 59 WASM smoke tests) is appropriate.

---

## 7. Decision Matrix

| Phase | Assume vals | Effort | Benefit | ROI | Recommendation |
|---|---|---|---|---|---|
| **Phase 1** (Tautologies) | 3 | Trivial (done) | Eliminates all Negligible-risk entries | **Excellent** | **COMPLETED** |
| **Phase 2** (LowStar FFI) | 8 | 2-4 weeks | Eliminates all Medium-risk FFI stubs | **Good** | **Next quarter** |
| **Phase 3A** (Crypto — irreducible) | ~3 | 1-2 weeks | Reduces some crypto boundaries | Moderate | Opportunistic |
| **Phase 3B** (Crypto — HACL\*) | ~3-5 | 3-6 months | Verified crypto for covered algorithms | Low | Defer unless compliance requires |
| **Phase 3C** (Crypto — permanent) | ~5 | N/A | Cannot be eliminated | N/A | **Document as permanent** |
| **Phase 4** (WASM host) | 5 | 6+ months | Eliminates host boundary | **Low** | **Document as permanent** |

---

## 8. Recommendation

### Immediate (done)
- Phase 1: All 3 tautologies proved.

### Completed (Q1 2026)
- Phase 1: All 3 tautologies proved (28 → 25).
- Phase 2: 6 of 8 LowStar JSON FFI stubs replaced with concrete Low\*
  implementations using `LowStar.Buffer` separation logic (25 → 19 → 13).
- Phase 3A: 6 crypto assume vals eliminated via `irreducible` technique
  (jws\_verify, disclosure\_digest, verify\_rsa\_pss, verify\_ed25519,
  verify\_signature, jwk\_thumbprint).

### Remaining work
- Phase 2: **COMPLETE.** All 9 FFI stubs eliminated. `json_parse_entries_to_c`
  replaced with concrete `noextract` implementation. Category B = 0.
- Phase 3B/3C: Crypto library integration is high effort with uncertain ROI.
  The current mitigations (FIPS-validated aws-lc-rs, Tamarin cross-validation,
  `irreducible` where applicable) provide adequate assurance. The promoted
  RS256 verifier now delegates to `aws-lc-rs`; HACL*/verified RSA integration
  remains future work rather than current claim closure.
- Phase 4: WASM host imports are inherent to the deployment architecture.
  The host contract documentation and reference implementation are the
  appropriate mitigation.

### Current state

- **12 assume vals** remaining across 8 files
- **6 crypto Lemma properties** (permanent) — honest computational hardness (SHA-256 CR, Ed25519 EUF-CMA)
- **2 HACL\* linkage assumptions** (permanent) — verified foreign code boundary
- **1 EverParse linkage assumption** (permanent) — generated parser bridge
- **2 OIDC hash runtime linkage assumptions** (permanent) — local C bridge contracts
- **1 WASM host import** (permanent) — replay store
- **0 Category A crypto function assume vals** — all eliminated (11 via `irreducible` + `reveal_opaque`, 1 via Bridge delegation)
- **0 FFI stubs** — Category B fully eliminated (all 9 proved via Low\*)
- **0 encoding model boundaries** — Category E fully eliminated (all 4 proved with concrete implementations)
- Every remaining assume val is a deliberate architectural boundary with
  explicit justification and CI-enforced drift detection
