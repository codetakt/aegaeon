# Current F* Assumption Register

Last updated: 2026-09-11

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, maintainers

This document is part of the split F* assumption register.

## Contract Qualification

This is an inventory of existing assumptions and their historical rationale,
not an accepted set of premises for foundation activation. The
[server contract](../assurance-case/assurance-contract.md) requires a soundness
audit. The concrete SHA-256 injectivity assumptions, the `ensures True`
Ed25519 statement and the different-key JWS assumption were removed on
2026-09-11 (see §3.1–§3.4); the dependent SD-JWT, hash, PKCE and JWS theorems
now carry explicit finite bad-event premises or exhibit collision witnesses.
The computational premises that those events are infeasible are recorded in
`spec/assumption-register.json` with status `specified-not-attested`; no
register entry is `accepted`, so nothing here activates a guarantee.
The effective premises of a verification run (tracked `assume val`
declarations, the builder-injected `C.Loops` module, lax-loaded provider
sources and provider `.checked` imports) are reconstructed by
`scripts/validation/assumption_graph.py`; see
[F\* assumption graph](../../fstar/assumption-graph.md). Historical
descriptions below as "honest" or "permanent" do not discharge any
obligation. See [contract status](../assurance-case/contract-status.md).

## 1. Introduction

### What is an `assume val`?

In F\*, an `assume val` declares a function signature and its type-level
contract (preconditions and postconditions) without providing a proof or
implementation. The F\* type-checker accepts the signature on trust and uses it
in downstream proofs. If the assumed contract is wrong, any proof that depends
on it may be unsound.

`assume val` is distinct from `admit()`:
- **`admit()`** skips a specific proof obligation inline. Aegaeon has **0** of these.
- **`assume val`** declares an entire function as an axiom. Aegaeon has **6** of these
  across **4 files** (in hand-written F\* specification modules under `fstar/`;
  test modules under `tests/fstar/` and generated modules under `generated/` are
  excluded from this count but generated modules referenced by `VerifiedReqs`
  entries remain within the formal claim).
  The 6 are all linkage contracts: 2 HACL\* linkage (B'), 2 OIDC hash runtime
  linkage (B'''), 1 EverParse linkage (B''), and 1 WASM host (C). No
  cryptographic hardness statement is an `assume val` any more.
- **Tracked declarations are not the whole effective premise set.** A
  verification run additionally admits the builder-generated `C.Loops.fst`
  (3 `assume val`s: `while`, `do_while`, `total_while`, injected by
  `scripts/flake/verify_fstar.sh` and shadowing the KaRaMeL module), every
  HACL\* and Steel module in the dependency closure (loaded lax from source
  because those providers ship no `.checked` files), and the EverParse/LowParse
  modules whose `.checked` artifacts become stale through the shadowed
  `C.Loops` and are therefore also lax-loaded. These are indexed per pass by
  the assumption graph and registered in `spec/assumption-register.json`.

### Why do assume vals exist?

Assume vals arise at boundaries where F\* cannot (or should not) reason about
the implementation. Five categories remain:

1. **Cryptographic trust boundaries** — **0 assume vals.** Cryptographic
   hardness is no longer stated inside F\*. The six former "honest
   assumption" lemmas were mathematically wrong or empty (universal
   injectivity of a fixed-output hash; an `ensures True` conclusion; a
   raw-key-inequality statement refuted by HMAC key padding). They are
   replaced by *definitions* of bad events (`sha256_collision`,
   `hash_collision`, `truncation_collision`, `disclosure_digest_collision`,
   `string_encoding_collision`, `ed25519_forgery`, `jws_mac_forgery`,
   `jws_eddsa_forgery`) and *proved* case-split theorems; the dependent
   protocol theorems are conditional on the absence of the event for the
   concrete issuance or exhibit a witness. The computational premises are
   register entries `A-SHA256-CR`, `A-SHA256-TRUNC128-CR`,
   `A-HMAC-SHA2-EUF-CMA` and `A-ED25519-EUF-CMA` (§3.1–§3.4).
2. ~~**FFI/C runtime**~~ — **ELIMINATED.** All 9 FFI stubs replaced with
   concrete Low\* implementations.
3. **WASM host imports** — The portable verification module (`verified_core.wasm`)
   calls host-provided functions for replay storage. F\* specifies the callback
   contracts. **1 assume val** (Phase D eliminated 4 of the original 5 by
   internalizing crypto via HACL\* and moving handle resolution to the C exports layer).
4. **HACL\* linkage stubs** — **2 assume vals.** The `VerifiedCore.Crypto.Hacl`
   module declares `hacl_sha256` and `hacl_ed25519_verify` as `assume val` with
   Low\* pre/postconditions. These are **not** host callbacks — they are linking
   stubs for **HACL\*-verified C code** already compiled into the WASM binary.
   The module is marked `-library` in KaRaMeL (not extracted). A thin C bridge
   (`c/verified-core/hacl_bridge.c`) maps extern names to HACL\* C functions.
   These represent a qualitatively different trust boundary than host callbacks:
   the implementations are themselves formally verified by the HACL\* project.
5. **EverParse linkage stub** — **1 assume val.** The JOSE header entry
   runtime bridge exposes a generated EverParse validator through a narrow,
   read-only Stack/C boundary.
6. **OIDC hash runtime linkage stubs** — **2 assume vals.** The
   `HashComputation.Low` runtime bridge copies bounded Low\* buffers and
   delegates SHA-2 computation to the C runtime shim backed by HACL\*/EverCrypt.
7. ~~**Encoding model boundaries**~~ — **ELIMINATED.** The 4 Base64url/Base64
   `assume val` properties (roundtrip x2, injectivity x2) in `FStar.Base64.fst`
   have been replaced with concrete encode/decode implementations and proved
   lemmas. Category E = 0.
8. ~~**Mathematical axioms**~~ — Eliminated. SHA-256 collision resistance is
   neither a tautology on an identity model nor an `assume val`; it is an
   external computational premise attached to a named event (§3.4).

**Strong-constraint rule (fixed policy):** cryptographic hardness claims must be
modeled as explicit premises, never as fake concrete proofs and never as
universal statements that are false for a fixed-output function. Inside F\*
they appear only as named bad events with proved case splits; the hardness
premise itself lives in `spec/assumption-register.json`. Runtime
function-shaped assumptions are explicit linkage contracts (`HACL*`,
`EverParse`, OIDC hash runtime, WASM host), not hidden claims that the project
proves third-party or host behaviour.

### Formal Claim Scope (VerifiedReqs)

The official verification claim applies only to requirements marked `verified`
in the compliance matrix **with formal proof references**. We define:

```text
VerifiedReqs = { r ∈ compliance-matrix
               | r.status = verified ∧ r.proof has a formal reference }
```

The assumptions listed in this register are the **only** unproved axioms
**inside the F\* logic** that qualify the claim over `VerifiedReqs`. Runtime
and TCB contracts that the claim additionally presupposes (entropy quality,
seed no-reuse, HMAC PRF security, replay-store atomicity, and others) are
enumerated in [runtime-contract-register.md](runtime-contract-register.md).
Any requirement outside `VerifiedReqs` is out of scope for formal claims,
regardless of implementation status.

### Crypto Profile Boundary

The strong‑constraint verification claim applies **only** to IdP/RP/trust‑chain
instances configured with the **verified allowlist** (see
`docs/verification/claims/crypto-allowlist.md`). Instances using a broader compat
allowlist (e.g., RSA/ECDSA paths implemented via ring/aws‑lc/mbedtls/p256) are
explicitly **out of scope** for the formal claim, even if they are supported at
runtime.

The OIDC `RS256 Required Slice` and server-side `RS256 Interop Slice` are now
explicit boundary-promotion exceptions recorded in
`spec/compliance-matrix.yaml` (`OIDC-1-010`, `OIDC-5-002`, `7523-116`,
`7523-402`) and the
corresponding OIDC slice documents. Remaining broad RSA, PS, ES, and
non-promoted JOSE interoperability paths remain compat-only.

### Reduction History

The project has systematically reduced assume vals through 10 proof campaigns:

| Date | Count | Delta | Key reductions |
|---|---|---|---|
| Phase 7 start | 75 | — | Initial count |
| Phase 7 end | 67 | -8 | AuthCode.Store seq lemmas, ParBinding, Jose.LowStar.Json, Pkce |
| Phase 8 restructuring | 62 | -5 | TrustMark, DeviceAuthz, OidcRp.Properties, Management.ClientLifecycle |
| P1 Store+Flow+SdJwt | 50 | -12 | AuthCode.Store (5→0), AuthCode.Flow (5→1), Jose.SdJwt (6→3) |
| Federation Policy | 44 | -6 | Federation policy algebra (resolve, restrictive, monotone, anchor, subsumes) |
| P1 Crypto Boundary | 33 | -11 | HashComputation.Model, Jose canonicalize, Pkce.s256, Pkce.Verification, Dpop.Ath |
| HeaderParser Spec/Stack | 32 | -1 | read\_u8\_safe eliminated via pure Seq parser |
| P0-P2 Reduction | 31 | -1 | ProtectedResourceMetadata.is\_known\_as\_issuer |
| Maximum Reduction | 28 | -3 | C.Loops deleted, JWS Verify consolidated, index\_member + allocate\_bytes proved |
| TCB Hardening | 25 | -3 | jws\_verify\_correct, disclosure\_digest\_deterministic, lemma\_verify\_signature\_true proved (tautologies) |
| Crypto Irreducible | 19 | -6 | jws\_verify, disclosure\_digest, verify\_rsa\_pss, verify\_ed25519, verify\_signature, jwk\_thumbprint → concrete `irreducible` |
| FFI Low\* Concrete | 17 | -2 | malloc\_bytes ×2 + free\_bytes → `LowStar.Buffer.malloc/free` (net -3 + 1 bridge) |
| FFI Low\* Phase 2 | 14 | -3 | collect\_members\_u32\_stack\_aux, malloc\_entry\_array, free\_entry\_array\_contents → concrete Low\* |
| FFI Low\* Phase 3 | 13 | -1 | free\_entry\_array → `Buffer.free` + ST effect + caller reorder |
| FFI Low\* Phase 4 | 12 | -1 | free\_bytes\_ffi → `Buffer.free` + freeable predicate propagation |
| FFI Low\* Phase 5 | 11 | -1 | json\_parse\_entries\_to\_c → concrete `noextract` (validate\_members\_utf8 + spec pipeline). Category B = 0. |
| Crypto reveal\_opaque | 5 | -6 | jws\_verify\_unforgeable, entity\_keys\_fresh, disclosure\_digest\_collision\_resistant, generate\_secure\_random, fresh\_challenge\_id, assumption\_collision\_resistance → proved via `reveal_opaque` |
| Phase A (HACL\*) | 12 | +6 | 3 Bridge crypto + 3 tautological proofs reverted to honest assume vals (identity/false models replaced with HACL\* specs) |
| Phase A Review v2 | 16 | +4 | 4 Base64url encoding model properties (roundtrip ×2, injectivity ×2) added to formalize previously-stub FStar.Base64 |
| Phase A Completion | 15 | -1 | Drbg.HmacSha256.hmac\_sha256 → Bridge delegation |
| Base64 Concrete Proofs | 11 | -4 | base64url\_roundtrip, base64url\_encode\_injective, base64\_roundtrip, base64\_encode\_injective → concrete encode/decode with proved lemmas |
| Phase D (WASM host) | 9 | -2 | host\_bytes\_len, host\_bytes\_eq, host\_crypto\_sha256, host\_crypto\_verify\_signature eliminated (−4); hacl\_sha256, hacl\_ed25519\_verify added (+2 HACL\* linkage) |
| JOSE EverParse Linkage | 10 | +1 | `jose_header_entry_error_code` added as an explicit Stack/C bridge to the generated JOSE header entry validator |
| OIDC Hash Runtime Linkage | 12 | +2 | `bytes_prefix_of_buffer` and `evercrypt_hash_incremental_hash` added as explicit Low\*/C bridge contracts for the OIDC hash runtime shim |
| Assumption boundary (2026-09-11) | 6 | -6 | `lemma_sha256_collision_resistant`, `lemma_sha256_of_string_collision_resistant`, `lemma_ed25519_unforgeable`, `assumption_collision_resistance`, `disclosure_digest_collision_resistant`, `jws_verify_unforgeable` removed as false/vacuous; replaced by bad-event definitions, proved case splits and external register premises |
| **Current** | **6** | | **82 eliminated total; 4 files; plus 3 builder-injected `C.Loops` premises and lax-loaded provider sources indexed by the assumption graph** |

### Relationship to VerifiedReqs

The formal definition of `VerifiedReqs` — the set of compliance-matrix entries
that carry assumption-qualified formal proofs — is given in
[claim-definition.md §0.2](../assurance-case/claim-definition.md#02-claim-scope).

The `assume val` declarations listed in §3 are the tracked unproved axioms
underlying `VerifiedReqs`, but they are **not** the whole effective premise
set: a proof also rests on the builder-injected `C.Loops` module (for the
EverParse-derived parsers and the Low\* JSON modules), on the HACL\*, Steel
and stale-cascade EverParse sources that F\* lax-loads, on the ulib/EverParse/
KaRaMeL `.checked` artifacts it imports, and on the external computational
premises attached to the bad events of §3.1–§3.4. The per-pass closure is
reconstructed (at module granularity, conservatively) by
`scripts/validation/assumption_graph.py`.

If any assume val's contract is violated at runtime (e.g., a crypto library
returns incorrect results, or a WASM host fails to satisfy its callback
contract), the dependent proofs may be unsound.

---

## 2. Assumption Categories

### Category A: Cryptographic Trust Boundaries

These model security properties of cryptographic algorithms. They are
**permanent** — proving them would require reimplementing the crypto in F\*.
For strong‑constraint claims, only instances using the **verified allowlist**
are in scope; compat crypto paths remain outside the formal claim even if they
are supported at runtime.

**Policy note:** there are **no Category A assume vals** at all. Category A
crypto functions (hash/HMAC/signature verification) are real HACL\* spec
computations; the hardness premises are external register entries attached
to named events (see §3.1–§3.4). Function-shaped runtime assumptions in B',
B'', and B''' are explicit linkage contracts, not hidden cryptographic
security lemmas.
The OIDC `RS256 Required Slice` and `RS256 Interop Slice` were closed as
**boundary-promotion tasks**, not by increasing the Category A `assume val`
surface. Broad RSA and non-promoted JOSE interoperability remain outside the
formal claim.

### Category B: FFI / C Runtime Stubs — ELIMINATED

All 9 original Category B assume vals (8 FFI stubs + 1 bridge) have been
replaced with concrete Low\* implementations. Category B = 0.

### Category C: WASM Host Imports

These declare contracts for functions provided by the WASM host environment.
They are **permanent** for the **portable WASM artifact** — the host is outside
the verification boundary. When the server links the native C output directly,
these host-import assumptions do **not** apply to the server runtime, only to
the distributed WASM module.

**Phase D update:** 4 of the original 5 Category C assume vals (#8–#11) have
been eliminated via the "raw buffer + HACL\* direct" approach. Only #12
(`host_replay_store_check_and_store`) remains.

### ~~Category D: Mathematical Axioms~~ — Merged into A

Formerly separate; collision resistance and unforgeability are now categorized
as crypto trust boundaries (Category A) since Phase A replaced all identity
models with honest assumptions on HACL\* spec implementations.

### ~~Category E: Encoding Model Boundaries~~ — ELIMINATED

All 4 Base64url/Base64 encoding `assume val` properties (roundtrip x2,
injectivity x2) have been replaced with concrete encode/decode implementations
and proved lemmas in `FStar.Base64.fst`. Category E = 0.

---

## 3. Full Assumption Register

### 3.1 JWS Signature Verification (Category A) — axiom REMOVED

**File:** `fstar/jose/Jose.Jws.Verify.fst` (with `fstar/crypto/Verified.Crypto.Hmac.KeyEquiv.fst`)

`jws_verify` is a real HACL\* dispatch (HMAC-SHA-2 for `HS256/384/512`,
Ed25519 for `EdDSA`, `false` otherwise), now `opaque_to_smt` so that the
lemmas in the module can reveal the dispatch body.

| # | Former declaration | Former statement | Why it was wrong | Replacement (all proved, no `assume val`) |
|---|---|---|---|---|
| 1 | `jws_verify_unforgeable` | `key1.k =!= key2.k /\ jws_verify key1 t = true ==> jws_verify key2 t = false` | HMAC pads keys shorter than the block with zero bytes, so `k` and `k ++ 0x00` are distinct raw keys with identical verification behaviour; the statement forbade every short-key HS256 verification (red control `RedJwsOldAxiom.fst`). It also named no key generation, signing oracle, freshness or compromise, so calling it EUF-CMA was a misnomer. | `mac_key_equiv` (extensional key equivalence per algorithm), `lemma_jws_verify_hs_key_equiv` (equivalent keys verify alike), `lemma_hmac_sha256_zero_pad_key_equiv` (machine-checked distinct-but-equivalent keys, via `friend Spec.Agile.HMAC`), `lemma_jws_verify_hs_accepts_mac` (the honest MAC is accepted: reachable success path), `jws_mac_forgery` / `jws_eddsa_forgery` (forgery events requiring honest key-generation provenance, a MAC/signing history and a compromised-key set) and `lemma_jws_verify_cases` (a verifying token is outside the key-generation domain, under a compromised key, honestly issued — possibly re-presented — or a qualified forgery event). Verification success never implies that the presenter knows the key. |

External premises (register, `specified-not-attested`): `A-HMAC-SHA2-EUF-CMA`
(PRF security of HMAC-SHA-2 implies MAC unforgeability for uniformly chosen,
uncompromised keys of adequate length) and `A-ED25519-EUF-CMA`. The HMAC
event checks an algorithm-specific generation record, key equivalence and
32/48/64-byte minima for HS256/384/512 on both generated and verifying keys.
`jws_verify` remains a primitive verifier with a nonempty-key guard; runtime
key-policy correspondence is not established. The Ed25519 events require the
public key in the honest key-generation history. These histories must come from
a consistent external game with honest generation and complete oracle/compromise
records; membership in an arbitrary list does not attest those properties.
Module-level graph binding does not discharge this argument-level obligation.

### 3.2 HACL\* Crypto Bridge (Category A) — axioms REMOVED

**File:** `fstar/crypto/Verified.Crypto.Bridge.fst`

The heavy wrappers (`sha256_hash`, `sha384_hash`, `sha512_hash`,
`ed25519_verify`) remain `irreducible` HACL\* spec computations; the thin
string wrapper `sha256_of_string` and the HMAC wrappers are `opaque_to_smt`.

| # | Former declaration | Former statement | Why it was wrong | Replacement (all proved) |
|---|---|---|---|---|
| 2 | `lemma_sha256_collision_resistant` | `sha256_hash a = sha256_hash b ==> a = b` | Universal injectivity of a 32-byte-output function on inputs of up to 2^32−1 bytes is false by counting (red control `RedHashInjectivity.fst`, `red_pigeonhole.py`). | `sha256_collision a b` (event: distinct in-range inputs, equal digests) and `lemma_sha256_hash_eq_cases` (`equal digests ==> equal inputs \/ sha256_collision`); SHA-384/512 counterparts. |
| 3 | `lemma_sha256_of_string_collision_resistant` | `sha256_of_string a = sha256_of_string b ==> a = b` | Same counting defect, and it silently assumed injectivity of `FStar.Bytes.bytes_of_string` (abstract in ulib, no lemma) through the same axiom. | `string_encoding_collision a b` (separate event for the abstract string→bytes boundary), `sha256_of_string_collision`, `lemma_sha256_of_string_eq_cases` (`equal outputs ==> equal strings \/ string_encoding_collision \/ sha256_collision (bytes a) (bytes b)`; base64url injectivity is a proved lemma so it adds no event), `lemma_sha2_limits_exceed_bytes` (the over-length fallback of the wrapper is unreachable for `FStar.Bytes`). |
| 4 | `lemma_ed25519_unforgeable` | `ed25519_verify pk m s = true ==> True` | Vacuous: provable by `()` (red control `RedEd25519Vacuous.fst`); it carried no unforgeability content. | `ed25519_signing_event` / `ed25519_message_signed` (honest signing history), `ed25519_forgery honest_keys history compromised pk m s` (key honestly generated, verifies, key uncompromised, message never honestly signed) and `lemma_ed25519_verify_cases`. Spec-level correctness of honest signatures is not proved here (residual). |

External premises: `A-SHA256-CR` (the `sha256_collision` event is
computationally infeasible for SHA-256 as specified in FIPS 180-4; generic
birthday bound 2^128; no numeric evaluation is produced) and
`A-ED25519-EUF-CMA` (Brendel, Cremers, Jackson, Zhao 2020; Bernstein et al.
2012). The string boundary `string_encoding_collision` and the runtime input
domain (Rust slices, C buffers) are symbolic-abstraction entries, not
cryptographic premises.

### 3.3 SD-JWT Digest (Category A) — axiom REMOVED

**File:** `fstar/jose/Jose.SdJwt.fst`

| # | Former declaration | Former statement | Why it was wrong | Replacement (all proved) |
|---|---|---|---|---|
| 5 | `disclosure_digest_collision_resistant` (SMTPat) | `e1 =!= e2 ==> disclosure_digest e1 =!= disclosure_digest e2` | Universal injectivity again, and SMTPat-triggered, so it was usable by any proof in the module without an explicit citation. | `disclosure_digest_collision`, `lemma_disclosure_digest_eq_cases`, `lemma_disclosure_digest_collision_witness` (a digest collision is a `sha256_of_string_collision`), the finite premises `no_collision_with_issued enc issued` / `no_presented_collision encs issued` over the concrete issuance, and the unconditional theorems `lemma_non_forgeability_or_collision` and `lemma_reconstruction_subset_or_collision` (any accepted forgery or out-of-set reconstructed claim yields an explicit collision witness `(enc, d)`). |

The composed disclosure-digest witness can be a string-encoding collision
or a SHA-256 collision on distinct byte images. Excluding the primitive collision
alone is insufficient; the `string_encoding_collision` boundary is separate.

**Downstream impact:** `forged_digest_not_in_build`, `lemma_non_forgeability`,
`lemma_digest_decode_claim_in_orig`, `lemma_reconstruct_acc_claims` and
`lemma_reconstruction_subset` now carry the finite no-collision premise;
`lemma_completeness`, `lemma_soundness_subset` and `lemma_no_duplicate` were
unaffected. Compliance entry: RFC 9901-001 (SD-JWT).

### 3.4 Hash Collision Resistance (Category A) — axiom REMOVED

**File:** `fstar/HashComputation.fst`

| # | Former declaration | Former statement | Why it was wrong | Replacement (all proved) |
|---|---|---|---|---|
| 6 | `assumption_collision_resistance` (SMTPat) | `i1 =!= i2 ==> compute_hash alg i1 =!= compute_hash alg i2` | Universal injectivity, SMTPat-triggered for every occurrence of `compute_hash`; it also claimed injectivity across the zero-byte fallback branch. | `hash_collision alg i1 i2`, `lemma_compute_hash_eq_cases`, `lemma_hash_collision_refines` (a model collision is a Bridge `sha*_collision`; the fallback is proved unreachable by `lemma_compute_hash_in_range`), `truncation_collision` (full digests differ, leftmost halves equal — the OIDC `at_hash`/`c_hash` form has only half the digest length and must not inherit the full-length premise), `oidc_hash_collision` and `lemma_oidc_hash_collision_cases`. |

External premises: `A-SHA256-CR`, `A-SHA384-CR` and `A-SHA512-CR` for
`hash_collision SHA256`, `hash_collision SHA384` and `hash_collision SHA512`,
respectively (256/384/512 output bits; generic birthday bounds 2^128/2^192/2^256),
`A-SHA256-TRUNC128-CR` for `truncation_collision SHA256` (generic bound 2^64).
`Pkce.fst` adds the analogous `s256_collision` and
`lemma_pkce_s256_binding_cases` for the PKCE S256 binding.

### 3.5 DRBG Crypto Trust Boundary (Category A) — ELIMINATED

**File:** `fstar/crypto/Drbg.HmacSha256.fst`

| # | Line | Function | Description | Runtime impl | Risk | Reducible? |
|---|---|---|---|---|---|---|
| ~~7~~ | — | ~~`hmac_sha256`~~ | **ELIMINATED** — replaced with concrete delegation to `Verified.Crypto.Bridge.hmac_sha256` (HACL\* `Spec.Agile.HMAC`). DRBG-specific precondition (key=32, data≤65) trivially satisfies Bridge preconditions (sha256\_max\_input ≈ 2^61, block\_length=64). | — | — | — |

### 3.7 Low\* Byte Buffer Allocation (Category B) — ELIMINATED

**File:** `fstar/jose/Jose.BytesBlock.fst`

| # | Line | Function | Description | Runtime impl | Risk | Reducible? |
|---|---|---|---|---|---|---|
| ~~13~~ | — | ~~`malloc_bytes`~~ | **ELIMINATED** — replaced with `let malloc_bytes len = Buffer.malloc HS.root 0uy len` (concrete Low\* allocation). Postcondition strengthened: `freeable`, `unused_in`, `modifies loc_none`. | — | — | — |
| ~~14~~ | — | ~~`free_bytes`~~ | **ELIMINATED** — replaced with `let free_bytes buf = Buffer.free buf` (concrete Low\* deallocation). Requires `freeable` precondition. | — | — | — |

**Note:** `Jose.BytesBlock.malloc_bytes` and `Jose.LowStar.Json.Stack.malloc_bytes`
are intentionally duplicated. The Stack module avoids Jose.\* dependencies for
clean KaRaMeL extraction. Both have been replaced with concrete implementations.

### 3.8 Low\* JSON Stack Layer (Category B) — ELIMINATED

**File:** `fstar/jose/LowStar/Json/Jose.LowStar.Json.Stack.fst`

| # | Line | Function | Description | Runtime impl | Risk | Reducible? |
|---|---|---|---|---|---|---|
| ~~15~~ | — | ~~`malloc_bytes`~~ | **ELIMINATED** — replaced with concrete `Buffer.malloc HS.root 0uy len` (Stack layer duplicate; see 3.9 note). | — | — | — |
| ~~16~~ | — | ~~`collect_members_u32_stack_aux`~~ | **ELIMINATED** — concrete 58-line recursive implementation with `members_nested_live` + `members_valid_lengths` ghost predicates and frame lemmas (`lemma_members_nested_live_preserved`, `lemma_members_valid_lengths_preserved`). | — | — | — |

### 3.9 Low\* JSON Runtime Layer (Category B) — ELIMINATED

**File:** `fstar/jose/LowStar/Json/Jose.LowStar.Json.Runtime.fst`

| # | Line | Function | Description | Runtime impl | Risk | Reducible? |
|---|---|---|---|---|---|---|
| ~~17~~ | — | ~~`malloc_entry_array`~~ | **ELIMINATED** — replaced with `let malloc_entry_array len32 = Buffer.malloc HS.root default_entry_out len32` (concrete Low\* allocation). Postcondition: `live`, `freeable`, `unused_in`, `modifies loc_none`. Requires `v len32 > 0`. | — | — | — |
| ~~18~~ | — | ~~`free_entry_array`~~ | **ELIMINATED** — replaced with `let free_entry_array buf = Buffer.free buf` (concrete Low\* deallocation). Callers migrated to ST effect; free reordered to run last so nested content frees (Stack) preserve `equal_domains`. | — | — | — |
| ~~19~~ | — | ~~`free_entry_array_contents`~~ | **ELIMINATED** — concrete recursive implementation in `Jose.LowStar.Json.fst` using disjointness frame lemmas (`lemma_free_preserves_remaining_entries`, `lemma_entries_buffer_preserved`, etc.). Uses `free_bytes_ffi` (see §3.12) for nested buffers. | — | — | — |

### 3.10 Low\* JSON Parse Pipeline (Category B) — ELIMINATED

**File:** `fstar/jose/LowStar/Json/Jose.LowStar.Json.fst`

| # | Line | Function | Description | Status |
|---|---|---|---|---|
| ~~20~~ | — | ~~`json_parse_entries_to_c`~~ | **ELIMINATED** — replaced with concrete `noextract let json_parse_entries_to_c` composing `validate_members_utf8` (Low\* UTF-8) → `collect_raw_members_stack` → `normalise_raw_members` → `parse_json_entries` → `build_success_result`/`build_error_result`. 6 localized `assume` statements also eliminated (WP1-8 plan, 2026-03-05). | Proved |
| ~~B+~~ | — | ~~`free_bytes_ffi`~~ | **ELIMINATED** — replaced with `let free_bytes_ffi buf = Buffer.free buf` (concrete Low\* deallocation). | Proved |

### 3.6 Base64url Encoding Model (Category E) — ELIMINATED

**File:** `fstar/FStar.Base64.fst`

All 4 Base64url/Base64 encoding `assume val` properties have been replaced
with concrete encode/decode implementations and proved lemmas. The roundtrip
and injectivity properties are now F\*-verified `let` lemmas, not axioms.

| # | Line | Function | Description | Runtime impl | Risk | Reducible? |
|---|---|---|---|---|---|---|
| ~~13~~ | — | ~~`base64url_roundtrip`~~ | **ELIMINATED** — proved as concrete `let` lemma via `base64url_decode_encode_roundtrip`. Concrete encode/decode implementations replace the former `irreducible` placeholders. | — | — | — |
| ~~14~~ | — | ~~`base64url_encode_injective`~~ | **ELIMINATED** — proved as concrete `let` lemma via `base64url_encode_injective`. Follows from decode roundtrip. | — | — | — |
| ~~15~~ | — | ~~`base64_roundtrip`~~ | **ELIMINATED** — proved as concrete `let` lemma via `base64_decode_encode_roundtrip`. Same technique as #13 for standard Base64. | — | — | — |
| ~~16~~ | — | ~~`base64_encode_injective`~~ | **ELIMINATED** — proved as concrete `let` lemma via `base64_encode_injective`. Same technique as #14 for standard Base64. | — | — | — |

**Note:** The ASCII precondition enforcement documented previously still applies
at all three string-to-hash runtime boundaries (PKCE code\_verifier, JWK thumbprint,
SD-JWT disclosure digest). These are now backed by concrete F\* proofs rather than
assumed properties.

### 3.7 WASM Host Imports (Category C)

**File:** `fstar/verifiedcore/api/VerifiedCore.Api.Claims.Runtime.fst`

These are external declarations for host-provided functions in the WASM
compilation target. Each has both a "verified spec" postcondition (checked by
F\*) and a "host contract" (documented but not machine-checked). The host
contract is the responsibility of the WASM embedder.

> **Phase D update (2026-03-08):** Assumptions #8–#11
> have been eliminated by the "raw buffer + HACL\* direct" approach. The C
> exports layer resolves `bytes_handle` values to `(B.buffer U8.t, U32.t)`
> pairs before calling F\* functions. HACL\* functions are declared as
> `-library` module interfaces, not assume vals. Only #12 remains.

| # | Line | Function | Description | Runtime impl | Risk | Reducible? |
|---|---|---|---|---|---|---|
| ~~8~~ | — | ~~`host_bytes_len`~~ | **ELIMINATED (Phase D)** — never called from F\*; handle→length resolution moved to C exports layer. | — | — | — |
| ~~9~~ | — | ~~`host_bytes_eq`~~ | **ELIMINATED (Phase D)** — never called from F\*; comparison done on raw buffers at C/F\* level. | — | — | — |
| ~~10~~ | — | ~~`host_crypto_sha256`~~ | **ELIMINATED (Phase D)** — replaced by inline `Hacl_Hash_SHA2_hash_256` call (HACL\* `-library` module, not assume val). | — | — | — |
| ~~11~~ | — | ~~`host_crypto_verify_signature`~~ | **ELIMINATED (Phase D)** — replaced by direct `Hacl_Ed25519_verify` dispatch. Verified path supports EdDSA only; ES256/RS256 are `CryptoProfile::Compat` (outside WASM verified path). Any future OIDC `RS256` slice closure is expected above this WASM signature path unless the architecture changes. | — | — | — |
| 12 | 119 | `host_replay_store_check_and_store` | Atomic check-and-store for replay detection. Signature updated to `(B.buffer U8.t, U32.t)` pair. **Thread safety contract:** MUST provide atomic check-and-store. | `include/verified_core.h :: vc_replay_store_check_and_store` | Medium | No (host boundary — permanent) |

### 3.8 HACL\* Linkage Stubs (Category B')

**File:** `fstar/verifiedcore/api/VerifiedCore.Crypto.Hacl.fst`

Phase D introduced this module as a `-library` interface to HACL\*-verified C
functions already compiled into the WASM binary. Unlike Category C host
callbacks, the implementations behind these `assume val` declarations are
**themselves formally verified** by the HACL\* project (spec/implementation
correspondence). A thin C bridge (`c/verified-core/hacl_bridge.c`) maps the
KaRaMeL-generated extern names to actual HACL\* C function names.

| # | Line | Function | Description | Runtime impl | Risk | Reducible? |
|---|---|---|---|---|---|---|
| NEW-1 | 28 | `hacl_sha256` | SHA-256 hash via HACL\* `Hacl_Hash_SHA2_hash_256`. Writes 32 bytes to output buffer. Pre: live, disjoint, `output.length >= 32`, `input_len <= input.length`. Post: modifies output only. | HACL\* `Hacl_Hash_SHA2.c` | Low | No (verified foreign code — `-library` linkage) |
| NEW-2 | 44 | `hacl_ed25519_verify` | Ed25519 signature verification via HACL\* `Hacl_Ed25519_verify`. Returns bool. Pre: live, disjoint, `pk.length >= 32`, `sig.length >= 64`, `msg_len <= msg.length`. Post: read-only (`h0 == h1`). | HACL\* `Hacl_Ed25519.c` | Low | No (verified foreign code — `-library` linkage) |

**Trust model:** These assume vals trust that (1) HACL\*'s spec/implementation
proof is correct, and (2) the C bridge correctly maps function names. Both are
well-established: HACL\* is peer-reviewed and machine-checked, and the bridge
is a trivial forwarding layer. The risk is qualitatively lower than host
callbacks because the implementation is verified, not arbitrary host code.

### 3.9 EverParse JOSE Entry Linkage Stub (Category B'')

**File:** `fstar/jose/Jose.HeaderParser.Runtime.fst`

This module introduces a narrow Stack-level bridge from Low*/KaRaMeL-extracted
code to the generated EverParse JOSE header entry validator. It preserves only
the coarse entry-framing result (`success`, `not_enough_data`, `other failure`)
and intentionally leaves ASCII/UTF-8/allow-list/trailing-byte policy checks in
the pure seq parser.

| # | Line | Function | Description | Runtime impl | Risk | Reducible? |
|---|---|---|---|---|---|---|
| NEW-3 | 27 | `jose_header_entry_error_code` | Returns the coarse EverParse validator error kind for one TLV entry buffer. Pre: live input buffer, `input_len <= input.length`. Post: read-only (`h0 == h1`). | `c/jose_header_runtime.c` → `generated/everparse/JoseHeaderWrapper.c` → `generated/everparse/JoseHeader.c` | Low | No (verified foreign code linkage for generated parser) |

### 3.10 OIDC Hash Runtime Linkage Stubs (Category B''')

**File:** `fstar/HashComputation.Low.fst`

This module is the Low\* dispatcher for OIDC hash values (`at_hash`, `c_hash`,
and related SHA-2 truncation). The exported runtime path is source-managed via
`generated/lowstar/oidc/hash/HashComputation_Low.{c,h}` and the local C shim
`c/hash_computation_runtime.c`. The two assume vals are linkage contracts for
copying a bounded buffer prefix and delegating SHA-2 computation to the C shim;
they do not assert cryptographic hardness.

| # | Line | Function | Description | Runtime impl | Risk | Reducible? |
|---|---|---|---|---|---|---|
| NEW-4 | 35 | `bytes_prefix_of_buffer` | Copies the first `len` bytes from a live Low\* output buffer into an `FStar.Bytes.bytes` value. The caller's truncation preconditions ensure `len` is bounded by the digest length. | `c/hash_computation_runtime.c::HashComputation_Low_bytes_prefix_of_buffer` | Low | No (runtime C bridge contract) |
| NEW-5 | 40 | `evercrypt_hash_incremental_hash` | Dispatches SHA-256 / SHA-384 / SHA-512 over a byte input and writes the full digest into the supplied output buffer. Precondition ties `input_len` to the byte-string length; postcondition preserves buffer liveness and frame. | `c/hash_computation_runtime.c::HashComputation_Low_evercrypt_hash_incremental_hash` backed by HACL\*/EverCrypt hash functions | Low | No (runtime C bridge contract) |

---

## 4. Risk Summary

### By Risk Level

| Risk | Count | Assume vals |
|---|---|---|
| **Low** | 5 | NEW-1, NEW-2, NEW-3, NEW-4, NEW-5 |
| **Medium** | 1 | #12 |
| **High** | 0 | — |
| **Removed** | 6 | #1–#6 (replaced by events and external premises; see §3.1–§3.4) |

### By Reducibility

| Status | Count | Notes |
|---|---|---|
| **Removed** (former computational hardness lemmas) | 6 | #1–#6; the premises are now `spec/assumption-register.json` entries `A-SHA256-CR`, `A-SHA256-TRUNC128-CR`, `A-HMAC-SHA2-EUF-CMA`, `A-ED25519-EUF-CMA` (`specified-not-attested`) |
| **Builder-injected** (not tracked in `fstar/`) | 3 | `C.Loops.while`, `C.Loops.do_while`, `C.Loops.total_while` generated by `scripts/flake/verify_fstar.sh`; reached by the EverParse-derived parsers and the Low\* JSON modules |
| **Provider sources lax-loaded** | closure-dependent | HACL\* (ships no `.checked`), Steel, and the EverParse/LowParse modules made stale by the shadowed `C.Loops`; indexed per pass by the assumption graph |
| **Permanent** (HACL\* linkage) | 2 | NEW-1, NEW-2 (verified foreign code) |
| **Permanent** (EverParse linkage) | 1 | NEW-3 (generated parser + local bridge) |
| **Permanent** (OIDC hash runtime linkage) | 2 | NEW-4, NEW-5 (local C bridge backed by HACL\*/EverCrypt) |
| **Permanent** (WASM host boundary) | 1 | #12 |
| **Eliminated (historical)** | 72+ | See §7, §8, and §9 for elimination record |

### By Category

| Category | Count | Risk profile |
|---|---|---|
| A: Crypto trust boundaries | **0** | No `assume val`. Bad events with proved case splits inside F\*; computational premises recorded externally with `specified-not-attested` status. |
| B: FFI / C runtime stubs | **0** | All 9 original FFI stubs eliminated via concrete Low\* implementations. |
| B': HACL\* linkage stubs | **2** | `hacl_sha256`, `hacl_ed25519_verify` in `VerifiedCore.Crypto.Hacl.fst`. Linking stubs for HACL\*-verified C code; implementations are themselves formally verified. |
| B'': EverParse linkage stubs | **1** | `jose_header_entry_error_code` in `Jose.HeaderParser.Runtime.fst`. A narrow linkage bridge to generated EverParse C validation with a read-only Stack contract. |
| B''': OIDC hash runtime linkage stubs | **2** | `bytes_prefix_of_buffer`, `evercrypt_hash_incremental_hash` in `HashComputation.Low.fst`. Runtime bridge contracts for the source-managed OIDC hash C shim. |
| C: WASM host imports | **1** | `host_replay_store_check_and_store` only. Phase D eliminated #8–#11 via raw buffer + HACL\* direct approach. |
| E: Encoding model boundaries | **0** | All 4 Base64url/Base64 properties proved with concrete implementations. |

---
