# F* Assumption Mitigation And Audit Checklist

Last updated: 2026-09-11

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, maintainers

This document is part of the split F* assumption register.

## 5. Mitigation Strategy

For each category of assume val, the following mitigations are in place:

### Crypto Boundaries (A) — 0 Assume Vals, Named Events

Phase A (2026-03-05) replaced all `irreducible` identity/false/constant crypto
models with genuine HACL\* spec-level implementations. The six "honest
computational hardness" lemma `assume val`s that Phase A introduced were
removed on 2026-09-11 because their content was false (universal injectivity
of SHA-256; verification failure under every distinct raw HMAC key) or empty
(`ensures True` for Ed25519). Inside F\* the boundary is now expressed as
definitions of bad events with proved case-split lemmas:

- **SHA-256 collision events** (`sha256_collision`, `hash_collision`,
  `disclosure_digest_collision`, `s256_collision`): distinct inputs with the
  same digest. The dependent SD-JWT and PKCE theorems are conditional on the
  absence of the event for the concrete issuance, or exhibit a witness
  (`lemma_reconstruction_subset_or_collision`,
  `lemma_non_forgeability_or_collision`, `lemma_pkce_s256_binding_cases`).
- **Boundary events kept separate from hashing**: `string_encoding_collision`
  (abstract `bytes_of_string`), `truncation_collision` (OIDC leftmost-half
  digests carry half the length), over-length fallbacks proved unreachable for
  `FStar.Bytes` (`lemma_sha2_limits_exceed_bytes`).
- **Forgery events** (`ed25519_forgery`, `jws_mac_forgery`,
  `jws_eddsa_forgery`) over an honest signing/MAC history and a
  compromised-key set; re-presentation of honestly issued material is not a
  forgery. HMAC unforgeability is stated over key equivalence classes
  (`mac_key_equiv`), because `Verified.Crypto.Hmac.KeyEquiv` proves that a key
  and its zero-padded form are distinct yet equivalent.

The computational premises that these events are infeasible are register
entries in `spec/assumption-register.json` (`A-SHA256-CR`,
`A-SHA256-TRUNC128-CR`, `A-HMAC-SHA2-EUF-CMA`, `A-ED25519-EUF-CMA`), each
naming the primitive, the standard, the generic bound as text and the F\*
event it covers. Their status is `specified-not-attested`: no numeric security
evaluation is produced and no guarantee is activated by them.

**Defense-in-depth (unchanged in kind, not a substitute):**
- **Tamarin models** verify protocol properties in the symbolic Dolev-Yao model
  (their builtins/equations/restrictions are indexed as premises by the
  assumption graph).
- **HACL\* spec implementations**: the F\* crypto models use the same spec
  functions verified by the HACL\* project. Note that the pinned HACL\* package
  ships no `.checked` files, so these modules are lax-loaded from source in
  every pass; their internal lemmas are provider-verified, not re-verified
  here (register entry `provider-lax-source:hacl`).

### FFI Stubs (B)

- **All 9 original FFI stubs eliminated:** `malloc_bytes` (×2), `free_bytes`,
  `collect_members_u32_stack_aux`, `malloc_entry_array`,
  `free_entry_array_contents`, `free_entry_array`, `free_bytes_ffi`,
  `json_parse_entries_to_c` — all replaced with concrete Low\*
  implementations. **Category B = 0.**
- **Detailed FFI contract documentation** in
  [FFI contract register](../../runbooks/ffi-contracts/README.md).
- **LowStar.Buffer separation logic** proofs used extensively:
  `members_nested_live` ghost predicate, `entries_buffers_disjoint` frame
  lemmas, `unused_in` + `modifies` composition for liveness preservation.

### WASM Host Imports (C) — 1 Remaining

Phase D eliminated 4 of the original 5 Category C assume vals (#8–#11) by
internalizing crypto operations via HACL\* and moving handle→pointer resolution
to the C exports layer. Only `host_replay_store_check_and_store` (#12) remains.

- **Host contract documentation** specifies required behavior for the replay
  store callback.
- **C ABI shim** (`c/verified_core.c`, `include/verified_core.h`) provides
  reference implementations that satisfy the contracts.
- **WASM smoke tests** (59+ tests in `tests/verified_core_wasm/`) validate the
  host interface.

### HACL\* Linkage Stubs (B') — 2

- **`-library` module:** `VerifiedCore.Crypto.Hacl.fst` is not extracted by
  KaRaMeL; it declares interfaces to HACL\* C functions.
- **Verified implementations:** HACL\* SHA-256 and Ed25519 are themselves
  formally verified (spec/implementation correspondence), making the trust
  boundary qualitatively different from host callbacks.
- **C bridge:** `c/verified-core/hacl_bridge.c` provides trivial name mapping
  from KaRaMeL extern names to HACL\* C function names.

### EverParse Linkage Stubs (B'') — 1

- **Narrow scope:** `Jose.HeaderParser.Runtime.jose_header_entry_error_code`
  does not replace the pure parser. It only exposes the generated EverParse
  TLV entry-framing validator to Stack callers.
- **Generated validator:** the underlying parser is the generated
  `JoseHeaderValidateJoseHeaderEntry` / `JoseHeaderGetJoseHeaderEntryErrorCode`
  path in `generated/everparse/`.
- **Local bridge:** `c/jose_header_runtime.c` is a thin forwarding shim from
  the KaRaMeL-generated extern name to the generated EverParse wrapper.
- **Fail-closed posture:** the bridge preserves only `success`,
  `not_enough_data`, and `other failure`; higher-level ASCII/UTF-8/trailing-byte
  policy remains in the verified seq parser until a fuller runtime integration
  is completed.

### OIDC Hash Runtime Linkage Stubs (B''') — 2

- **Narrow scope:** `HashComputation.Low` is limited to runtime SHA-2 dispatch
  and digest truncation for OIDC hash values.
- **Source-managed shim:** `c/hash_computation_runtime.c` owns the C bridge and
  delegates SHA-2 computation to HACL\*/EverCrypt.
- **Runtime tests:** strict OIDC hash vector lanes exercise the exported
  `HashComputation_Low_compute_oidc_hash_bytes(...)` entrypoint.
- **Boundary status:** these are runtime linkage contracts, not claims that the
  project proves OS, compiler, or C runtime behaviour from first principles.

### Encoding Model Boundaries (E) — ELIMINATED

All 4 Base64url/Base64 encoding `assume val` properties (#13-#16) have been
eliminated by implementing concrete encode/decode functions in `FStar.Base64.fst`
and proving the roundtrip and injectivity lemmas as concrete `let` lemmas.
Category E = 0.

---

## 6. Audit Checklist

For a security auditor reviewing this register:

1. **Verify the count:** Run `grep -rn '^\s*assume val' fstar/ --include='*.fst' --include='*.fsti'`
   and confirm exactly **6** results across **4 files** (2 HACL\* B',
   1 EverParse B'', 2 OIDC hash B''', 1 host C). Then run
   `python3 scripts/validation/assumption_graph.py check` on a `verify-fstar`
   evidence directory: it must report every tracked declaration, the 3
   builder-injected `C.Loops` premises, the lax-loaded provider modules and
   the effective solver identity, and reconcile them with
   `spec/assumption-register.json`.
2. **Review crypto events (A):** Confirm that no `assume val`, `assume` or
   `admit` states a cryptographic property; that `sha256_collision`,
   `hash_collision`, `disclosure_digest_collision`, `ed25519_forgery`,
   `jws_mac_forgery` and `jws_eddsa_forgery` are definitions; that the
   case-split lemmas are proved; and that the success paths
   (`lemma_jws_verify_hs_accepts_mac`, real HACL\* computations) remain.
   Confirm the register entries `A-*` are `specified-not-attested`.
3. **Cross-reference Tamarin:** Tamarin independently verifies protocol-level
   properties in the symbolic Dolev-Yao model; the assumption graph indexes
   each selected theory's builtins, equations and restrictions.
4. **Review FFI contracts:** Category B = 0 (all eliminated). Review
   [FFI contract register](../../runbooks/ffi-contracts/README.md) for historical elimination details.
5. **Check WASM host contracts:** Category C = 1 (only #12
   `host_replay_store_check_and_store`). Review the `include/verified_core.h`
   documentation and the reference implementation in `c/verified_core.c`.
   Phase D eliminated #8–#11 by internalizing crypto via HACL\* and moving
   handle resolution to the C exports layer.
6. **Check HACL\* linkage (B'):** Verify `VerifiedCore.Crypto.Hacl.fst`
   declares exactly 2 assume vals (`hacl_sha256`, `hacl_ed25519_verify`) with
   correct Low\* pre/postconditions. Confirm the C bridge
   (`c/verified-core/hacl_bridge.c`) correctly maps to HACL\* C functions.
7. **Check EverParse linkage (B''):** Verify
   `Jose.HeaderParser.Runtime.fst` declares exactly 1 assume val and that
   `c/jose_header_runtime.c` forwards to the generated EverParse wrapper.
8. **Check OIDC hash linkage (B'''):** Verify `HashComputation.Low.fst`
   declares exactly 2 assume vals and that `c/hash_computation_runtime.c`
   implements the buffer-copy and HACL\*/EverCrypt hash dispatch contracts.
9. **Verify encoding model (E):** Category E = 0 (all eliminated). Confirm
   `FStar.Base64.fst` contains concrete encode/decode implementations with
   proved roundtrip and injectivity lemmas (no `assume val` remaining).
10. **Verify crypto profile:** Confirm `Algorithm::is_verified()` in
   `crates/jose/src/algorithms/mod.rs` matches `verified_allowed` in
   `fstar/jose/Jose.Alg_policy.fst`.

---
