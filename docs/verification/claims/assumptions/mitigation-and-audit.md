# F* Assumption Mitigation And Audit Checklist

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, maintainers

This document is part of the split F* assumption register.

## 5. Mitigation Strategy

For each category of assume val, the following mitigations are in place:

### Crypto Boundaries (A) — 6 Honest Assumptions

Phase A (2026-03-05) replaced all `irreducible` identity/false/constant crypto
models with genuine HACL\* spec-level implementations. Phase A completion
eliminated the last Category A crypto function assume val (`hmac_sha256` in
DRBG) by delegating to the HACL\* Bridge. The 6 remaining Category A assume
vals are **honest computational hardness assumptions** — they cannot be proved
from first principles but are standard assumptions in cryptography:

- **SHA-256 collision resistance** (#2, #3, #5, #6): distinct inputs produce
  distinct digests. 20+ years of cryptanalysis, no full-round collision.
  NIST SP 800-107, FIPS 180-4.
- **EUF-CMA unforgeability** (#1, #4): valid signature implies signer held key.
  Standard for HMAC-SHA2 and Ed25519. PRF assumption for HMAC, hardness of ECDLP for Ed25519.

**Defense-in-depth:**
- **Tamarin models** independently verify the same security properties at the
  protocol level (247 lemmas, Dolev-Yao model).
- **Runtime libraries**: FIPS-validated (aws-lc-rs) or extensively audited (ring).
- **HACL\* spec implementations**: the F\* crypto models now use the same spec
  functions verified by the HACL\* project (Spec.Agile.Hash, Spec.Agile.HMAC,
  Spec.Ed25519).

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
   and confirm exactly **12** results across **8 files** (6 crypto A,
   2 HACL\* B', 1 EverParse B'', 2 OIDC hash B''', 1 host C).
2. **Review crypto assumptions (A):** Verify the 6 Category A assume vals
   (#1-#6) model standard computational hardness properties (collision
   resistance, EUF-CMA unforgeability). Confirm they use honest HACL\* spec
   implementations, not identity/false/constant models.
3. **Cross-reference Tamarin:** Tamarin independently verifies the same
   security properties at the protocol level (247 lemmas, Dolev-Yao model).
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
