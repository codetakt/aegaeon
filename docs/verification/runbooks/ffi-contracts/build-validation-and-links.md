# FFI Contract Build Validation And Links

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Verification

Audience: verification contributors, maintainers

This document is part of the split FFI contract register.

## 6. Build Pipeline

The FFI build is orchestrated by `crates/ffi/build.rs`:

1. **cbindgen** generates `aegaeon_tlv.h` from `src/tlv.rs`
2. **pkg-config** probes for mbedtls, libsodium (optional), EverCrypt
3. **KaRaMeL** runtime headers and `fstar_uint32.c`, `fstar_bytes.c` are located
4. **cc::Build** compiles:
   - Hand-written C: `c/jws.c`, `c/rsa_signatures.c`, `c/jwe.c`, `c/json_lowstar_runtime.c`, error handlers
   - KaRaMeL extraction: `artifacts/karamel/Jose_LowStar_Json_Stack.c`, `generated/lowstar/jose/Jose_Dcr.c`
   - EverParse: 7 schema `.c` files + their `Wrapper.c` files
5. Output is linked as static library `jose`

Conditional compilation:
- `test` / `kani` / `no_mbedtls`: C compilation is skipped entirely; Rust fallbacks used
- `CARGO_FEATURE_EVERPARSE_IDTOKEN`: opt-in IdToken extraction
- `CARGO_FEATURE_IDTOKEN_RUNTIME`: opt-in IdToken.Low.Runtime

---

## 7. Relationship to Existing Documentation

This document supersedes and consolidates:
- `docs/verification/jose/json-lowstar-ffi-contracts.md` (2025-11-16, partial)

The older document covered a subset of the FFI surface. This register is
comprehensive and aligned with the current Assumption Register (2026-03-02).

---

## 8. Validation

FFI contract consistency is validated by:
- **CI drift detection:** `scripts/validation/verify_ffi_contracts.sh`
  verifies Category B = 0 (all FFI assume vals eliminated)
- **F\* verification:** The 9 eliminated assume vals are now type-checked by F\*
  (`nix build .#verify-fstar`); any regression would be a compilation failure
- **Integration tests:** `cargo test` exercises Rust ↔ C paths in non-`no_mbedtls` builds
- **WASM smoke tests:** `tests/verified_core_wasm/` (59 tests)
- **Static analysis:** `clippy -D warnings` + `cargo deny` in CI
