# JOSE Context Migration - Complete (Phase 1-6)

Last updated: 2026-07-08

Status: historical record

Owner: Program Management

Audience: maintainers, planning contributors

## Summary

Per-request context support has been fully implemented across the verification stack: F\* specification, Low\* extraction, KaRaMeL compilation to C, and Rust FFI integration. The JoseContext API is now available for production use with backward compatibility maintained.

## Completed Phases

### Phase 1: Context Type and Lemmas ✅
- Created `Jose.Context.fst` with `jose_context` type
- Created `Jose.Arith.Bounds.fst` with UInt32 conversion lemmas
- No changes to existing code

### Phase 2: Context-based Functions ✅
- Added `*_with_context` functions to `Jose.LowStar.fst`
- Legacy functions now wrap `default_context`
- Added `Jose.HeaderParser.fst` context-based buffer parsers

### Phase 3: Proof and Type Checking ✅
- All F* modules type-check successfully
- All verification conditions discharged
- Consolidated arithmetic lemmas in `Jose.Arith.Bounds.fst`

### Phase 4: KaRaMeL Extraction Warnings ✅
- Fixed Fatal Warning 2 by marking `context_header_max_length_u32` as `noextract`
- C/H files generated successfully:
  - `Jose_Context.c/h` - Context type and constructors
  - `Jose_LowStar.c/h` - JOSE Low* parser types
  - `Jose_LowStar_Json.c/h` - JSON Low* implementation
- Warning 15 (mathematical integers) expected for spec functions

## Generated C API

```c
typedef krml_checked_int_t Jose_Context_jose_context;

extern krml_checked_int_t Jose_Context_default_context;  // = 4096

krml_checked_int_t Jose_Context_make_context(krml_checked_int_t max_len);
```

### Phase 5: Rust FFI Integration ✅
- FFI bindings for `Jose_Context` API (`crates/ffi/src/lib.rs`)
- Safe `JoseContext` wrapper type with bounds checking
- Context parameters wired through JWS/JWE APIs
- New context-based functions:
  - `jws::verify_compact_with_context()`
  - `jwe::decrypt_rsa_oaep_a256gcm_pkcs8_with_context()`
- Backward-compatible wrappers using `JoseContext::default()`
- Added `Jose_Context.c` to FFI build system

### Phase 6: Documentation and Compliance ✅
- Updated `docs/policies/jose-header-policy.md` with:
  - Per-request context API documentation
  - Migration guide from global `header_max_len()`
  - Verification alignment across F*/Low*/Rust stack
- Updated `CHANGELOG.md` with API migration details
- Updated program management documentation

## Impact

- ✅ Per-request header length limits supported across full verification stack (F\* → Low\* → C → Rust)
- ✅ KaRaMeL extraction pipeline operational with verified context propagation
- ✅ Type-safe UInt32 conversion infrastructure
- ✅ Production-ready Rust API with thread-safe per-request configuration
- ✅ Backward compatible (default_context = 4096, legacy APIs wrap new implementation)
- ✅ Foundation for future per-request policies (algorithm restrictions, key size limits, etc.)

## Files Modified

**F* Layer**:
- `fstar/jose/Jose.Context.fst` (new)
- `fstar/jose/Jose.Arith.Bounds.fst` (extended)
- `fstar/jose/Jose.LowStar.fst` (context functions added)
- `fstar/jose/LowStar/Json/Jose.LowStar.Json.fst` (lemmas consolidated)

**Build/Extraction**:
- `scripts/extraction/run_jose_lowstar.sh` (Jose.Context added)

**Generated**:
- `generated/lowstar/jose/Jose_Context.{c,h}`
- `generated/lowstar/jose/Jose_LowStar.{c,h}`
- `generated/lowstar/jose/Jose_LowStar_Json.{c,h}`

**Rust FFI Layer (Phase 5)**:
- `crates/ffi/src/lib.rs` (FFI bindings + JoseContext wrapper)
- `crates/ffi/build.rs` (added Jose_Context.c to compilation)
- `crates/jose/src/policy.rs` (re-export JoseContext, deprecate header_max_len)
- `crates/jose/src/jws.rs` (context-based verify API)
- `crates/jose/src/jwe.rs` (context-based decrypt API)

**Documentation (Phase 6)**:
- `docs/policies/jose-header-policy.md` (context API + migration guide)
- `CHANGELOG.md` (API changes documented)
- `docs/program-management/historical/initiatives/jose/context-migration-phase1-4-summary.md`
  (this file)

## Status: Complete ✅

All 6 phases of the JOSE context migration are complete. The per-request context API is ready for production use with full verification stack coverage and backward compatibility.

## Next Steps

Future enhancements building on this foundation:
- Extend `JoseContext` with additional per-request policies (algorithm restrictions, key size limits)
- Low* Stack JSON parser integration (currently using serde_json in Rust layer)
- Integration tests with custom context values
- Performance benchmarks comparing context-based vs legacy APIs
