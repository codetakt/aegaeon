# FFI External Boundaries And Runtime Checks

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Verification

Audience: verification contributors, maintainers

This document is part of the split FFI contract register.

## 2. EverParse FFI Boundary

EverParse generates memory-safe C parsers from `.3d` schema definitions. These
are called from Rust via `extern "C"` declarations in `crates/ffi/src/`.

All EverParse validators share a common signature pattern:
```c
BOOLEAN SchemaCheckEntry(uint8_t *base, uint32_t len);
```

They return non-zero on success (valid input) and zero on failure (malformed).
Input buffer `base` must be mutable (EverParse may write intermediate state)
but contents are restored before return.

| Schema | C function | Rust binding | Source |
|---|---|---|---|
| `JoseHeader.3d` | `JoseHeaderCheckJoseHeaderEntry` | `crates/ffi/src/jose_header.rs:46` | `generated/everparse/JoseHeader.c` |
| `DCR.3d` | `DcrCheckRegistrationRequest` | `crates/ffi/src/dcr_parser.rs:75` | `generated/everparse/DCR.c` |
| `DCR.3d` | `DcrCheckRegistrationResponse` | `crates/ffi/src/dcr_parser.rs:76` | `generated/everparse/DCR.c` |
| `DcrRegistration.3d` | `DcrRegistrationCheck...` | `crates/ffi/src/dcr_parser.rs` | `generated/everparse/DcrRegistration.c` |
| `Dpop.3d` | `DpopCheckDpopClaims` | `crates/ffi/src/lib.rs:414` | `generated/everparse/Dpop.c` |
| `IdTokenSchema.3d` | `IdTokenSchemaCheckIdTokenClaimsEntry` | `crates/ffi/src/id_token.rs:175` | `generated/everparse/IdTokenSchema.c` |
| `IdTokenSchema.3d` | `IdTokenSchemaCheckUserinfoResponseEntry` | `crates/ffi/src/id_token.rs:176` | `generated/everparse/IdTokenSchema.c` |
| `RequestObjectSchema.3d` | `RequestObjectSchemaCheckRequestObjectClaimsEntry` | `crates/ffi/src/request_object_parser.rs:48` | `generated/everparse/RequestObjectSchema.c` |
| `LogoutTokenSchema.3d` | (not runtime-invoked) | — | `generated/everparse/LogoutTokenSchema.c` |

**CI gate:** 7 of 7 schemas are F\*-verified via `nix build .#verify-fstar`.
The `Dpop` schema was renamed to `DpopSchema` to avoid module name conflict
with `dpop/Dpop.fst`; the original generated `Dpop` files remain the C build input.

---

## 3. Crypto / JOSE FFI Boundary

These C functions are called from Rust for JWS verification, JWE
encryption/decryption, and Low\* DCR validation. They are **not** `assume val`s
in F\* — they are direct C implementations exposed via Rust `extern "C"`.

**C files:** `c/jws.c`, `c/jwe.c`, `c/rsa_signatures.c`
**Rust bindings:** `crates/ffi/src/lib.rs`

| C function | Rust wrapper | Purpose | Library |
|---|---|---|---|
| `jws_hmac_verify` | `verify_hmac` | HMAC-SHA256/384/512 verification | mbedtls / EverCrypt |
| `jws_rsa_verify` | `verify_rsa` | RSA-PSS signature verification | mbedtls |
| `Jose_Jwe_chacha20poly1305_encrypt` | `encrypt_chacha20poly1305` | ChaCha20-Poly1305 AEAD | EverCrypt (HACL\*) |
| `Jose_Jwe_chacha20poly1305_decrypt` | `verify_decrypt_jwe` | ChaCha20-Poly1305 AEAD decrypt | EverCrypt (HACL\*) |
| `Jose_Dcr_validate_dcr_metadata_c` | `validate_metadata` | Low\*-extracted DCR policy check | KaRaMeL extraction |

**Test/Kani fallback:** All extern C functions have Rust fallback implementations
gated by `#[cfg(any(test, kani, no_mbedtls))]` that use pure Rust crates
(ed25519-dalek, hmac, chacha20poly1305) instead of the C libraries.

---

## 4. Rust ↔ C UTF-8 Bridge

**Rust file:** `crates/ffi/src/lib.rs`
**Called from:** `c/json_lowstar_runtime.c` (in `json_parse_entries_to_c`)

| Function | Direction | Purpose |
|---|---|---|
| `aegaeon_ffi_decode_utf8` | C → Rust | Validates UTF-8, returns CString (caller frees) |
| `aegaeon_ffi_free_string` | C → Rust | Frees a CString allocated by `decode_utf8` |

These are `#[no_mangle] pub extern "C"` functions in Rust, called from C during
the JSON parsing pipeline (#20a). The C code calls into Rust for UTF-8 validation
because Rust's `String::from_utf8` provides safer validation than C alternatives.

---

## 5. Runtime Check Mapping

All Category B assume vals have been eliminated. The 9 original entries
(8 FFI stubs + 1 bridge) are now formally proved by F\* via concrete Low\*
implementations and no longer require runtime validation of FFI contracts.
`json_parse_entries_to_c` was the final elimination — replaced with a
concrete `noextract` implementation composing `validate_members_utf8` +
`collect_raw_members_stack` + `parse_json_entries`.

### 5.1 Remaining Assume Vals

**None.** Category B = 0.

### 5.2 Eliminated Assume Vals (all formally verified)

| ~~#~~ | Former Assume Val | Replacement | Verification |
|---|---|---|---|
| ~~13~~ | `Jose.BytesBlock:malloc_bytes` | `Buffer.malloc HS.root 0uy len` | F\* type-checked |
| ~~14~~ | `Jose.BytesBlock:free_bytes` | `Buffer.free buf` | F\* type-checked |
| ~~15~~ | `Jose.LowStar.Json.Stack:malloc_bytes` | `Buffer.malloc HS.root 0uy len` | F\* type-checked |
| ~~16~~ | `Jose.LowStar.Json.Stack:collect_members_u32_stack_aux` | Concrete recursive + ghost predicates | F\* type-checked + frame lemmas |
| ~~17~~ | `Jose.LowStar.Json.Runtime:malloc_entry_array` | `Buffer.malloc HS.root default_entry_out len32` | F\* type-checked |
| ~~18~~ | `Jose.LowStar.Json.Runtime:free_entry_array` | `Buffer.free buf` (ST + freeable + caller reorder) | F\* type-checked |
| ~~19~~ | `Jose.LowStar.Json.Runtime:free_entry_array_contents` | Concrete recursive + disjointness frame lemmas | F\* type-checked + frame lemmas |
| ~~B+~~ | `Jose.LowStar.Json:free_bytes_ffi` | `Buffer.free buf` + `freeable` propagation | F\* type-checked |

**CI coverage:** All Category B contracts are now formally verified by F\*.
Runtime integration tests (`cargo test`) and WASM smoke tests
(`tests/verified_core_wasm/`) provide defense-in-depth for the linked C
implementations.

---
