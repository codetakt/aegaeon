# JOSE Phase 0 Foundations

Last updated: 2026-07-07

Status: active plan

Owner: Program Management

Audience: maintainers, planning contributors

**Last updated:** 2025-12-20
**Phase 0 completed:** 2025-10-18

This memo captures the concrete decisions taken while completing Phase 0 of the
JOSE implementation plan. It doubles as the reference for reviewers and future
phases so that we do not revisit the same design questions.

## Module & API Sketch

| Module | Purpose | Key Types / Functions |
|--------|---------|------------------------|
| `crates/jose/src/jws.rs` | JWS header parsing and signature verification | `JwsHeader`, `JwsError`, `VerificationKey`, `verify_compact`, per-algorithm helpers (`verify_hmac_sha256`, `verify_rsa_pkcs1_sha256`, `verify_rsa_pss_sha256`, `verify_ecdsa_p256_sha256`) |
| `crates/jose/src/jwt.rs` | JWT claim validation | `JwtClaims`, `ValidationContext`, `JwtValidationError` |
| `crates/jose/src/jwk.rs` / `jwe.rs` | JWK parsing, JWE helpers | `JwkError`, `JweError`, decrypt helpers |
| `crates/ffi/src/lib.rs` | C ABI surface for Low*/EverParse integration | `jws_hmac_verify`, `jws_rsa_verify`, `Jose_Jwe_chacha20poly1305_{encrypt,decrypt}`; safe wrappers `verify_hmac`, `verify_rsa` etc. |

## Error Taxonomy

- `JwsError` covers algorithm mismatch, format errors, Base64/JSON decode, and
  signature failures. Additional variants (`UnsupportedAlgorithm`,
  `AlgorithmMismatch`, `InvalidKey`) ensure consumers can react appropriately.
- A repo-wide `JoseError` enum remains an optional follow-up to unify error
  mapping across JWS/JWE/JWT surfaces. Track status in
  `docs/program-management/initiatives/jose/jose-implementation-plan.md`.

## Crypto Crate Selection

- **HMAC / SHA-256:** `hmac` + `sha2`
- **RSA & ECDSA:** `aws-lc-rs` (preferred over `ring` directly to follow
  project-wide dependency policy) with `p256` for ES256 verification convenience.
- **Randomness:** `aws-lc-rs::rand::SystemRandom`
- **No** additional OpenSSL/Lazy-Sodium dependencies introduced.

These choices are reflected in `crates/jose/Cargo.toml` and remain compatible
with the repository’s licensing constraints.

## FFI Boundary Contract

The following externs must remain stable so that future Low*/EverParse extraction
can slot in without touching consumer code:

- `jws_hmac_verify`
- `jws_rsa_verify`
- `Jose_Jwe_chacha20poly1305_encrypt`
- `Jose_Jwe_chacha20poly1305_decrypt`

Safe wrappers in the same file (`verify_hmac`, `verify_rsa`, etc.) are the
intended integration points for Rust callers; FFI replacements only need to
maintain the C ABI. Any new JOSE primitives should follow the same pattern
(e.g. `jwe_decrypt_aesgcm`, `jwk_parse_from_c`).

## Next Steps

- This memo records Phase 0 decisions only; for current implementation status and open work, see `docs/program-management/initiatives/jose/jose-implementation-plan.md`.
