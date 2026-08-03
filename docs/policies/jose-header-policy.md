# JOSE Protected Header Length Policy

Last updated: 2026-07-07

Status: current implementation baseline

Owner: Governance

Audience: contributors, maintainers

## Ownership
- Owner: Crypto/FFI
- Review by: Security/Verification

This policy defines the operational guard rails for Base64URL-encoded JOSE protected
headers (JWS/JWE) processed by Aegaeon and documents the handling of optional header
fields that are currently unsupported by the Low*/C roadmap.

## Rationale

- Keeps parsing and verification costs predictable.
- Prevents unbounded attacker-controlled memory consumption.
- Aligns runtime behaviour with F*/Low*/C verification assumptions.

## Default Limit

- `JOSE_HEADER_MAXLEN = 4096` characters (Base64URL string length).
- Value chosen to remain well below common HTTP header size caps (~8 KB) while
  comfortably exceeding typical JOSE header sizes (tens to hundreds of bytes).

## Configuration

### Per-Request Context API (Recommended)

The `JoseContext` type provides per-request configuration of JOSE processing policies:

```rust
use aegaeon_jose::policy::JoseContext;
use aegaeon_jose::jws;

// Use default context (4096 byte limit)
let context = JoseContext::default();
jws::verify_compact_with_context(jws_string, key, &context)?;

// Use custom limit for specific request
let context = JoseContext::new(8192);
jws::verify_compact_with_context(jws_string, key, &context)?;
```

Benefits:
- Thread-safe without global mutable state
- Allows different limits for different request types
- Aligns with F*/Low* verified context propagation
- Future-extensible for additional per-request policies

### Server Runtime Policy

- Active database policy field: `policy.joseHeaderMaxLen`
  - Default: `4096`
  - Valid range: `1..=65536`
  - Applies to server request-object, PAR, client assertion, JWT bearer, and other
    server JOSE admission paths that construct a per-request `JoseContext`.
- Removed server environment variable: `AEGAEON_JOSE_HEADER_MAXLEN`.
  Server startup fails closed if this variable is present; PostgreSQL-backed
  management policy is authoritative.
- The hydrated server policy is also propagated to the deprecated
  `aegaeon_jose::policy::header_max_len()` fallback for legacy crate call sites.
- **Migration**: Replace direct calls to `header_max_len()` with explicit
  `JoseContext::new(policy.joseHeaderMaxLen)` propagation or `JoseContext::default()`
  where a server-managed policy is not available.

### Enforcement

- Requests exceeding the configured limit are rejected before Base64 decode and
  logged for auditing.
- Both old `verify_compact()` and new `verify_compact_with_context()` enforce limits.
- The context-based API provides the path forward for verified per-request policies.

## Verification Alignment

### F* Specification Layer
- `fstar/jose/Jose.Context.fst` defines the abstract `jose_context` type and verified
  constructor `make_context`.
- `fstar/jose/Jose.Policy.fst` captures the limit extraction from context (`header_max_length`).
- `fstar/jose/Jose.LowStar.fst` (`lemma_jwe_parse_length_sound`, `lemma_jws_parse_length_sound`)
  prove that any successful parse implies the input length is within the
  configured limit.

### Low* Extraction Layer
- `generated/lowstar/jose/Jose_Context.{h,c}` exports:
  - `Jose_Context_jose_context` type (krml_checked_int_t)
  - `Jose_Context_default_context` constant (4096)
  - `Jose_Context_make_context()` constructor
- KaRaMeL extraction ensures type safety and memory layout compatibility with C ABI.
- The current JOSE header JSON Low* path uses the
  `Jose.LowStar.Json.Stack` / `bytes_block` representation, so extracted member
  buffers and lengths are carried through `UInt32`-backed machine integers
  rather than nat-heavy public records. This is the current mitigation for the
  former Warning 15 pressure on the JOSE header path and keeps the exposed C ABI
  aligned with fixed-width integer expectations.

### Rust FFI Layer
- `crates/ffi/src/lib.rs` provides:
  - FFI bindings to Low* `Jose_Context_*` functions
  - Safe `JoseContext` wrapper with bounds checking
  - Default context accessor matching Low* constant
- `crates/jose/src/{jws,jwe}.rs` propagate context through verification APIs.
- Both legacy (`verify_compact`) and new (`verify_compact_with_context`) APIs
  enforce limits, ensuring backward compatibility.

### Test Coverage
- `tests/fstar/property/TestJoseHeaderMicro.fst` checks that the micro header parser
  agrees with the sanitized spec parser for string-valued fields.
- Rust unit tests `crates/jose/src/{jws,jwe}.rs` verify rejection of oversized headers.
- Integration tests validate context propagation from Rust → FFI → Low\* → F\*.

## Migration Guide

### From Global `header_max_len()` to `JoseContext`

**Before (deprecated):**
```rust
use aegaeon_jose::jws;
use aegaeon_jose::policy::header_max_len;

// Global configuration via environment variable or set_header_max_len()
let payload = jws::verify_compact(jws_string, key)?;
```

**After (recommended):**
```rust
use aegaeon_jose::jws;
use aegaeon_jose::policy::JoseContext;

// Per-request context - use default
let context = JoseContext::default();
let payload = jws::verify_compact_with_context(jws_string, key, &context)?;

// Or create custom context for specific requests
let context = JoseContext::new(8192);
let payload = jws::verify_compact_with_context(jws_string, key, &context)?;
```

### Migration Checklist

1. **Update imports**: Add `use aegaeon_jose::policy::JoseContext;`
2. **Create context**: Add `let context = JoseContext::default();` or custom limit
3. **Update function calls**:
   - `jws::verify_compact(jws, key)` → `jws::verify_compact_with_context(jws, key, &context)`
   - `jwe::decrypt_rsa_oaep_a256gcm_pkcs8(jwe, key)` → `jwe::decrypt_rsa_oaep_a256gcm_pkcs8_with_context(jwe, key, &context)`
4. **Remove `header_max_len()` calls**: No longer needed with context-based API
5. **Update tests**: Use context-based APIs in test code

### Backward Compatibility

The legacy APIs (`verify_compact`, `decrypt_rsa_oaep_a256gcm_pkcs8`) remain
available for backward compatibility but are deprecated. They internally use
`JoseContext::default()`. New code should use the context-based APIs.

## Operational Guidance

- Keep the default unless a documented interoperability requirement mandates an
  increase; review security impact before raising the limit.
- Lowering the limit is safe provided it remains above the largest expected
  production header (monitor logs for rejections when tightening).
- Document any deviation from the default in release notes and update F* proofs
  if the new bound exceeds 4096.
- Use per-request contexts to apply different limits to different request types
  (e.g., stricter limits for untrusted sources).

## Optional Header Handling (Interim)

Until Phase 2.1 of the Low*/C roadmap delivers verified parsing for all optional
fields, the following policies apply:

- `zip` (RFC 7516 §4.1.3): Compression is not yet supported; reject any protected
  header where `zip` is present unless the value is exactly `DEF` and an explicit
  feature flag enables it. Default posture: reject.
- `crit` (RFC 7515 §4.1.11): Must be rejected unless every listed extension is
  explicitly understood. Aegaeon rejects `crit` in both the TLV and JSON decoders;
  regressions are monitored via the unit tests `jwe_header_rejects_crit` /
  `verify_compact_rejects_crit_header` in `crates/jose/src/jwe.rs` and
  `crates/jose/src/jws.rs`.
- `kid` (RFC 7515 §4.1.4): If present must be ASCII and 1–255 characters. Longer or
  empty identifiers are rejected before signature verification. The tests
  `kid_validation_rejects_empty` / `kid_validation_rejects_too_long_or_non_ascii`
  in `crates/jose/src/jws.rs` cover ASCII + length constraints and align with the
  F* lemma `valid_kid_string`.
- `typ` / `cty` (RFC 7515 §4.1.9 / §4.1.10): Accepted as informational hints when
  ≤ 255 ASCII characters; values exceeding the bound or containing non-printable
  characters are rejected. Verification coverage will be added alongside Low*
  extraction.
- Additional custom headers: reject unless documented and supported by policy.

The compliance matrix rows `7515-CRIT-NOT-SUPPORTED`, `7516-ENC-ALLOWLIST` and
related entries reference this section as the authoritative run-time behaviour.
