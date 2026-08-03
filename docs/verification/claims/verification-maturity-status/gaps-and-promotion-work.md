# Verification Maturity Gaps And Promotion Work

Last updated: 2026-07-08

Status: snapshot

Owner: Verification

Audience: verification reviewers, maintainers

> **Status note (2026-07-08):** Snapshot of the current verification maturity assessment; rerun the evidence checks before using it for a new release review.

This document is part of the split verification maturity-status snapshot.

## 5. Why Level 2 Is Not Yet Satisfied

Level 2 requires all in-scope decision kernels in the claim-bearing path to use
verified or extracted implementations, with missing verified artefacts causing
build failure or explicit fail-closed behaviour.

That condition is **not** yet met.

### 5.1 JOSE raw input is not end-to-end verified

- `crates/jose/src/json_lowstar.rs` first parses raw bytes with
  `serde_json`, using a duplicate-preserving object visitor that keeps JOSE
  header member order and rejects duplicate keys before the Low* bridge.
- `crates/jose/src/raw_json.rs` now centralizes the duplicate-preserving
  top-level object admission used by JOSE headers and Request Object raw
  payload handling; server-side DCR admission also reuses that helper before
  surface-specific normalization. The helper is surface-aware and records the
  ingress (`generic-object`, `jose-header`, `request-object`,
  `client-registration`, `software-statement`,
  `private-key-jwt-payload`, `jwt-bearer-assertion-payload`,
  `oidc-id-token-payload`,
  `jwt-access-token-header`, `jwt-access-token-payload`,
  `federation-entity-statement`, `federation-trust-mark`) that selected the
  current backend. `jose-header`, `request-object`, `client-registration`,
  `software-statement`, `oidc-id-token-payload`, `jwt-access-token-header`,
  `jwt-access-token-payload`, `federation-entity-statement`, and
  `federation-trust-mark` now default to the `verified-structural-v1` backend
  and reach surface-specific typed decoders directly from the structural IR
  (`key + (string | null)` for JOSE headers, `RequestObjectClaims` plus the
  JWT validation subset for Request Objects, typed metadata extraction for
  client registration, SSA Profile v1 registered-claim plus typed DCR metadata
  admission for software statements, `IdTokenClaims` for Required-RS256 OIDC payloads,
  `kid` / `typ` extraction for JWT access-token headers,
  `iss` / `sub` / `aud` / `exp` / `iat` / `jti` extraction for JWT
  access-token payloads, `iss` / `sub` / `iat` / `exp` plus bounded nested
  JSON slices for federation entity statements, and
  `iss` / `sub` / `id` / `iat` / `exp` / `ref_` extraction for federation
  trust marks, and registered-claim shape for `private-key-jwt-payload` and
  `jwt-bearer-assertion-payload`), while the remaining compat-only surface
  (`generic-object`) still tokenizes raw bytes through the `SerdeCompat`
  implementation. The claim-bearing helper flows for software statements,
  promoted `private_key_jwt`, and JWT bearer assertions now bind to dedicated
  promoted surfaces instead of sharing `generic-object`; DPoP nonce extraction
  no longer depends on a separate raw JSON helper surface. The
  broad semantic object-decode wrappers are now explicitly named
  `deserialize_compat_*`, which makes the compat-only boundary visible in code
  without changing the released formal claim.
- This is an improvement over `serde_json::Value` object materialization, but it
  still means first-stage tokenization for the residual `generic-object`
  compatibility surface is not a verified parser on the original raw JSON byte
  stream.

### 5.2 JOSE header paths still have non-verified parser fallbacks

- `crates/jose/src/jws.rs`
  - `peek_alg_from_b64(...)` falls back to the local
    `json_lowstar::parse_json_header_pairs_compat(...)`
    on `JsonError::ParserUnavailable`
  - `parse_header_bytes(...)` does the same
- `crates/jose/src/jwe.rs`
  - `JweHeader::from_slice(...)` falls back to the same
    `json_lowstar::parse_json_header_pairs_compat(...)`
    on `JsonError::ParserUnavailable`
- `crates/ffi/src/lib.rs`
  - test / Kani / `no_mbedtls` builds return `JsonError::ParserUnavailable`
    from the JSON parser stub

A non-default Cargo feature now exists to isolate these branches:

- `aegaeon-jose --features verified-claim`
  - disables the serde fallback in `jws.rs` / `jwe.rs`
  - fails closed on JOSE TLV EverParse entry-validator unavailability
  - turns `ParserUnavailable` into an explicit fail-closed error
  - is exercised by JOSE vector/parity runs plus targeted fail-closed CI tests
- `aegaeon-server --features verified-claim`
  - fails closed on OIDC Required-RS256 ID Token structure-parser unavailability
  - fails closed on OIDC hash runtime unavailability / failure
  - requires canonical EverParse self-checks for DCR metadata and Request
    Object claims even when the compatibility env gates are off

Level 2 is still not closed because the default compatibility surface retains
these fallbacks for interoperability, and `json_lowstar.rs` still begins from a
non-verified `serde_json` tokenization stage instead of a raw-byte verified parser.

### 5.3 An explicit strict profile now exists, but it is not yet sufficient

- `crates/jose/Cargo.toml`
  - `verified-claim = ["ffi/verified-claim", "everparse_jose_header_entry"]`
- `crates/server/Cargo.toml`
  - `verified-claim = ["ffi/verified-claim", "aegaeon-jose/verified-claim"]`
- `scripts/flake/verify_jose_check.sh`
  - now runs JOSE vector/parity coverage across the default,
    `everparse_jose_header_entry`, `ffi_jose_header_tlv`, and
    `verified-claim` profiles, plus targeted OIDC strict-boundary regressions
    for the ID Token structure parser and OIDC hash runtime
- `.github/workflows/verification.yml`
  - runs JOSE vector/parity tests across the default,
    `everparse_jose_header_entry`, `ffi_jose_header_tlv`, and
    `verified-claim` profiles, plus targeted fail-closed smoke tests for JOSE
    parser unavailability and OIDC structure-parser/hash handling
- `scripts/security/run_security_suite.sh`
  - the `jose-boundaries` stage now records TLV parity artifacts across the
    default, `everparse_jose_header_entry`, `ffi_jose_header_tlv`, and
    `verified-claim` profiles

This is progress toward Level 2 because the intended claim-bearing profile is now
named and exercised. It is still insufficient because:

- JOSE raw input still begins with non-verified serde tokenization before Low*
  checks, even though duplicate-key collapse through `serde_json::Value` has
  now been removed
- the server-side JWT assertion surfaces reviewed here now reject duplicate
  top-level claim keys before deserialization: Required-RS256 ID Tokens,
  promoted RS256 `private_key_jwt`, software statements, JWT bearer
  assertions, JWT access tokens, federation entity statements, and federation
  trust marks. The DPoP nonce extraction helper also now rejects duplicate
  top-level keys before selecting `nonce`. These surfaces still begin with
  non-verified `serde_json` tokenization rather than verified raw-byte parsers
- DCR / Request Object raw admission now rejects duplicate top-level keys
  before normalization, but it still begins with non-verified `serde_json`
  tokenization and only reaches EverParse after Rust-side decoding
- the OIDC hash path now uses a dedicated C runtime shim in the strict profile,
  but it is still not restored as a fully extracted / proof-linked runtime path

### 5.4 EverParse self-checks do not yet validate raw DCR / Request Object inputs

- `crates/server/src/dcr.rs`
  - the registration endpoints now re-parse the raw top-level JSON object,
    reject duplicate metadata keys before normalization, and then run the
    canonical EverParse self-check on the normalized metadata
- `crates/server/src/request_object.rs`
  - `everparse_self_check_request_object_claims(...)` is likewise a canonical
    self-check after Rust-side decoding
- `crates/jose/src/request_object.rs`
  - the verified Request Object flow now re-decodes the raw JWT payload bytes,
    rejects duplicate top-level claim keys before normalization, and only then
    converts into `RequestObjectClaims`
- `crates/server/tests/jar_par_binding_test.rs`
  - the `/authorize` Request Object (`request`) integration path now has an
    RS256 regression test proving duplicate top-level claim keys fail closed
    before the authorization response is issued
- `crates/ffi/src/dcr_parser.rs` and `crates/ffi/src/request_object_parser.rs`
  - expose parser-unavailable behaviour in some builds

In `--features verified-claim`, the server now treats both canonical self-checks
as mandatory and fails closed on parser unavailability. DCR and Request Object
handling have both improved beyond pure post-parse self-checking: the raw
top-level object is now checked for duplicate keys before normalization. Even
so, Level 2 is still not closed because:

- DCR / Request Object raw parsing still begins with `serde_json`
  tokenization rather than a verified parser
- the EverParse stage still runs only after Rust-side decoding and
  canonicalization

### 5.5 OIDC hash computation is routed through a strict-profile runtime shim, not yet extracted closure

- `crates/server/src/oidc/id_token.rs`
  - `compute_hash(...)` first tries `ffi_id_token::compute_oidc_hash_bytes(...)`
  - in the default compatibility build, `OidcHashError::Unavailable` or other
    FFI failure still falls back to the Rust hash implementation
  - in `--features verified-claim`, the profile enables `ffi/lowstar_hash`,
    which links `c/hash_computation_runtime.c` and exercises that runtime via
    `oidc_hash_vectors`; unavailability or runtime failure still fails closed

This is still not enough for Level 2 closure because the OIDC hash runtime is a
source-managed C shim around the Tot-level model, not an extracted /
proof-linked Low* implementation. The extracted
`generated/lowstar/oidc/id_token/` runtime artefacts are now source-managed and
compile-checked, but they remain opt-in and are not part of the current strict
profile.

### 5.6 Important F* boundaries remain assumption-qualified

The stronger Level 2+ wording also depends on closing or explicitly limiting
remaining F* assumption boundaries. Relevant files still contain `assume val`
contracts for hardness or runtime linkage:

- `fstar/crypto/Verified.Crypto.Bridge.fst`
- `fstar/verifiedcore/api/VerifiedCore.Crypto.Hacl.fst`
- `fstar/verifiedcore/api/VerifiedCore.Api.Claims.Runtime.fst`
- `fstar/jose/Jose.Jws.Verify.fst`
- `fstar/HashComputation.fst`
- `fstar/jose/Jose.SdJwt.fst`

These do not invalidate Level 0/1, but they matter for stronger
implementation-closure wording.

## 6. Why Level 3 Is Not Yet Satisfied

Level 3 requires the authoritative security-critical state machines to live in
verified kernels or to have an explicit refinement trace from the Rust
implementation to the verified model.

Fresh code evidence shows the critical state-transition kernels are still
authoritative Rust implementations:

- **Authorization code store / single use**
  - `crates/server/src/authcode/store.rs`
  - `AuthCodeStore` uses `HashMap`, `RwLock`, and direct Rust mutation for
    `store_code(...)`, `use_code(...)`, and nonce/state TTL cleanup.
- **Refresh-token rotation**
  - `crates/server/src/authcode/store.rs`
  - `TokenStore::rotate_refresh_token(...)` is implemented directly in Rust.
- **Authorization code exchange / token issuance**
  - `crates/server/src/authcode/token.rs`
  - issuance, redemption, refresh rotation orchestration, and JWT access-token
    issuance/verification (`sign_jwt(...)`, `verify_jwt(...)`) are custom Rust.
- **PAR single-use storage**
  - `crates/server/src/par.rs`
  - `ParStore::store_request(...)` and `consume_request(...)` are direct Rust
    state transitions over `HashMap` / `RwLock`.
- **Replay prevention**
  - `crates/server/src/middleware/replay_store.rs`
  - `ReplayStore::check_and_store(...)` is implemented in ordinary Rust for both
    in-memory and Redis-backed stores.

The repository does contain state-machine specifications in F*, but the current
authoritative runtime state kernels are not yet verified implementations and do
not yet have an explicit refinement closure document that would satisfy Level 3.

## 7. Why Level 4 Is Not Yet Satisfied

Level 4 is the first level where the stronger implementation-closure statement
becomes defensible.

That level is not yet satisfied because:

- Level 2 is not closed
- Level 3 is not closed
- the claim-bearing surface still contains optional verified paths, parser
  unavailability stubs, and Rust fallbacks
- the explicit TCB inventory exists, but the runtime kernel has not yet been
  reduced to verified decision kernels plus explicit TCB only

## 8. Practical Interpretation

The repository is currently best described as follows:

- it clearly exceeds a "proofs only on paper" state
- it has live verified decision-kernel linkages in runtime code
- it does **not** yet have fail-closed verified decision-kernel closure
- it does **not** yet have verified state-transition-kernel closure
- it therefore cannot yet support the stronger Level 4 statement:

> The JOSE / PKCE / DPoP / DCR / OIDC security-critical decision kernel, and the
> authorization code / refresh rotation / PAR / replay prevention
> state-transition kernel, are implemented as formally verified code. DB, OS
> entropy, HTTP fetch, KMS, and external stores are explicit TCB elements.

## 9. Promotion Work Needed

To reach **Level 2**:

- promote the new `verified-claim` profile from smoke-tested scaffolding to the
  actual claim-bearing profile for the intended released surface
- replace the current OIDC hash shim with an extracted / proof-linked runtime
  closure so `verified-claim` does not depend on a source-managed bridge for
  that surface
- move raw JOSE / DCR / Request Object / ID Token admission onto verified or
  extracted parsers, or explicitly narrow the claimed scope

To reach **Level 3**:

- move authorization-code, refresh-rotation, PAR, and replay-store kernels into
  verified implementations, or
- produce explicit refinement traces from the authoritative Rust code to the
  verified F* models (function-symbol-level traces now exist for all 161
  MUST-level verified entries as of 2026-07-29 and are gate-enforced via
  `--require-trace-must`; promotion to this maturity level additionally
  requires the kernel-closure work above)

To reach **Level 4**:

- close both decision-kernel and state-transition-kernel gaps
- keep remaining DB / OS entropy / HTTP fetch / KMS / external store
  dependencies as explicit, documented TCB contracts only
