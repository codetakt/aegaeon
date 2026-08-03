# Verified Crypto Allowlist (Strong-Constraint Mode)

Last updated: 2026-08-02

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, maintainers

This document defines the algorithm allowlist that is eligible for the **strong-constraint**
verification claim (F\* specs + HACL\*/EverCrypt implementations). The intent is:

- **Only algorithms with a verified implementation** (HACL*/EverCrypt) are in-scope.
- Algorithms implemented only via `ring`, `aws-lc-rs`, `mbedtls`, or `p256` are
  **out of scope** for the strong-constraint allowlist.

## Program posture update (2026-06-29)

Aegaeon keeps a **modern-crypto-first** verification posture:

- The server management policy is now fixed to `policy.cryptoProfile=verified`;
  `compat` is not a selectable server runtime posture.
- The **general verified allowlist** remains limited to algorithms backed by
  HACL*/EverCrypt.
- **RSA remains legacy / compat by default**, except for verified `PS256`
  verification; we do not treat “verify all of RSA” as a prerequisite for the
  main verification claim.
- **OIDC exception policy:** the OIDC Core mandatory `RS256` ID Token surface is
  now promoted as a narrow **boundary exception** (`RS256 Required Slice`)
  without reclassifying broad RSA as part of the general verified allowlist.
- The OIDC `RS256 Interop Slice` (signed Request Objects / `request_uri`,
  JWT bearer grant assertions, and `private_key_jwt`) is also now promoted as a
  narrow server-claim exception.
  Broad RSA remains outside the current claim.
- Server-issued JWT signing is an algorithm and key-selection boundary, not a
  proof that every signing backend is implemented by verified code. Local
  `databaseEncrypted` signing uses the Rust runtime crypto provider and hosted
  KMS/HSM signing is an external provider contract; verified Ed25519 coverage is
  claimed for verification paths and protocol admission, not for local private-key
  signing arithmetic.

## Boundary-promotion exceptions

The following items are **inside the formal claim by explicit exception**, even
though they are **not** part of the general verified allowlist:

1. **`RS256 Required Slice` — promoted (OIDC Core mandatory surface)**
   - OP ID Token `RS256` signing and verification semantics
   - PKCS#1 v1.5 + SHA-256 binding used by ID Tokens
   - `at_hash` / `c_hash` SHA-256 rules
   - Discovery / DCR / runtime consistency for `id_token_*` metadata
   - canonical record: `docs/verification/oidc/rs256-required-slice.md`
   - compliance row: `OIDC-1-010`
2. **`RS256 Interop Slice` — promoted (server-side interoperability surface)**
   - signed Request Objects / `request_uri`
   - JWT bearer grant assertions
   - `private_key_jwt`
   - `request_object_signing_alg_values_supported` and
     `token_endpoint_auth_signing_alg_values_supported` when `RS256` is used
   - canonical record: `docs/verification/oidc/rs256-interop-slice.md`
   - compliance rows: `OIDC-5-002`, `7523-116`, `7523-402`

The `RS256 Required Slice` and `RS256 Interop Slice` are **promoted boundary
exceptions**, not changes to the general verified allowlist. Broad `RS256` /
RSA support outside those slices remains compat.
The promoted RS256 slices are in scope for **protocol logic and boundary
conditions only**; the underlying RSA/SHA-256 implementation is unverified
`aws-lc-rs` TCB (RC-7 in the
[Runtime Contract Register](assumptions/runtime-contract-register.md)).

## Phase A Integration Status (2026-03-05) — COMPLETE

Phase A replaced all `irreducible`/`opaque_to_smt` identity/false/constant crypto models
with genuine HACL* spec-level implementations via `Spec.Agile.Hash` (SHA-256/384/512),
`Spec.Ed25519` (Ed25519 verification), and `Spec.Agile.HMAC` (HMAC-SHA256/384/512).

### Deliverables

| Component | Status | Notes |
|---|---|---|
| F* bridge module (`Verified.Crypto.Bridge.fst`) | Done | 10 HACL* wrapper functions, `irreducible`, Tot |
| 9 F* model replacements | Done | All identity/false/constant → HACL* spec calls |
| 3 tautological proofs → honest assume vals | Done | collision resistance, EUF-CMA unforgeability |
| KaRaMeL extraction + WASM build | Done | 212KB WASM binary, all crypto symbols exported |
| C bridge (`c/crypto_bridge.c`) | Done | OOM trap (KRML_HOST_EXIT), NULL checks |
| Rust `CryptoProfile::allows()` | Done | HS256/384/512, PS256 verification, EdDSA in verified allowlist |
| Rust `CryptoProfile` (Verified/Compat) | Done | `policy.cryptoProfile=verified` enforcement |
| `nix build .#verify-fstar` | Green | All passes (1, 1b, 2a-1, 2a-2, 2b) |
| `nix build .#verified-core-wasm` | Green | HACL* SHA-2 + HMAC + Ed25519 compiled |

### Crypto operations covered by Phase A

| Operation | Source module | HACL* spec | Status |
|---|---|---|---|
| SHA-256 hash | `Spec.Agile.Hash.hash SHA2_256` | `Spec.SHA2.fst` | Complete |
| SHA-384 hash | `Spec.Agile.Hash.hash SHA2_384` | `Spec.SHA2.fst` | Complete |
| SHA-512 hash | `Spec.Agile.Hash.hash SHA2_512` | `Spec.SHA2.fst` | Complete |
| HMAC-SHA256 | `Spec.Agile.HMAC.hmac SHA2_256` | `Spec.Agile.HMAC.fst` | Complete |
| HMAC-SHA384 | `Spec.Agile.HMAC.hmac SHA2_384` | `Spec.Agile.HMAC.fst` | Complete |
| HMAC-SHA512 | `Spec.Agile.HMAC.hmac SHA2_512` | `Spec.Agile.HMAC.fst` | Complete |
| Ed25519 verify | `Spec.Ed25519.verify` | `Spec.Ed25519.fst` | Complete |
| Base64url encode | Spec-level model | N/A (encoding) | Complete |

### F* functions replaced (9 targets) — ALL COMPLETE

1. `s256` (Pkce.fst) — identity → `Verified.Crypto.Bridge.sha256_hash`
2. `sha256` (Pkce.Verification.fst) — constant → `Verified.Crypto.Bridge.sha256_hash`
3. `base64url_encode` (Pkce.Verification.fst) — constant → spec model (irreducible)
4. `verify_ed25519` (Jose.Rsa_signatures.fst) — false → `Verified.Crypto.Bridge.ed25519_verify`
5. `verify_signature` (Dpop.Signature.fst) — false → `Verified.Crypto.Bridge.ed25519_verify`
6. `jwk_thumbprint` (Jose.Jwk_thumbprint_uri.fst) — identity → `Verified.Crypto.Bridge.sha256_of_string`
7. `jws_verify` (Jose.Jws.Verify.fst) — false → `Verified.Crypto.Bridge.{hmac,ed25519}` dispatch
8. `disclosure_digest` (Jose.SdJwt.fst) — identity → `Verified.Crypto.Bridge.sha256_of_string`
9. `compute_hash` (HashComputation.fst) — identity → `Verified.Crypto.Bridge.sha256_hash`

### Security property lemmas (3 targets) — ALL CONVERTED

Previously "proved" via `reveal_opaque` on identity/false models (tautological).
Phase A converts them to honest crypto `assume val` assumptions:

1. `jws_verify_unforgeable` — EUF-CMA assumption (unforgeability)
2. `disclosure_digest_collision_resistant` — SHA-256 collision resistance
3. `assumption_collision_resistance` — SHA-256 collision resistance

## Verified allowlist (eligible)

### JWS/JWT (alg)
- `HS256`
- `HS384`
- `HS512`
- `PS256` (verification only, via `Hacl_RSAPSS` on the JOSE verified dispatch,
  including promoted request-object and client-assertion routing; signing remains compat)
- `EdDSA` (Ed25519 only)

### JWE (alg / enc)
- **None yet** under strong-constraint mode.
  - `RSA-OAEP` is not available in HACL*/EverCrypt.
  - `A256GCM` is available in EverCrypt, but JWE key management is not.

## Currently supported but **not** eligible for verified allowlist

These are implemented in Rust and/or C today but **cannot be claimed as verified**
under the strong-constraint policy.

### JWS/JWT
- RSA PKCS#1 v1.5: `RS256`, `RS384`, `RS512` (aws-lc-rs on the promoted
  RS256 verifier path; other compat call sites remain provider-specific)
- RSA-PSS signing: `PS256`, `PS384`, `PS512` (`aws-lc-rs` / KMS)
- RSA-PSS verification: `PS384`, `PS512` (compat; `PS256` verification moved
  to the verified allowlist above)
- ECDSA P-256/P-384/P-521: `ES256`, `ES384`, `ES512` (ring / p256)

### JWE
- `RSA-OAEP` + `A256GCM` (RSA key management not verified)

## Blockers for expanding the verified allowlist (RS/ES)

The verified allowlist is intentionally limited to algorithms with **HACL*/EverCrypt
implementations**. `PS256` verification is wired directly to the verified
`Hacl_RSAPSS` implementation. Other RSA families and ECDSA are not wired to
HACL*/EverCrypt in this codebase, so they remain out of scope for strong-constraint
claims. Expanding the verified allowlist further requires:

1. Adding verified spec modules for RSA/ECDSA (or equivalent) and wiring them through
   `Verified.Crypto.Bridge.fst`.
2. Extracting those implementations via KaRaMeL and linking them in the C/WASM layer.
3. Updating `fstar/jose/Jose.Alg_policy.fst` and `Algorithm::is_verified()` to include
   RS/ES only after the above steps are complete.

### Alternative path: targeted OIDC `RS256` slice

The project no longer treats “general RS/ES verification” as the only viable
route forward. For OIDC positioning, a narrower path is acceptable:

1. keep the **general verified allowlist** modern-only;
2. add only `RSASSA-PKCS1-v1_5 + SHA-256` (`RS256`) required by OIDC;
3. leave broader RSA (`RS384/512`, `PS384/512`, `PS256` signing, `RSA-OAEP`)
   and non-`RS256` ECDSA in compat unless separately justified.

This targeted path now uses `aws-lc-rs` instead of project-local bigint
verification for the promoted verifier, reducing implementation risk without
changing claim status. A verified arithmetic / verification backend plus
explicit hardness assumptions is still required before RC-7 can be removed.

## Notes

- The verified allowlist is codified in `fstar/jose/Jose.Alg_policy.fst` as
  `verified_allowed` / `is_verified_alg`.
- The legacy allowlist (non-verified) remains defined separately to preserve
  interoperability until the verified integration is complete.
- The OIDC `RS256 Required Slice` and `RS256 Interop Slice` are now part of the
  formal server claim by explicit boundary promotion. Broad RSA remains compat.
- EdDSA here means **Ed25519 only**. Ed448 is **not** included.

## CryptoProfile Enforcement Map

Because server `policy.cryptoProfile` is fixed to `verified`, only algorithms with
HACL*/EverCrypt implementations plus the promoted `RS256` boundary-exception slices are
accepted on claim-bearing server paths. The enforcement is applied at the following
verification entry points:

| Entry Point | Enforced? | Mechanism | Rationale |
|---|---|---|---|
| `private_key_jwt` | **Yes for promoted `RS256` and `PS256` verification** | Management/runtime policy defaults `clientJwtAllowedAlgs` to `RS256` and permits explicit `PS256`; both use promoted client-assertion verifier routing | `RS256` remains a boundary exception; `PS256` routes to verified `Hacl_RSAPSS`; PS384/512 and ES client-auth remain unavailable |
| JWT bearer grant | **Yes for promoted `RS256` and `PS256` verification** | `ClientRegistry::try_validate_jwt_bearer_grant_assertion` applies the client JWT allow-list and routes both algorithms through promoted verification | `RS256` remains a boundary exception; `PS256` routes to verified `Hacl_RSAPSS`; broader RSA-PSS and ES assertions remain unavailable |
| DPoP proof | **Inherently verified** | `ffi::verify_dpop` hardcodes EdDSA (Ed25519); metadata advertises EdDSA only | Only accepts OKP/Ed25519 keys; metadata aligned |
| Federation trust chain | **Bypassed / compat-only** | Uses `verify_compact_with_context` (profile-blind) | ES256 is required by OIDC Federation trust chains and remains outside the server strong-constraint claim; Federation OP signing is disabled in the verified server runtime until an ES256 promotion exists |
| Request object (JAR) | **Yes for promoted `RS256` and `PS256` verification** | `ClientRegistry::verify_request_object` pre-decodes the JOSE header and routes `RS256` to the boundary-exception verifier and `PS256` to `Hacl_RSAPSS`; other algorithms retain the profile gate | `RS256` remains part of the Interop Slice boundary exception; `PS256` is verified-backend routing; PS384/512 and ES remain rejected under `Verified` |
| JWT Access Token / Introspection signing | **Yes for algorithm and key-selection boundary** | Runtime key policy and database constraints allow `EdDSA` only for OAuth JWT signing usages; local signing uses `aegaeon_crypto::signing::Ed25519SigningKey` and hosted signing must be treated as a provider contract | Server-issued OAuth JWT signing does not admit ES256/RS256/HS* for those usages. The strong claim covers policy admission, key/JWKS consistency, and verified EdDSA verification paths; the local signing backend itself is a runtime crypto TCB unless separately promoted |
| JWS verification (generic) | **Available** | `verify_compact_with_profile` | Caller must opt in |

## Profiles and claim boundary

- Allowlist selection remains **per instance** for non-server consumers (IdP, RP,
  federation chain), not a server-global library constant.
- The server runtime is configured with the verified allowlist only.
- Non-server consumers using the compat allowlist remain outside the
  strong-constraint verification claim.
