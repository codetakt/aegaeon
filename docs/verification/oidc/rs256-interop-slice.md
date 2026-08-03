# OIDC `RS256 Interop Slice`

Last updated: 2026-07-24

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, contributors

## Purpose

This document records the explicit **boundary-promotion exception** that brings
the server-side OIDC / OAuth interoperability surfaces using `RS256` inside the
formal server claim **without** reclassifying broad RSA as part of the general
verified allowlist.

The canonical compliance rows for this exception are:

- `OIDC-5-002` — signed Request Objects / `request_uri`
- `7523-116` — JWT bearer grant assertions when `RS256` is allowed
- `7523-402` — `private_key_jwt` when `RS256` is allowed

## Scope

### In scope

- Direct signed Request Objects using `request=` when `alg=RS256`
- `request_uri` / PAR consumption when the referenced Request Object uses
  `RS256`
- JWT bearer grant assertion validation when `RS256` is allowed
- `private_key_jwt` validation when `RS256` is allowed
- Discovery / runtime consistency for `request_parameter_supported` and the
  `RS256`-related request-object / client-auth metadata
- The narrow runtime helpers and verification paths used by those surfaces

### Out of scope

- General-purpose RSA verification
- `RS384`, `RS512`, `PS*`, `ES*`, `RSA-OAEP`, and broad JOSE RSA support
- JWKS overlap / rotation proof promotion (tracked separately as `OIDC-2-003`)
- Any standalone client / RP product claim

## Boundary statement

- The **general verified allowlist** remains modern-only (`HS*`, `EdDSA`).
- The OIDC `RS256 Required Slice` and `RS256 Interop Slice` are both **promoted
  boundary exceptions**, not changes to the general allowlist.
- The slice remains assumption-qualified: EUF-CMA / collision resistance remain
  theorem premises, and the `aws-lc-rs` RSA PKCS#1 v1.5 SHA-256 verifier
  remains a narrow unverified TCB dependency under RC-7.
- What is promoted is the **server-side interoperability surface** for
  `RS256`-signed Request Objects, `request_uri`, JWT bearer grant assertions,
  and `private_key_jwt`, along with the associated fail-closed policy and
  protocol binding.

## Formal evidence bundle

### F*

- `fstar/par/RequestObject.fst`
  - `lemma_merge_request_object_wins`
- `fstar/auth/Pkjwt.fst`
  - `jwt_bearer_assertion_valid`
  - `jwt_bearer_jti_single_use_within_window`
  - `pkjwt_signature_verified_and_alg_allowed`
  - `pkjwt_audience_matches_expected`

### Tamarin

- `proofs/tamarin/par/jar_par_fixation.spthy`
  - `jar_parameter_fixation`
- `proofs/tamarin/client_auth/private_key_jwt.spthy`
  - `pkjwt_unforgeability`
  - `pkjwt_audience_binding`
- `proofs/tamarin/jwt_bearer/jwt_bearer_security.spthy`
  - `jwt_bearer_unforgeability`
  - `jwt_bearer_grant_integrity`
  - `jwt_bearer_no_replay`

### Runtime tests

- `crates/server/src/web/token_exchange_tests/request_object_retention.rs`
- `crates/server/src/par/tests/request_lifecycle.rs`
- `crates/server/src/client_registry/jwks_helpers_tests/registry_core.rs`
- `crates/server/src/authcode/token/tests/jwt_bearer.rs`

## Runtime linkage

- `crates/jose/src/request_object.rs`
- `crates/server/src/client_registry.rs`
- `crates/server/src/web/token_endpoint/client_auth.rs`
- `crates/server/src/web/token_jwt_bearer.rs`
- `crates/server/src/oidc/discovery.rs`
- `crates/jose/src/jws.rs`
- `crates/crypto/src/signature.rs`

The slice is intentionally narrow. It reuses the promoted `RS256` verifier path
for server-side interoperability surfaces without broadening the general RSA
claim.
The shared RS256 verifier now encodes JWK RSA public components as SPKI and
delegates PKCS#1 v1.5 SHA-256 verification to `aws-lc-rs`; Wycheproof invalid
RSA signature vectors are regression-tested in `aegaeon-jose`.

## Validation required for this promotion

The promotion record must be backed by command output captured from the repository root.
Before a release claim references this slice, refresh the evidence bundle and record the artifact
path or CI run ID for the following checks:

```bash
python3 scripts/validation/validate_compliance_matrix.py --check
python3 scripts/validation/generate_claim_index.py
python3 scripts/validation/check_runtime_drift.py --generate
cargo test -p aegaeon-server --lib web::token_exchange_tests::request_object_retention -- --nocapture
cargo test -p aegaeon-server --lib par::tests::request_lifecycle -- --nocapture
cargo test -p aegaeon-server --lib client_registry::jwks_helpers_tests::registry_core -- --nocapture
cargo test -p aegaeon-server --lib test_jwt_bearer -- --nocapture
timeout 180 tamarin-prover --prove=jar_parameter_fixation --derivcheck-timeout=180 proofs/tamarin/par/jar_par_fixation.spthy
timeout 180 tamarin-prover --prove=pkjwt_unforgeability --derivcheck-timeout=180 proofs/tamarin/client_auth/private_key_jwt.spthy
timeout 180 tamarin-prover --prove=pkjwt_audience_binding --derivcheck-timeout=180 proofs/tamarin/client_auth/private_key_jwt.spthy
timeout 180 tamarin-prover --prove=jwt_bearer_unforgeability --derivcheck-timeout=180 proofs/tamarin/jwt_bearer/jwt_bearer_security.spthy
timeout 180 tamarin-prover --prove=jwt_bearer_grant_integrity --derivcheck-timeout=180 proofs/tamarin/jwt_bearer/jwt_bearer_security.spthy
timeout 180 tamarin-prover --prove=jwt_bearer_no_replay --derivcheck-timeout=180 proofs/tamarin/jwt_bearer/jwt_bearer_security.spthy
```

## Relationship to the remaining roadmap

- **Closed now:** OIDC `RS256 Required Slice`
- **Closed now:** OIDC `RS256 Interop Slice`
- **Still open:** broader RSA promotion and non-`RS256` JOSE interoperability
- **Tracked separately:** JWKS overlap / rotation promotion (`OIDC-2-003`)
