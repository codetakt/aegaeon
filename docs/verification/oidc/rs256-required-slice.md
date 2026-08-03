# OIDC `RS256 Required Slice`

Last updated: 2026-07-24

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, contributors

## Purpose

This document records the explicit **boundary-promotion exception** that brings
Aegaeon's OIDC Core mandatory `RS256` ID Token surface inside the formal claim
**without** reclassifying broad RSA as part of the general verified allowlist.

The canonical compliance row for this exception is `OIDC-1-010` in
`spec/compliance-matrix.yaml`.

## Scope

### In scope

- OP ID Token `RS256` issuance for the OIDC Core server claim
- `RS256`-specific `at_hash` / `c_hash` computation and truncation rules
- ID Token structural framing checks before claim validation
- ID Token claim validation rules already modeled in F* (`iss`, `aud`, `azp`,
  time, `nonce`, `max_age`, hash binding)
- Discovery / DCR / runtime consistency for the mandatory `id_token_*` metadata
- Centralized runtime helper used by the mandatory ID Token path

### Out of scope

- General-purpose RSA verification
- `RS384`, `RS512`, `PS*`, `RSA-OAEP`, and broad JOSE RSA support
- Signed Request Objects / `request_uri` / JWT bearer grant assertions /
  `private_key_jwt` when they use `RS256` (tracked separately as the
  `RS256 Interop Slice`)
- Any client / RP product claim

## Boundary statement

- The **general verified allowlist** remains modern-only (`HS*`, `EdDSA`).
- The OIDC `RS256 Required Slice` is a **promoted exception**, not a change to
  the general allowlist.
- The slice is still assumption-qualified: EUF-CMA / collision resistance remain
  theorem premises, and the `aws-lc-rs` RSA PKCS#1 v1.5 SHA-256 verifier
  remains a narrow unverified TCB dependency under RC-7.
- What is promoted is the **OIDC-required surface**: the formally modeled claim
  semantics, structural checks, protocol binding, and fail-closed runtime path
  for mandatory `RS256` ID Tokens.

## Formal evidence bundle

### F*

- `fstar/oidc/IdToken.Spec.fst`
  - `well_formed_id_token_prop`
  - `oidc_token_prop`
- `fstar/HashComputation.Model.fst`
  - `compute_oidc_hash_bytes_tot`

### EverParse / Kani

- `fstar/lowparse/IdTokenSchema.3d`
- `generated/everparse/IdTokenSchema.c`
- `crates/ffi/src/id_token.rs`
  - `oidc_id_token_jwt_canonicalisation_no_panic`

### Tamarin

- `proofs/tamarin/oidc/oidc_core.spthy`
  - `id_token_session_binding`
  - `token_binding_integrity`

## Runtime linkage

- `crates/server/src/oidc/required_rs256.rs`
- `crates/server/src/authcode/token.rs`
- `crates/server/src/web/token_authorization_code.rs`
- `crates/server/src/web/upstream_id_token/signature.rs`
- `crates/server/src/oidc/discovery.rs`
- `crates/jose/src/jws.rs`
- `crates/crypto/src/signature.rs`

The helper module centralizes the promoted slice so the OP issuance path and the
server-side RP/brokering verification path use the same narrow `RS256` helper.
The server claim is driven by the OP mandatory ID Token surface; helper reuse in
RP/brokering code is implementation hygiene and regression coverage, not a broad
client claim.
The RSA PKCS#1 v1.5 verifier now delegates to `aws-lc-rs` through
`aegaeon_crypto::signature::verify_rsa_pkcs1_sha256`; the previous project-local
bigint envelope check is no longer part of this path.

## Fresh validation used for this promotion

The promotion record is backed by fresh command output captured in this session
under `artifacts/verification/oidc-rs256-required-slice/20260309T014321Z`.

The commands were run via `nix develop .#verification` and include:

```bash
cargo test -p aegaeon-server required_rs256 -- --nocapture
cargo test -p aegaeon-server --lib decode_upstream_id_token_accepts_rs256_required_slice -- --nocapture
cargo test -p aegaeon-server --lib validate_upstream_id_token_requires_access_token_when_at_hash_present -- --nocapture
cargo test -p aegaeon-server --test upstream_refresh_test -- --nocapture
python3 scripts/validation/validate_compliance_matrix.py --check
timeout 180 tamarin-prover --prove=id_token_session_binding --derivcheck-timeout=180 proofs/tamarin/oidc/oidc_core.spthy
timeout 180 tamarin-prover --prove=token_binding_integrity --derivcheck-timeout=180 proofs/tamarin/oidc/oidc_core.spthy
cd fstar && fstar.exe --use_hints --hint_dir . --expose_interfaces \
  crypto/Verified.Crypto.Bridge.fst \
  jose/Jose.False.fst \
  HashComputation.fst \
  HashComputation.Model.fst \
  oidc/IdToken.Spec.fst
timeout 180 cargo kani --manifest-path crates/ffi/Cargo.toml --features kani \
  --harness oidc_id_token_jwt_canonicalisation_no_panic
```

## Relationship to the remaining roadmap

- **Closed now:** OIDC `RS256 Required Slice`
- **Closed now:** OIDC `RS256 Interop Slice`
- **Still out of scope:** general RSA promotion and any standalone client / RP
  verification claim
