# OIDC KMS/HSM Signing Design

Last updated: 2026-07-08

Status: active plan

Owner: Engineering

Audience: implementation contributors, maintainers

This document fixes the current design baseline for Workstream E in
`docs/program-management/roadmaps/active/management-platform-follow-on-plan.md`.
Its job is to describe how OIDC signing can move from locally loaded RSA keys to
KMS/HSM-backed signing without silently changing the current release wording or
claim boundary.

It is a design document, not an implementation-complete runbook.

## Implementation status

As of 2026-06-27, the following parts are implemented in the backend:

- `OidcSigningKey` now supports both:
  - local PKCS#8 key material loaded from management-database runtime keys
  - feature-gated AWS KMS-backed signing loaded from management-database runtime keys
- production OIDC signing configuration is built from the active
  `aegaeon.runtime_keys` snapshot through
  `OidcConfig::from_management_snapshot(...)` /
  `OidcConfig::from_management_snapshot_async(...)`
- startup OIDC signing environment variables are rejected in production by the
  management-database runtime boundary; they are retained only for focused
  parity/evidence harnesses
- local and AWS KMS runtime-key paths fail closed when the published
  management-database `public_jwk` does not match the actual private key or
  provider-derived public key
- existing OIDC signing call sites continue to use the same `sign_rs256_jwt(...)` and `jwks()`
  façade
- a focused AWS KMS OIDC parity test exists in `crates/server/tests/kms_integration_test.rs` and
  exercises the KMS-backed `OidcSigningKey` path when LocalStack is available

The following work is still pending:

- final release classification of any concrete KMS/HSM-backed deployment as claim-preserving or
  compat-only

The following local backend-side follow-on is now implemented:

- always-on provider-backed parity enforcement in CI / release evidence via
  `scripts/validation/run_oidc_kms_parity.sh`
- operator runbooks for KMS/HSM-backed OIDC signing under
  `docs/operations/oidc-kms-signing.md`

## 1. Current code baseline

The current production OIDC signing path is management-database runtime-key
based. PostgreSQL is mandatory for the server runtime, and the active
configuration snapshot, not process environment, is the production authority for
OIDC signing material.

### 1.1 Configuration entry point

- `crates/server/src/oidc/config.rs`
  - `OidcConfig::from_management_snapshot(...)`
  - `OidcConfig::from_management_snapshot_async(...)`
- `crates/server/src/oidc/config/runtime_keys.rs`
  - reads active and retiring `OIDC_ID_TOKEN_SIGNING` runtime keys
  - builds either local PKCS#8 or AWS KMS `OidcSigningKey` instances
  - rejects mismatched `public_jwk` values before any signer is exposed
- Required production inputs:
  - an active `OIDC_ID_TOKEN_SIGNING` runtime key in `aegaeon.runtime_keys`
  - `databaseEncrypted` provider with encrypted PKCS#8 key material, or
  - `awsKms` provider with encrypted KMS key id and provider configuration
- Optional overlap publication:
  - retiring `OIDC_ID_TOKEN_SIGNING` runtime keys in the same snapshot

`OidcSigningKey` currently bundles four responsibilities into one type:

1. signer custody through either local RSA key material or AWS KMS
2. active signing `kid`
3. active public JWK derivation and runtime-key consistency checking
4. JWKS overlap publication

The historical `OidcConfig::from_env(...)` and
`AEGAEON_OIDC_SIGNING_*` startup-key variables are no longer production
configuration surfaces. They exist only for isolated tests, parity scripts, and
evidence harnesses that do not construct a full management snapshot.

### 1.2 Runtime call sites

The active local RSA signer is consumed in these places:

- `crates/server/src/authcode/token.rs`
  - `required_rs256::sign_required_id_token(...)`
- `crates/server/src/web/mod.rs`
  - `build_backchannel_logout_token(...)`
  - `decode_id_token_hint(...)` via `cfg.signing_key.jwks()`
- `crates/server/src/oidc/discovery.rs`
  - discovery metadata continues to advertise `RS256`

### 1.3 KMS abstraction boundary

`crates/server/src/kms/mod.rs` and `crates/server/src/kms/aws.rs` are not the
production OIDC signing abstraction.

- `KeyManager` is oriented around:
  - HMAC signing/verification for token paths
  - federation-specific ES256 signing
- `LegacyAwsKmsKeyManager` currently uses
  `SigningAlgorithmSpec::RsassaPssSha256`
- OIDC ID Token signing requires `RS256`, which is
  `RSASSA-PKCS1-v1_5 + SHA-256`, not PSS
- JWKS publication for OIDC requires modulus/exponent and a stable `kid`

The production AWS KMS OIDC path therefore uses the OIDC-specific
`OidcAwsKmsSigner` behind `OidcSigningKey` and is selected only by
management-database runtime-key provider metadata.

## 2. Design constraints

The implementation must preserve the following properties.

### 2.1 Release / claim constraints

- Do not silently widen the current formal claim.
- Keep the existing promoted OIDC `RS256 Required Slice` posture explicit.
- Treat KMS/HSM as an external runtime dependency / TCB element, not as
  something that becomes formally verified by being connected.

### 2.2 Protocol constraints

- Continue emitting standards-compliant `RS256` ID Tokens.
- Keep discovery and JWKS views coherent with the active signing key.
- Keep overlap/rotation behavior safe for relying parties that cache JWKS.
- Do not change `id_token_hint` verification semantics.

### 2.3 Operational constraints

- Never reuse a `kid` for different key material.
- Fail closed if public-key derivation, signer capability detection, or
  algorithm classification is ambiguous.
- Keep the active signer and published JWKS derived from the same key material.

## 3. Claim posture classification

Every KMS/HSM-backed OIDC signing path must be classified into one of these
postures before release use.

### 3.1 Claim-preserving path

A KMS/HSM-backed path is claim-preserving only if all of the following hold:

1. the external signer performs exact `RS256`
    (`RSASSA-PKCS1-v1_5 + SHA-256`)
2. the JWS signing input is still constructed by Aegaeon in the same way as the
    current local path
3. the active public JWK is derived from the same key via an authoritative
    provider API or an equivalently checked import path
4. JWKS overlap / rollback rules remain unchanged from the local-key path
5. focused regression tests prove parity with the current local signer

If any of these conditions is missing, the path must not be described as
claim-preserving.

### 3.2 Compat-only path

A path is compat-only if any of the following applies:

- the provider exposes only PSS or another non-`RS256` algorithm
- the integration relies on a gateway that returns a finished JWT blob rather
  than a raw signature over the local signing input
- the public JWK is operator-supplied without a key-match check against the
  actual signer
- overlap publication cannot be kept coherent during rotation
- tests prove operational support only, not parity with the current promoted
  slice

Compat-only paths may still be useful operationally, but they must stay outside
the stronger release wording.

## 4. Target architecture

### 4.1 Split the current `OidcSigningKey` responsibilities

The current `OidcSigningKey` should be refactored into:

- a signer-facing abstraction for raw JWS signatures
- a JWKS/public-material view
- a posture/classification marker

The implementation shape can be a trait object or an enum, but the runtime API
must cover at least:

```rust
trait OidcSigner {
    fn kid(&self) -> &str;
    fn alg(&self) -> &'static str;
    fn sign_jws_input(&self, signing_input: &[u8]) -> Result<Vec<u8>, OidcSigningError>;
    fn active_public_jwk(&self) -> &Jwk;
    fn additional_public_jwks(&self) -> &[Jwk];
    fn posture(&self) -> OidcSigningPosture;
}
```

The important design point is not the exact Rust syntax. The important point is
that OIDC signing must stop depending directly on
`jsonwebtoken::EncodingKey` at the config boundary.

### 4.2 Initial concrete implementations

The first two implementations should be:

1. `LocalPemOidcSigner`
    - wraps the current PEM/`EncodingKey` behavior
    - keeps the existing path as the baseline
2. `AwsKmsOidcSigner`
    - performs raw `RS256` signing via AWS KMS
    - derives the active public JWK from `GetPublicKey`
    - must match the derived public JWK against the management-database
      runtime-key `public_jwk`

The generic `KeyManager` trait should not be overloaded to hide OIDC-specific
requirements unless it is explicitly expanded to model:

- `RS256` vs `PS256` distinction
- active public JWK export
- OIDC-specific posture classification

### 4.3 JWT construction rule

The server must continue to assemble the JWT header and payload locally, encode
them with base64url, construct the signing input locally, and ask the external
signer only for the raw signature bytes.

That preserves:

- header semantics
- claim serialization ownership
- parity with the current `RS256 Required Slice`

It also avoids coupling release wording to opaque provider-side JWT assembly.

## 5. AWS KMS-specific requirements

For the first KMS-backed implementation, use AWS KMS only in the following
mode:

- asymmetric RSA signing key
- signing algorithm:
  `SigningAlgorithmSpec::RsassaPkcs1V15Sha256`
- public key fetched via `GetPublicKey`
- `kid` owned by Aegaeon configuration, not inferred ad hoc from KMS aliases

Implications:

- the existing `LegacyAwsKmsKeyManager` implementation is not sufficient for OIDC
  because it is PSS-oriented today
- Workstream E should add a separate OIDC signer rather than mutating the
  existing access-token/federation key path in place

## 6. JWKS publication, overlap, and rollback

The active OIDC JWKS view must remain stable across local and KMS-backed paths.

### 6.1 Active key publication

- publish the active public JWK from the active signer
- merge overlap keys using the same invariants currently enforced by
  `merge_signing_public_jwks(...)`

### 6.2 Rotation sequence

Use this operator sequence for KMS-backed OIDC signing:

1. provision a new signing key and derive its public JWK
2. assign a fresh `kid`
3. publish the new public JWK in overlap form before or at the same time as the
    signer cutover
4. switch the active signer to the new key
5. keep the previous public key in the overlap set until at least:
    - maximum ID Token TTL
    - verification leeway / clock skew
    - logout-token validity window where applicable
6. remove the retired key only after that window has elapsed

### 6.3 Rollback rule

- rollback may restore an older signer only if its public JWK is still
  published
- rollback must never reuse a `kid` for different key material

## 7. Implementation batches

### 7.1 Batch E1 — completed by this document

- map the current OIDC signing path
- classify claim-preserving vs compat-only paths
- define JWKS / rotation / rollback expectations

### 7.2 Batch E2 — code refactor

Status: implemented on 2026-05-12.

- introduce the signer abstraction
- convert ID Token signing and logout-token signing away from direct
  `EncodingKey` usage
- keep verification and JWKS behavior unchanged

### 7.3 Batch E3 — AWS KMS-backed signer

Status: partially implemented on 2026-05-12.

- implement `AwsKmsOidcSigner`
- derive JWK from `GetPublicKey`
- add parity tests vs the local signer for:
  - ID Token issuance
  - logout-token issuance
  - JWKS publication

### 7.4 Batch E4 — runbooks and release wording

- add operator runbooks for KMS-backed OIDC signing
- update claim/compat wording docs
- keep regulated-environment release checks aligned with the implemented path

## 8. Non-goals

This work does not currently aim to:

- generalize all server JWT/JWS signing onto KMS/HSM in one batch
- change the Request Object encryption path
- reclassify broad RSA support into the general verified allowlist
- move admin-console or SDK surfaces into the server claim by implication

## 9. Related documents

- `docs/program-management/roadmaps/active/management-platform-follow-on-plan.md`
- `docs/program-management/roadmaps/active/current-execution-plan.md`
- `docs/operations/management-platform-regulated-environment.md`
- `docs/operations/jwks-operations.md`
- `docs/verification/claims/crypto-allowlist.md`
- `docs/verification/claims/assurance-case/claim-definition.md`
- `docs/security/tcb-inventory.md`
