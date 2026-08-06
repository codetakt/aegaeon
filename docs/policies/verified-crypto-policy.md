# Verified Crypto Policy

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Governance

Audience: contributors, maintainers

## Ownership
- Owner: Security/Verification
- Review by: Crypto/FFI

## Scope
- This policy defines what “verified crypto” means for Aegaeon’s strong-constraint claim and for
  `global-002`.
- The canonical algorithm posture lives in `docs/verification/claims/crypto-allowlist.md`.
- The strong-constraint claim applies only to instances configured with the **verified allowlist**.
- Instances that use the **compat allowlist** are supported for interoperability but remain outside
  that claim unless a narrower boundary-closure exception is explicitly documented.

## Program Posture Update (2026-07-06)

Aegaeon uses a **modern-crypto-first** posture:

- The general verified allowlist is limited to algorithms backed by HACL*/EverCrypt.
- Broad RSA support remains in the compat boundary by default.
- OIDC uses two promoted boundary exceptions:
  - **`RS256 Required Slice`** — the mandatory ID Token `RS256` surface required for the server OIDC
    Core claim.
  - **`RS256 Interop Slice`** — signed Request Objects / `request_uri`, JWT bearer grant assertions,
    and `private_key_jwt` when they use `RS256`.

Those slices are inside the server claim as explicit boundary exceptions. Broad RSA remains
compat-only and is not part of the general verified allowlist.

Server runtime selection is intentionally narrower than the full compatibility inventory:

- `clientJwtAllowedAlgs` is fixed to `RS256` for `private_key_jwt` and JWT bearer assertions.
- `allowedSigningAlgorithms` is limited to `RS256` and `EdDSA`; JWT access-token and JWT
  introspection signing keys are restricted to `EdDSA`.
- Server-issued JWT signing is a runtime key-selection boundary. Local `databaseEncrypted`
  signing uses the Rust runtime crypto provider, while hosted KMS/HSM signing is an external
  provider contract. The verified Ed25519 claim applies to verification/admission paths, not to
  every private-key signing backend.
- Federation OP signing is disabled in the verified server runtime because it currently requires
  `ES256`. Federation trust-chain ES256 verification remains a compat-only boundary.

## Definition of Verified
An implementation is “verified” when it is:
- Specified and proven in F* and extracted with KaRaMeL, or
- Provided by HACL*/EverCrypt with verified specifications and integrated through the F* wrapper.

“Verified usage” means the production code path selected by the **verified profile** calls those
verified implementations for the operation.

“Compat usage” means the runtime supports the operation via a broader non-verified path for
interoperability. Compat usage may be production-grade, but it is outside the strong-constraint claim.

## Status Criteria
- **Verified**: the verified-profile runtime path uses verified code, verified artefacts are linked,
  and tests prove that the verified path is active.
- **Compat only**: runtime support exists only through non-verified libraries or host paths.
- **Partial**: verified artefacts exist, but coverage is optional, incomplete, or does not yet back the
  default verified-profile path.
- **Trusted boundary**: the operation is intentionally outside the project’s formal crypto claim
  (for example OS entropy or TLS infrastructure).

## Evidence Requirements
- F* spec modules and proofs for the operation or the verified wrapper.
- KaRaMeL / EverCrypt / HACL* artefacts checked in or reproduced in CI when applicable.
- Rust/FFI integration that routes the verified profile to the verified implementation.
- Tests that assert the verified path is executed, plus compliance-matrix references where the claim is surfaced.

## Current Coverage Snapshot

Status reflects the current **verified profile vs compat profile** split. Update this table whenever
default runtime paths, crypto dependencies, or the verified allowlist change.

### Runtime crypto inventory

| Operation | Verified-profile runtime | Compat/runtime-only path | Status | Evidence |
| --- | --- | --- | --- | --- |
| JWS HMAC verification (`HS256/384/512`) | `ffi::verify_hmac` → verified C / EverCrypt path | Same algorithm family also available in compat | Verified | `crates/jose/src/jws.rs`, `crates/ffi/src/lib.rs`, `docs/verification/claims/crypto-allowlist.md` |
| JWS Ed25519 verification (`EdDSA`) | `ffi::verify_ed25519` → verified Ed25519 path | Same algorithm identifier also supported in compat runtime wiring | Verified | `crates/jose/src/jws.rs`, `crates/ffi/src/lib.rs`, `docs/verification/claims/crypto-allowlist.md` |
| Server-issued JWT Ed25519 signing (`EdDSA`) | Algorithm/key selection only; local signing uses the Rust runtime crypto provider | Hosted signing is a KMS/HSM provider contract when configured | Runtime crypto TCB | `crates/server/src/kms/managed.rs`, `crates/crypto/src/signing.rs`, `docs/verification/claims/crypto-allowlist.md` |
| JWS RSA PKCS#1 verification (`RS256`) | Promoted only for the server `RS256 Required Slice` and `RS256 Interop Slice`; rejected by the general verified allowlist | `aws-lc-rs` RSA PKCS#1 v1.5 SHA-256 verification (`RSA_PKCS1_2048_8192_SHA256`); the promoted-slice and broad paths share this verifier — the distinction is policy/allowlist, not implementation | Promoted boundary exception for the two server slices; broad RSA compat-only | `crates/jose/src/jws.rs`, `docs/verification/claims/crypto-allowlist.md`, `docs/verification/oidc/rs256-required-slice.md`, `docs/verification/oidc/rs256-interop-slice.md` |
| JWS RSA-PSS verification (`PS256`) | `ffi::verify_rsa` → `Hacl_RSAPSS_rsapss_pkey_verify` / libevercrypt on the JOSE verified dispatch, including request-object and client-assertion promoted routing | Local signing and KMS signing remain compat provider paths | Verified for verification; signing remains compat | `c/rsa_signatures.c`, `crates/jose/src/jws.rs`, `crates/jose/src/request_object.rs`, `crates/server/src/client_registry/request_object_keys.rs` |
| JWS ECDSA P-256 verification (`ES256`) | Rejected by the verified allowlist today | `p256` crate | Compat only | `crates/jose/src/jws.rs` |
| JWE content encryption (ChaCha20-Poly1305) | Verified C shim + EverCrypt | Same path | Verified | `crates/ffi/build.rs`, `c/jwe.c`, `docs/verification/runbooks/hacl-integration.md` |
| JWE content encryption (AES-256-GCM) | Not on the verified allowlist | `aws-lc-rs` | Compat only | `crates/jose/src/jwe.rs` |
| JWE key encryption (RSA-OAEP) | Not on the verified allowlist | `aws-lc-rs` / mbedtls | Compat only | `crates/jose/src/jwe.rs`, `crates/ffi/build.rs` |
| Randomness / nonce / token entropy | External host / OS CSPRNG boundary | External host / OS CSPRNG boundary | Trusted boundary | `docs/verification/claims/assumptions/current-register.md`, `crates/server/Cargo.toml` |
| TLS | Infrastructure / transport boundary | rustls + ring/aws-lc | Trusted boundary | `docs/verification/claims/assurance-case/claim-definition.md`, `crates/server/Cargo.toml` |

### Verified parsing coverage (security-critical but not crypto)

| Parser / Schema | Implementation | Status | Evidence |
| --- | --- | --- | --- |
| JOSE header / DCR / DPoP schemas | EverParse-generated C | Verified (parsing only) | `generated/everparse/*`, `crates/ffi/build.rs` |

## Approved Exceptions and Planned Promotions

| Surface | Current path | Why outside the strong-constraint claim | Risk posture | Future plan |
| --- | --- | --- | --- | --- |
| Broad `RS256` / RSA PKCS#1 outside promoted server slices | `aws-lc-rs` RSA PKCS#1 v1.5 SHA-256 verification (`RSA_PKCS1_2048_8192_SHA256`) | Only the server `RS256 Required Slice` and `RS256 Interop Slice` are promoted; broad RSA is not part of the general verified allowlist | Medium — standard and well-studied, but broad RSA remains outside the current proof boundary | Keep broad RSA compat by default; any additional surface promotion must update proofs, compliance rows, and this policy together |
| `PS256` signing | Local `aws-lc-rs`; hosted KMS provider | Signature generation is not routed through `Hacl_RSAPSS` | Low | Keep signing compat; the verified promotion applies only to verification |
| `ES256` (JWS ECDSA P-256) | `p256` crate | No HACL*/EverCrypt-backed Rust path in the current verified profile | Medium | Promote only if product scope requires it; otherwise remain compat |
| AES-256-GCM | `aws-lc-rs` | Not currently routed through a verified profile path | Low | Consider verified bindings later; no current product need to promote |
| RSA-OAEP | `aws-lc-rs` / mbedtls | Broad RSA encryption is outside the current verification scope | Low | Keep compat by default |
| TLS | rustls + ring/aws-lc | Transport stack is outside this project’s formal crypto proof scope | Low | Remains an infrastructure TCB concern |
| RNG / entropy | OS + host contracts | Computational entropy quality is modeled as an external contract | Low | Remains an explicit trust assumption |

## Governance
- New compat-only crypto dependencies are allowed for interoperability, but they must be recorded here and in the relevant architecture / verification docs.
- Do not advertise the strong-constraint claim for compat-profile instances.
- Do not treat documentation alone as evidence; pair any claim update with fresh compliance-matrix links and current artefacts or command output.
- Any promotion from compat to verified must update `docs/verification/claims/crypto-allowlist.md`, the relevant roadmap(s), and `spec/compliance-matrix.yaml`.

## Upgrade Checklist
To move an operation or slice to **Verified**:
1. Implement and prove the operation in F\* (or via a verified HACL\*/EverCrypt wrapper).
2. Route the **verified profile** to the verified implementation by default.
3. Keep any remaining non-verified fallback explicitly scoped as compat.
4. Add tests that prove the verified path is exercised.
5. Update `docs/verification/claims/crypto-allowlist.md`, `spec/compliance-matrix.yaml`, and the relevant product-positioning docs together.
