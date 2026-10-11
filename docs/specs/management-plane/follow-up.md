# Management Plane Follow-up Items

Last updated: 2026-07-08

Status: future plan

Owner: Product / Engineering

Audience: implementers, reviewers

## Remaining open decisions (track in Phase 1)

The core invariants are fixed above (SoT model, rollback safety gates, CSRF, disclosure policy,
issuer immutability). The items below must be resolved before implementation reaches production:

- Configuration snapshot canonicalization:
  - define canonicalization + `configurationHash` computation rules for `schemaVersion = 1`.
- Security downgrade detection:
  - specify exact downgrade rules (fail-closed) for TTL increases, allowlist widening, and policy
    relaxation.
- Revocation ledger storage:
  - define where `revokedSigningKeyIds` / `revokedClientSecretIds` live (separate table vs derived),
  - define “usable” states precisely (e.g. JWKS membership for `RETIRING` vs `REVOKED`).
- Session hardening details (Phase 1):
  - session cookie name, lifetime/idle timeout, rotation policy,
  - CSRF token issuance path and refresh rules.

## Cryptography posture and future FIPS track (Phase 1 guidance)

- The Phase 1 management plane and data plane adopt EverCrypt/HACL\* as their cryptographic foundation, as does the existing Verified Core. The implementation assumes components extracted from F\*/Low\*/KaRaMeL and the EverCrypt C implementation; the operational layer controls TLS and hardware boundaries.
- Design cryptographic provider replacement through an abstraction layer (for example, allow a keystore plugin to switch to the OpenSSL FIPS Provider or an AWS-LC FIPS build).
- FIPS 140-3 certification has not been obtained at this stage. Record the following topics for consideration in case FIPS becomes a contractual requirement:
  1. Evaluate cryptographic provider implementations for FIPS mode (OpenSSL FIPS Provider / AWS-LC FIPS, etc.) and define the conditions for switching from EverCrypt.
  2. Add an initialization flow that satisfies FIPS operating requirements, including self-tests (KAT), random generator initialization, and disabling prohibited algorithms.
  3. Verify consistency with Verified Core when FIPS mode is enabled (whether proved code can wrap the FIPS provider or a separate code path is used only in FIPS mode).
- Reflect the results in `docs/program-management/initiatives/sdk/client-sdk-architecture.md` and track FIPS support as future work in
  `docs/program-management/roadmaps/future/future-projects.md`.
