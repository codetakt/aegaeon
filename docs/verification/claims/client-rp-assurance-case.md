# Client / RP Assurance Case

Last updated: 2026-03-10

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, maintainers

> **Status note (2026-03-10):** This is the pre-release assurance boundary for the
> future client / RP track. It records the completed P1 client-core baseline. It
> does **not** by itself create a released client-product claim; use
> `docs/product-positioning.md` for outward-facing wording and
> `docs/verification/claims/assurance-case/claim-definition.md` for the current released formal claim.

## Purpose

This document records what the repository can now defend about the **client-core**
track after closing P1 in `docs/program-management/roadmaps/active/verified-oidc-server-client-backlog.md`.

It exists to prevent two failure modes:

- treating the current server assurance case as if it already covered a released client product
- treating runtime adapter progress as if it already justified a broad "verified client SDK" claim

## Scope

This document covers:

- the Verified Core WASM client-core baseline now present in this repository
- the current Node and browser reference adapters
- the source-managed client-claim boundary recorded in `spec/client-claim-boundary.current.json`
- the source-managed promotion gate recorded in `spec/client-claim-promotion.current.json`
- the source-managed released-client wording policy recorded in `spec/released-client-claim.current.json`
- the managed commercial-provider evidence contract recorded in `spec/managed-provider-evidence.schema.json`
- the admin-console SDK evidence contract recorded in `spec/admin-sdk-evidence.schema.json`
- the remaining trust boundary for claims, replay, parsing, and runtime handles
- the explicit gaps that still block a released client / RP product claim

This document does **not** change the current outward-facing product statement.

## Current P1 Baseline

P1 is considered complete for the **client-core blocker** because the repository now has:

- a non-stub claims path for client-relevant JWT / DPoP verification
- reference Node and browser adapters that consume the current WASM artefact
- real-crypto adapter tests for PKCE, JWT, and DPoP
- packaged artefact discipline suitable for SDK handoff (`manifest.json`, hashes, ABI, SBOM, optional signature)

The current technical baseline is:

- **EdDSA path**: compact and claims verification remain inside the current Verified Core / HACL\* boundary
- **ES256 / RS256 path**: the reference adapters verify the JWS signature in host crypto
  (`node:crypto` or WebCrypto), then call the claims exports with the
  `SIGNATURE_PREVERIFIED` flag so that Verified Core still enforces claims, time,
  and replay semantics
- **WASM import boundary**: the default fixture remains at 7 imports, limited to
  replay-store I/O, compact parsing, handle registration, and handle resolution

This means the repository now supports a **claimable client-core precondition**,
but not yet a released client-product claim.

The intended client-claim boundary is now source-managed:

- backend source of truth: `spec/client-claim-boundary.current.json`
- SDK mirror: `../aegaeon-sdk/sdk/spec/client-claim-boundary.current.json`

The intended promotion gate is also source-managed:

- backend source of truth: `spec/client-claim-promotion.current.json`
- SDK mirror: `../aegaeon-sdk/sdk/spec/client-claim-promotion.current.json`

The released-client wording target is source-managed too:

- backend source of truth: `spec/released-client-claim.current.json`
- SDK mirror: `../aegaeon-sdk/sdk/spec/released-client-claim.current.json`

Hosted commercial-provider evidence is source-managed as well:

- backend schema: `spec/managed-provider-evidence.schema.json`
- SDK mirror: `../aegaeon-sdk/sdk/spec/managed-provider-evidence.schema.json`

Admin-console SDK evidence is source-managed too:

- backend schema: `spec/admin-sdk-evidence.schema.json`
- SDK mirror: `../aegaeon-sdk/sdk/spec/admin-sdk-evidence.schema.json`
- admin-console producer: `../aegaeon-admin-console/scripts/build-admin-sdk-evidence.ts`
- admin-console auth boundary: `../aegaeon-admin-console/spec/admin-auth-boundary.current.json`

That file freezes the current posture as:

- `verified-core` profile: EdDSA-only verified client core
- `aegaeon-rs256` profile: the default, with a promoted narrow `RS256` client slice
- `compat-interop` profile: interoperability-oriented, with `ES256` still outside the first released client-claim target

## Evidence

The P1 baseline is supported by the following repository evidence:

- `tests/verified_core_wasm/test_instantiate.ts`
  - verifies that claims exports are functional
  - verifies that preverified `RS256` is accepted on claims paths
  - verifies that non-preverified `RS256` remains rejected in the current WASM path
- `tests/verified_core_wasm/runtime_node_reference_test.ts`
  - covers Node reference-adapter PKCE, JWT, and DPoP paths
  - includes `RS256` JWT and `ES256` DPoP adapter-side preverification
- `tests/verified_core_wasm/runtime_web_reference_test.ts`
  - covers browser-facing WebCrypto adapter PKCE, JWT, and DPoP paths
  - includes `RS256` JWT and `ES256` DPoP adapter-side preverification
- `tests/verified_core_wasm/package_dist_test.ts`
  - covers packaged artefact generation, optional signing, and fetch / verify flow
- `tests/verified_core_wasm/managed_provider_evidence_test.ts`
  - covers the managed-provider evidence bundle builder and schema validator
- `tests/verified_core_wasm/client_claim_promotion_test.ts`
  - covers the frozen promotion gate against the client boundary, release attestation, lane set, managed-provider evidence, and admin-console SDK evidence
- `tests/verified_core_wasm/run_all.sh`
  - aggregates the current WASM client-core smoke suite
  - skips the native equivalence sub-lane only when the local Rust toolchain
    exposes a broken linker wrapper or the environment otherwise lacks the
    prerequisites for native equivalence

## Trust Boundary

The current client-core boundary remains assumption-qualified.

### In scope for this pre-release baseline

- Verified Core logic for PKCE, JWT claims checks, DPoP claims checks, time-window checks, and replay semantics
- HACL\*-backed EdDSA verification used inside the current WASM path
- adapter-side integrity checks for the distributed WASM artefact

### Explicit assumptions / external contracts

- computational hardness assumptions, OS/device entropy, and TCB boundaries already documented in
  `docs/verification/claims/assumptions/current-register.md`
- Node `crypto` / WebCrypto correctness for the current adapter-side `ES256` / `RS256` signature-preverification path
- replay-store behaviour
- compact-parser behaviour
- handle registration / resolution contracts across the WASM boundary

### Still out of scope

- published `@aegaeon/runtime-node` / `@aegaeon/runtime-web` packages
- `@aegaeon/issuer-spa`, `@aegaeon/rp-core`, and management client product surfaces
- browser-required CI lanes on release-capable runners
- real upstream IdP end-to-end coverage beyond the current Dex + Keycloak baselines
- hosted managed-provider evidence generated from an actual commercial-provider pass
- broad `RS256` interoperability surfaces (`request_uri`, signed Request Objects, `private_key_jwt`)
- any outward-facing "formally verified client SDK" statement

## Interpretation

The correct reading of the current state is:

- **yes** — the repository now contains a defensible, tested, client-core verification baseline
- **no** — this does not yet justify a released standalone client / RP product claim

The current released wording therefore remains server-side, as defined in
`docs/product-positioning.md`.

## Exit Criteria For A Released Client Claim

Before Aegaeon can safely claim a released client / RP product boundary, all of
the following still need to be closed:

1. move the staged runtime adapters and packaging flow into the real separate SDK repository
2. promote browser-capable CI and diagnostics lanes to required release gates
3. add real upstream IdP end-to-end coverage
4. generate managed commercial-provider evidence that satisfies `spec/managed-provider-evidence.schema.json`
5. generate admin-console SDK evidence that satisfies `spec/admin-sdk-evidence.schema.json`
   from an admin-console build that also passes `spec/admin-auth-boundary.current.json`
6. fix production signing / attestation / release custody for the distributed artefacts
7. satisfy the frozen promotion gate in `spec/client-claim-promotion.current.json` against both managed-provider and admin-console evidence before widening any released wording
8. build and validate the released-client claim report from `spec/released-client-claim.current.json` and clear its publication-org blockers
9. pass the source-managed released-client activation gate before any released wording is switched on
10. promote the source-managed pre-release client boundary into a released client claim only after the corresponding evidence bundle and release custody are in place

Until those items are complete, this document is a **pre-release assurance note**
for engineering and planning, not a change to the released product claim.
