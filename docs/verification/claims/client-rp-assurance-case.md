# Client / RP Assurance Case

Last updated: 2026-09-07

Status: snapshot

Owner: Verification

Audience: verification reviewers, maintainers

> **Status note (2026-09-07):** This records the historical P1 client-core evidence
> boundary, not completion of the SDK implementation guarantee. The
> [SDK assurance contract](sdk-assurance/assurance-contract.md) and
> [standards/output baseline](sdk-assurance/standards-baseline.md) now define the
> obligations. The [qualified SDK claim is inactive](sdk-assurance/contract-status.md).
> Existing promotion records and this snapshot cannot activate it.

## Purpose

This document records the **client-core** evidence inventory from P1 in
`docs/program-management/roadmaps/active/verified-oidc-server-client-backlog.md`.
Its component results need reconciliation with current code, audited assumptions,
and the actual distributed outputs before use in a new release claim.

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

The recorded client-core boundary was assumption-qualified. The assumptions below
are an inventory to audit. Under the SDK contract, external primitive/platform
behavior may remain an explicit premise; SDK-owned parsing, preverification glue,
handle handling, store coordination, and callbacks require implementation proof.

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

### Not established by the historical P1 evidence

- published `@aegaeon/runtime-node` / `@aegaeon/runtime-web` packages
- `@aegaeon/issuer-spa`, `@aegaeon/rp-core`, and management client product surfaces
- browser-required CI lanes on release-capable runners
- real upstream IdP end-to-end coverage beyond the current Dex + Keycloak baselines
- hosted managed-provider evidence generated from an actual commercial-provider pass
- broad `RS256` interoperability surfaces (`request_uri`, signed Request Objects, `private_key_jwt`)
- any outward-facing "formally verified client SDK" statement

## Interpretation

The interpretation of this evidence inventory is:

- **yes** — the repository contains client-core verification assets and adapter tests
- **no** — this does not yet justify a released standalone client / RP product claim

Current public wording and separate server/SDK activation criteria are defined in
`docs/product-positioning.md`.

## Exit Criteria For A Released Client Claim

Use [the SDK activation backlog](sdk-assurance/contract-status.md). Closure now
requires all applicable SDK requirements and C-01 through C-20, including emitted
JavaScript/WASM correspondence, adapters, orchestration, packed-output testing,
and release-specific evidence. The earlier browser/provider/admin evidence,
publication custody, and promotion gates remain additional controls. Their
evaluators must be reconciled with the new contract before stronger wording is
enabled. This snapshot is evidence input, not the release decision.
