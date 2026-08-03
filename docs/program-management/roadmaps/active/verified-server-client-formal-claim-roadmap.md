# Verified Server / Client Formal Claim Roadmap

Last updated: 2026-05-20

Status: active plan

Owner: Program Management

Audience: maintainers, planning contributors

## Purpose

This roadmap defines the Phase 5 work needed before Aegaeon can use combined
server/client formal-assurance wording.

It does **not** activate a public claim. The public wording is controlled by the
machine-readable gate in:

- `spec/server-client-formal-assurance-claim.current.json`

## Target Claim Shape

The first safe target is:

> Assumption-qualified formally verified OIDC/OAuth server with a released
> client/RP SDK containing a verified client core and explicit runtime-adapter
> and external-dependency TCB boundaries.

The broad phrase `formally verified server and client` is acceptable only as
shorthand next to the bounded wording above. It must not imply that browser
runtimes, Node/WebCrypto, OS entropy, external IdPs, deployment storage,
third-party dependencies, or compat-only algorithm surfaces are formally proved
by this project.

## Boundary Model

Included boundaries:

- Server-side OIDC/OAuth protocol core covered by the current
  assumption-qualified assurance case.
- Promoted server `RS256 Required Slice` and `RS256 Interop Slice`.
- Server-side RP / federation broker runtime support, scoped separately from a
  standalone client product claim.
- Verified Core client logic for claims, time, and replay semantics.
- Released SDK / RP runtime only after the released-client gate is active.

Explicit TCB / excluded boundaries:

- cryptographic hardness premises
- OS, browser, HSM, KMS, and device entropy sources
- Rust / TypeScript / browser / Node / TLS / OS dependencies
- runtime-adapter signature preverification for non-core signature paths
- external IdP hosts, network, DNS, and TLS termination
- browser storage, callback hosting, and application session persistence
- compat-only algorithm and interop surfaces
- admin UI rendering and React/browser visual behaviour

## Phase Plan

### P5.0 — Source-Managed Claim Gate

Status: complete

Deliverables:

- `spec/server-client-formal-assurance-claim.schema.json`
- `spec/server-client-formal-assurance-claim.current.json`
- `spec/server-client-formal-assurance-evidence-bundle.schema.json`
- `spec/server-client-pre-public-blocker-closure.schema.json`
- `scripts/validation/validate_server_client_formal_assurance.py`
- `scripts/validation/validate_server_client_pre_public_blockers.py`
- local self-tests and `verify_reqs` integration

Exit criteria:

- The current gate validates with `claim_active=false`.
- Activation fails closed while the released-client claim remains inactive.
- Required TCB boundaries are machine-checked.

### P5.1 — Internal Implementation Closure

Status: complete

Deliverables:

- Current server assurance baseline is bound into the Phase 5 internal bundle.
- Current Verified Core / SDK boundary is bound through the client/RP assurance
  case and client claim boundary.
- Released-client activation remains blocked and explicitly recorded.
- No widening of the adapter-preverified boundary occurs.

Exit criteria:

- Every required evidence item in the server/client claim gate is either
  `complete` or explicitly documented as a public-activation blocker.
- `docs/releases/evidence/server-client-formal-assurance-phase5-internal-bundle.json`
  validates.
- `docs/releases/evidence/phase5-pre-public-blockers.json`
  validates and records no remaining non-public blockers.
- The released-client gate remains inactive until publication custody is ready.

### P5.2 — Evidence Bundle and Hosted Dependencies

Status: publication-org rollout closed; hosted-evidence refresh pending

Deliverables:

- A `server-client-formal-assurance` evidence bundle validating against
  `spec/server-client-formal-assurance-evidence-bundle.schema.json`.
- Fresh managed commercial-provider evidence.
- Fresh admin SDK hosted evidence.
- Signed release attestation, SBOM, provenance, and publication-org rollout
  records. Publication-org rollout is now ready in
  `.artifacts/release/publication-org-rollout-report.json` and is consumed by
  the released-client report / publication bundle.

Exit criteria:

- Public readiness remains false until all blockers are empty.
- A public-ready bundle requires `release_stage=external-complete`, fresh
  complete evidence, ready dependent gates, and approved reviews.

### P5.3 — Review Passes

Status: internal reviews complete; external reviews pending

Required review scopes:

- claim wording
- formal boundary
- server implementation
- SDK adapter
- release custody
- external security

Exit criteria:

- Internal claim wording, formal-boundary, server-implementation, and SDK-adapter
  review passes are approved in the Phase 5 internal bundle.
- Release-custody and external-security review passes remain pending public
  activation blockers.
- Every review pass is approved and archived in the public-ready evidence bundle.
- Review findings that alter the claim boundary are reflected in the spec gate
  before public activation.

### P5.4 — Public Activation

Status: planned

Activation requirements:

- `spec/released-client-claim.current.json` is active.
- `spec/client-claim-boundary.current.json` is promoted to the released claim
  profile.
- Client promotion and publication-org gates are complete.
- The server/client evidence bundle is public-ready.
- Product positioning uses only the bounded wording.

## Immediate Next Steps

1. Keep the Phase 5 validators and generated bundle freshness check green in
   `verify_reqs`.
2. Refresh hosted managed-provider and admin SDK evidence before changing any
   public server/client wording.
3. Replace pending release-custody and external-security reviews with approved
   evidence before external publication.
4. Generate a public-ready `external-complete` evidence bundle only after all
   blockers are closed.

## Non-Goals

- Do not claim a proof of OS entropy, external hosts, browser rendering,
  third-party dependency correctness, or cryptographic hardness from first
  principles.
- Do not use `fully formally verified server and client` without the
  assumption-qualified boundary and TCB disclosure.
- Do not use this track to widen admin UI formal-verification claims.
