# Current Execution Plan

Last updated: 2026-07-07

Status: active plan

Owner: Program Management

Audience: maintainers, planning contributors

This document tracks the remaining execution sequence after the delivered OAuth/OIDC, management
API, primary-authority, broker/federation, SDK, and admin-console baselines. It should not duplicate
completed implementation history. Completed delivery records live under
`docs/program-management/historical/roadmaps/`; current behaviour lives under `docs/specs/`.

## Baseline

- The server OAuth/OIDC baseline is implemented and evidence-backed through
  `spec/compliance-matrix.yaml`.
- Primary-authority local user management is current product behaviour; see
  `docs/specs/primary-authority-user-management.md`.
- Broker / upstream IdP control-plane management is current product behaviour; see
  `docs/specs/oidc-rp-brokering-spec.md`.
- The promoted OIDC `RS256 Required Slice` and `RS256 Interop Slice` are both inside the current
  server claim as narrow exceptions; broad RSA remains compat by default.
- Initial OSS publication and baseline conformance work are complete. Remaining work is about
  hosted evidence, publication custody, broader conformance, and future claim positions.

## Execution Principles

1. Standards-first defaults remain fail closed.
2. `spec/compliance-matrix.yaml` is the authoritative requirement-status tracker.
3. A feature is not claim-bearing until linked tests, proof/evidence, wording, and release artefacts
   agree.
4. SDK/admin-console publication evidence does not widen the server verification claim by itself.
5. HSM/KMS-backed signing paths must be classified as claim-preserving or compat-only before public
   wording uses them.

## Active Sequence

### 1. Publication-Org Rollout

Objective: apply source-managed branch-protection, repository-settings, and release-custody
contracts in the real publication organization.

Exit criteria:

- final owner/repository pair is recorded
- hosted branch-protection and repository-settings audits pass
- release custody remains fail closed
- rollout evidence is archived and linked from release docs

### 2. Managed-Provider Evidence

Objective: replace local/sandbox provider readiness with fresh hosted evidence from provisioned
commercial tenants.

Exit criteria:

- managed-provider configuration validates against the source-managed schema
- hosted evidence workflow passes with retained diagnostics
- emitted evidence feeds the client-claim promotion and released-client readiness gates

### 3. Released Client Claim Activation And Package Publication

Objective: move the SDK/client track from runtime-readiness to published packages and an activated
released-client claim.

Exit criteria:

- hosted promotion gate uses fresh managed-provider and admin-SDK evidence
- released-client readiness has no publication-org blockers
- packages are published with provenance, SBOM, release attestation, and claim report

### 4. Post-Beta External Conformance Expansion

Objective: broaden OIDF/OAuth conformance coverage beyond the current publication baseline.

Initial targets:

- resolve OIDC Basic manual evidence modules
- archive additional OAuth/OIDC plan exports under `artifacts/conformance/<plan>/`
- index each accepted plan under `docs/releases/`

### 5. Verification Evidence Maintenance

Objective: keep the current formal claim narrow, fresh, and defensible.

Maintenance scope:

- refresh dudect and verifier evidence when OIDC `RS256` or JOSE verifier paths change
- keep the remaining non-`verified` OIDC-adjacent matrix rows explicitly triaged
- continue JOSE/TLV extraction hardening and remaining proof-gap reduction
- preserve trust-boundary documentation for FFI, crypto, WASM host imports, and RNG

### 6. Deferred Protocol Expansion

Objective: add new product surfaces only after the evidence model and operator story are clear.

Deferred candidates:

- FAPI Baseline / Advanced
- JARM response modes
- signed UserInfo and optional `claims` parameter support
- broader OIDF certification investment
- verified server/client claim expansion beyond the current server-first posture

## Definition Of Done

Each workstream is done only when:

- `nix flake check --print-build-logs` is green for repository-affecting changes
- relevant compliance-matrix rows are updated and validated
- tests, proof/evidence artefacts, and release/runbook links are present
- public wording remains aligned with `docs/product-positioning.md`
- any non-default or compat-only posture is explicit and operator-controlled

## References

- Current summary: `../summary/current-program-summary.md`
- Future backlog: `../future/future-projects.md`
- Management follow-on details: `management-platform-follow-on-plan.md`
- Standards coverage: `oauth-rfc-coverage-roadmap.md`, `oidc-spec-coverage-roadmap.md`
- Proof maintenance: `proofs-roadmap.md`
- Historical delivery records: `../historical/roadmaps/`
