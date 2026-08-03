# Program Master Plan

Last updated: 2026-07-08

Status: active plan

Owner: Program Management

Audience: maintainers, planning contributors

This is the top-level programme map for current priorities and future work. It intentionally avoids
phase-by-phase implementation history. Use `current-program-summary.md` for the shortest overview,
`docs/specs/` for current implementation behaviour, and
`docs/program-management/historical/roadmaps/` for completed delivery records.

## Current Baseline

- OAuth/OIDC server behaviour is implemented, evidence-backed, and tracked in
  `spec/compliance-matrix.yaml`.
- Primary-authority local user management is delivered; canonical spec:
  `docs/specs/primary-authority-user-management.md`.
- Broker / upstream IdP control-plane management is delivered; canonical spec:
  `docs/specs/oidc-rp-brokering-spec.md`.
- Management API, PostgreSQL persistence, audit, RBAC, policy-profile CRUD, and downgrade
  detection are current backend behaviour.
- Sibling SDK/admin-console repositories carry the active client and control-plane surfaces; this
  repository remains the backend and verification source of truth.
- The OIDC `RS256 Required Slice` and `RS256 Interop Slice` are promoted, narrow server-claim
  exceptions. Broad RSA and wider JOSE interoperability remain compat unless separately promoted.

## Active Objectives

1. **Publication-org rollout**
   - Apply branch-protection, repository-settings, and release-custody contracts in the real
     publication organization.
   - Detail: `../active/current-execution-plan.md`, `../active/management-platform-follow-on-plan.md`.
2. **Hosted evidence and released-client activation**
   - Capture managed-provider and admin-SDK evidence, then publish packages and activate the
     released-client claim only after custody gates pass.
   - Detail: `../active/management-platform-follow-on-plan.md`.
3. **Post-beta external conformance**
   - Expand OIDF/OAuth plan coverage and archive accepted exports.
   - Detail: `../future/external-conformance-and-beta-plan.md`, `../future/future-projects.md`.
4. **Verification evidence maintenance**
   - Keep claim-supporting proof/test evidence, OIDC `RS256` slice wording, and trust-boundary docs
     aligned with implementation changes.
   - Detail: `../active/proofs-roadmap.md`, `docs/verification/`.

## Deferred Objectives

- FAPI Baseline / Advanced and JARM enablement
- optional OIDC surfaces such as `claims`, signed UserInfo, or WebFinger
- broader verified OIDC server/client claim positions
- formal OIDF certification application once selected external plans pass and publication evidence
  is stable

## Status Sources

- Requirement status: `spec/compliance-matrix.yaml`
- Released wording: `docs/product-positioning.md`
- Formal claim and assumptions:
  `docs/verification/claims/assurance-case/claim-definition.md`,
  `docs/verification/claims/assumptions/current-register.md`
- Current specs: `docs/specs/README.md`
- Current execution: `../active/current-execution-plan.md`
- Future backlog: `../future/future-projects.md`
- Historical delivery: `../historical/`

## Gates

No roadmap item becomes claim-bearing until:

- implementation and tests are merged
- proof or runtime evidence is linked
- compliance-matrix rows are validated
- public wording is reviewed against the formal boundary
- release or operations docs point to the retained evidence
