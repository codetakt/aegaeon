# Current Program Summary

Last updated: 2026-07-07

Status: current implementation baseline

Owner: Program Management

Audience: maintainers, planning contributors

This is the shortest reliable summary of the current programme state. Use this page to answer
three questions quickly:

1. what is already delivered?
2. what is actively being maintained or finished?
3. what is intentionally deferred or post-beta?

For requirement-by-requirement status, use `spec/compliance-matrix.yaml`. For the canonical
detailed programme summary, use `program-master-plan.md`.

## 1. Completed baseline

- Server claim baseline is delivered:
  - OAuth Sprints 0–7 are complete.
  - OIDC-1…OIDC-5 are complete under the PostgreSQL-backed environment policy
    snapshot (`policy.oidcEnabled` and related policy fields).
  - The current server claim already includes the promoted `RS256 Required Slice` and
    `RS256 Interop Slice`; broad RSA remains compat-only by default.
- OSS publication baseline is delivered:
  - Phases 10 and 11 are complete.
  - `v0.9.0-beta` is tagged.
  - Baseline release-readiness and external-conformance artefacts exist.
- Management/control-plane baseline is delivered:
  - backend admin API, PostgreSQL persistence, audit, RBAC, policy-profile CRUD, and downgrade
    detection are live in this repository
  - Primary Authority Phase A is complete
  - federated broker / downstream IdP Phase B is complete
  - current specs live in `docs/specs/primary-authority-user-management.md` and
    `docs/specs/oidc-rp-brokering-spec.md`
  - sibling `aegaeon-sdk` and `aegaeon-admin-console` repositories carry the current SDK and
    control-plane surfaces plus hosted workflow contracts
- Cross-repository governance baseline is largely aligned:
  - commitlint, workflow inventory, and hook-driven file hygiene are aligned across `aegaeon`,
    `aegaeon-sdk`, and `aegaeon-admin-console`
  - TypeScript strictness is source-managed across the current SDK surfaces
  - this repository's strict Rust lane is now workspace-wide across the current Rust packages:
    `aegaeon-client`, `aegaeon-core`, `aegaeon-crypto`, `aegaeon-jose`, `aegaeon-jose-tlv`,
    `aegaeon-loadtest`, `aegaeon-observability`, `aegaeon-server`, `ffi`, and `xtask`
  - a repo-wide strict-Rust claim is now accurate for the current Rust workspace in this
    repository

## 2. Active execution and maintenance

- Keep the delivered server claim fail-closed and evidence-backed:
  - maintain `spec/compliance-matrix.yaml`, artefacts, and linked runbooks
  - keep proof/test drift closed in JOSE/TLV, Tamarin, F\*, Kani, fuzz, and security lanes
- Finish the remaining broad management-platform follow-on:
  - publication-org branch protection and repository-settings rollout
  - managed-provider hosted evidence from real tenants
  - released-client claim activation and package publication
  - provider/deployment-specific KMS/HSM classification and fresh parity evidence where operators
    want claim-preserving OIDC signing
- Preserve the current product boundaries:
  - admin console stays a control-plane SPA
  - management auth stays server-owned
  - end-user credential submission stays on server-handled `/auth/*`
  - SDK/admin evidence must not be described as a claim expansion by itself

## 3. Planned or deferred follow-on

- Post-beta external conformance expansion:
  - broader OIDF plan coverage beyond the current baseline
  - archived exports and release indexing for additional plans
- Longer-horizon platform work:
  - FAPI and JARM enablement
  - stronger verified OIDC server/client follow-on positions
  - further runtime-support rows that are intentionally outside the current claim
- Operational hardening that is useful but not needed to restate the current shipped baseline.

## Read next

- `program-master-plan.md`: canonical detailed summary and priority ordering
- `../active/current-execution-plan.md`: remaining execution sequence and DoD
- `../active/management-platform-follow-on-plan.md`: remaining cross-repository management-platform work
- `../active/proofs-roadmap.md`: current verification posture and proof-maintenance backlog
- `../future/future-projects.md`: future and deferred backlog
