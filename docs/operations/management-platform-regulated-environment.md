# Management Platform Regulated-Environment Runbook

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

> **Status note (2026-05-12):** This runbook defines the backend-side operator posture for the
> broad management-platform track in regulated environments. It complements the SDK-side release
> runbooks and applies when operators need stronger evidence retention, review cadence, and
> fail-closed handling than the current baseline publication path.

## 1. Scope

This runbook applies to the cross-repository management-platform release path involving:

- this repository (`aegaeon`)
- the sibling `../aegaeon-sdk` repository
- the sibling `../aegaeon-admin-console` repository

It covers:

- the minimum evidence set required before promotion/readiness/publication decisions
- evidence freshness expectations
- evidence retention expectations
- fail-closed handling when hosted evidence, repository-policy rollout, or boundary controls drift

It does **not** redefine the formal verification boundary. For the current product claim and
assumptions, use:

- `docs/verification/claims/assurance-case/claim-definition.md`
- `docs/verification/claims/assumptions/current-register.md`
- `docs/verification/claims/crypto-allowlist.md`

## 2. Fixed release boundaries

When operating in a regulated environment, keep these boundaries fixed:

- the admin console remains a **control-plane SPA**
- management authentication remains server-owned and cookie/session based unless a separately
  reviewed management-auth change is promoted
- end-user credential submission remains on the server-handled issuer/auth surface (`/auth/*`)
- managed-provider evidence and admin-SDK evidence are **release inputs**, not proof that the UI or
  SDK themselves are formally verified
- any KMS/HSM-backed OIDC signing path must be explicitly classified as either:
  - claim-preserving under the current promoted boundary, or
  - compat-only and therefore outside the stronger release wording
- use `docs/design/oidc-kms-signing-design.md` as the backend-side design baseline when making that
  classification

## 3. Minimum evidence set

For a regulated-environment promotion or release decision, collect at least the following evidence.

### 3.1 Backend evidence

- backend verification/build status for the targeted release input
- Verified Core handoff bundle when the SDK/runtime packages consume a refreshed core artifact
- any backend-side operational note that changes the claim/compat posture

### 3.2 SDK evidence

- release attestation
- release publication bundle
- workspace SBOM
- client-claim promotion report when promotion is being evaluated
- released-client readiness report when released wording is being evaluated
- publication-org rollout report while publication-org rollout is still pending or being changed

### 3.3 Hosted runtime/control-plane evidence

- fresh admin-SDK evidence from the hosted admin-console stack lane
- fresh managed-provider evidence from the hosted managed-provider lane whenever the released-client
  or promotion gates require it

### 3.4 Boundary contracts

- admin-console SDK boundary contract
- admin-console auth boundary contract
- SDK client-claim boundary / promotion / released-client policy contracts
- SDK repository-settings / release-custody / hosted-evidence-source contracts

## 4. Freshness policy

Use the following rule set unless a stricter deployment-specific policy overrides it.

### 4.1 Hosted evidence freshness

- Admin-SDK evidence and managed-provider evidence must satisfy the current SDK-side frozen
  policy window before they can be used for promotion or released-client decisions.
- At the time of writing, the sibling SDK repository expects those evidence bundles to be fresh
  within **168 hours** for the released-client policy path.
- If the SDK-side policy changes, the SDK source-managed policy files are authoritative and this
  runbook must be updated in the same workstream.

### 4.2 Release artefact freshness

- Release attestation, release publication bundle, SBOM, and any claim report must be generated for
  the same release candidate / publication attempt that is being approved.
- Do not reuse a previous release candidate's attestation or publication bundle after material
  changes to:
  - package contents
  - repository-policy rollout status
  - hosted evidence inputs
  - release-custody settings

### 4.3 Publication-org rollout freshness

- Regenerate the publication-org rollout report before the first released-client activation and
  after any change to:
  - branch protection
  - repository settings / secrets / variables
  - release-custody configuration
  - hosted workflow naming or artifact routing

## 5. Retention policy

At minimum, retain the full evidence set for:

- the entire supported lifetime of the published release, and
- any additional period required by deployment-specific legal, contractual, or regulatory policy

Store the evidence in immutable or append-only storage where feasible.

Minimum retained artifact set:

- Verified Core handoff manifest / dispatch payload when applicable
- admin-SDK evidence
- managed-provider evidence
- release attestation
- release publication bundle
- workspace SBOM
- client-claim promotion report
- released-client readiness report
- publication-org rollout report

## 6. Key custody

Regulated deployments must make key custody explicit before release approval.

Minimum requirements:

- classify each active OIDC signing deployment as `claim-preserving` or
  `compat-only`
- keep local private-key material out of admin-console, SDK, and browser
  surfaces
- record the active `kid`, key backend, rotation state, and rollback key set in
  the release evidence bundle
- require reviewed operator action for key introduction, key deactivation,
  JWKS overlap changes, and emergency rollback
- run KMS/HSM parity evidence before using claim-preserving wording for an
  external signing backend

If key custody or backend classification is ambiguous, downgrade the affected
deployment to compat-only wording until the classification is repaired.

## 7. Audit retention

Retain audit evidence for security-sensitive operator actions, release
decisions, and boundary changes.

Minimum retained audit classes:

- release approval and publication decisions
- repository-policy and publication-org rollout changes
- secrets, variables, package-publishing, and branch-protection changes
- key-management changes, including `kid`, JWKS, KMS/HSM, and rollback actions
- management-session, administrator, and privileged API activity where the
  deployment produces those logs
- incident-response timelines and exception approvals

Store release evidence in immutable or append-only storage where feasible.
Preserve enough metadata to connect each artifact to its source revision,
workflow run, operator, and review decision.

## 8. Backup, restore, and disaster recovery

Regulated deployments must have a tested recovery path for the management and
issuer state included in the release claim.

Minimum requirements:

- define RPO/RTO for the issuer, management API, persistence layer, audit logs,
  and evidence store
- back up the primary database, audit logs, release evidence, and key-custody
  metadata on a documented cadence
- test restore into an isolated environment before relying on the procedure for
  enterprise-readiness wording
- verify restored JWKS / signer state before returning the issuer to service
- keep rollback instructions aligned with `docs/operations/hardened-reference-deployment.md`
  and `docs/operations/oidc-kms-signing.md`

If restore validation is stale or missing, treat operational readiness evidence
as incomplete for the affected deployment.

## 9. Incident response

Use fail-closed incident handling when evidence, custody, or boundary controls
are compromised.

Minimum response flow:

1. Preserve current logs, release evidence, and relevant artifacts.
2. Disable or suspend stronger public wording for the affected deployment.
3. Identify whether the incident affects protocol correctness, key custody,
   auditability, release evidence, hosted evidence, or administrator access.
4. Rotate or revoke impacted credentials, sessions, tokens, and signing keys.
5. Re-run the relevant evidence lanes before reactivating stronger wording.
6. Record the incident timeline, owner, impact, customer notification decision,
   and follow-up controls.

Do not reuse pre-incident evidence after a material security or custody change.

## 10. Operator access review

Review privileged operator access before release activation and at least
quarterly while the regulated deployment remains active.

Minimum review scope:

- repository administration and branch-protection bypass rights
- package publication and release-signing rights
- production secrets and environment-variable management
- database, audit-log, and evidence-store access
- KMS/HSM key administration and signing permissions
- break-glass accounts and emergency access procedures

Remove stale access before approving a regulated release decision. Record
exceptions with owner, expiration, and compensating controls.

## 11. Mandatory operator checks

Before approving a regulated-environment promotion or release:

1. Confirm the admin-console boundary has not widened.
2. Confirm the SDK-side claim policy files still match the intended wording.
3. Confirm hosted admin-SDK evidence is present and fresh.
4. Confirm hosted managed-provider evidence is present and fresh when the SDK policy requires it.
5. Confirm publication-org rollout blockers are either closed or still explicitly recorded as
   blockers.
6. Confirm the release publication bundle and attestation were generated from the same release
   candidate being approved.
7. Confirm any KMS/HSM-backed signing path used by the release is explicitly classified as
   claim-preserving or compat-only.
8. Confirm backup/restore evidence and operator access review are fresh for the deployment.

## 12. Fail-closed response rules

### 12.1 Missing or stale admin-SDK evidence

- Block promotion/readiness/publication decisions.
- Re-run the hosted admin-console stack lane and replace the evidence bundle.
- Do not substitute ad hoc local screenshots or manual browser assertions for the required
  machine-readable artifact.

### 12.2 Missing or stale managed-provider evidence

- Block any promotion/readiness/publication path that requires the managed-provider lane.
- Re-run the hosted managed-provider workflow against a provisioned tenant.
- If the managed-provider lane is intentionally not in scope for a given wording decision, keep the
  SDK-side policy explicit about that reduced scope rather than silently bypassing it.

### 12.3 Publication-org rollout incomplete

- Keep the publication-org blockers explicit in the readiness/report artifacts.
- Do not activate released wording while required publication-org tasks remain pending.

### 12.4 Boundary drift

- If the admin console starts importing forbidden OIDC/RP packages or hand-rolling auth/session
  logic, treat that as a blocker until the boundary contract, threat model, tests, and evidence are
  updated together.

### 12.5 KMS/HSM posture ambiguity

- If a KMS/HSM-backed signing path is in use but its claim posture is undocumented, treat that path
  as compat-only for release wording until the classification and operator procedure are fixed.

### 12.6 Backup, restore, or operator-access drift

- If restore evidence, DR procedure, or operator access review is stale, block
  regulated release activation until the review is refreshed.
- If break-glass access was used, preserve the timeline and require
  post-incident access review before reactivation.

## 13. Review cadence

Review this runbook:

- before the first regulated-environment release decision
- whenever the SDK-side frozen claim policy changes
- whenever hosted evidence sources or publication-org routing changes
- whenever KMS/HSM-backed OIDC signing changes the operator workflow
- at least quarterly while the broad management-platform follow-on work remains active

## 14. Related documents

- `docs/program-management/roadmaps/active/management-platform-follow-on-plan.md`
- `docs/design/oidc-kms-signing-design.md`
- `docs/operations/oidc-kms-signing.md`
- `docs/operations/sdk-release.md`
- `docs/releases/evidence/release-security-evidence.md`
- `../../../aegaeon-sdk/docs/operations/sdk-release.md`
- `docs/development/current-delivery-context.md`
- `docs/development/admin-console-handoff.md`
