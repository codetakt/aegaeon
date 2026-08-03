# Management Platform Follow-on Plan

Last updated: 2026-07-07

Status: active plan

Owner: Program Management

Audience: maintainers, planning contributors

This plan covers the **remaining broad management-platform work** after the delivered server-side
admin API baseline, Phase A local-IAM completion, Phase B broker/federation completion, and the
current sibling SDK/admin-console baseline.

The focused cross-repository quality baseline and ongoing drift policy are tracked separately in
`docs/policies/management-platform-quality-profile.md`.

It is a **cross-repository execution plan**:

- this repository (`aegaeon`) remains the source of truth for the backend runtime, verification
  boundary, and backend-side operational posture
- the sibling `../aegaeon-sdk` repository owns package publication, hosted client-evidence gates,
  and SDK release custody
- the sibling `../aegaeon-admin-console` repository owns the control-plane SPA, admin-SDK
  evidence, and the control-plane browser boundary

This plan does **not** widen the current released verification claim by itself.

## 1. Fixed boundaries

These boundaries remain non-negotiable while executing the follow-on work:

- keep the admin console as a **control-plane SPA**
- keep management authentication on the current server-owned management-session / management-auth
  boundary
- keep end-user credential submission on the server-handled issuer/auth surface (`/auth/*`)
- do not treat SDK publication or hosted browser evidence as a claim expansion by themselves
- do not widen the verified claim when integrating KMS/HSM paths; any HSM-backed OIDC signing path
  must either preserve the current promoted `RS256` slice or be documented as compat-only

## 2. Current delivered baseline

### 2.1 Backend baseline (this repository)

- admin APIs for teams, tenants, environments, configurations, policies, connections, clients,
  keys, users, audit, and broker/federation operations are implemented
- PostgreSQL-backed persistence and migration baseline is implemented
- audit read/export surfaces are implemented
- policy-profile CRUD and downgrade detection are implemented
- local primary-authority user management (Phase A) is complete
- broker/federation control-plane management (Phase B) is complete

### 2.2 SDK baseline (`../aegaeon-sdk`)

- package workspaces exist for:
  - `@aegaeon/verified-core`
  - `@aegaeon/runtime-node`
  - `@aegaeon/runtime-web`
  - `@aegaeon/management-client`
  - `@aegaeon/issuer-spa`
  - `@aegaeon/rp-core`
- hosted workflows exist for:
  - `verify-core.yml`
  - `ci.yml`
  - `lint.yml`
  - `playwright.yml`
  - `managed-provider-evidence.yml`
  - `client-claim-promotion.yml`
  - `released-client-readiness.yml`
  - `publish.yml`
- residual quality drift is governed by `docs/policies/management-platform-quality-profile.md`
- source-managed release / evidence / custody contracts already exist under `sdk/spec/`

### 2.3 Admin-console baseline (`../aegaeon-admin-console`)

- the console depends on `@aegaeon/management-client` as its only SDK package
- the current SDK boundary and auth boundary are source-managed in:
  - `spec/admin-sdk-boundary.current.json`
  - `spec/admin-auth-boundary.current.json`
- hosted workflows currently observed on 2026-05-14 are:
  - `ci.yml`
  - `lint.yml`
  - `stack-e2e.yml`
- residual quality drift is governed by `docs/policies/management-platform-quality-profile.md`
- the hosted `stack-e2e.yml` workflow emits admin-SDK evidence for the SDK-side gates

## 3. Remaining workstreams

### 3.1 Workstream A — Publication-org rollout

Objective:

- move the current source-managed repository-policy contracts from sandbox state into the real
  publication organization without drift

Primary repository:

- `../aegaeon-sdk`

Inputs:

- `sdk/spec/branch-protection.main.json`
- `sdk/spec/repository-settings.current.json`
- `sdk/spec/release-custody.current.json`
- `sdk/spec/workflow-inventory.current.json`
- `sdk/spec/hosted-evidence-sources.current.json`

Execution checklist:

- [ ] identify the final publication-org owner/repository pair
- [ ] apply branch protection from `branch-protection.main.json`
- [ ] apply repository variables/secrets and verify they match `repository-settings.current.json`
- [ ] apply release-custody settings and confirm real publish remains fail-closed
- [ ] run the publication-org rollout report and archive the result
- [ ] keep deferred publication-org blockers explicit until they are actually closed

Evidence / output:

- hosted publication-org rollout report
- remote audit output for branch protection / repository settings / release custody

### 3.2 Workstream B — Managed-provider evidence

Objective:

- replace “plan-only” managed commercial-provider readiness with fresh hosted evidence from a
  provisioned tenant that can feed the promotion/readiness gates

Primary repository:

- `../aegaeon-sdk`

Dependencies:

- publication-time secrets/variables for the managed-provider lane
- validated managed-provider config matching `sdk/spec/managed-external-provider.schema.json`

Execution checklist:

- [ ] provision at least one managed commercial-provider tenant and capture the operator contract
- [ ] validate the config against `managed-external-provider.schema.json`
- [ ] keep repository-settings audit fail-closed for the managed-provider secret set
- [ ] run the hosted `managed-provider-evidence.yml` lane successfully
- [ ] validate the emitted `managed-provider-evidence.json`
- [ ] feed the hosted artifact into `client-claim-promotion.yml` and
      `released-client-readiness.yml`

Evidence / output:

- `.artifacts/managed-provider/managed-provider-evidence.json`
- hosted workflow artifact + retained Playwright diagnostics

### 3.3 Workstream C — Released client claim activation and package publication

Objective:

- move the SDK/client track from runtime-readiness into an actually published, claim-bearing
  release posture

Primary repository:

- `../aegaeon-sdk`

Dependencies:

- Workstream A complete
- Workstream B complete
- admin-console hosted evidence fresh and valid

Execution checklist:

- [ ] keep `client-claim-boundary.current.json`, `client-claim-promotion.current.json`, and
      `released-client-claim.current.json` aligned with intended wording
- [ ] run hosted promotion gate against fresh managed-provider + admin-SDK evidence
- [ ] run hosted released-client readiness gate with publication-org blockers cleared
- [ ] publish packages with provenance and release attestation
- [ ] archive publication bundle, SBOM, attestation, and final claim report

Evidence / output:

- release attestation
- release publication bundle
- published package versions
- released-client-claim report without publication-org blockers

### 3.4 Completed Backend Follow-On — Regulated-Environment Operations Hardening

Objective:

- add the operator-facing runbooks required for environments that need stronger custody,
  traceability, and operational evidence than the current baseline

Primary repository:

- this repository (`aegaeon`)

Delivered baseline:

- regulated-environment key-management runbook (KMS/HSM-specific details remain coupled to
  Workstream E)
- management-platform evidence retention and review cadence
- publication / release evidence retention policy for SDK/admin evidence inputs
- operator workflow for fail-closed handling of managed-provider drift or stale evidence

Execution checklist:

- [x] define which operator tasks are mandatory in regulated environments
- [x] document the required evidence retention set and freshness windows
- [x] document incident/fallback handling when hosted evidence is missing or stale
- [x] link the runbooks from `docs/operations/README.md`

Evidence / output:

- new or updated runbooks under `docs/operations/`

### 3.5 Completed Backend Follow-On — KMS/HSM-backed OIDC Signing Integration

Objective:

- allow OIDC signing keys to come from backend KMS/HSM abstractions while preserving the current
  verification-boundary posture

Primary repository:

- this repository (`aegaeon`)

Key constraints:

- do not silently widen the verified claim
- the JWKS view must remain coherent during overlap/rotation
- operator procedures must distinguish “claim-preserving path” from “compat-only path”

Design baseline:

- `docs/design/oidc-kms-signing-design.md`

Execution checklist:

- [x] map the current OIDC signing path onto `crates/server/src/kms/` abstractions
- [x] define how JWKS publication derives public material from KMS/HSM-backed keys
- [x] define overlap / rotation / rollback rules for KMS-backed OIDC signing keys
- [x] document whether each path is claim-preserving or compat-only
- [x] introduce a backend signer abstraction inside `OidcSigningKey`
- [x] wire databaseEncrypted and feature-gated awsKms `OIDC_ID_TOKEN_SIGNING` runtime keys
  into `OidcConfig`; production `aegaeon-server` rejects startup
  `AEGAEON_OIDC_SIGNING_*` variables and uses them only in focused parity/evidence
  harnesses outside the server runtime authority
- [x] add a feature-gated AWS KMS signer scaffold and config fail-closed tests
- [x] add a LocalStack-aware focused parity test for AWS KMS-backed OIDC signing
- [x] promote provider-backed parity evidence into an always-on CI / release lane
- [x] add operational runbooks

Concrete deployment classification remains operator-specific: a real deployment
is only claim-preserving when the runbook classification, provider behaviour,
and fresh parity evidence all match the promoted `RS256` slice posture.

Evidence / output:

- code changes in the backend repo
- focused tests
- updated ops/security docs

## 4. Recommended execution order

Use this order unless an explicit release need changes sequencing:

1. Workstream A — Publication-org rollout
2. Workstream B — Managed-provider evidence
3. Workstream C — Released client claim activation and package publication

Rationale:

- A/B/C are the shortest path from “implemented” to “published with hosted evidence”
- regulated-environment runbooks and KMS/HSM signing integration are now backend baselines; concrete
  deployment classification remains evidence-specific

## 5. Immediate next step

The next programme step should be:

1. apply publication-org branch protection and repository-settings contracts
2. run managed-provider hosted evidence against provisioned tenants
3. feed fresh evidence into released-client readiness and package-publication gates

This keeps the remaining work focused on publication custody and hosted evidence rather than
re-opening completed backend implementation tracks.
