# Enterprise Readiness, Certification, and Verified UI Claim Plan

Last updated: 2026-05-20

Status: active plan

Owner: Program Management

Audience: maintainers, planning contributors

This plan turns three currently-too-strong outward-facing statements into
explicit workstreams:

1. `fully enterprise-ready`
2. `fully certified`
3. `formally verified UI included`

The current product baseline is already feature-complete for the phase-release
posture: server-side OIDC/OAuth, management control plane, local primary-authority
user management, and federated broker / downstream IdP operation are delivered.
This plan is about claim upgrade and commercial-hardening evidence, not about
reopening the completed local-IAM or broker/federation feature scope.

## Fixed Baseline

The current safe public wording remains:

- assumption-qualified formally verified and security-tested OIDC 1.0 /
  OAuth 2.0/2.1 identity-provider server
- OpenID Connect Federation runtime support
- first-party admin console as a constrained control-plane UI
- feature-complete beta / phase-release baseline for local primary-authority
  user management and federated broker / downstream IdP operation

Do not switch to any stronger wording until the relevant exit gates below are
closed and `docs/product-positioning.md` is updated in the same change set.

## Phase Advancement and Claim Activation Policy

Treat phase execution and public wording as separate concerns. Each workstream
has three statuses:

- **Engineering status**: source-managed implementation, schemas, validators,
  runbooks, model files, and CI wiring exist and pass local checks.
- **Evidence status**: concrete hosted, external, deployment, certification, or
  operational artifacts exist and pass the relevant validators.
- **Public claim status**: outward-facing wording is enabled by setting the
  relevant claim gate to `claim_active=true` and updating product/release
  wording in the same reviewed change set.

Rules:

- Engineering work for later phases may proceed before earlier public claim
  gates close. In particular, Phase 2 certification work and Phase 3 admin UI
  assurance work should not wait for Phase 1 enterprise-readiness evidence.
- Missing external evidence blocks public claim activation, not unrelated
  engineering work.
- Claim-gate evidence may be marked `complete` only when real evidence passes
  the relevant validator. Do not use mock, stale, expired, local-only, or
  hand-edited placeholder evidence to close a public claim blocker.
- Phase 4 is the only phase allowed to activate stronger public wording.

## Target Claim Gates

### Claim A - Fully Enterprise-Ready

Meaning:

- Aegaeon can be operated by an enterprise customer with defensible security,
  support, evidence retention, deployment, key-management, upgrade, and incident
  procedures.

Minimum gates:

- publication organization branch-protection, repository-settings, release
  custody, secrets, and package-publication controls are applied and audited
- managed-provider evidence is generated from at least one provisioned real
  commercial tenant, not only local Dex / Keycloak baselines
- KMS/HSM-backed OIDC signing is classified for concrete deployments as
  claim-preserving or compat-only, with fresh parity evidence
- regulated-environment runbooks cover key custody, audit retention, evidence
  review cadence, backup/restore, DR, incident response, and operator access
  review
- reference deployment hardening exists for DB, TLS, networking, secrets,
  observability, alerting, upgrades, rollback, and data retention
- release evidence, SBOM, vulnerability scan, dependency policy, and support
  response procedures are archived and linkable
- load/performance SLO baselines exist for the management and issuer surfaces
  included in the enterprise claim

### Claim B - Fully Certified

Meaning:

- The product has completed the named external certification process for the
  explicitly scoped certification target.

Minimum gates:

- define the certification target before execution:
  - OIDF Certified OP
  - selected OAuth / FAPI plan
  - SOC 2 / ISO 27001 / similar organizational certification
  - other named certification
- for OIDF/OAuth conformance, every claim-bearing plan has archived PASS
  exports, suite commit, screenshots/manual evidence where required, and release
  index links
- all `REVIEW`, `WARNING`, and `SKIPPED` modules are either resolved or
  documented as outside the claimed certification scope
- formal OIDF certification, if claimed, completes fee/legal/submission/review
  and public certification listing
- certification scope is reflected in `docs/product-positioning.md` without
  implying broader protocol or UI certification

### Claim C - Formally Verified UI Included

Meaning:

- The UI-related claim must be scoped to a formally specified and mechanically
  checked security-critical boundary. It must not imply that React, the browser,
  CSS, rendering, extensions, or every possible UI behaviour is formally proven.

Recommended target wording:

- "admin control-plane security boundary with formally specified and
  mechanically checked authorization/session state-machine invariants"

Minimum gates:

- define an admin UI assurance case separate from the server assurance case
- freeze the UI claim boundary:
  - management-session/auth boundary
  - route authorization policy
  - dangerous-operation confirmation and anti-downgrade flow
  - SDK/API contract boundary
  - CSRF/origin/cookie handling assumptions
  - excluded browser/rendering/platform behaviour
- model-check or formally specify the security-critical state machine
  using an agreed method such as TLA+, Alloy, F*, or another mechanically
  checked model
- bind generated SDK/API contracts to the UI model with schema drift checks
- keep Playwright / E2E evidence as runtime regression evidence, not as the
  formal proof itself
- update admin-console boundary contracts and product positioning only after
  the formal UI boundary has its own evidence bundle

## Execution Phases

### Phase 0 - Claim Contract Freeze

Objective:

- freeze what each stronger claim means before doing more implementation work.

Tasks:

- [x] draft exact allowed and forbidden wording for all three claims
- [x] update `docs/product-positioning.md` with future-gated target wording
- [x] create or update evidence schemas for enterprise-readiness, certification,
      and admin-UI assurance bundles
- [x] decide whether "formally verified UI included" means the recommended
      bounded admin-security claim or an infeasible full-browser/UI claim

Exit criteria:

- a reviewer can determine from source-managed docs whether a claim is allowed,
  blocked, or out of scope

Status: complete as of 2026-05-19. The current gates are source-managed in
`spec/enterprise-readiness-claim.current.json`,
`spec/certification-claim.current.json`, and
`spec/admin-ui-assurance-claim.current.json`; all three remain inactive until
their evidence items are complete. Validate the gates with
`nix develop .#default --command bash -c 'python3 scripts/validation/validate_claim_gates.py --all'`.
The validator also rejects duplicate `required_evidence` IDs and insecure
`http://` evidence URIs, and rejects absolute local evidence paths, so
activation review cannot depend on ambiguous, downgradeable, or
machine-local evidence references.

### Phase 1 - Enterprise-Readiness Closure

Objective:

- close the operational evidence gaps that block an enterprise-ready claim.

Tasks:

- [x] define publication-org rollout report schema, validator, and evidence note
- [ ] complete publication-org rollout and archive the rollout report
- [x] define managed-provider enterprise evidence validator and evidence note
- [ ] provision managed commercial-provider tenant(s) and run hosted evidence
- [x] define local release-publication bundle gate for SDK released-client
      readiness and publication evidence
- [ ] run released-client readiness and publication gates with fresh evidence
- [x] define KMS/HSM deployment classification schema, validator, and runbook
- [ ] complete KMS/HSM deployment classification manifests for target environments
- [x] publish regulated-environment runbooks and evidence-retention procedures
- [x] publish a hardened reference deployment guide
- [x] publish release security evidence archive procedure, schema, and validator
- [ ] bind release security evidence validation to a
      concrete release-candidate archive
- [x] define enterprise SLO baseline evidence schema, validator, and rules
- [ ] refresh management / issuer load and observability baselines
- [x] define enterprise-readiness evidence bundle schema and validator
- [x] define final Phase 1 closure validator tying complete claim-gate evidence
      IDs to an approved enterprise-readiness bundle
- [ ] validate a concrete enterprise-readiness evidence bundle for the release candidate

Exit criteria:

- enterprise readiness is supported by fresh hosted evidence, operator runbooks,
  release custody, and deployment-hardening documentation

Current status:

- Engineering status: evidence schemas, validators, runbooks, and final closure
  validator are in place.
- Evidence status: blocked on external publication-org, managed-provider,
  KMS/HSM, SLO, and release-security artifacts.
- Public claim status: blocked; `claim_active` must remain `false` until
  `collect_enterprise_readiness_phase1_evidence.py --phase1-check` passes on a
  reviewed release-candidate bundle.

### Phase 2 - Certification Closure

Objective:

- turn beta/self-certification evidence into named external certification where
  justified by business need.
- proceed independently from Phase 1 public claim activation.

Tasks:

- [x] select the first internal certification target and scope
- [x] run the included OIDF OP Config + Basic plans in the TLS conformance stack
- [x] resolve or scope out review/warning/skipped modules for internal evidence
- [x] archive exports, screenshots, suite commit, plan JSON, and result JSON for
      the internal evidence baseline
- [ ] submit formal certification package when claiming formal certification
- [ ] update release docs and product positioning with the exact certified scope

Exit criteria:

- every public certification claim maps to a named certification artifact or
  public listing

Current status:

- Engineering status: complete for the Phase 2 internal evidence baseline.
  `validate_certification_evidence_bundle.py` now validates the certification
  bundle shape, repo-relative artifact paths, result counts, non-PASS
  dispositions, inactive claim-gate binding, and internal-vs-external
  completion semantics.
- Evidence status: internal-complete for the bounded
  `OIDF OpenID Provider Config + Basic internal evidence baseline` recorded in
  `docs/releases/evidence/certification-phase2-internal-bundle.json`. External
  completion remains blocked on formal submission / review / public listing and
  remaining public-claim blocker dispositions.
- Public claim status: blocked; `spec/certification-claim.current.json` has
  `certification_scope.selected=true` for internal evidence work but
  `claim_active=false`, and the required public activation evidence remains
  incomplete.

### Phase 3 - Admin UI Assurance Boundary

Objective:

- produce a defensible, bounded UI assurance claim without pretending the whole
  browser stack is formally verified.
- proceed independently from Phase 1 public claim activation and Phase 2
  external certification submission.

Tasks:

- [x] write `docs/verification/claims/admin-ui-assurance-case.md`
- [x] define the admin route/action/session state machine
- [x] encode authorization/session invariants in a mechanically checked model
- [x] bind UI routes/actions to OpenAPI / management-client contract drift checks
- [x] add local gates that fail on route/action/model drift
- [ ] refresh admin-console hosted stack evidence against the formal boundary
- [x] update product positioning with the bounded UI assurance wording

Exit criteria:

- the admin-console claim is backed by a separate assurance case, a checked
  model, schema drift gates, and hosted runtime evidence

Current status:

- Engineering status: complete for the Phase 3 internal assurance boundary.
  `validate_admin_ui_assurance.py` validates the assurance bundle, finite
  state-machine model, route/action operation classes, OpenAPI to
  management-client operation coverage, and write-method CSRF/Origin guard
  hooks.
- Evidence status: internal-complete for the bounded admin control-plane
  security boundary recorded in
  `docs/releases/evidence/admin-ui-assurance-phase3-internal-bundle.json`. Hosted
  runtime evidence remains deferred and is a public-claim blocker.
- Public claim status: blocked; `spec/admin-ui-assurance-claim.current.json`
  keeps `claim_active=false` and continues to exclude React/browser/rendering
  behaviour.

### Phase 4 - Claim Activation Review

Objective:

- activate stronger wording only after the relevant evidence is complete.
- keep this as the only phase that changes public product/release wording.

Tasks:

- [x] run the server verification and security baseline as an internal preflight gate
- [ ] run SDK/admin hosted evidence gates
- [x] run certification evidence validation as an internal preflight gate
- [x] validate all evidence bundle schemas as an internal preflight gate
- [x] record Phase 4 internal preflight with explicit external/public blockers
- [ ] update `docs/product-positioning.md`, release notes, launch assets, and
      README wording in one coordinated change set
- [ ] tag the release only after claim and evidence review passes

Exit criteria:

- the release can safely use only the stronger claims whose gates are closed

Current status:

- Internal preflight status: complete. The canonical preflight bundle is
  `docs/releases/evidence/phase4-claim-activation-preflight.json` and is validated by
  `validate_phase4_activation_preflight.py`.
- Evidence status: blocked only on external hosted evidence, external
  certification / publication evidence, and the final public wording release
  change set.
- Public claim status: blocked; all stronger claim gates remain inactive until
  the external blocker list is resolved and a final activation-review change set
  updates public wording and release tags.

## Recommended Order

Use parallel engineering execution with sequential public activation:

1. Phase 0 remains closed as the claim-contract baseline.
2. Continue Phase 1 evidence acquisition as the enterprise-readiness public
   claim blocker.
3. Start Phase 2 certification scope selection and conformance evidence work
   without waiting for Phase 1 public claim closure.
4. Start Phase 3 admin UI assurance modelling and drift-gate work without
   waiting for Phase 1 or Phase 2 public claim closure.
5. Keep Phase 4 as the single activation checkpoint for public wording.

Reasoning:

- enterprise-readiness evidence depends on external operational setup, so it
  can stall for reasons unrelated to certification or UI assurance engineering
- certification depends on selecting exact targets and running external
  processes, which can proceed while enterprise-readiness evidence is gathered
- UI assurance has a separate bounded claim and can make engineering progress
  through model and drift-gate work before hosted evidence is final
- public wording remains safe because Phase 4 is the only activation point

## Current Next Tasks

Keep Phase 1 public blockers explicit:

1. regenerate `publication-org-rollout-report.json` with non-empty detail for
   both done publication-org tasks
2. produce an enterprise-ready SDK release-publication bundle with
   `release_phase=released-client-claim` and no deferred publication or
   attestation requirements
3. provision at least one managed commercial/enterprise provider tenant and run
   hosted evidence with full `refs/*` GitHub source metadata
4. provide reviewed concrete KMS/HSM classification manifests and fresh
   management/issuer SLO baseline manifests for the release candidate
5. run `collect_enterprise_readiness_phase1_evidence.py --phase1-check` against
   those artifacts and only then mark the Phase 1 claim-gate evidence complete

Use `docs/releases/runbooks/phase1-evidence-acquisition.md` as the operator runbook for
regenerating the blocking SDK, KMS/HSM, SLO, and release-archive evidence.

Phase 2 internal completion is closed. Defer Phase 2 external completion to the
final public activation pass:

1. submit the formal OIDF package only when the release is ready to claim
   certification publicly
2. resolve upstream `REVIEW` / `WARNING` / `SKIPPED` outcomes or replace the
   internal bundle with an external-complete bundle whose dispositions are no
   longer public-claim blockers
3. switch public wording only in Phase 4 after the external bundle validates

Phase 3 internal completion is closed. Defer Phase 3 external/public completion
to the final public activation pass:

1. refresh hosted admin-console stack evidence against the bounded assurance
   model
2. replace the internal bundle with an external-complete bundle only after
   hosted evidence is approved
3. switch public wording only in Phase 4 after the external bundle validates

Phase 4 internal preflight is closed. Remaining work is intentionally external
or public-release work:

1. gather publication-org, managed-provider, KMS/HSM, release-security, and SLO
   evidence for the enterprise-readiness gate
2. complete formal OIDF certification submission / review / public listing or
   replace the internal certification bundle with an external-complete bundle
3. refresh hosted admin-console stack evidence against the bounded assurance
   model
4. perform one final public wording / README / release-note / launch-asset /
   tag change set for only the claim gates that are externally complete

## Closure Attempt Record

2026-05-20: Phase 1 closure was attempted against the currently available
local/sibling SDK artifacts. The collector correctly failed closed before
archive generation because the publication-org rollout report had `ready=true`
but lacked non-empty `detail` fields for
`publication_org_branch_protection` and `publication_org_secret_rollout`.
Direct validation also showed that the available SDK publication bundle remains
`pre-release-client-baseline`, and the available managed-provider evidence does
not yet carry full `refs/*` GitHub source metadata. The available
`artifacts/oidc-kms-phase1-local/summary.json` is parity output, not a
KMS/HSM deployment classification manifest, and no enterprise SLO baseline
manifest was present for the closure attempt. These artifacts must be
regenerated or authored from the real publication, hosted-provider,
deployment-classification, and SLO workflows; do not change
`spec/enterprise-readiness-claim.current.json` to `complete` until the collector
and final Phase 1 validator pass on the regenerated evidence.
