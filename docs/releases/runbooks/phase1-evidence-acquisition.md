# Phase 1 Evidence Acquisition Runbook

Last updated: 2026-07-08

Status: snapshot

Owner: Release Engineering

Audience: release managers, maintainers

> **Status note (2026-07-08):** Point-in-time release evidence; rerun the named validator before using it for a new release decision.

## Scope

This runbook defines how to acquire the real artifacts required to close Phase 1
enterprise-readiness. It is an evidence-acquisition procedure, not a substitute
for the validators.

Do not mark any Phase 1 claim-gate evidence `complete` until:

- source evidence passes `collect_enterprise_readiness_phase1_evidence.py --preflight-only`
- the collector writes a release archive
- `validate_enterprise_readiness_phase1.py` passes against the generated bundle
- a reviewer approves the generated release manifest, KMS/HSM classifications,
  enterprise SLO baseline, and enterprise-readiness bundle

## Current Blockers

2026-06-24 Google validation setup:

- The integrated IaC repository has configured the Google hosted OIDC
  validation lane for the `aegaeon-validation` environment, using GitHub
  Environment `aegaeon-validation-google` and test user
  `sdk-google@validation.aegaeon.systems`.
- Google hosted managed-provider evidence passed in
  `codetakt/aegaeon-sdk-ci` run `28063433114` at SDK commit
  `fc5020db86c9a45ab2568e42696e28efac8a1358`. The downloaded
  `managed-provider-evidence.json` is stored at
  `artifacts/phase1-closure-attempt/google-managed-provider-28063433114/`
  and validates with both the SDK validator and the server-side enterprise
  managed-provider gate.
- The evidence records `runtime.claim_phase=released-client-claim`,
  `lane.hosted=true`, `provider.class=commercial`,
  `provider.name=google-cloud-identity-validation`,
  `provider.issuer=https://accounts.google.com`,
  `source.github_repository=codetakt/aegaeon-sdk-ci`, and
  `source.github_ref=refs/heads/enterprise/released-client-activation-candidate-ci`.
- Investigation note: Google consent UI required explicit waits before the
  optional consent click. The SDK workflow did not need a product-code change,
  but SDK commit
  `fc5020d test: document managed provider optional clicks` now documents and
  regression-tests the managed-provider runner semantics: `clickIfVisible` is
  an immediate optional click and does not wait for delayed UI. Delayed optional
  UI should first use `waitForSelector` or `waitForURL`.

2026-06-23 Auth0 validation setup:

- The integrated IaC repository has applied the Auth0 validation stack for the
  `aegaeon-validation` environment. Managed resources are:
  `aegaeon-sdk-managed-provider-auth0`,
  `aegaeon-validation-users`, and the test user
  `sdk-auth0@validation.aegaeon.systems`.
- The SDK managed-provider config for Auth0 validates against
  `managed-external-provider.schema.json`, and issuer discovery for
  `https://aegaeon-validation.jp.auth0.com/` returns the same issuer plus
  RS256 support.
- `codetakt/aegaeon-sdk-ci` now has
  `AEGAEON_MANAGED_EXTERNAL_PROVIDER_CONFIG_JSON` set to the Auth0 validation
  config and keeps `AEGAEON_MANAGED_EXTERNAL_PROVIDER_ENABLED=false` so the
  tenant-backed lane remains manual-dispatch only.
- Auth0 hosted managed-provider evidence passed in
  `codetakt/aegaeon-sdk-ci` run `28063269163` at SDK commit
  `fc5020db86c9a45ab2568e42696e28efac8a1358`. The downloaded
  `managed-provider-evidence.json` is stored at
  `artifacts/phase1-closure-attempt/auth0-managed-provider-28063269163/`
  and validates with both the SDK validator and the server-side enterprise
  managed-provider gate:
  `runtime.claim_phase=released-client-claim`, `lane.hosted=true`,
  `provider.class=commercial`, and
  `source.github_ref=refs/heads/enterprise/released-client-activation-candidate-ci`.
- Follow-up SDK candidate commit
  `cd57b18 fix(release): accept validation evidence repositories` teaches the
  released-client promotion/readiness policy to accept both production and
  validation repository suffixes (`aegaeon-sdk` / `aegaeon-sdk-ci`,
  `aegaeon-admin-console` / `aegaeon-admin-console-ci`) without weakening
  workflow/job/ref/SHA provenance checks.
- Follow-up SDK candidate commit
  `2bfb65c ci: wire release evidence environment into sdk workflows` wires the
  promotion/readiness/publish workflows to a release evidence GitHub
  Environment and ensures release-attestation generation records npm provenance
  before the readiness gate evaluates the bundle.
- Remaining SDK publication blocker: enterprise release-publication evidence
  still requires a signed release attestation and SBOM-publication posture from
  the release evidence GitHub Environment. As of the 2026-06-24 check,
  `codetakt/aegaeon-sdk-ci` exposes only
  `aegaeon-validation-auth0` and `aegaeon-validation-google` environments;
  `aegaeon-validation-release` is not present, `AEGAEON_COSIGN_KEY` is not
  visible, and repository variables still record
  `AEGAEON_SDK_SIGNED_RELEASE_ATTESTATION=false` and
  `AEGAEON_SDK_SBOM_PUBLICATION=false`. Provision the release signing key
  through IaC, sync it to GitHub Environment secrets, set the release evidence
  variables to `true`, and rerun hosted released-client readiness/publish
  evidence before attempting Phase 1 collection.

2026-06-20 follow-up:

- SDK activation-candidate work was staged and pushed to
  `codetakt/aegaeon-sdk-ci` as
  `enterprise/released-client-activation-candidate-ci` at
  `5375af52bd3da6489c97cd58e2dedea374e7a2d3`.
- Local SDK validation for that branch passed:
  `validate_client_claim_boundary.py`,
  `validate_released_client_claim.py`,
  `validate_client_claim_promotion.py`, `pnpm run build:tools`,
  `pnpm run build:tests:node`, `client_claim_boundary_test.js`,
  `release_attestation_test.js`, and `managed_provider_evidence_test.js`.
- A temporary managed-provider evidence build from the activation-candidate
  branch emitted `runtime.claim_phase=released-client-claim`, confirming that
  hosted evidence generated from this branch will target the released-client
  claim posture.
- `codetakt/aegaeon-sdk-ci` still has no visible
  `AEGAEON_MANAGED_EXTERNAL_PROVIDER_USERNAME`,
  `AEGAEON_MANAGED_EXTERNAL_PROVIDER_PASSWORD`, or
  `AEGAEON_MANAGED_EXTERNAL_PROVIDER_CLIENT_SECRET` secret, and the local
  environment has no corresponding managed-provider credential variables.
  Therefore the real hosted managed-provider lane was not dispatched in this
  follow-up. Fresh tenant-backed evidence remains the next external blocker.

2026-06-19 follow-up:

- Server-side schema drift for
  `publication_org_rollout_report` in the SDK release-publication bundle has
  been fixed.
- The enterprise managed-provider validator now accepts recorded
  `runtime.compat_only_surfaces` as compatibility surfaces outside the
  released-client formal claim, while still rejecting `compat-interop` as the
  default profile.
- Fresh admin-console stack evidence was collected from
  `codetakt/aegaeon-admin-console-ci` run `27808331413` and validated against
  the SDK admin-SDK evidence schema.
- The regenerated SDK released-client report now has a single readiness
  blocker: managed-provider evidence is older than 168 hours.
- The `codetakt/aegaeon-sdk-ci` repository variables currently keep
  `AEGAEON_MANAGED_EXTERNAL_PROVIDER_ENABLED=false`; the repository has no
  managed-provider tenant credential secrets visible to the evidence preflight.
  A fresh managed-provider pass therefore still requires provisioning a real
  tenant config plus credentials before claim activation.
- `release-publication-bundle.json` must remain
  `release_phase=pre-release-client-baseline` until that fresh managed-provider
  evidence exists and the released-client claim policy/boundary are deliberately
  activated in a reviewed change set.

The 2026-05-20 closure attempt is recorded at:

- `artifacts/phase1-closure-attempt/current/phase1-closure-status.json`

That record is intentionally fail-closed: it preserves the available evidence,
validator logs, and live GitHub audit outputs, but it does not close Phase 1.

The currently available local/sibling SDK artifacts do not close Phase 1:

- `publication-org-rollout-report.json` has `ready=true` but lacks non-empty
  `detail` for the done publication-org tasks.
  Live GitHub audit of `codetakt/aegaeon-sdk-ci` also showed `main` was not
  protected and repository rulesets were empty at the time of the closure
  attempt, so the publication-org branch-protection task cannot be considered
  done from current evidence.
- `release-publication-bundle.json` is still
  `release_phase=pre-release-client-baseline`.
- `managed-provider-evidence.json` was produced/imported with `github_ref=main`
  instead of a full `refs/*` value and remains in pre-release claim posture.
  The last hosted `managed-provider-evidence` artifact was expired at the time
  of the closure attempt.
- `artifacts/oidc-kms-phase1-local/summary.json` is parity output, not a
  KMS/HSM deployment classification manifest.
- no fresh enterprise SLO baseline manifest is present for the release
  candidate.
- the checked `codetakt/aegaeon-server-ci` Security Suite runs at the time of
  the 2026-06-24 closure attempt were
  failing, so a fresh green release-security log was not available for the
  closure bundle.

Use the current artifacts only as debugging material. Regenerate the evidence
from real workflows and deployment-specific manifests.

## Required Evidence Set

Collect these files before running the server-side collector:

- publication rollout report:
  `publication-org-rollout-report.json`
- SDK release-publication bundle:
  `release-publication-bundle.json`
- managed provider evidence:
  `managed-provider-evidence.json`
- at least one reviewed KMS/HSM deployment classification manifest:
  `*-classification.json`
- enterprise SLO baseline manifest:
  `enterprise-slo-baseline.json`
- release build / verification / security / SBOM / support-response files

## SDK Publication Evidence

Run from the sibling SDK repository against the real publication organization.
Do not use inline imported evidence for Phase 1 unless the imported JSON itself
contains full GitHub source metadata and passes the server-side validators.

Managed provider evidence:

```bash
gh workflow run managed-provider-evidence.yml \
  --repo <owner>/aegaeon-sdk \
  --ref main \
  -f provider_class=commercial
```

For the current validation repository (`codetakt/aegaeon-sdk-ci`), the
2026-06-20 preflight state was:

- `AEGAEON_MANAGED_EXTERNAL_PROVIDER_ENABLED=false`
- no `AEGAEON_MANAGED_EXTERNAL_PROVIDER_USERNAME`,
  `AEGAEON_MANAGED_EXTERNAL_PROVIDER_PASSWORD`, or
  `AEGAEON_MANAGED_EXTERNAL_PROVIDER_CLIENT_SECRET` secret was visible through
  `gh secret list`
- `AEGAEON_RELEASED_CLIENT_CLAIM_ACTIVE=false`,
  `AEGAEON_SDK_SIGNED_RELEASE_ATTESTATION=false`, and
  `AEGAEON_SDK_SBOM_PUBLICATION=false`

Before a managed-provider run can close enterprise readiness:

1. Create an SDK activation-candidate branch that sets the released-client
   policy and client boundary to the intended `released-client-claim` posture.
   Do not merge or publish this branch until all validators pass.
2. Provision a real commercial or enterprise OIDC tenant and author a
   `managed-external-provider.json` matching
   `sdk/spec/managed-external-provider.schema.json`.
3. Store credentials as repository or environment secrets, never in the config
   JSON:

```bash
gh secret set AEGAEON_MANAGED_EXTERNAL_PROVIDER_USERNAME \
  --repo <owner>/aegaeon-sdk
gh secret set AEGAEON_MANAGED_EXTERNAL_PROVIDER_PASSWORD \
  --repo <owner>/aegaeon-sdk
gh secret set AEGAEON_MANAGED_EXTERNAL_PROVIDER_CLIENT_SECRET \
  --repo <owner>/aegaeon-sdk
```

4. Dispatch the managed-provider workflow on the activation-candidate branch
   with the config JSON as an explicit one-off input:

```bash
gh workflow run managed-provider-evidence.yml \
  --repo <owner>/aegaeon-sdk \
  --ref <activation-candidate-branch> \
  -f provider_class=commercial \
  -f managed_provider_config_json="$(jq -c . <managed-external-provider.json>)"
```

The emitted `managed-provider-evidence.json` must be fresh, use a full
`refs/*` source ref, and record `runtime.claim_phase=released-client-claim`.

Released-client readiness:

```bash
gh workflow run released-client-readiness.yml \
  --repo <owner>/aegaeon-sdk \
  --ref main \
  -f dispatch_hosted=true \
  -f claim_active=false \
  -f publication_org_branch_protection_status=done \
  -f publication_org_secret_rollout_status=done
```

Publication:

```bash
gh workflow run publish.yml \
  --repo <owner>/aegaeon-sdk \
  --ref main \
  -f dispatch_hosted=true \
  -f dry_run=false \
  -f dist_tag=latest \
  -f claim_active=false \
  -f publication_org_branch_protection_status=done \
  -f publication_org_secret_rollout_status=done
```

The publication rollout report must include non-empty `detail` for each done
task. Details should be audit-grade references, for example:

- `publication_org_branch_protection`: branch/ruleset identifier, protected
  branch, required status checks, review requirements, and audit timestamp
- `publication_org_secret_rollout`: secret names or environment names, rotation
  timestamp, repository/environment scope, and reviewer

If the SDK workflow artifact still lacks task details, generate the source
report from audited rollout data before server-side collection:

```bash
nix develop .#default --command bash -c \
  'python3 scripts/validation/build_publication_org_rollout_report.py \
    --owner <owner> \
    --repo aegaeon-sdk \
    --branch main \
    --task publication_org_branch_protection=done=<ruleset-id-and-required-checks> \
    --task publication_org_secret_rollout=done=<secret-scope-and-rotation-record> \
    --out <publication-org-rollout-report.json>'
```

After downloading the workflow artifacts, validate them from the server
repository:

```bash
nix develop .#default --command bash -c \
  'python3 scripts/validation/validate_publication_org_rollout.py \
    --require-ready <publication-org-rollout-report.json>'

nix develop .#default --command bash -c \
  'python3 scripts/validation/validate_sdk_release_publication_bundle.py \
    --require-enterprise-ready <release-publication-bundle.json>'

nix develop .#default --command bash -c \
  'python3 scripts/validation/validate_managed_provider_evidence.py \
    --require-enterprise-ready <managed-provider-evidence.json>'
```

## KMS/HSM Deployment Evidence

Run the OIDC KMS parity lane against the concrete deployment signer. Then author
a classification manifest using
`spec/kms-hsm-deployment-classification.schema.json`; do not pass the raw parity
`summary.json` to the Phase 1 collector as the classification.

For a claim-preserving deployment, the classification must record:

- `classification=claim-preserving`
- `algorithm.jose_alg=RS256`
- exact provider algorithm for RSASSA PKCS#1 v1.5 SHA-256
- Aegaeon-owned JWS signing input
- provider returns raw signatures, not finished JWTs
- public JWK key-match check
- JWKS overlap/rollback parity with local-key path
- `kid` reuse prevention
- parity evidence URI
- external signer recorded as TCB
- reviewer approval

Validate each classification:

```bash
nix develop .#default --command bash -c \
  'python3 scripts/validation/validate_kms_hsm_classification.py \
    <kms-classification.json>'
```

Source-managed baseline classifications are available in
`artifacts/release/kms-hsm-classifications/`. They are useful for exercising the
collector and documenting the claim-preserving vs compat-only decision shape,
but fresh hosted or production deployments still need their own parity evidence
and reviewed manifest before Phase 1 can close.

## Enterprise SLO Evidence

Run load and observability collection against an HTTPS target deployment. Local
HTTP smoke evidence does not close Phase 1.

The manifest must include all required scenarios:

- `smoke`
- `auth-code`
- `dpop`
- `introspection`
- `revocation`
- `par`
- `discovery`
- `jwks`
- `policy-mixed`
- `management-api`

Each scenario must be `pass` with a report URI, or `not_applicable` with an
explicit scope-reduction note. At least one observability URI is required.

Validate the SLO manifest:

```bash
nix develop .#default --command bash -c \
  'python3 scripts/validation/validate_enterprise_slo_baseline.py \
    <enterprise-slo-baseline.json>'
```

## Server Release Archive Collection

Before collection, run the source-evidence preflight. This reports all blockers
without writing an archive:

```bash
nix develop .#default --command bash -c \
  'python3 scripts/validation/collect_enterprise_readiness_phase1_evidence.py \
    --release-id <release-id> \
    --publication-org-rollout <publication-org-rollout-report.json> \
    --sdk-release-publication-bundle <release-publication-bundle.json> \
    --managed-provider-evidence <managed-provider-evidence.json> \
    --kms-classification <kms-classification.json> \
    --enterprise-slo-baseline <enterprise-slo-baseline.json> \
    --build-log <nix-flake-check.log> \
    --verification-log <verified-reqs.log> \
    --security-log <security-suite.log> \
    --sbom <aegaeon-sbom.json> \
    --support-response <support-response.md> \
    --preflight-only'
```

After preflight passes, collect the archive and run final Phase 1 validation:

```bash
nix develop .#default --command bash -c \
  'python3 scripts/validation/collect_enterprise_readiness_phase1_evidence.py \
    --release-id <release-id> \
    --publication-org-rollout <publication-org-rollout-report.json> \
    --sdk-release-publication-bundle <release-publication-bundle.json> \
    --managed-provider-evidence <managed-provider-evidence.json> \
    --kms-classification <kms-classification.json> \
    --enterprise-slo-baseline <enterprise-slo-baseline.json> \
    --build-log <nix-flake-check.log> \
    --verification-log <verified-reqs.log> \
    --security-log <security-suite.log> \
    --sbom <aegaeon-sbom.json> \
    --support-response <support-response.md> \
    --reviewer <reviewer-id> \
    --phase1-check'
```

The collector writes:

- `artifacts/releases/<release-id>/manifest.json`
- `artifacts/releases/<release-id>/enterprise-readiness-bundle.json`

## Activation Rule

Only after the final command passes should the enterprise-readiness claim gate
be updated from `in_progress` to `complete`. Keep `claim_active=false` during
evidence review; public wording changes must happen in a separate reviewed
activation change set.

## Related Documents

- `docs/releases/evidence/enterprise-readiness-evidence-bundle.md`
- `docs/releases/evidence/release-security-evidence.md`
- `docs/releases/evidence/publication-org-rollout.md`
- `docs/releases/evidence/managed-provider-evidence.md`
- `docs/operations/kms-hsm-deployment-classification.md`
- `docs/performance/enterprise-slo-baselines.md`
