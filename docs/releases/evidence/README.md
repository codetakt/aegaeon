# Release Evidence

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Release Engineering

Audience: release managers, maintainers

This directory contains source-managed release evidence summaries, claim-gate
preflight records, and small curated JSON bundles. Raw logs and current machine
outputs belong under `artifacts/`.

## Scope

- point-in-time release and conformance summaries
- internal claim-gate evidence bundles
- source-managed JSON manifests used by release validators

## Canonical Documents

- `[evidence]` Claim-gate evidence:
  [Phase 4 preflight](phase4-claim-activation-preflight.md),
  [enterprise readiness](enterprise-readiness-evidence-bundle.md),
  [certification Phase 2](certification-phase2-internal-evidence.md),
  [Admin UI assurance Phase 3](admin-ui-assurance-phase3-internal-evidence.md),
  and [server / client formal assurance Phase 5](server-client-formal-assurance-phase5-internal-evidence.md).
- `[evidence]` Provider and rollout evidence:
  [managed provider evidence](managed-provider-evidence.md) and
  [publication organization rollout](publication-org-rollout.md).
- `[snapshot]` Conformance and security snapshots:
  [beta conformance](beta-conformance.md) and
  [release security evidence archive](release-security-evidence.md).
- `[index]` [KMS/HSM classification manifests](kms-hsm-classifications/README.md).

## Reading Rule of Thumb

1. Treat these files as curated summaries, not live evidence.
2. Validate JSON bundles with the matching scripts under `scripts/validation/`.
3. Use `../runbooks/` for refresh procedures and `artifacts/` for current outputs.
