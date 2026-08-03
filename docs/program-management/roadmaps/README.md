# Roadmaps (Future And Active Plans)

Last updated: 2026-07-07

Status: active plan

Owner: Program Management

Audience: maintainers, planning contributors

This directory indexes programme roadmaps for work that is still future-facing,
not complete, or kept as an ongoing evidence-maintenance track. Completed
implementation plans should live either as current specifications under
`docs/specs/` or as delivery records under `docs/program-management/historical/`.

## Scope

- active execution and claim-upgrade plans
- future or deferred program plans
- current programme summaries that point to canonical specs and evidence

## Canonical Documents

- `[index]` `summary/README.md`: programme summary and master-plan entrypoint.
- `[index]` `active/README.md`: active execution, compliance, verification, and claim-upgrade plans.
- `[index]` `future/README.md`: deferred conformance expansion and future backlog.
- `[publication]` `../../publication/launch-assets/v0.1.0/aegaeon-pr-plan-2026.md`: revised
  2026 PR / launch schedule plus publication-ready Japanese press release drafts.
- `[publication]` `../../publication/launch-assets/README.md`: launch-asset index for the v0.1.0
  product page, whitepaper, Spec Sheet, preview form, and GitHub launch prep.

## Current References

- `spec/compliance-matrix.yaml`: authoritative requirement-by-requirement status with linked proof/test/runtime evidence.
- `docs/verification/claims/crypto-allowlist.md`: authoritative verified-vs-compat crypto posture.
- `docs/verification/workplans/verification-boundary-roadmap.md`: authoritative plan when runtime support outruns the current formal claim.
- `docs/product-positioning.md`: authoritative outward-facing wording derived from the current claim and evidence.
- Fresh command output and `artifacts/`: operational evidence for current state. Documentation alone is not sufficient evidence.
- Current primary-authority implementation spec: `docs/specs/primary-authority-user-management.md`.
- Current broker/federation implementation spec: `docs/specs/oidc-rp-brokering-spec.md`.

## Historical delivery records (read-only)

Completed execution plans are kept under `docs/program-management/historical/roadmaps/`:

- `../historical/roadmaps/oauth2-execution-plan.md`
- `../historical/roadmaps/oidc-execution-plan.md`
- `../historical/roadmaps/primary-authority-user-management-delivery.md`
- `../historical/roadmaps/federated-broker-idp-delivery.md`
- `../historical/roadmaps/management-ui-and-ts-sdk-delivery.md`

## Reading Rule of Thumb

1. Use `summary/` for programme-level orientation.
2. Use `active/` for work that is currently being sequenced.
3. Use `future/` for intentionally deferred work.
4. Move completed delivery details into `../historical/roadmaps/`.
