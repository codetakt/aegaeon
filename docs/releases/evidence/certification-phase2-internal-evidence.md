# Certification Phase 2 Internal Evidence

Last updated: 2026-07-08

Status: snapshot

Owner: Release Engineering

Audience: release managers, maintainers

> **Status note (2026-07-08):** Point-in-time release evidence; rerun the named validator before using it for a new release decision.

This document records the internal Phase 2 certification closure baseline. It is
not a public certification claim.

## Status

- Internal Phase 2 status: complete for the bounded OIDF OP Config + Basic
  evidence baseline.
- Public certification status: blocked until formal submission, external review,
  and public listing are complete.
- Claim gate: `spec/certification-claim.current.json` remains
  `claim_active=false`.

## Scope

Included internal target:

- `oidcc-config-certification-test-plan`
- `oidcc-basic-certification-test-plan`

Excluded from internal completion:

- formal OIDF fee/legal/submission/review/public listing
- Form Post Basic execution
- FAPI and JARM certification plans
- organizational certifications such as SOC 2 or ISO 27001

## Canonical Bundle

The machine-readable bundle is:

- `docs/releases/evidence/certification-phase2-internal-bundle.json`

It references the current local conformance exports under `artifacts/conformance/`
and records explicit dispositions for every `REVIEW`, `WARNING`, and `SKIPPED`
module in the Basic plan. All such dispositions remain public-claim blockers
until the external certification closure phase resolves or approves them.

## Validation

Run the validator from the pinned dev shell:

```bash
nix develop .#default --command bash -c \
  'python3 scripts/validation/validate_certification_evidence_bundle.py \
    docs/releases/evidence/certification-phase2-internal-bundle.json'
```

Run the validator self-tests:

```bash
nix develop .#default --command bash -c \
  'python3 scripts/validation/test_certification_evidence_validators.py'
```

The internal bundle may pass while public certification remains blocked. External
completion requires `phase2_status=external-complete`, `public_claim_ready=true`,
approved or publicly listed formal evidence, and no remaining public-claim
blocker dispositions.
