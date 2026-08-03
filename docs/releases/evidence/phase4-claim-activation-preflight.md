# Phase 4 Claim Activation Preflight

Last updated: 2026-07-08

Status: snapshot

Owner: Release Engineering

Audience: release managers, maintainers

> **Status note (2026-07-08):** Point-in-time release evidence; rerun the named validator before using it for a new release decision.

This document records the Phase 4 internal preflight. It does not activate any
stronger public claim.

## Status

- Internal preflight: complete.
- Public claim activation: blocked.
- Remaining blockers: external hosted evidence, external certification /
  publication evidence, and the final public wording release change set.

## Canonical Bundle

The machine-readable preflight bundle is:

- `docs/releases/evidence/phase4-claim-activation-preflight.json`

It verifies that:

- enterprise-readiness, certification, and admin UI assurance claim gates remain
  inactive
- internal schemas, validators, runbooks, internal bundles, and positioning
  documents exist
- all non-complete activation evidence is explicitly listed as an external or
  public-release blocker
- no stronger public wording is activated before the final reviewed release
  change set

## Validation

Run the validator from the pinned dev shell:

```bash
nix develop .#default --command bash -c \
  'python3 scripts/validation/validate_phase4_activation_preflight.py \
    docs/releases/evidence/phase4-claim-activation-preflight.json'
```

Run the validator self-tests:

```bash
nix develop .#default --command bash -c \
  'python3 scripts/validation/test_phase4_activation_preflight.py'
```

## Remaining External Inputs

- publication organization rollout and released package custody evidence
- real managed-provider hosted tenant evidence
- concrete KMS/HSM deployment classification evidence
- release-candidate security evidence archive and SLO baselines
- external OIDF certification submission / review / public listing
- hosted admin-console runtime evidence
- final product-positioning / README / release-note wording and release tag
