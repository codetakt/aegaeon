# Admin UI Assurance Phase 3 Internal Evidence

Last updated: 2026-07-08

Status: snapshot

Owner: Release Engineering

Audience: release managers, maintainers

> **Status note (2026-07-08):** Point-in-time release evidence; rerun the named validator before using it for a new release decision.

This document records the internal Phase 3 admin UI assurance closure baseline.
It is not a public "formally verified UI" claim.

## Status

- Internal Phase 3 status: complete for the bounded admin control-plane security
  boundary.
- Public UI assurance status: blocked until hosted runtime evidence is refreshed
  and the final Phase 4 claim-activation review is approved.
- Claim gate: `spec/admin-ui-assurance-claim.current.json` remains
  `claim_active=false`.

## Boundary

The included boundary is limited to:

- management-session acquisition and loss
- CSRF and Origin guarded management API writes
- `@aegaeon/management-client` transport use
- route groups that require an active management session
- dangerous operation confirmation and audit expectations
- OpenAPI to management-client operation drift

The excluded boundary remains:

- React runtime correctness
- browser rendering, CSS/layout, extensions, and OS UI behaviour
- all possible visual interactions
- end-user credential submission on the admin SPA

## Canonical Bundle

The machine-readable bundle is:

- `docs/releases/evidence/admin-ui-assurance-phase3-internal-bundle.json`

It references the assurance case, finite state-machine model, model schema,
validator, validator self-test, and bounded product-positioning wording.

## Validation

Run the validator from the pinned dev shell:

```bash
nix develop .#default --command bash -c \
  'python3 scripts/validation/validate_admin_ui_assurance.py \
    docs/releases/evidence/admin-ui-assurance-phase3-internal-bundle.json'
```

Run the validator self-tests:

```bash
nix develop .#default --command bash -c \
  'python3 scripts/validation/test_admin_ui_assurance_validators.py'
```

The internal bundle may pass while public UI assurance remains blocked. External
completion requires `phase3_status=external-complete`, `public_claim_ready=true`,
approved hosted runtime evidence, and Phase 4 product wording activation.
