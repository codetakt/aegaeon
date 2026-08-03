# F* Assumption Register

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, maintainers

This compatibility entrypoint preserves the historical `docs/verification/claims/assumptions.md` path. The detailed assumption register now lives in `assumptions/`.

Retained for: temporary compatibility with historical links, generated evidence, and release artifacts that still reference this moved path.

Review after: 2026-10-08

For quick claim-boundary triage, start with [Assumption boundary overview](assumption-boundary-overview.md). For exact assumption IDs, use the split register below.

## Scope

- compatibility pointer for the current F* assumption register
- navigation to current, mitigation, audit, and historical assumption details

## Canonical Documents

- `[claim]` [Assumption boundary overview](assumption-boundary-overview.md)
- `[index]` [Assumption register details](assumptions/README.md)
- `[claim]` [Current register](assumptions/current-register.md)
- `[claim]` [Mitigation and audit checklist](assumptions/mitigation-and-audit.md)
- `[historical]` [Historical reductions](assumptions/historical-reductions.md)

## Reading Rule of Thumb

1. Use [assumption-boundary-overview.md](assumption-boundary-overview.md) for a short reader entrypoint.
2. Use [assumptions/current-register.md](assumptions/current-register.md) for normative assumption IDs and current categories.
3. Do not add new detailed assumption content to this compatibility page.
