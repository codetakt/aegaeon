# Kani 0.66.0 On NixOS: libkani.rlib Archive Fix

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Verification

Audience: verification contributors, maintainers

This compatibility entrypoint preserves the historical `docs/verification/kani/kani-nixos-fix.md` path. The maintained RCA and runbook now live in `kani-nixos-fix/`.

Retained for: temporary compatibility with historical links, generated evidence, and release artifacts that still reference this moved path.

Review after: 2026-10-08

## Scope

- compatibility pointer for the Kani NixOS archive fix note
- navigation to current fix, root cause, alternatives, validation, and limitations

## Canonical Documents

- `[index]` [Kani NixOS fix details](kani-nixos-fix/README.md)
- `[runbook]` [Problem and root cause](kani-nixos-fix/problem-and-root-cause.md)
- `[runbook]` [Implemented fix and validation](kani-nixos-fix/implemented-fix-and-validation.md)
- `[reference]` [Alternatives and technical details](kani-nixos-fix/alternatives-and-technical-details.md)

## Reading Rule of Thumb

1. Use [kani-nixos-fix/README.md](kani-nixos-fix/README.md) as the maintained map.
2. Update the split files directly; do not add new RCA content to this compatibility page.
