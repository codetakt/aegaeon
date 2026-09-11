# Kani NixOS Fix Details

Last updated: 2026-09-11

Status: historical record

Owner: Verification

Audience: verification contributors, maintainers

This directory contains the split RCA and implementation note for the Kani 0.66.0 NixOS `libkani.rlib` archive fix.

The archive-reconstruction approach recorded here is superseded. Current
packaging uses the pinned upstream builder and preserves compiler-produced
libraries. See the [packaging invariants](../../../../nix/kani/README.md) and
[Kani verification guide](../README.md) for current implementation and checks.

## Scope

- historical packaging fix and validation record
- root-cause analysis for NixOS archive differences
- alternatives, technical details, limitations, and references

## Canonical Documents

- `[reference]` [Problem and root cause](problem-and-root-cause.md)
- `[reference]` [Implemented fix and validation](implemented-fix-and-validation.md)
- `[reference]` [Alternatives and technical details](alternatives-and-technical-details.md)

## Reading Rule of Thumb

1. Start with the [packaging invariants](../../../../nix/kani/README.md) for the current fix.
2. Use [problem-and-root-cause.md](problem-and-root-cause.md) when diagnosing similar archive failures.
3. Use [alternatives-and-technical-details.md](alternatives-and-technical-details.md) for historical tradeoffs.
