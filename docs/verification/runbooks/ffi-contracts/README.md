# FFI Contract Register Details

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Verification

Audience: verification contributors, maintainers

This directory contains the split FFI contract register.

## Scope

- eliminated Category B FFI assumptions
- external FFI boundaries and runtime checks
- build pipeline, validation, and related documentation links

## Canonical Documents

- `[runbook]` [Category B elimination](category-b-elimination.md)
- `[runbook]` [External boundaries and runtime checks](external-boundaries-and-runtime-checks.md)
- `[runbook]` [Build validation and links](build-validation-and-links.md)

## Reading Rule of Thumb

1. Start with [category-b-elimination.md](category-b-elimination.md) for eliminated assumptions.
2. Use [external-boundaries-and-runtime-checks.md](external-boundaries-and-runtime-checks.md) for remaining FFI boundaries.
3. Use [build-validation-and-links.md](build-validation-and-links.md) when reproducing checks.
