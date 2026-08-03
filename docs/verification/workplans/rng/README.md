# DRBG And Entropy Input Workplan Details

Last updated: 2026-07-08

Status: active plan

Owner: Verification

Audience: verification contributors, maintainers

This directory contains the split DRBG specification and entropy-input workplan.

## Scope

- DRBG scheme and entropy-input contract
- F* signatures, effect handling, and caller impact
- proof boundaries, completion criteria, file map, and risk assessment

## Canonical Documents

- `[workplan]` [DRBG and entropy input](drbg-and-entropy.md)
- `[workplan]` [F* effects and caller impact](fstar-effects-and-callers.md)
- `[workplan]` [Proof boundaries and completion criteria](proof-boundaries-and-criteria.md)

## Reading Rule of Thumb

1. Start with [drbg-and-entropy.md](drbg-and-entropy.md) for the model contract.
2. Use [fstar-effects-and-callers.md](fstar-effects-and-callers.md) before changing call sites.
3. Use [proof-boundaries-and-criteria.md](proof-boundaries-and-criteria.md) for claim limits and completion criteria.
