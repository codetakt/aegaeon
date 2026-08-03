# JOSE Verification Overview

Last updated: 2026-07-07

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, contributors

This directory contains current JOSE verification notes and runtime-boundary
records.

## Scope

- JOSE verification summaries
- raw JSON claim-boundary notes
- Low*/FFI contract summaries for JOSE JSON handling

## Canonical Documents

- `[claim]` [Raw JSON claim boundary](raw-json-boundary.md)
- `[snapshot]` [Phase 4 verification summary](phase4-verification-summary.md)
- `[runbook]` [JSON Low*/FFI contract summary](json-lowstar-ffi-contracts.md)

## Reading Rule of Thumb

1. Start with the raw JSON boundary when claim wording depends on JOSE parsing.
2. Use `../../program-management/initiatives/jose/README.md` for active JOSE plans.
3. Use `../claims/crypto-allowlist.md` for algorithm posture.
