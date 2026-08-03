# OIDC Verification Overview

Last updated: 2026-07-07

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, contributors

This directory contains OIDC-specific proof plans, formal verification DoD, and
RS256 slice-closure records.

## Scope

- OIDC formal-verification scope and Definition of Done
- RS256 required and interop slice claim records
- Low* runtime promotion policy for OIDC artefacts

## Canonical Documents

- `[workplan]` [OIDC-1 formal verification DoD](oidc-1-formal-verification-dod.md)
- `[claim]` [RS256 required slice](rs256-required-slice.md)
- `[claim]` [RS256 interop slice](rs256-interop-slice.md)
- `[policy]` [Low* runtime promotion policy](lowstar-runtime-policy.md)

## Reading Rule of Thumb

1. Start with the formal verification DoD for OIDC proof scope.
2. Use RS256 slice records before changing RSA-related claim wording.
3. Use `../claims/crypto-allowlist.md` for canonical crypto posture.
