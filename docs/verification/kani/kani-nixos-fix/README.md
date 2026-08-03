# Kani NixOS Fix Details

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Verification

Audience: verification contributors, maintainers

This directory contains the split RCA and implementation note for the Kani 0.66.0 NixOS `libkani.rlib` archive fix.

## Scope

- current packaging fix and validation record
- root-cause analysis for NixOS archive differences
- alternatives, technical details, limitations, and references

## Canonical Documents

- `[runbook]` [Problem and root cause](problem-and-root-cause.md)
- `[runbook]` [Implemented fix and validation](implemented-fix-and-validation.md)
- `[reference]` [Alternatives and technical details](alternatives-and-technical-details.md)

## Reading Rule of Thumb

1. Start with [implemented-fix-and-validation.md](implemented-fix-and-validation.md) for the current fix.
2. Use [problem-and-root-cause.md](problem-and-root-cause.md) when diagnosing similar archive failures.
3. Use [alternatives-and-technical-details.md](alternatives-and-technical-details.md) for historical tradeoffs.
