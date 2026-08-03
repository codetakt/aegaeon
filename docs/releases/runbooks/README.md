# Release Runbooks

Last updated: 2026-07-07

Status: current implementation baseline

Owner: Release Engineering

Audience: release managers, maintainers

This directory contains human-executed release procedures and validation
runbooks. Point-in-time evidence and generated bundle summaries belong in
`../evidence/`.

## Scope

- release validation procedures
- evidence acquisition instructions
- operator commands for release readiness gates

## Canonical Documents

- `[runbook]` [Beta deployment validation](beta-deployment.md)
- `[runbook]` [Phase 1 evidence acquisition](phase1-evidence-acquisition.md)

## Reading Rule of Thumb

1. Start here when running a release or refreshing evidence.
2. Store fresh machine output under `artifacts/`, not in this directory.
3. Promote durable release results into `../evidence/` only when they should be source-managed.
