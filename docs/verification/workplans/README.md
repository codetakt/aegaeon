# Verification Workplans Overview

Last updated: 2026-07-08

Status: active plan

Owner: Verification

Audience: verification contributors, maintainers

This directory contains active and future verification work. Use these documents
for sequencing, blocker analysis, and proof-library structure decisions.

## Scope

- boundary-closure roadmaps
- crypto extraction and RNG plans
- lemma-hardening and Phase D work
- blocker/tool-warning analyses and source-structure guidance

## Canonical Documents

- `[roadmap]` [Verification boundary roadmap](verification-boundary-roadmap.md)
- `[roadmap]` [Crypto extraction roadmap](crypto-extraction-roadmap.md)
- `[index]` [Phase D plan](phase-d/README.md)
- `[workplan]` [Lemma hardening plan](lemma-hardening-plan.md)
- `[index]` [RNG plan](rng/README.md)
- `[index]` [Analysis notes](analysis/README.md)
- `[guide]` [Verification artefact structure guidelines](structure-guidelines.md)

## Reading Rule of Thumb

1. Start with the boundary roadmap when runtime support outruns the current claim.
2. Keep completed delivery history under `../../program-management/historical/`.
3. Promote stable operational instructions into `../runbooks/` when a plan becomes
  repeatable maintenance work.
