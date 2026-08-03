# Development Overview

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Engineering

Audience: contributors, maintainers

This directory contains developer-facing onboarding, validation, and short
current-context entrypoints.

## Scope

- local developer workflow and setup
- validation / verification command references
- current implementation-facing navigation for adjacent projects or teams

## Canonical Documents

- `[runbook]` [Database setup](database.md)
- `[runbook]` [Validation tools](validation-tools.md)
- `[guide]` [Claude agent guide](claude-agent-guide.md)
- `[context]` [Current delivery context](current-delivery-context.md) — live
  implementation entrypoints only
- `[handoff]` [Admin console frontend handoff](admin-console-handoff.md)

## Context Retention Rule

Keep implementation context and handoff notes here only while they describe
current integration work. Move them to `../program-management/historical/` when
the referenced repository, workflow, or delivery phase is complete and the
durable requirement has been promoted to specs, operations docs, or verification
claims.

## Reading Rule of Thumb

1. Start here for local developer workflow.
2. Jump to `docs/specs/` for normative API / product shape.
3. Jump to `docs/verification/` when a developer note touches proof scope or verified-vs-compat boundaries.
4. Keep completed thread handoffs under `docs/program-management/historical/`.
