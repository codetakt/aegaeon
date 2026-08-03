# Operations Overview

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

This directory contains operator-facing runbooks for runtime behaviour, key use,
sender constraints, and release handling.

## Scope

- runtime operations and troubleshooting guidance
- sender-constrained-token and key-management runbooks
- monitoring / alerting samples and release-operation notes

## Canonical Documents

- `[runbook]` [Runtime configuration operations](runtime-configuration.md) —
  runtime authority, environment, and startup troubleshooting.
- `[runbook]` [JWKS operations](jwks-operations.md) — key distribution,
  caching, pinning, and circuit behaviour.
- `[index]` [Monitoring overview](monitoring/README.md) — metrics, alerts, and
  sample dashboard configuration.
- `[runbook]` [Hardened reference deployment](hardened-reference-deployment.md)
  — production-oriented deployment baseline.
- `[reference]` [KMS/HSM deployment classification](kms-hsm-deployment-classification.md)
  — key-management deployment classes and evidence expectations.
- `[runbook]` [SDK release runbook](sdk-release.md) — release handling for SDK
  publication.

Use [Documentation index](../index.md) for the exhaustive generated inventory.

## Reading Rule of Thumb

1. Start here for operator workflow.
2. Jump to `docs/policies/` when you need the normative posture behind a runbook.
3. Jump to `docs/verification/` when a runbook mentions the verified-vs-compat boundary.
