# Configuration Overview

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

This directory holds configuration documentation that should remain valid over time.

## Scope

- environment variable reference for `aegaeon-server`
- deployment-facing configuration notes (TLS termination, reverse proxies, etc.)
- stable operator guidance that is not tied to a single investigation or sprint

## Canonical Documents

- `[reference]` [Environment variables](environment/README.md) — canonical split server environment-variable reference
- `[runbook]` [Networking](networking.md) — reverse-proxy trust boundary and forwarded-header policy

## Reading Rule of Thumb

1. Start here when you need deployment or runtime configuration details.
2. Jump to `docs/policies/` for normative policy decisions.
3. If you find long-lived configuration guidance elsewhere, promote it here and update references.
