# Management Plane Specification Overview

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Product / Engineering

Audience: implementers, reviewers

This directory contains the split Management Plane Phase 1 specification. It keeps the original specification boundary while making the API, configuration, operations, and endpoint details easier to review independently.

## Scope

- Phase 1 management-plane product and API model
- control-plane configuration and rollback invariants
- RBAC, audit, key-management, and endpoint references
- follow-up decisions that remain outside the current implementation baseline

## Canonical Documents

- `[spec]` [Overview](overview.md)
- `[spec]` [API and authorization](api-auth.md)
- `[spec]` [Configuration model](configuration.md)
- `[spec]` [Database schema](database.md)
- `[spec]` [Operations](operations.md)
- `[reference]` [Endpoint reference](endpoint-reference.md)
- `[workplan]` [Follow-up items](follow-up.md)

## Reading Rule of Thumb

1. Start with [Overview](overview.md) for scope, hierarchy, and product split.
2. Use [API and authorization](api-auth.md) before changing routes, RBAC, or sessions.
3. Use [Configuration model](configuration.md) and [Operations](operations.md) for runtime-affecting state.
4. Use [Endpoint reference](endpoint-reference.md) when updating OpenAPI output or frontend integration.
