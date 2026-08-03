# Server Environment Reference

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

This directory contains the split canonical environment-variable reference for the `aegaeon-server` binary.

## Scope

- process-global startup environment variables
- removed negative-inventory environment variables
- management-plane, OAuth/OIDC, federation, observability, test, and load settings

## Canonical Documents

- `[configuration]` [Core system settings](core-system.md)
- `[configuration]` [Management plane settings](management-plane.md)
- `[configuration]` [Network and runtime policy settings](network-and-policy.md)
- `[configuration]` [OAuth and OIDC runtime settings](oauth-oidc-runtime.md)
- `[configuration]` [Federation, observability, and test settings](federation-observability-and-test.md)

## Reading Rule of Thumb

1. Start with [Core system settings](core-system.md) for bootstrap and authority boundaries.
2. Use the topic file that owns the setting before changing runtime code or tests.
3. Add new issuer-scoped runtime policy as database-backed Environment configuration unless it is truly process-global.
