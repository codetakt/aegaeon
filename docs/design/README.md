# Design Overview

Last updated: 2026-07-07

Status: active plan

Owner: Engineering

Audience: implementation contributors, maintainers

This directory contains implementation-facing designs for runtime, Verified
Core, and platform-boundary work. These documents guide implementation work, but
they do not redefine product/API specifications or the formal verification claim.

## Scope

- implementation architecture and adapter designs
- Verified Core follow-up implementation plans
- platform-boundary designs that support operational runbooks

## Canonical Documents

- `[design]` [Runtime adapter design](runtime-adapter-design.md)
- `[workplan]` [Verified Core API export follow-up plan](verified-core-api-plan.md)
- `[workplan]` [Verified Core claims runtime follow-up plan](verified-core-claims-runtime-plan.md)
- `[design]` [OIDC KMS/HSM signing design](oidc-kms-signing-design.md)
- `[workplan]` [External-boundary naming plan](external-boundary-naming-plan.md)

## Related Planning

- [SDK initiative](../program-management/initiatives/sdk/README.md)

## Reading Rule of Thumb

1. Start with `../specs/README.md` when you need normative product or API behaviour.
2. Use this directory when implementing runtime, Verified Core, or platform-boundary designs.
3. Use `../program-management/initiatives/sdk/README.md` for SDK/client planning.
4. Use `../verification/README.md` for claim scope, assumptions, and proof status.
