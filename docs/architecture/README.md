# Architecture Overview

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Architecture

Audience: architects, maintainers

This directory contains architecture documents describing how Aegaeon is intended
to be operated as a product (SaaS / Enterprise) without weakening the verified
OAuth/OIDC core.

## Scope

- product-level architecture and boundaries
- control-plane / data-plane separation
- architecture references that complement the normative product specs

## Canonical Documents

- `[index]` [Specifications overview](../specs/README.md)
- `[architecture]` [Management plane architecture](management-plane.md)
- `[spec]` [Management plane Phase 1 specification](../specs/management-plane/README.md)

## Reading Rule of Thumb

1. Start here for architectural context and boundary framing.
2. Jump to `docs/specs/` for normative API / data-model definitions.
3. Jump to `docs/verification/` when architecture text intersects the formal claim boundary.
