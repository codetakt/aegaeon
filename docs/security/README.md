# Security Overview

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Security

Audience: security reviewers, maintainers

This directory contains security-facing inventories, release reviews, and key-management notes.

## Scope

- system-level trust-boundary and TCB inventories
- point-in-time security review snapshots
- operational key-management notes for released artefacts

## Canonical Documents

- `[reference]` [TCB inventory](tcb-inventory.md)
- `[snapshot]` [Security review](security-review/README.md)
- `[reference]` [Key inventory](key-inventory.md)
- `[policy]` [Unsafe code policy](../policies/unsafe-code-policy.md)

## Reading Rule of Thumb

1. Start with `docs/verification/claims/formal-claim-overview.md` if the question is about the formal claim.
2. Read `tcb-inventory.md` for broader system trust boundaries and `security-review/README.md` for release-readiness assessment.
3. Use fresh scan output and release evidence before citing point-in-time security status.
