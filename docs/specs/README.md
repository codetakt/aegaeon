# Specifications Overview

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Product / Engineering

Audience: implementers, reviewers

This directory contains durable product, API, and integration specifications.
Use this index to find the canonical document for each concern and to avoid
reading overlapping design notes as if they were normative product specs.

## Scope

- durable product and platform specifications
- API / ABI / data-model references
- runtime artefact references that describe shipped or source-managed interfaces

Important boundary: formal-claim scope is defined in `docs/verification/`, not in
this directory. Specs here may describe runtime capability or future design work
without expanding the current verified claim. For released product wording and
what can safely be claimed today, use `../product-positioning.md`. For
implementation-facing designs, use `../design/README.md`. For SDK/client
handoff planning, use `../program-management/initiatives/sdk/README.md`.

## Canonical Documents

- `[index]` [Management plane](management-plane/README.md) - Phase 1 product,
  API, configuration, database, operations, and endpoint details.
- `[spec]` Primary Authority:
  [user management](primary-authority-user-management.md) and
  [local credential plane](primary-authority-local-credential-plane.md).
- `[spec]` Federation and RP runtime:
  [OpenID Federation](openid-federation-spec.md),
  [OIDC RP brokering](oidc-rp-brokering-spec.md), and
  [federation logout recovery](federation-logout-recovery-spec.md).
- `[reference]` Verified Core artefacts:
  [WASM extraction](verified-core-wasm.md) and [ABI](verified-core-abi.md).
- `[index]` Related implementation context:
  [Design overview](../design/README.md) and
  [SDK initiative](../program-management/initiatives/sdk/README.md).

## Reading Rule of Thumb

1. Start with a canonical spec above.
2. Read design references only when implementing or changing that area.
3. For proof scope, crypto posture, or verification status, jump back to `docs/verification/README.md`.
