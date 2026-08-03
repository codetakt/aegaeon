# External-Boundary Naming Plan

Last updated: 2026-07-07

Status: active plan

Owner: Engineering

Audience: implementation contributors, maintainers

## Canonical Rule

External-boundary names are being normalized as follows:

- Environment variables, GitHub secrets, GitHub variables, workflow inputs, workflow env, Docker/Compose env:
  - legacy: `AEG_*`
  - target: `AEGAEON_*`
- Non-standard wire keys and metadata extensions:
  - legacy: `aeg_*`
  - target: `aegaeon_*`
- Artifact and workflow-facing names:
  - target prefix: `aegaeon-`
- Internal code symbols:
  - no product prefix

This is a **breaking cutover**. The migration does **not** introduce compatibility aliases.

## Source Of Truth

- Policy: `spec/external-boundary-naming.current.json`
- Static audit: `scripts/sdk/tools-src/check-external-boundary-naming.ts`
- Focused test: `tests/verified_core_wasm/external_boundary_naming_policy_test.ts`

## Execution Order

The rename must happen in this order:

1. `policy`
2. `server`
3. `sdk`
4. `admin-console`
5. `ci-mirrors`
6. `verification`

That order is also recorded in `spec/external-boundary-naming.current.json`.

## Migration Constraints

- Do not mix `AEG_*` and `AEGAEON_*` for the same external boundary once a phase is migrated.
- Do not mix `aeg_*` and `aegaeon_*` for the same non-standard wire surface once a phase is migrated.
- Do not add new `AEG_*` or `aeg_*` names while the migration is in progress.
- Keep internal code symbols prefix-free.

## Why This Exists

The current repository family now spans:

- backend/server
- SDK/client
- admin console
- private CI mirrors

That makes short prefixes (`AEG_*`, `aeg_*`) less desirable. The longer `AEGAEON_*` / `aegaeon_*`
forms are more explicit, easier to audit, and better aligned with a publication-grade release
posture.
