# FFI Contract Register

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Verification

Audience: verification contributors, maintainers

This compatibility entrypoint preserves the historical `docs/verification/runbooks/ffi-contracts.md` path. The maintained FFI contract register now lives in `ffi-contracts/`.

Retained for: temporary compatibility with historical links, generated evidence, and release artifacts that still reference this moved path.

Review after: 2026-10-08

## Scope

- compatibility pointer for the FFI contract register
- navigation to Category B elimination, external boundaries, runtime checks, and validation details

## Canonical Documents

- `[index]` [FFI contract register details](ffi-contracts/README.md)
- `[runbook]` [Category B elimination](ffi-contracts/category-b-elimination.md)
- `[runbook]` [External boundaries and runtime checks](ffi-contracts/external-boundaries-and-runtime-checks.md)
- `[runbook]` [Build validation and links](ffi-contracts/build-validation-and-links.md)

## Reading Rule of Thumb

1. Use [ffi-contracts/README.md](ffi-contracts/README.md) as the maintained map.
2. Update the split files directly; do not add new contract details to this compatibility page.
