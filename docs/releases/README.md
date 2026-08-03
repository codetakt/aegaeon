# Releases Overview

Last updated: 2026-07-07

Status: current implementation baseline

Owner: Release Engineering

Audience: release managers, maintainers

This directory contains operator-facing release runbooks and curated release
evidence summaries. Keep release procedures in `runbooks/` and point-in-time
evidence in `evidence/`.

## Scope

- release procedures and validation summaries
- pointers to machine-generated release evidence under `artifacts/`
- human-readable indices for conformance, deployment validation, and release readiness

## Canonical Documents

- `[index]` [Release runbooks](runbooks/README.md)
- `[index]` [Release evidence](evidence/README.md)
- `[index]` [KMS/HSM classification manifests](evidence/kms-hsm-classifications/README.md)

## Evidence Locations

- `artifacts/conformance/` — conformance-suite exports
- `artifacts/sbom/` — SBOM and vulnerability scans
- `artifacts/release/` — release smoke / build transcripts
- `artifacts/releases/<release-id>/` — enterprise-readiness release evidence bundle

## Reading Rule of Thumb

1. Use `runbooks/` when executing release procedures.
2. Use `evidence/` for source-managed summaries and bundle manifests.
3. Treat `artifacts/` as the authoritative home for current machine-generated outputs.
4. Use `docs/program-management/` for planning and `docs/verification/` for formal-claim scope.
