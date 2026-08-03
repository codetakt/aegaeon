# `artifacts/`

This directory is used to store outputs from verification, compliance checks, and
security/testing workflows.

By default, most files under `artifacts/` are **ignored** by Git (see
`.gitignore`). Only a small, curated subset is tracked to preserve provenance
and aid debugging across environments.

## What may be tracked

- Small, non-secret reports that are useful for auditing and regressions
  (examples in this repo include compliance validation logs, Kani reports, and
  selected KaRaMeL extraction outputs).
- Deterministic outputs where regeneration is well-defined and documented.

## What must NOT be tracked

- Anything containing secrets or credentials (tokens, Authorization headers,
  private keys, client secrets, etc.).
- Large or environment-specific dumps (raw conformance exports, full CI logs,
  cache directories, build outputs).

## Regeneration

Preferred entry points are Nix flake targets and scripts in `scripts/` (e.g.
`nix flake check`, `nix run .#security-suite`). Keep the tracked subset small
and reproducible.
