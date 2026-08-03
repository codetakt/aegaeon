# `ci/` — CI helpers and verification notes

This directory contains small helper scripts and documentation for reproducing
CI checks locally. Not every script here is executed by GitHub Actions; some are
local-only helpers or deprecated entry points preserved for reference.

## Source of truth

- **Workflow definitions**: `.github/workflows/*.yml`
- **Toolchain pins**: `flake.nix` + `flake.lock` (Nix), `rust-toolchain.toml` (Rust)
- **Extraction/regeneration**: `scripts/extraction/run_jose_lowstar.sh`

## Script index

| Path | Purpose | Used by GitHub Actions | Notes |
|------|---------|------------------------|-------|
| `ci/tamarin_docker.sh` | Prove selected Tamarin lemmas inside a container | ✅ | Invoked from `verification.yml`. |
| `ci/validate_slos.py` | Validate load-test JSON report against SLOs | ✅ | Used by `performance.yml` for the scheduled/manual load-test lanes (`smoke`, `policy-mixed`). |
| `ci/run-full-verification.sh` | Convenience wrapper for running multiple checks locally | ❌ | Requires tools installed; prefer Nix apps (`nix run .#verify-*`). |
| `ci/run-with-environment.sh` | Run a command under Nix if available | ❌ | Local helper. |
| `ci/detect-environment.sh` | Detect `nix` vs `local` | ❌ | Local helper. |
| `ci/tamarin.sh` | Legacy wrapper delegating to `proofs/tamarin/run_tamarin.sh` | ❌ | Deprecated. |
| `ci/*.sh` (others) | Historical/local helpers (Docker-based or ad-hoc checks) | ❌ | Not wired into current GitHub Actions. |

## Toolchain pins

The project is **Nix-first** for reproducibility. Exact toolchain revisions are
pinned in `flake.lock` and implemented via the Nix expressions under `nix/`
(`nix/everparse.nix`, `nix/karamel.nix`, `nix/hacl.nix`, `nix/kani/`).

For local use, prefer:

- `nix flake check`
- `nix build .#server`
- `nix run .#security-suite`
- `nix run .#verify-fstar`
- `nix run .#verify-tamarin`
- `nix run .#verify-kani`
- `nix run .#verify-dudect`
