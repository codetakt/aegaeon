# `ci/` — CI helpers and verification notes

This directory contains small helper scripts and documentation for reproducing
CI checks locally. Not every script here is executed by GitHub Actions; some are
local-only helpers or deprecated entry points preserved for reference.

## Source of truth

- **Workflow definitions**: `.github/workflows/*.yml`
- **Toolchain pins**: `flake.nix` + `flake.lock` (Nix), `rust-toolchain.toml` (Rust)
- **Extraction/regeneration**: `scripts/extraction/run_jose_lowstar.sh`
- **Functional versus external qualification**:
  [CI execution boundary](../docs/development/ci-execution-boundary.md)
- **Optimization status and remaining work**:
  [CI execution efficiency](../docs/automation/ci-optimization.md)

## Script index

| Path | Purpose | Used by GitHub Actions | Notes |
|------|---------|------------------------|-------|
| `scripts/verify/verify_tamarin_ci.sh` | Build the pinned Tamarin check and validate its retained admission evidence | ✅ | Current `verification.yml` entry; this wrapper lives outside `ci/`. |
| `ci/tamarin_docker.sh` | Historical container-based Tamarin helper | ❌ | Retained for local callers; it is not the current workflow entry. |
| `ci/validate_load_smoke.py` | Validate functional load accounting, errors and report structure | ✅ | Current `performance.yml` validator for executed load scenarios; unavailable scenario prerequisites remain pending. |
| `ci/validate_slos.py` | Validate load-test JSON against performance thresholds | Lint/type checks and helper fixtures | Ordinary Hosted CI does not use this validator for performance acceptance; external qualification remains separate. |
| `ci/run-full-verification.sh` | Historical local multi-tool wrapper | ❌ | May skip unavailable tools and accept an existing Tamarin log. Its summary is not a replacement for current Required checks or fresh qualification. |
| `ci/run-with-environment.sh` | Run a command under Nix if available | ❌ | Local helper. |
| `ci/detect-environment.sh` | Detect `nix` vs `local` | ❌ | Local helper. |
| `ci/tamarin.sh` | Legacy wrapper delegating to `proofs/tamarin/run_tamarin.sh` | ❌ | Deprecated. |
| `ci/karamel.sh` | Extract JOSE and archive the output | ❌ | Requires the pinned Nix verification shell; writes `artifacts/karamel.log` and `artifacts/karamel/jose-lowstar.tar.gz`. |
| `ci/*.sh` (others) | Historical/local helpers (Docker-based or ad-hoc checks) | No direct current workflow entry | Local, runbook and generated callers must be checked before deprecating or removing a helper. |

This index describes current checked-in workflow entries, not every possible
external caller. It does not authorize helper deletion. Historical proof logs,
tool-availability skips and a successful wrapper exit cannot replace the current
producer's complete admission evidence.

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
- `nix build .#verify-dudect` (build and non-timing callback self-tests)

The Dudect build does not acquire new timing evidence. Ordinary Hosted load
checks likewise establish functionality, not latency or throughput acceptance.
Physical measurement, provider qualification and release admission retain the
separate responsibilities in the execution-boundary document above.
