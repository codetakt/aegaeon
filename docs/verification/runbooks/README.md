# Verification Runbooks Overview

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Verification

Audience: verification contributors, maintainers

This directory contains local reproduction steps, extraction status, runtime
linkage, and implementation-facing verification runbooks. For CI workflow
ownership, see `../../automation/ci-cd-guide.md`.

## Scope

- verification command entrypoints
- extraction and generated-artefact status
- FFI, runtime linkage, and HACL*/EverCrypt integration notes
- sanitizer and operations guidance

## Canonical Documents

- `[snapshot]` [Extraction status](extraction-status.md)
- `[reference]` [Runtime linkage](runtime-linkage.md)
- `[runbook]` [Verification operations guide](verification-ops.md)
- `[index]` [FFI contracts](ffi-contracts/README.md)
- `[runbook]` [HACL* integration](hacl-integration.md)
- `[runbook]` [Sanitizers guide](sanitizers.md)

## How to Run

```bash
# Main merge guard (matches CI)
nix flake check --print-build-logs

# Tool-specific verification gates
nix build .#verify-fstar -L
nix build .#verify-tamarin -L
nix build .#verify-dudect -L
nix build .#verify-jose -L
nix build .#verify-kani -L
nix run .#verify-lowstar
```

## EverParse / LowParse Cache Priming

When EverParse / LowParse sources live in the Nix store, `.checked` files can
look stale. Use the local tree mode to rebuild LowParse checks and avoid the
stale-cache warning:

```bash
AEG_USE_EVERPARSE_LOCAL=1 AEG_PRIME_LOWPARSE_CACHE=1 AEG_PRIME_LOWPARSE_ADMIT=0 nix develop .#verification --command scripts/extraction/run_jose_lowstar.sh
```

- `AEG_USE_EVERPARSE_LOCAL=1` builds a temporary EverParse tree under
  `/tmp/aegaeon-everparse` unless `AEG_EVERPARSE_LOCAL_ROOT` is set.
- `AEG_PRIME_LOWPARSE_CACHE=1` rebuilds LowParse `.checked` files into
  `fstar/.cache`.
- `AEG_PRIME_LOWPARSE_ADMIT=0` forces full LowParse verification.
- `AEG_UPSTREAM_WARNINGS_LOG_DIR=/path` captures upstream warning logs.

## Known Limitations / Monitoring

- Kani: HashMap-heavy harnesses can trigger ICEs or state-space blowups; keep
  them as reproducers and use bounded array models for CI gating.
- F* / KaRaMeL extraction: `EverCrypt.Helpers` include resolution can drift by
  environment; see `../fstar/troubleshooting.md#evercrypthelpers-name-resolution-monitoring`.
- F*: CI runs `nix build .#verify-fstar` in short-lived batches to avoid known
  single-process instability.
- Rust: CI exports `CARGO_INCREMENTAL=0` for toolchain-specific incremental
  compilation issues.

## Generated Artefacts Policy

The authoritative policy lives in `../../automation/ci-cd-guide.md`. In short:

- source-managed generated trees are reproducible inputs
- `nix run .#verify-lowstar` is the extraction drift gate
- `nix build .#verify-jose -L` compile-checks the opt-in
  `ffi --features verified-claim,idtoken_runtime` combination
- OIDC Low* runtime artefacts remain opt-in; see
  `../oidc/lowstar-runtime-policy.md`

## Reading Rule of Thumb

1. Start here when reproducing verification checks locally.
2. Use `../claims/` for public claim wording and evidence boundaries.
3. Keep raw command output under `artifacts/`; keep only stable runbook guidance here.
