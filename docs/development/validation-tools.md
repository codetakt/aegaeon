# Validation Tools Documentation

Last updated: 2026-07-07

Status: current implementation baseline

Owner: Engineering

Audience: contributors, maintainers

## Overview
This document describes the validation and verification tools available for the Aegaeon project.

For the Nix flake entry points (`nix run .#…`, `nix build .#…`) and their mapping to GitHub Actions
jobs, see `docs/automation/ci-cd-guide.md`.

## Quick Validation

### Flake Check (Recommended)
```bash
nix flake check
```
Runs the CI-equivalent checks exposed by the flake (build, tests, verification hooks, etc.).

## Specific Validation Tools

### 1. RFC Compliance Testing
```bash
./scripts/validation/test_rfc_compliance.sh
```
- Tests all 15 RFC MUST requirements
- 38 individual test cases
- Required for release validation

### 2. RFC Update Monitoring
```bash
python3 scripts/validation/check_rfc_updates.py
```
- Monitors IETF for RFC updates
- Creates GitHub issues for changes
- Should run weekly in CI

### 3. Formal Verification (Kani)
```bash
nix run .#verify-kani
```
- Runs Kani bounded model checker
- Verifies Rust code properties
- Checks for undefined behavior

### 4. Constant-Time Analysis (Dudect)
```bash
nix build .#verify-dudect
```
- Statistical timing analysis
- Verifies constant-time operations
- Critical for cryptographic code

### 5. Load Testing
```bash
nix run .#perf-load
```
- Performance validation (spawns server + load harness)
- SLO compliance checking (fails if thresholds violated)
- Throughput and latency metrics dropped in `artifacts/perf/load-test/`
- `performance.yml` runs the public `smoke` lane on scheduled/manual heavy runs
- The OIDC-backed policy lane is available via `nix run .#perf-load -- --scenario policy-mixed`

### 6. Security Suite (deny / audit / vet)
```bash
nix run .#security-suite
```
- Runs `cargo deny check` and `cargo audit`
- Executes `cargo vet check` in soft-fail mode (warns but does not abort)
- Logs aggregated output to `artifacts/security/latest/summary/security.log`

## CI Integration

All validation tools are integrated into the CI pipeline:

```bash
# Run full CI suite locally
nix flake check
```

Individual CI checks:
```bash
nix develop -c cargo fmt --all -- --check      # Formatting
nix develop -c cargo clippy --workspace --all-features -- -D warnings  # Linting
nix develop -c cargo test --workspace          # Unit tests
nix run .#verify-kani                          # Formal verification (local runner)
nix build .#verify-dudect                      # Constant-time analysis
```

## SBOM Generation
For SBOM generation + scanning (Grype by default), use:

```bash
nix run .#security-sbom
```

The release pipeline also ships a SBOM-only helper script:

```bash
./scripts/release/generate_sbom.sh
```

## Release Validation

Before creating a release:
1. Run `nix flake check`
2. Ensure all checks pass
3. Generate SBOM + scan with `nix run .#security-sbom`
4. Create release with `./scripts/release/create_release.sh <version>`
