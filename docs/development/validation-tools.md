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

Run it in the pinned `nix develop .#ci` environment. It copies the tracked worktree
files, including local edits, into a temporary directory and generates the server's
CycloneDX inventory there. Untracked files and existing generated Cargo SBOMs are
excluded. Generation must finish successfully without changing `Cargo.lock`; the
result must identify the server package and version from that snapshot.

`OUTPUT_DIR` defaults to `artifacts/sbom`. Each successful run retains its original
SBOM, normalized SBOM, input digests, tool version, command, and provenance in a new
directory. The default `artifacts/sbom/aegaeon-sbom-latest.json` pointer selects
the last successful run. On failure,
the helper exits nonzero and leaves that pointer unchanged; callers must check the
exit status. Failure logs are retained separately. `SBOM_TIMEOUT_SECONDS` defaults
to 60 and terminates the generator and its descendants on expiry.

Callers can set `SBOM_RESULT_FILE` to receive the completed run's exact artifact
path and SHA-256 in JSON. The security scanner uses that record and checks its
digest, so another invocation updating the shared pointer cannot select its SBOM.

`ENABLE_COSIGN_SIGNING=1` requires cosign, successful signing, and nonempty signature
and certificate outputs before publishing the new pointer. The helper records
their digests; certificate identity, issuer, and signature verification remain a
separate release acceptance step. With signing disabled, the output is unsigned.

This is a Cargo dependency inventory with default features for the generator host
target. It is not an inventory of a Nix runtime closure or evidence of a particular
release binary, protocol conformance, or an activated assurance claim. Full
CycloneDX schema validation and artifact-bound acceptance remain separate checks.

## Release Validation

Before creating a release:
1. Run `nix flake check`
2. Ensure all checks pass
3. Generate SBOM + scan with `nix run .#security-sbom`
4. Create release with `./scripts/release/create_release.sh <version>`
