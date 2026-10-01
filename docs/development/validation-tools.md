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
path and SHA-256 in JSON. The record is written before any shared pointer is
updated. If record creation or replacement fails, existing pointers stay
unchanged and the completed inventory remains available in its run directory.
The result path must not be one of these shared symlinks. The security scanner uses
that record and checks its digest, so another invocation updating the shared
pointer cannot select its SBOM.

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
4. Complete the applicable release acceptance and approve the release notes and signing identity.
5. Create and verify the local signed tag with explicit inputs:

```bash
./scripts/release/create_release.sh v1.2.3-rc.1 \
  --commit <full-commit-sha> \
  --notes-file <release-notes-file> \
  --signing-key <full-openpgp-fingerprint>
```

The helper requires Python 3.11 or later, Git and GnuPG. It requires a clean checkout
(including nonignored untracked files), HEAD equal to the full commit ID, an unused
v-prefixed SemVer tag and matching committed `package.version` values for the existing
release cohort: server, client, jose, observability and loadtest. It parses TOML;
a matching dependency version does not satisfy the package check.

Notes must be nonempty UTF-8 without NUL or an embedded PGP signature block. The
helper signs the notes, source commit, source tree and SHA-256 of the original note
bytes. It appends a newline when needed without changing that digest. The supplied
full fingerprint selects the signing key; append `!` to require that exact signing
key rather than a signing subkey of the specified primary key. Use a reviewed key
identity: a cryptographically valid signature alone does not establish release authority.

Successful output is a JSON receipt containing the tag object, commit, tree, notes
digest and verified signing fingerprint. Signature verification uses the immutable
tag object and checks its target and message. The helper prepares an unreachable
signed object with GnuPG and `git mktag`, verifies it, then creates the tag ref with
`git update-ref --no-deref` only if absent. Symbolic refs cannot redirect creation
into another namespace. Failure leaves no new tag ref, and concurrent tag
creation is rejected without replacement. Unreferenced objects may remain in the
local object database for Git's normal garbage collection. Signing follows Git's
`gpg.openpgp.program` or `gpg.program` setting, otherwise `gpg`.

This helper creates a local tag. Artifact production, SBOM/closure correspondence,
CI and assurance acceptance, authorized publication and post-publication verification
remain separate release steps. There is no default version, unsigned fallback,
automatic push or generated compliance claim.

The `release-tags` flake check exercises real signatures with disposable keys and
repositories, plus invalid input and failure controls:

```bash
nix build .#checks.x86_64-linux.release-tags
```
