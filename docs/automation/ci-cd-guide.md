# Automation & CI/CD (GitHub Actions + Nix flake)

Last updated: 2026-07-07

Status: current implementation baseline

Owner: CI / Automation

Audience: CI maintainers, contributors

This document is the single, maintained reference for:

- **GitHub Actions** orchestration under `.github/workflows/`
- **Local reproduction** via `flake.nix` (apps, packages, devShells)

## Principles

1) **Flake-first**: checks that matter must be reproducible via `nix flake check` and/or `nix run .#…`.
2) **Fail-close**: verification tooling should fail on drift (e.g., generated artefacts out of sync).
3) **Evidence-driven**: conformance/verification should emit machine-readable artefacts (stored under `artifacts/`) and keep
   human-readable indices under `docs/releases/` and `docs/verification/`.

## Shared CI vocabulary

Across `aegaeon`, `aegaeon-sdk`, and `aegaeon-admin-console`, use the following terms consistently:

- **Setup Nix CI** — the repo-local composite GitHub Action under `/.github/actions/setup-nix-ci/`; workflows should use this action for Nix bootstrap instead of inlining install/cache steps.
- **Hook baseline** — the explicit `pre-commit run --all-files` gate mirrored locally before pushing.
- **Workflow inventory audit** — the source-managed drift check for workflow filenames, top-level display names, job names, and artifact names.
- **Required checks** — the hosted status checks enforced by branch protection; each repo keeps its canonical names in its own CI plan or policy document.

### Toolchain stability constraints (2026-01-15)

- **Rust**: All CI jobs run with `CARGO_INCREMENTAL=0`. When caching build artefacts, set `CARGO_TARGET_DIR=target/<toolchain-id>` (e.g. `target/nightly-2025-11-05`) to avoid reusing incremental state across compiler upgrades. Local reproductions should mirror these env vars before filing toolchain issues.
- **F\***: `nix build .#verify-fstar` is executed as a *chunked* job. The driver splits the F* module list into batches so each `fstar.exe` invocation stays short-lived (mitigating the segfault observed during long runs). Use `--detail_errors` only when re-running the failing batch; the steady-state command keeps logging minimal.

## Environments (Nix vs Docker)

- **Default (recommended)**: use the Nix flake (`nix develop`, `nix flake check`, `nix run .#…`).
- **Docker is a supported tool**, mainly for stacks and tools that are naturally containerised:
  - OIDF conformance runner (`scripts/oidf_conformance/`)
  - selected verification jobs in CI (e.g., Tamarin container)
- **Avoid “manual setup”**: if you cannot use Nix, prefer the project’s Docker entry points over
  ad-hoc host installs to reduce drift.

## Quick local loop (recommended)

```bash
# Hook baseline (explicit CI pre-commit gate)
PRE_COMMIT_HOME=/tmp/pre-commit-aegaeon nix develop . --command bash -lc 'pre-commit run --all-files'

# Workflow inventory audit (explicit CI drift gate)
nix develop .#default --command node tests/verified_core_wasm/workflow_inventory_policy_test.mjs

# Documentation structure audit
python3 scripts/validation/check_docs_structure.py

# Main merge guard (matches the merge-guard job)
nix flake check --print-build-logs

# OpenAPI drift gate
cargo xtask openapi --check

# Full gate (merge guard + security suite)
nix run .#verify-full

# Release build artefact
nix build .#server --print-build-logs --out-link result-server

# Security suite (deny/audit/vet + fuzz/sanitizers/SBOM/geiger/udeps)
nix run .#security-suite

# Longer fuzz runs (optional; writes under artifacts/security/)
nix run .#security-suite -- --fuzz-long

# Performance smoke
nix run .#perf-load
```

## Nix entry points

### Dev shells (`nix develop`)

- `nix develop .#default`: day-to-day dev (Rust toolchain + common tools)
- `nix develop .#verification`: F*/EverParse/KaRaMeL/Tamarin tooling
- `nix develop .#asan`: AddressSanitizer toolchain + sanitizer scripts (see `docs/verification/runbooks/sanitizers.md`)

### Apps (`nix run .#…`)

| App | Command | Purpose |
| --- | --- | --- |
| `dev-server` | `nix run .#dev-server` | Run `aegaeon-server` |
| `dev-watch` | `nix run .#dev-watch` | `cargo watch -x run` loop |
| `dev-services-up` | `nix run .#dev-services-up` | Bring up docker-compose deps in `tests/docker/docker-compose.yml` |
| `dev-services-down` | `nix run .#dev-services-down` | Tear down docker-compose deps |
| `security-suite` | `nix run .#security-suite` | Security suite aggregator (`scripts/security/run_security_suite.sh`) |
| `security-sbom` | `nix run .#security-sbom` | SBOM + scanners (`scripts/security/run_sbom_scan.sh`) |
| `perf-bench` | `nix run .#perf-bench` | Benchmarks (`cargo bench`) |
| `perf-load` | `nix run .#perf-load` | Load test runner (`scripts/perf/run_load_tests.sh`) |
| `perf-coverage` | `nix run .#perf-coverage` | Coverage HTML (`cargo llvm-cov --html`) |
| `verify-lowstar` | `nix run .#verify-lowstar` | Regenerate/verify Low* extraction artefacts |
| `verify-kani` | `nix run .#verify-kani` | Run Kani suite (`scripts/kani/run_kani.sh`) |
| `verify-full` | `nix run .#verify-full` | Run merge guard + security suite |
| `oidc-rp-flow` | `nix run .#oidc-rp-flow` | OIDC RP flow harness |
| `docker-build` | `nix run .#docker-build` | `docker build` wrapper |
| `docker-run` | `nix run .#docker-run` | `docker run` wrapper |

Notes:

- `flake.nix` also exposes `everparse` and `karamel` as `nix run` apps for debugging toolchain issues.
- Prefer the `nix` entry points; the repository no longer ships a `justfile`.

### Verification packages (`nix build .#…`)

These are “build-time” verification commands that produce a `result/` tree with logs:

- `nix build .#verify-fstar -L`
- `nix build .#verify-tamarin -L`
- `nix build .#verify-dudect -L`
- `nix build .#verify-jose -L`
- `nix build .#verify-kani -L`

`verify-jose` runs the Python JOSE conformance script plus RFC 7520 vectors and
TLV parity for the default, `verified-claim`, `ffi_jose_header_tlv`, and
`ffi_jose_header_tlv,verified-claim` JOSE header parser profiles. It also
compile-checks the opt-in `ffi --features verified-claim,idtoken_runtime`
combination so the source-managed OIDC Low* runtime artefacts stay buildable.

## GitHub Actions workflows (summary)

All workflows live under `.github/workflows/`. The source of truth for their file names and top-level display names is `spec/workflow-inventory.current.json`; audit it with `nix develop .#default --command node tests/verified_core_wasm/workflow_inventory_policy_test.mjs`.

| Workflow | File | When it runs | What it does | Local equivalent |
| --- | --- | --- | --- | --- |
| Core CI | `ci.yml` | push/PR `main`, manual | `nix flake check`, OpenAPI drift check, build server, extra clippy, generated-artefact drift check, dependency policy gate (`cargo deny`) | `cargo xtask openapi --check` + `nix flake check` + `nix build .#server` |
| Formal verification | `verification.yml` | push `main`, PR `main` (non-draft), manual | F\* (container), EverParse artefact drift check, Low\* parity, Tamarin, Kani, JOSE vectors, dudect, merge guard | `nix flake check` + `nix build .#verify-fstar` + `nix build .#verify-tamarin` + `nix run .#verify-kani` |
| Security suite | `security.yml` | push/PR `main`, weekly | `nix run .#security-suite` (+ drift check) | `nix run .#security-suite` |
| Performance | `performance.yml` | push `main`, daily, manual (PR: note only) | observability smoke + coverage on `push`; scheduled/manual runs also execute `perf-load` public smoke and OIDC-backed `policy-mixed` smoke | `nix run .#perf-coverage` + `nix run .#perf-load` + `nix run .#perf-load -- --scenario policy-mixed` |
| Compliance | `compliance.yml` | push `main`, PR (RFC MUST only), daily, manual | RFC MUST checks, JOSE vectors, `cargo audit`, SBOM generation, container scan; OIDF/OAuth conformance is local-only | `./scripts/validation/test_rfc_compliance.sh` + `nix run .#security-sbom` |
| F* compatibility stub | `verify-fstar-ci.yml` | push/PR `main`, manual | Preserves the historical `F* Verification / verify-fstar` check name; the real F* execution lives in `verification.yml` | None (compatibility-only) |
| Docker image | `docker-build.yml` | push, tags, PR (Docker-related paths only), manual | Builds and (on non-PR) pushes `ghcr.io/.../aegaeon-server` | `nix run .#docker-build` (local build) |
| Release | `release.yml` | tags, manual | Packages binaries + SBOM + RFC smoke and publishes GitHub release | Prefer `nix flake check` + `nix build .#server` + `nix run .#security-sbom` before tagging |
| Dependency watch | `check-dependency-updates.yml` | weekly, manual | Checks for important dependency updates and files issues | `cargo search …` + `gh issue create` |
| OIDF suite (bootstrap) | `oidf-conformance.yml` | manual | Starts suite + exports `/api/plan/available`; full run is gated off | Use `scripts/oidf_conformance/` for real HTTPS runs |

## Generated artefacts policy

### OpenAPI + generated code drift

CI also treats OpenAPI artefact drift as a hard failure:

- OpenAPI JSON: `generated/openapi/`

If you touch any Utoipa input or management/ops API schema:

```bash
cargo xtask openapi
git diff -- generated/openapi
```

### EverParse + Low* drift

CI treats generated artefact drift as a hard failure:

- EverParse: `generated/everparse/`
- Low* extraction: `generated/lowstar/`

The source-managed OIDC Low* subtree currently lives under
`generated/lowstar/oidc/id_token/`. It remains opt-in at runtime, but it is
still part of the drift-checked generated artefact set.

If you touch any F*/EverParse inputs:

```bash
scripts/extraction/run_everparse_batch.sh
scripts/extraction/run_jose_lowstar.sh
git diff -- generated/everparse generated/lowstar
```

Commit regenerated output when it changes.

## Fuzzing notes (security suite)

- Default smoke settings are intentionally short (≈30s/target). Outputs land under `artifacts/security/latest/fuzz/` and roll up history under `artifacts/security/history/`.
- For longer local runs, use `--fuzz-long` (5m/target, 600s total by default):
  - `nix run .#security-suite -- --fuzz-long`
- Override fuzz parameters (local runs):
  - Targets: `FUZZ_TARGETS="fuzz_bearer_token fuzz_dpop_proof ..."`
  - Smoke budgets: `FUZZ_TIMEOUT=1m FUZZ_MAX_TOTAL=30`
  - Long-run budgets: `FUZZ_TIMEOUT_OVERRIDE=10m FUZZ_MAX_TOTAL_OVERRIDE=600 FUZZ_TOTAL_TIMEOUT_OVERRIDE=1200s`

## OIDF conformance (local-only for now)

Upstream OP plans require **HTTPS** endpoints and validate URL strings. For local evidence and exports:

- Entry point: `scripts/oidf_conformance/README.md`
- Evidence summary: `docs/releases/evidence/beta-conformance.md`

Baseline plan runner (auto-exports machine-readable artefacts under `artifacts/conformance/`):

```bash
./scripts/oidf_conformance/run_oidcc_basic_plan.sh
```

## Troubleshooting

- **Reproduce merge guard failures**: start with `nix flake check --print-build-logs`.
- **Kani**: start with `docs/verification/kani/README.md` (runbook) and `nix/kani/README.md` (packaging checklist).
- **Sanitizers**: see `docs/verification/runbooks/sanitizers.md` (`nix develop .#asan`).
- **OIDF HTTPS**: see `scripts/oidf_conformance/README.md` (nginx TLS termination).

### GitHub Actions local runs (`act`)

The dev shell includes `act`. Typical usage:

```bash
./scripts/ci/run_act.sh -W .github/workflows/ci.yml
./scripts/ci/run_act.sh -W .github/workflows/security.yml
```

Notes:

- Jobs that rely on `nix` must run in an `act` image that has Nix available (or you must install it).
- Artifact uploads and some GitHub-only integrations may behave differently under `act`.

### Debug logging

To increase verbosity in GitHub Actions, set repository/organization secrets or workflow env:

- `ACTIONS_STEP_DEBUG=true`
- `ACTIONS_RUNNER_DEBUG=true`

## References

- Branch protection policy: `docs/policies/branch-protection.md`
- Verification index: `docs/verification/README.md`
- Compliance matrix: `spec/compliance-matrix.yaml`
- Validation tooling: `docs/development/validation-tools.md`
