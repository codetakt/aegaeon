# Security Analysis Execution

Last updated: 2026-09-08

Status: current implementation baseline

Owner: CI / Automation

Audience: contributors, security reviewers

## Cargo Geiger

`nix run .#security-suite -- --stage geiger` requires successful analysis of every
Cargo workspace member. A failed command, missing or malformed JSON, missing
workspace metrics, or an unscanned workspace source file fails the stage. FFI is
included in this completeness check; this does not impose a zero-unsafe policy.
The result is an unsafe-code inventory, not a security proof or assurance claim.

The pinned cargo-geiger 0.13 requires a concrete package manifest. The runner
therefore invokes it once per workspace member, with all features, its
`--all-targets` option, and test-code counting enabled. Each JSON report supplies
both the workspace completeness decision and the dependency inventory. Dependency
metrics gaps remain visible in the report. They do not excuse a compiler failure
or incomplete workspace analysis. Geiger's target selection and static metrics
do not establish that every target or test was compiled or executed.

The previous runner executed separate gate and dependency scans and passed
`--no-deps`, which this pinned version silently ignores. It also captured the
status of shell negation rather than the failed command. The current runner
preserves command failure and makes scan completeness blocking in Security Suite.

The report validator checks package name, version, and path against Cargo
metadata. It recognizes the exact malformed Path spelling emitted by version
0.13 with modern Cargo package IDs, derived from that same metadata; matching
only a package name is insufficient. JSON success alone is insufficient because
this version reports zero warnings in JSON mode even when metrics are missing.

Raw JSON, diagnostics, metadata, and validated `.gate.json` views are retained
under `artifacts/security/latest/geiger/run.*`. The aggregate `gate.json` is
removed before each attempt and written only when every selected scan succeeds.
Its `complete` status describes scan completeness only. Use
`--manifest-path crates/NAME/Cargo.toml` for a single-member diagnostic run.

The runner retains `run.*` directories without automatic pruning. After local
triage, the operator may remove completed runs that are no longer needed. Preserve
the run referenced by `gate.json`, evidence for unresolved findings, and any
release evidence until it has been archived. Perform cleanup while no scan is
using that artifact directory.

Hosted Security jobs upload the reports even on failure. Their upload steps use
the repository or organization's artifact retention settings without a workflow
override. Archive evidence needed for a release or an ongoing investigation
before the hosted artifacts expire; the runner's local filesystem is temporary.

Cargo uses the caller's normal configuration, including Nix vendoring. The
runner does not replace `CARGO_HOME` or force a crates.io Git-index download.
An optional `--offline` argument disables network access. Geiger itself cleans
its compilation inputs, so a disposable target directory protects the caller's
normal build outputs; sharing a normal Cargo target is not a safe optimization.

## Regression checks

```bash
nix develop .#integrity --command python3 -m unittest discover \
  -s tests/ci -p test_geiger.py
```

The tests exercise command failures, stale success removal, missing and malformed
reports, package identity, incomplete source metrics, and single-scan execution.

## Cacheable Cargo lint checks

The Core workflow uses Nix build outputs for supplemental Clippy and the server
inventory gate. `nix/cargo-lint-checks.nix` defines the derivations shared by the
package entry points and `nix flake check`:

| Package | Flake check | Profile |
| --- | --- | --- |
| `lint-supplemental-clippy` | `supplemental-clippy` | dev |
| `lint-server-clippy-inventory-dev` | `server-clippy-inventory-dev` | dev |
| `lint-server-clippy-inventory` | `server-clippy-inventory` | release |

The dev checks retain the profiles and target selection of the previous direct
Cargo commands. The existing release-profile inventory check is also retained.
Both inventory derivations invoke the complete shell gate, including the exact
`unwrap_or_default` call-site inventory comparison. A Clippy pass alone does not
satisfy that gate.

The dev checks share `cargo-lint-artifacts`, which builds dependency metadata in
the same dev profile. Release checks continue using the existing release
artifacts. Source, Cargo.lock, lint scripts, inventory policy, native libraries,
and the pinned toolchain remain derivation inputs. Test and verification source
fixtures are retained. No cache key based only on branch or commit names is used.

```bash
nix build .#lint-supplemental-clippy .#lint-server-clippy-inventory-dev \
  .#lint-server-clippy-inventory --no-link -L
```

Because the package and check aliases resolve to identical derivations, invoking
the named workflow steps after `nix flake check` reuses the realized outputs.
FlakeHub can also reuse these outputs on another runner when all inputs match.
An uncached run must also build the dev dependency metadata. Measure initial
builds and cache reuse separately; a local cached repeat does not establish a
hosted CI speedup.
This does not cache network-dependent advisory freshness or replace a security
evaluation of a release.
