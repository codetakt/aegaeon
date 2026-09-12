# Kani Evidence Admission

Last updated: 2026-09-09

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, maintainers

## Meaning and selection

Kani evidence establishes properties of the selected program within its actual
input domain and configuration. A fixed fixture, a substituted implementation
(`cfg(kani)` model) and a production function must be distinguished. A passing
harness does not close a more general requirement, and the fact that a harness is
required in CI is a statement about execution, not about the grade of any claim.
The [assurance claim definition](../claims/assurance-case/claim-definition.md)
governs these distinctions; compliance-matrix status is an evidence inventory, not
release assurance or proof of implementation refinement.

The selection is [`spec/kani-evidence.json`](../../../spec/kani-evidence.json)
(version 2, schema [`spec/kani-evidence.schema.json`](../../../spec/kani-evidence.schema.json),
contract `kani-0.66.0-text-v1`). It lists every `#[kani::proof]` site in the
repository in exactly one of three classes:

| Class | Meaning | Today |
| --- | --- | --- |
| `required` / `evidence` | admitted finite slices that compliance-matrix rows may cite; a rejection fails the gate | 6 (`ffi-evidence`, package `ffi`, feature `kani`, x86_64) |
| `required` / `regression` | blocking executions with no matrix evidence value: toolchain smoke/ICE regressions and model regressions | 18 (`kani-harness-regressions` 9, `server-regressions` 9) |
| `diagnostic` | executed and recorded, never counted and never a gate | 2 (`jwks-rotation-models`, provisional) |
| `excluded` | every remaining source site with a reason; never executed | 126 (triage exclusions, planned federation models, `kani-reproducers`, uncited sites) |

Every harness entry carries its fully qualified name, source file, matrix rows,
and a `domain` sentence naming what the harness actually checks (production helper
over `kani::any()` input, `cfg(kani)` model with fixed traces, fixed byte strings,
…). Loading the registry rejects unknown keys, duplicates, ambiguous
`(file, short name)` pairs, missing files, a changed registered Cargo config, and
any proof site that is neither selected nor excluded — there is no implicit
exclusion. The former `kani.toml` suites and `AEG_KANI_*` environment knobs are
retired; `scripts/kani/run_kani.sh` is a thin wrapper that rejects them.

## What one admitted result means

For a required or diagnostic request the runner
(`scripts/validation/run_kani_evidence.py`) records and checks, in this order:

1. **Controlled build environment.** The child environment is built from an
   allowlist and `RUSTFLAGS="-C panic=abort -Z panic-abort-tests --cfg kani"` is set
   by the runner. Any inherited `RUSTC`, `RUSTC_WRAPPER`, `RUSTC_WORKSPACE_WRAPPER`,
   `CARGO_BUILD_RUSTC*`, `CARGO_ENCODED_RUSTFLAGS`, `CARGO_BUILD_RUSTFLAGS`,
   `CARGO_BUILD_TARGET`, `CARGO_TARGET_*_RUSTFLAGS` or a non-policy `RUSTFLAGS`
   rejects the run before any compilation (a wrapper that adds `--cfg` flags was
   shown to turn a failing harness into a passing one). The effective Cargo
   configuration (`cargo config get`) and every config file Cargo would read are
   recorded; `build.rustc*`, `build.rustflags`, `build.target` and unregistered
   `rustflags`/`linker`/`[env]` entries reject, while Nix vendoring
   (`source.*`/`net.*`) is allowed.
2. **Tool identity.** The Nix `cargo-kani` wrapper is resolved to the store
   closure: `cargo-kani`, `kani-driver`, `kani-compiler`, the bundled `rustc`
   (`rustc -vV`, host must equal the policy target) and `cbmc`, each with a SHA-256;
   `cadical` is CBMC's built-in SAT backend and is identified through the `cbmc`
   component, while any other configured solver must resolve to a binary on the
   wrapper's PATH. A reported version other than the registry's rejects.
3. **Cargo identity.** `cargo metadata` for the group's manifest with the group's
   features and `--filter-platform` yields the package id, the single lib target
   (must equal the registry `crate`) and the workspace path dependencies whose
   sources join the input digest set.
4. **Discovery.** `cargo kani … --only-codegen` with exactly the group's
   package/lib/features/no-default-features flags compiles once into a discovery
   target and yields the crate's `*.kani-metadata.json`: every executable entry of
   the group must be present at its declared file. (`cargo kani list` cannot take
   feature flags and fails on feature-gated harness crates; it is not used.)
5. **Invocation.** One process per request, from a fresh per-run group target:
   `timeout --kill-after=10 <budget> cargo-kani kani --manifest-path … -p <package>
   --lib [--features …] [--no-default-features] --exact --harness <name> --solver
   <solver> --default-unwind <n> [--unwind <per-harness>]`, with RLIMIT_AS and wall
   and CPU seconds recorded. A request is executed at most once per run.
6. **Acceptance (structural).** Exit status 0; the `Kani Rust Verifier <version>`
   banner; exactly one `Checking harness <name>...` equal to the request; one
   `RESULTS:`/`SUMMARY:` block; consecutively numbered `Check N:` records each with
   status `SUCCESS` or `UNREACHABLE` (a successful `unwind` check is accepted;
   `FAILURE`/`UNDETERMINED` reject); the summary line
   `** 0 of N failed[ (k unreachable)]` equal to the counted properties;
   `VERIFICATION:- SUCCESSFUL`; `Complete - 1 successfully verified harnesses, 0
   failures, 1 total`. The harness's own `UNREACHABLE` assertions must equal the
   reviewed allowlist (`unreachable_assertions`, keyed by Kani property identity
   with the assertion text); the registered entries are `let … else {
   kani::assert(false, …); return; }` guards that the fixed trace never takes,
   and any change to a harness's guard set rejects until it is re-reviewed.
   Callee unreachable properties are recorded as review notes.
   Non-zero exits are classified — 124 budget, 128+n or −n signal, 101 process
   panic when a panic marker exists, otherwise `unknown nonzero` — and always reject.
7. **Compiled identity.** Exactly one new `*.kani-metadata.json` appeared during
   the invocation; its `crate_name` equals the registry `crate`; its
   `proof_harnesses` lists exactly the requested `pretty_name`, and its
   `original_file` joined onto the crate's Cargo `workspace_root` (recorded in
   `cargo-metadata.json`; Kani writes the path relative to that root, so
   `src/lib.rs` of the excluded `crates/kani-harness` resolves to
   `crates/kani-harness/src/lib.rs`) equals the registry `file`; the retained file
   must be a JSON object typed as `kani_metadata` 0.66.0 serialises it:
   non-empty `crate_name`, `pretty_name`, `mangled_name` and `original_file`,
   source lines `1 ≤ start ≤ end`, and `attributes` with `kind` a `HarnessKind`
   (`Proof`, `Test` or `{"ProofForContract": {"target_fn": …}}`), `should_panic`
   a bool, `solver` null or a `CbmcSolver` variant (`Cadical`, `Kissat`, … or
   `{"Binary": …}`), `unwind_value` null or a `u32` (0 is valid and kept),
   `stubs` a list of `{original, replacement}` and `verified_stubs` a list of
   strings — a missing key is never presumed, and `null`, unreadable, incomplete
   or mistyped content rejects. The selected harness must have `kind: Proof`,
   `should_panic: false` and empty `stubs`/`verified_stubs`. Effective unwind is
   the registry override, else the attribute (including 0), else the group
   default, as `kani-driver` resolves it.
   Effective unwind is the CLI override, else the attribute, else the group default;
   the record labels each value by what proves it (argv, cargo metadata, compiled
   metadata, tool output).

Records live under `artifacts/kani-evidence/run-<id>/`: `policy.json` (registry
copy), `schema.json`, `tools.json`, `environment.json`,
`groups/<id>/{cargo-metadata.json, discovery.kani-metadata.json, discovery.log,
discovery.json}` (or `groups/<id>/fault.json` when the group's preflight failed),
`requests/<NN>/{command.json, output.log, kani-metadata.json, result.json}`,
`unreachable_diff.json` (baseline comparison, report-only) and `evaluation.json`.
The evaluation carries the checkout `root`, the `tools` and `environment`
summaries (equal to the retained records), `inputs` (SHA-256 of the source
snapshot the run depends on: registry, schema, runner and citation checker, compliance matrix,
`Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `flake.lock`,
`.cargo/config.toml`, `nix/kani/`, every selected package directory and every
workspace path dependency reported by `cargo metadata`; taken before the first
discovery and re-taken after the last request, a difference is a fault),
`records` (SHA-256 of every other retained file of the run), `faults`, `counts`
(required/diagnostic accepted and rejected, faults) and `status` (`accepted`,
`rejected`, `recorded` for non-full scopes, `fault`). `gate.json` is removed at
the start of every run and written only by a **full-scope** run without faults
whose result set is exactly the registry's required plus diagnostic entries, with
every required result accepted, and only after the runner has reconstructed its
own records through the replay path below. `--scope diagnostic` and
`--scope partial --groups …` never write a gate. Stdout carries one
`KANI-EVIDENCE` JSON line per request, one `KANI-ADMISSION` fault line per fault,
the bounded log tail of every rejected request, and one `KANI-ADMISSION` summary
line, so a failed Nix build keeps the reasons in its log.

Reconstruction (`--verify-records <run-dir>`, and the evidential citation check)
re-derives the run from its raw records under the caller's trust inputs and never
from a stored status: the caller's registry, schema and runner must equal the
recorded digests (and the retained `policy.json`/`schema.json` copies); the
evaluation must record the checkout root; the retained `tools.json` must be a
typed, policy-consistent tool identity (the store's `cargo-kani` wrapper,
`kani-driver`, `kani-compiler`, the bundled `rustc` whose host is the policy
target and `cargo`, `cbmc` and the configured solver, each with a SHA-256, and
the policy version) equal to its summary copy — provenance of what ran, not a
requirement that those binaries exist at replay time; the retained
`environment.json` must keep only allowlisted variables, carry no forbidden
Cargo overrides and equal its summary copy; every recorded file must exist
with its digest and no unrecorded file may be present;
the source snapshot recomputed from the caller's tree must equal the recorded
`inputs`; every group's discovery is re-derived from its raw
`discovery.kani-metadata.json` (typed validation, crate, unique names, file
normalisation) and must equal the stored `discovery.json` summary, whose exit
code must be 0 and whose metadata digest must name that raw file; the request
set must be exactly the selected groups' harnesses in registry order; every
discovery and request invocation record must equal the command derived from
the registry, the validated wrapper path and the recorded root (`timeout`
prefix, manifest, package, `--lib`, features, harness, solver,
`--default-unwind`/`--unwind`; absent, extra, duplicated or weakened options
reject), run from that root under the policy budgets, and the effective
solver/unwind reported for a request come from that validated invocation
reconciled with the compiled attributes (`--unwind`, else the attribute, else
`--default-unwind`, as `kani-driver` resolves them); each request is
re-decided from `command.json`, `output.log`, `kani-metadata.json` and the
group's discovery (or reconstructed as a fault from
`groups/<id>/fault.json`), and the stored `result.json` and the summary entry must
equal the reconstruction in every field (group, class, gating, harness, status,
reasons, properties, callee unreachable notes, compiled identity and the
command/log/metadata digests; a request whose invocation produced one metadata
file must retain it); counts, status and gate presence are recomputed and must match, and an
existing `gate.json` must bind that evaluation. A diagnostic mathematical failure
is retained as a complete rejection record and never changes the gate; a runner
fault (missing tool, cargo metadata or discovery failure, unknown selection, a
source change during the run, write error) is typed `fault`, blocks every scope,
and a run with faults never has a gate and never replays successfully. There is
no crate-wide fallback execution anywhere in the gate path.

`--baseline <evaluation.json>` compares each request's property set (ids,
statuses, descriptions) against an earlier evaluation and writes
`unreachable_diff.json` (`new context` when tool versions, effective
unwind/solver, cfg/features or the domain differ; `baseline: none` when no
baseline was given). The comparison is report-only and never changes admission.

## Matrix binding

`scripts/validation/check_kani_citations.py` binds every `type: kani` proof entry
of `spec/compliance-matrix.yaml` to exactly one registry entry by `(file, short
name)`. A `verified` row may bind only to a `required`/`evidence` harness; in
evidential mode (`--gate <gate.json>`, run by the gate paths) that harness must be
accepted in the bound run. `partial` and `planned` rows may cite required,
diagnostic or excluded entries and are reported as `accepted-evidence`,
`accepted-regression`, `diagnostic-rejected`, `excluded-not-run` or
`missing-from-run`; none of these fails the gate by itself, while a required
failure fails the gate regardless of citation. `ci_check` values are reported
only. Structural binding is never displayed as admission. The evidential mode does not read the stored summary: it reconstructs the gate run itself under the caller's registry, schema, runner and source tree (the same reconstruction as `--verify-records`), requires the reconstructed gate, and binds the matrix it reads to the digest recorded in the run's `inputs`; missing, duplicated or foreign records, a registry that differs from the recorded one, or any required rejection fail the check before any citation is classified.

## Gate wiring

`nix build .#verify-kani` (`scripts/flake/verify_kani_check.sh`) runs the
full-scope admission, replays the records, and runs the evidential citation check;
the derivation fails on any required rejection or runner fault. The hosted
`Kani (Pure Harness)` job runs the same script with the pinned Nix toolchain and
uploads `artifacts/kani-evidence/`; the hosted `Kani Model Checking` job now runs
the diagnostic groups with the same pinned toolchain and uploads its records —
it is labelled diagnostic and is not evidence. `scripts/flake/verify_reqs.sh` runs
`tests/ci/test_kani_*.py` (real 0.66.0 fixtures under
`tests/fixtures/kani_admission/` plus a controlled fake toolchain) and the
structural citation check.

## Selection dispositions (2026-09-09)

| Matrix row | Disposition |
| --- | --- |
| `7515-007` | `partial`: five admitted layout/pointer/context cases do not establish general validated-input FFI memory safety |
| `OIDC-1-007`, `OIDC-1-010` | `partial` / qualified: six fixed compact-JWT strings through production Rust framing; the deliberately unreachable `unexpected canonicalisation error` assertion is pinned by identity |
| `OIDC-2-003` | moved to `partial`: the two `proof_overlap_*` harnesses check the `cfg(kani)` model of the pure JWKS helpers (u8 identifiers, ≤5 keys, one symbolic bool), now the diagnostic group `jwks-rotation-models`; runtime coverage is the `/jwks` tests |
| `OIDC-3-005` | moved to `partial`: the three cited harnesses are fixed sequential traces against `BoundedKaniSessionStore`, executed as blocking model regressions in `server-regressions`; no production-correspondence argument exists |
| `server-regressions` guards | the seven `BoundedKaniSessionStore` regressions report their `let … else` capacity/logout guards as `UNREACHABLE` (the guarded call never fails on the fixed trace); each guard is registered by identity after reading the harness, and every harness keeps reachable `SUCCESS` assertions of its own |
| `fed-op-001..009` | `planned`: cite bounded federation models recorded as excluded sites; execution admission is future work |

Excluded candidates keep their triage reasons in the registry (`verify_utf8_decode_valid_input`
solver OOM and driver panic; the two `verify_parse_json_entries_*` harnesses
exercise the `cfg(kani)` `ParserUnavailable` stub; the three standalone JWT
introspection models; six SD-JWT and three upstream fixtures, several of which reach
the `size_of_val_raw` intrinsic placeholder loop). Real recordings of these
outcomes are the negative fixtures of the regression suite.

This adapter covers the registered selection. It is not a general proof-result
evaluator, an independent review, or the release assurance decision procedure.

## Exchange lifetime helper

The required `server-exchange-lifetime` group calls production
`token_exchange_expires_in` with the pinned x86_64 Linux `SystemTime` implementation.
It quantifies every i64 second field and valid nanosecond field for both timestamps,
and every positive u64 configured TTL. Negative Unix timestamps and the full range
of positive time differences are included. No helper or standard-library operation
is replaced by a stub. Unwinding and memory-safety checks remain enabled.

The expected result is a division-free i128 seconds/borrow calculation whose
integer equivalence is proved by `TokenExchange.Lifetime`. Accepted output must be
positive, respect configured TTL, and produce a representable expiry no later than
the subject. The positive-TTL premise is explicit. This slice does not close JWT
encoding, real clocks, Redis, root revocation, or complete exchange correspondence.
