# Kani Troubleshooting (Toolchain / Panic Strategy)

Last updated: 2026-07-07

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, contributors

> **Note:** We standardise on running Kani via Nix: `nix build .#verify-kani -L` or
> `nix run .#verify-kani`.

## Recommended workflow (Nix)

1. CI-equivalent run (preferred)
   ```bash
   nix build .#verify-kani -L
   ```

2. Local run (writes logs under `artifacts/kani/`)
   ```bash
   nix run .#verify-kani

   # Or run the wrapper directly with an explicit Kani package:
   # The suites and env knobs are retired: the wrapper runs the registry selection.
   nix build ".#kani'" --out-link result-kani
   KANI_ROOT="$(readlink -f result-kani)"
   PATH="$KANI_ROOT/bin:$KANI_ROOT/toolchain/bin:$PATH" ./scripts/kani/run_kani.sh
   ```

## Common errors and fixes

### `panic_abort` / `panic_unwind` panic strategy mismatch

Symptoms:
- `error: the crate panic_abort does not have the panic strategy abort`
- `error: the crate panic_unwind does not have the panic strategy unwind`

Cause: invoking Kani outside the Nix-provided toolchain/sysroot, so the panic strategy expectations
do not match.

Fix: use `nix build .#verify-kani -L` (preferred) or run inside a Nix devShell so `cargo-kani` and
its sysroot stay aligned.

### `unknown unstable option: build-std`

Cause: external `RUSTFLAGS` / `CARGO_BUILD_STD` leaking into the run, or invoking `cargo kani`
manually with a mismatched rustc.

Fix: run via `./scripts/kani/run_kani.sh` (it clears/sets the required flags) and avoid custom `cargo kani`
invocations unless you know exactly what sysroot/toolchain is in use.

### Panic strategy

The runner fixes `RUSTFLAGS` to `-C panic=abort -Z panic-abort-tests --cfg kani` for every
request and rejects inherited overrides; there is no knob to switch strategies, and a run
made with other flags is not admissible evidence.

## Logs and artefacts

- Per-request tool output: `artifacts/kani-evidence/run-*/requests/<NN>/output.log`
  (with `command.json`, `kani-metadata.json` and `result.json` beside it)
- Per-group discovery: `artifacts/kani-evidence/run-*/groups/<id>/discovery.log`
- Machine-readable records: `artifacts/kani-evidence/run-*/evaluation.json` (and `gate.json` for an accepted full-scope run)
- Stdout of the gate: one `KANI-EVIDENCE` line per request and a `KANI-ADMISSION` summary line

If the issue persists, attach the request's `output.log` and the run's `evaluation.json` when filing an issue.

## HashMap harnesses (practical limitation)

- `std::collections::HashMap` is typically impractical to verify with CBMC/Kani under CI budgets,
  and can also trigger Kani ICEs in some toolchain versions.
- Root cause: HashMap seeding and internal randomness (via `getrandom`) can introduce unbounded
  symbolic state, leading to very large verification problems (time/memory blow-ups), and in the
  ICE case the compiler fails before CBMC runs.

Recommended posture:

- Verify **bounded array models** (e.g. `[(K, V); N]`) with Kani, and keep the production code using
  HashMap for performance.
- Validate behavioural equivalence between the array model and HashMap implementation with ordinary
  unit/integration tests.

References:

- Historical ICE repro (Kani 0.65 era): `docs/verification/kani/hashmap-ice-repro.md`
- Current runbooks and posture: `docs/verification/kani/README.md`
