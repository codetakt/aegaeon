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
   nix build ".#kani'" --out-link result-kani
   KANI_ROOT="$(readlink -f result-kani)"
   PATH="$KANI_ROOT/bin:$KANI_ROOT/toolchain/bin:$PATH" \
     AEG_KANI_SUITE=regression \
     AEG_KANI_RUN_SERVER=1 \
     ./scripts/kani/run_kani.sh
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

### Experimenting with panic strategy

```bash
AEG_KANI_PANIC=abort nix run .#verify-kani
AEG_KANI_PANIC=unwind nix run .#verify-kani
```

## Logs and artefacts

- Detailed run log: `artifacts/kani/run_<run_id>.log`
- Machine-readable summary: `artifacts/kani/report.json`
- Human summary log: `artifacts/kani/report.log`
- XDG state/cache dirs: `artifacts/kani/xdg-state/`, `artifacts/kani/xdg-cache/`

If the issue persists, attach the relevant `run_<run_id>.log` when filing an issue.

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
