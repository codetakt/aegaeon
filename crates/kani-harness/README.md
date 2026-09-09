# Kani Verification Harness

Status: ✅ WORKING (as of 2025-12-18)

This crate contains Kani verification harnesses for Aegaeon's bounded stores and security-critical components.

## Current Status

`cargo kani` runs successfully with the Nix-packaged Kani sysroot after fixing the sysroot build and `libkani`/`std` compatibility.

Evidence is recorded in:
- `../../docs/verification/kani/README.md`
- `../../artifacts/kani-evidence/run-*/evaluation.json` (runner records; see docs/verification/kani/evidence-admission.md)

## Running Harnesses

```bash
# CI-equivalent (runs inside a Nix build sandbox)
nix build .#verify-kani -L

# Local run of the registry selection (spec/kani-evidence.json); writes artifacts/kani-evidence/
nix build ".#kani'" --out-link result-kani
PATH="$(readlink -f result-kani)/bin:$PATH" ./scripts/kani/run_kani.sh

# Only this crate's regression group (never writes gate.json)
PATH="$(readlink -f result-kani)/bin:$PATH" ./scripts/kani/run_kani.sh --scope partial --groups kani-harness-regressions

# Single harness (from this crate)
cd crates/kani-harness
PATH="$(readlink -f ../../result-kani)/bin:$PATH" cargo kani --unwind 16 --no-unwinding-checks --harness proof_trivial_arithmetic
```

## Notes

- This crate intentionally avoids FFI-heavy dependencies to keep Kani runs fast and reproducible.
- Server harnesses form the `server-regressions` group of the registry; run them alone with `./scripts/kani/run_kani.sh --scope partial --groups server-regressions` (never writes `gate.json`).

## References

- [Verification overview](../../docs/verification/README.md)
- [Kani Verification (Status + How to Run)](../../docs/verification/kani/README.md)
- [Kani GitHub Issues](https://github.com/model-checking/kani/issues)
