# Kani Verification Harness

Status: ✅ WORKING (as of 2025-12-18)

This crate contains Kani verification harnesses for Aegaeon's bounded stores and security-critical components.

## Current Status

`cargo kani` runs successfully with the Nix-packaged Kani sysroot after fixing the sysroot build and `libkani`/`std` compatibility.

Evidence is recorded in:
- `../../docs/verification/kani/README.md`
- `../../artifacts/kani/report.json`

## Running Harnesses

```bash
# CI-equivalent (runs inside a Nix build sandbox)
nix build .#verify-kani -L

# Local run (reads defaults from kani.toml; writes artifacts/kani/report.json + report.log)
nix build ".#kani'" --out-link result-kani
PATH="$(readlink -f result-kani)/bin:$PATH" AEG_KANI_SUITE=regression ./scripts/kani/run_kani.sh

# Optional: run server harness shims too
PATH="$(readlink -f result-kani)/bin:$PATH" AEG_KANI_SUITE=regression AEG_KANI_RUN_SERVER=1 ./scripts/kani/run_kani.sh

# Single harness (from this crate)
cd crates/kani-harness
PATH="$(readlink -f ../../result-kani)/bin:$PATH" cargo kani --unwind 16 --no-unwinding-checks --harness proof_trivial_arithmetic
```

## Notes

- This crate intentionally avoids FFI-heavy dependencies to keep Kani runs fast and reproducible.
- Server harnesses are not run by default; see `scripts/kani/run_kani.sh` and `AEG_KANI_RUN_SERVER=1`.

## References

- [Verification overview](../../docs/verification/README.md)
- [Kani Verification (Status + How to Run)](../../docs/verification/kani/README.md)
- [Kani GitHub Issues](https://github.com/model-checking/kani/issues)
