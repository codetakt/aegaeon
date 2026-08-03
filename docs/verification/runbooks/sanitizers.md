# Sanitizers - Developer Guide

Last updated: 2026-07-07

Status: current implementation baseline

Owner: Verification

Audience: verification contributors, maintainers

This page describes how to run sanitizers (primarily AddressSanitizer / ASan). The current workflow
is standardised on Nix.

## Quickstart

### Via the security suite (recommended)

```bash
# Runs deny/audit/vet plus fuzz/sanitizers/SBOM/geiger/udeps.
nix run .#security-suite
```

### Run sanitizers explicitly

```bash
# Enter the ASan devShell.
nix develop .#asan

# Confirm the shared runtime path (set automatically).
echo "$SANITIZER_RUNTIME_DIR"
ls "$SANITIZER_RUNTIME_DIR"/libclang_rt.asan-*.so

# Run the sanitizer suite.
scripts/run_sanitizers.sh
```

You can tune the targets via environment variables.

```bash
# Targets to run (comma-separated).
export SANITIZER_TARGETS=ffi

# Sanitizers to run.
export SANITIZERS=address

# Additional cargo flags.
export SANITIZER_CARGO_FLAGS="--no-default-features"

# Output directory.
export SANITIZER_TARGET_DIR=target/sanitizers
```

## devShell differences

| Item | `nix develop .#default` | `nix develop .#asan` |
|------|--------------------------|----------------------|
| Rust toolchain | nightly (standard) | fenix nightly + ASan |
| Shared runtime | none | bundles `libclang_rt.asan.*` |
| Primary use | day-to-day development | running sanitizers |

`nix run .#security-suite` invokes `nix develop .#asan --command scripts/run_sanitizers.sh`
internally, so you can run the short smoke suite without entering the devShell manually. For more
extensive runs, execute commands directly inside the ASan devShell.

## ASan options

You can tune runtime behaviour via `ASAN_OPTIONS`. The scripts use the following defaults:

```bash
ASAN_OPTIONS=abort_on_error=1:detect_stack_use_after_return=1:detect_leaks=0:verify_asan_link_order=0:verbosity=1
```

To write logs to a file, add `log_path`:

```bash
ASAN_OPTIONS="$ASAN_OPTIONS:log_path=asan.log"
```

## Troubleshooting

- **Link-order warnings**: suppress them with `ASAN_VERIFY_LINK_ORDER=0` (default). Only set it to
  `1` when you need extra diagnostics and can tolerate the warnings.
- **LeakSanitizer false positives**: CI runs with `detect_leaks=0`. For local leak checks, add
  `detect_leaks=1` to `ASAN_OPTIONS`.
- **Sanitizer crashes**: inspect the binaries/logs under `target/sanitizers`, then rerun the exact
  command recorded in the final section of `scripts/run_sanitizers.sh` to capture more detail.

## References

- [AddressSanitizer Runtime](https://clang.llvm.org/docs/AddressSanitizer.html)
- [Nix devShell (`flake.nix`)](../../../flake.nix)
