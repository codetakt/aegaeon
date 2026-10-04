# Sanitizers - Developer Guide

Last updated: 2026-10-04

Status: current implementation baseline

Owner: Verification

Audience: verification contributors, maintainers

This page describes how to run sanitizers (primarily AddressSanitizer / ASan). The current workflow
is standardised on Nix.

## Quickstart

```bash
# Run the security suite, including its sanitizer stage.
nix run .#security-suite

# Run sanitizers directly in the supported environment.
nix develop .#asan --command bash scripts/sanitizers/run_sanitizers.sh
```

The runner requires Rust, Cargo, Clang, the configured ASan runtime, Python 3.11 or later,
`nm` and `readelf`. It passes an explicit native `--target` matching the Rust
host so host build scripts and procedural macros do not receive target ASan
linker flags. The default ffi features and serial curve backend are retained.

Execution evidence requires Rust's standard libtest harness. The runner reads
each selected package's Cargo manifest because Cargo metadata omits the harness
setting. A selected test-enabled target with `harness = false` is rejected before
any package build, including custom Criterion benchmarks. Disabled targets stay
outside the required inventory; a custom harness is never skipped to report
success. Standard libtest library, binary, integration-test, example and benchmark
targets remain supported.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `SANITIZERS` | `address` | The configured runtime supports AddressSanitizer. Other selections fail. |
| `SANITIZER_TARGETS` | `ffi` | Comma-separated Cargo packages; must include `ffi`. Additional packages extend the required inventory. |
| `SANITIZER_CARGO_FLAGS` | empty | Supported feature, scheduling and reporting options, for example `--features lowstar_hash`. Unknown options and positional arguments fail. |
| `SANITIZER_TARGET_DIR` | `target/sanitizers` | Cargo outputs, separated by sanitizer, package and host target. |
| `SANITIZER_ARTIFACT_DIR` | `$SANITIZER_TARGET_DIR/artifacts` | Raw command output and `run-summary.json`. |
| `SANITIZER_TIMEOUT` | `120` | Fallback deadline in seconds. |
| `SANITIZER_BUILD_TIMEOUT` | `$SANITIZER_TIMEOUT` | Metadata/build command deadline. |
| `SANITIZER_RUN_TIMEOUT` | `$SANITIZER_TIMEOUT` | Deadline for each binary listing, inspection and execution. |
| `SANITIZER_TIMEOUT_KILL` | `130` | Grace after termination before killing a remaining process group. |
| `ASAN_VERIFY_LINK_ORDER` | `0` | ASan runtime link-order check; accepts `0` or `1`. |

The shared Cargo parser accepts `--features`/`-F`, `--all-features`,
`--no-default-features`, `--jobs`/`-j`, `--color`, `--quiet`/`-q`,
`--verbose`/`-v`, `--locked`, `--offline`, `--frozen`, `--keep-going`,
`--no-run` and `--future-incompat-report`. Value options support split and
equals forms; `-F` and `-j` also accept attached values. Short-option bundles
are rejected, except repeated `-v`. Package, profile, target, Cargo configuration
and unstable `-Z` options cannot pass through this channel.
`SANITIZER_BUILD_EXTRA_ARGS` separately accepts only `-Zbuild-std=std` or
`-Z build-std=std`; an empty value uses the ordinary configured build.

Both entry routes reject inherited Bash functions before helper calls. They
leave prior evidence untouched when startup admission is refused; the nonzero
exit cannot be accepted as a completed current attempt. They
also reject `RUSTC`, `RUSTC_WRAPPER`, `RUSTC_WORKSPACE_WRAPPER` and any
`CARGO_BUILD_RUSTC*` environment override, including empty values, before Cargo
metadata or builds. Use the supported shell's compiler on `PATH`; inherited
encoded Rust flags are replaced by the runner's fixed sanitizer flags.
The build-std convenience entry delegates to the same admission and preflight
before any tool invocation; it selects `-Zbuild-std=std` and its default output
directory without a separate compiler/runtime setup.

Deadlines must be positive and finite; the `s`, `m`, `h` and `d` suffixes are
accepted. A timeout fails the run. The supervisor terminates remaining processes
in each command's process group on timeout, interruption or capture failure.
A normally exiting leader with running descendants also fails after cleanup.
If process inspection fails, cleanup still kills the owned group and reaps its
leader, then reports the inspection failure.
Interrupted evidence writes retain the signal-derived exit status; an earlier
failure keeps its original status if the final receipt cannot be written.
The existing security job's outer timeout still bounds the whole stage.

The security-suite dispatcher resolves `SANITIZER_TARGET_DIR` before removing
transient outputs after the sanitizer stage. Cleanup rejects the workspace
itself and every workspace ancestor, including `/`, even through symlinks or
`..` aliases. It also rejects targets equal to, inside, or containing the
resolved current artifact or retained history directory (`SECURITY_ARTIFACT_DIR`
or `SECURITY_HISTORY_DIR`). The same check applies during bound wrapper re-entry and recovery;
history paths are normalized before logging or stage execution. The suite writes
sanitizer evidence to its current artifact `sanitizers` subdirectory. A rejected
cleanup fails a successful stage; an earlier child failure retains its original
exit code. An exit before the sanitizer stage cleans an outstanding prepared
target and records the earlier stage failure without replacing detailed child
evidence. Each admitted cleanup attempt is consumed once.
Custom output directories must resolve outside these protected locations.

The runner sets these execution options explicitly:

```text
ASAN_OPTIONS=abort_on_error=1:detect_stack_use_after_return=1:detect_leaks=0:verify_asan_link_order=0:verbosity=0
LSAN_OPTIONS=abort_on_error=1:detect_leaks=0
UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1
```

`ASAN_VERIFY_LINK_ORDER` accepts only `0` or `1`; other values fail before Cargo
metadata or build execution. It changes only that ASan option. Leak detection
is disabled in this suite. `SANITIZER_EXEC_LD_PRELOAD` or
`SANITIZER_EXEC_FORCE_PRELOAD=1` enables the existing execution preload route.

## Required execution and evidence

Cargo metadata defines every test-enabled library, binary, integration test,
example and benchmark target. The runner selects each explicitly with `--lib`,
`--bin`, `--test`, `--example` or `--bench`; unsupported test-enabled kinds fail.
Library crate kinds share the library selector. Disabled targets are not selected;
an unexpected test executable still fails. Every selected target must produce
named libtest JSON completion, including custom harnesses and benchmark targets.
The nine baseline ffi targets remain a required minimum. A successful Cargo build
must report an executable for every applicable target through compiler-artifact
JSON. Binary basenames need not contain `ffi`. Valid Cargo cache reuse is
accepted when Cargo binds the executable to the selected package, target,
source and native output directory. Missing, duplicate, malformed or unrelated
artifacts fail even if an old executable exists. Target name and kind distinguish
same-named libraries and binaries, with package and canonical source bound
independently. Example test executables must be in the native `debug/examples`
directory; other test executables must be in `debug/deps`. Duplicate target names
receive unique metadata-index log labels across all selected packages, and those
raw logs retain the same attempt-history policy.

For each binary the runner retains symbol and ELF inspection, lists all and
ignored test identities, and validates normal libtest JSON completion against
those names. Ignored tests retain their existing policy and are reported
separately. Every required binary needs runnable tests, including the native
JOSE header integration test. When `lowstar_hash` is disabled,
`oidc_hash_runtime_test` has no applicable tests: its binary must still build,
list and execute normally, and the summary qualifies that zero-test result.
Enabling the feature requires nonempty execution in that binary too.

`run-summary.json` records commands, deadlines, exits, target/source/binary
identities and SHA-256 digests, flags, runtime linkage, expected tests and named
results. Raw stdout and stderr are retained for successful and failed commands.
Build failures, crashes, missing named completion, malformed evidence and output
or cleanup errors fail the run.

ASan markers and the isolated validation canary establish instrumentation of
the Rust test binaries checked. They do not establish instrumentation of all C
libraries or dependencies, universal memory safety, or release-server coverage.

## Troubleshooting

- **Missing tools/runtime**: enter `nix develop .#asan` and inspect
  `SANITIZER_RUNTIME_DIR`; required inputs cannot be skipped.
- **Link-order warnings**: the default is `ASAN_VERIFY_LINK_ORDER=0`. Enable the
  check only when investigating runtime ordering.
- **Build/test failure**: inspect `run-summary.json` and the corresponding raw
  logs under the artifact directory. Reproduce the recorded command and flags
  in the same pinned environment.
- **Deadline exceeded**: distinguish build time from binary execution time in
  the summary. Preserve the failed evidence before adjusting a deadline.

## References

- [AddressSanitizer Runtime](https://clang.llvm.org/docs/AddressSanitizer.html)
- [Nix devShell (`flake.nix`)](../../../flake.nix)
