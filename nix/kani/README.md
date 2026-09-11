# Kani Nix Packaging Notes (Checklist)

This document tracks packaging invariants and regression checks for the
Nix-packaged Kani verifier under `nix/kani/`.

If you are debugging a Kani run today, start here (quick checklist). For deeper
RCA and historical context, see `docs/verification/kani/kani-nixos-fix/README.md`.

This file is intentionally **timeless**: avoid date-stamped "status" statements
that tend to rot. Current posture and latest evidence live in
`docs/verification/kani/README.md`.

## Invariants (regression checks)

### 1) No duplicate stdlib candidates in sysroot

**Invariant**: the sysroot must not contain multiple competing candidates for
stdlib crates (notably `std`, `core`, `alloc`, `panic_*`, `unwind`, `proc_macro`,
`test`, and related workspace crates).

**Symptom if broken**: multiple competing `.rlib`/`.rmeta` candidates inside
`lib/rustlib/<triple>/lib`, leading to brittle or non-deterministic resolution.

**Fix**: install the artifacts selected by the pinned upstream `tools/build-kani`
builder. Do not copy driver `target/release/deps` or the ordinary toolchain's
standard libraries over the verification sysroot.

**Regression check**: `nix build ".#kani'"` must produce a sysroot that can
compile a trivial crate and a `kani::any()` crate under `-C panic=abort`
(see also `docs/verification/kani/README.md`).

### 2) Sysroot and Kani crates agree on `panic=abort` + MIR std

**Invariant**: Kani compiles user crates with `-C panic=abort`, and the sysroot
as well as `kani_core`/`kani`/`kani_metadata` must be built consistently against
the MIR-encoded `std` used by that sysroot.

This showed up as:
- `error: the crate 'panic_abort' does not have the panic strategy 'abort'`
- `E0460` / `E0463` when compiling code that uses `kani::any()` (including dependencies such as `zerocopy` under `cfg(kani)`).

**Root causes**:
1. MIR sysroot was built with the default panic strategy (`unwind`) while Kani compiles with `-C panic=abort`.
2. `libkani*.rlib` was built against the toolchain `std` and then placed in a sysroot that forces a MIR-encoded `std`.

**Fix**: the upstream builder compiles the verification libraries together with
`-Z build-std=panic_abort,std,test`, using `kani-compiler` and
`profile.dev.panic="abort"`. It separately builds the playback and no-core
libraries. The binary build's release flags do not apply to verification MIR.

**Quick validation**:
```bash
# Build the package from this repo
nix build ".#kani'"

SYSROOT="$(readlink -f result)/kani-0.66.0"
RUSTC="$SYSROOT/toolchain/bin/rustc"

# panic=abort works with the sysroot
printf 'fn main(){}' > /tmp/kani_abort.rs
"$RUSTC" /tmp/kani_abort.rs -C panic=abort --sysroot "$SYSROOT"

# kani::any works with the sysroot
printf 'pub fn f(){ let _x: u8 = kani::any(); }' > /tmp/kani_any.rs
"$RUSTC" /tmp/kani_any.rs --crate-type lib -C panic=abort -Z unstable-options --cfg kani \\
  --sysroot "$SYSROOT" -L "$SYSROOT/lib" --extern kani
```

### 3) Verification-library MIR preserves intrinsic hooks

Release MIR inlining can erase the `size_of_val` and `align_of_val` hook calls,
leaving the placeholder infinite loop instead. String and vector clones can
then fail unwinding even for a single byte. Increasing the unwind bound does
not repair that library.

Use the pinned upstream `tools/build-kani` builder. It builds the binaries in
release mode and the verification libraries through `kani-compiler` in the dev
profile, with its explicit debug-assertion, panic, cfg and MIR options. Install
the compiler-produced archives without rewriting them or overwriting them with
driver dependencies.

`nix build ".#kani'"` runs the installed wrapper on arithmetic, sized and sliced
size/alignment, string clone and vector clone controls. An intentionally wrong
size assertion must fail specifically at that assertion. Timeout, incomplete
output, compilation errors and unwind failures reject the package. The seven
case records live in `$out/share/kani-library-checks/RESULTS.json`.
The classifier reconciles every property with the `SUMMARY` counts, including
failures and unreachable callee checks. The named positive assertion must be
reachable; the `Complete` line separately confirms the single harness finished.

The public `$out/bin/kani` wrapper starts upstream's proxy, which invokes
`$KANI_HOME/kani-0.66.0/bin/kani-driver`. `setup-kani-env` links that release
directory to the installed bundle, so the driver resolves its libraries there.
The `nix run .#verify-kani` app supplies Python with `jsonschema` and `yaml`;
it must work with the caller's `PYTHONPATH` unset.

These package regressions do not prove application properties. After a tool
change, rerun the registry selection and re-admit its records.

### 4) Wrapper must not write into read-only vendor trees

**Invariant**: Nix builds must not attempt to create `$HOME`, `KANI_HOME`, or
`RUSTUP_HOME` under the current working directory when compiling vendored
dependencies from `/nix/store/...`.

**Symptom**: `cargo kani` failed in Nix build sandboxes while compiling dependencies from the vendored `/nix/store/...` source tree, with errors like:

```text
mkdir: cannot create directory '$HOME': Permission denied
```

**Root cause**: Wrapper defaults for `KANI_HOME` / `RUSTUP_HOME` used literal `'$HOME/…'` strings, so the wrapper attempted to create a directory named `$HOME` relative to the current working directory (read-only when compiling vendored crates).

**Fix**: Remove wrapper-level defaults and rely on `kani-*/bin/setup-kani-env`, which derives a writable `KANI_HOME` from XDG variables / `$HOME` and creates `RUSTUP_HOME` + toolchain links there.
