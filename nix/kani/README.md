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

**Fix**: keep MIR-encoded stdlib crates from the `-Z build-std` step, and avoid copying
competing versions from `rustWithComponents` into the sysroot. The exclusion filter covers:
`std`, `core`, `alloc`, `panic_*`, `unwind`, `proc_macro`, `test`, and related workspace crates.

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

**Fix**:
- Build the MIR sysroot with `-C panic=abort` (host + target rustflags) when running `-Z build-std=panic_abort,std,test`.
- Rebuild `kani_core`, `kani`, and `kani_metadata` against the MIR sysroot with `--sysroot $KANI_SYSROOT` and `-C panic=abort`.

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
```text

### 3) Wrapper must not write into read-only vendor trees

**Invariant**: Nix builds must not attempt to create `$HOME`, `KANI_HOME`, or
`RUSTUP_HOME` under the current working directory when compiling vendored
dependencies from `/nix/store/...`.

**Symptom**: `cargo kani` failed in Nix build sandboxes while compiling dependencies from the vendored `/nix/store/...` source tree, with errors like:

```text
mkdir: cannot create directory '$HOME': Permission denied
```

**Root cause**: Wrapper defaults for `KANI_HOME` / `RUSTUP_HOME` used literal `'$HOME/…'` strings, so the wrapper attempted to create a directory named `$HOME` relative to the current working directory (read-only when compiling vendored crates).

**Fix**: Remove wrapper-level defaults and rely on `kani-*/bin/setup-kani-env`, which derives a writable `KANI_HOME` from XDG variables / `$HOME` and creates `RUSTUP_HOME` + toolchain links there.
