# Kani NixOS Fix Problem And Root Cause

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Verification

Audience: verification contributors, maintainers

This document is part of the split Kani NixOS archive-fix note.

## Problem Discovery Timeline

### 1. Initial Symptom (2025-11-12)

```bash
$ cargo kani --harness proof_standalone
error[E0463]: can't find crate for `kani`
```

Dependencies like zerocopy-0.8.27 could not locate the kani crate despite:
- libkani.rlib existing in the sysroot
- Correct PATH and KANI_HOME environment variables
- Successful Kani installation via Nix

### 2. First Hypothesis: Filename Mismatch

**Observation**: NixOS build produced `libkani-ef1073637ed45e71.rlib` instead of `libkani.rlib`

**Attempted Fix #1**: Create symlink
```bash
ln -sf libkani-ef1073637ed45e71.rlib libkani.rlib
```

**Result**: ❌ FAILED
- Symlink created successfully
- `strace` confirmed rustc opened the file
- Crate resolution still failed with same error

### 3. Second Attempt: File Renaming

**Attempted Fix #2**: Rename outer file
```bash
mv libkani-ef1073637ed45e71.rlib libkani.rlib
```

**Result**: ❌ FAILED
- File renamed successfully
- Same error persisted
- Led to deeper investigation of archive internals

### 4. Critical Discovery: Internal Archive Structure

Using `ar t` to examine archive contents revealed the **root cause**:

**Official Kani 0.66.0** (from GitHub release):
```bash
$ ar t kani-0.66.0/lib/libkani.rlib
lib.rmeta
```

**NixOS Build**:
```bash
$ ar t /nix/store/.../kani-0.66.0/lib/libkani.rlib
lib.rmeta
kani-ef1073637ed45e71.kani.7e4ac72588423fe7-cgu.0.rcgu.o
```

**Key Finding**: The internal object file still contained the metadata hash (`kani-ef1073637ed45e71...`) even after renaming the outer archive.

---

## Root Cause Analysis

### Why the Metadata Hash Causes Failure

Rustc's crate resolution logic:
1. When `--extern kani` (no path) is specified
2. Rustc searches the sysroot for `libkani.rlib`
3. Opens the archive and examines internal object file names
4. **Checks if object file names match expected patterns**
5. If object files have unexpected metadata hashes, resolution fails

### Why NixOS Builds Differ from Official Kani

#### Official Kani Build Process

From `tools/build-kani/src/sysroot.rs` (lines 112-174):

```rust
fn build_kani_lib(...) -> Result<Vec<Artifact>> {
    let args = [
        "build",
        "-Z", "unstable-options",
        "--target-dir", target_dir,
        "-Z", "target-applies-to-host",
        "-Z", "host-config",
        "--profile", "dev",  // ← Dev profile, not release
        "--config", "profile.dev.debug-assertions=false",
        "--config", "host.rustflags=[\"--cfg=kani\", \"--cfg=kani_sysroot\"]",
        "--target", target,
        "--message-format", "json-diagnostic-rendered-ansi",
    ];

    let rustc_args = vec![
        "--cfg=kani",
        "--cfg=kani_sysroot",
        "-Z", "always-encode-mir",
        "-Z", "mir-enable-passes=-RemoveStorageMarkers",
    ];
    // NO -C metadata= flag!
}
```

**Key characteristics**:
- Uses `cargo build` with unstable flags
- **NO** `-C metadata=` flag
- Dev profile with specific configuration
- `-Z build-std` context (from workspace)
- Results in **metadata-only library** (lib.rmeta only)

#### NixOS buildRustPackage Behavior

NixOS's `buildRustPackage`:
1. Automatically adds `-C metadata=<hash>` during compilation
2. Creates **full libraries** with both:
   - `lib.rmeta` (metadata)
   - `*.rcgu.o` (compiled object files with hashed names)
3. Metadata hash: 16-character hex string (e.g., `ef1073637ed45e71`)
4. Embedded in object file names: `kani-<hash>.kani.<hash>-cgu.0.rcgu.o`

### Why It Matters

**Outer filename**: Can be fixed with symlink or rename
**Internal object file names**: Cannot be fixed externally; must rebuild archive

Rustc resolution checks **internal structure**, not just outer filename.

---
