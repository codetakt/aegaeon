# Kani NixOS Alternatives And Technical Details

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Verification

Audience: verification contributors, maintainers

This document is part of the split Kani NixOS archive-fix note.

## Alternative Solutions Considered

### Option 1: Use Official Build Process
**Approach**: Invoke `cargo run -p kani-build -- build` instead of `buildRustPackage`

**Pros**:
- Uses exact same process as official Kani
- Guaranteed compatibility

**Cons**:
- Requires manual patchelf for all generated binaries
- `cargo run` binaries not automatically patched by Nix
- More complex integration with Nix infrastructure
- Harder to maintain

**Verdict**: ❌ Rejected - Too complex for Nix integration

### Option 2: Suppress Metadata Hash (Attempted)
**Approach**: Prevent cargo from adding `-C metadata=` flag

**Attempts**:
- `CARGO_ENCODED_RUSTFLAGS=""`
- Cargo.toml `[profile.dev]` modifications
- Custom build script overrides

**Result**: ❌ Failed - `buildRustPackage` internals override these settings

**Verdict**: ❌ Not feasible with buildRustPackage

### Option 3: Force Metadata-Only Build
**Approach**: Configure cargo to generate metadata-only libraries

**Issues**:
- No clear cargo flag for metadata-only builds
- `-C prefer-dynamic` doesn't prevent object generation
- Would require forking buildRustPackage internals

**Verdict**: ❌ Rejected - Too invasive

### Option 4: Post-Build Archive Reconstruction (CHOSEN) ✅
**Approach**: Rebuild archives after build completes

**Implementation**: postFixup hook (described above)

**Pros**:
- Minimal changes to existing build process
- Preserves all Nix infrastructure benefits (patchelf, etc.)
- Simple and maintainable
- Perfect result matching official Kani

**Cons**:
- Slight build time overhead (~1-2 seconds)
- Requires `ar` tool (already available)

**Verdict**: ✅ **CHOSEN** - Best balance of simplicity and effectiveness

---

## Technical Deep Dive

### Rust .rlib Archive Format

An `.rlib` file is a standard Unix `ar` archive containing:
1. **lib.rmeta**: Rust metadata (crate information, type signatures, etc.)
2. **Object files** (optional): Compiled code as `.rcgu.o` files

**Metadata-only library**: Contains only lib.rmeta, used for:
- Dependency resolution
- Type checking
- Macro expansion
- No actual code linking

**Full library**: Contains lib.rmeta + object files, used for:
- All of the above
- Actual code linking and execution

### Cargo Metadata Hash

**Purpose**: Disambiguate multiple versions of same crate

**Format**: 16-character hexadecimal string
- Example: `ef1073637ed45e71`
- Derived from: Crate name, version, source, dependencies

**Usage**:
- Added via `-C metadata=<hash>` rustc flag
- Embedded in:
  - Outer filename: `libkani-<hash>.rlib`
  - Object file names: `kani-<hash>.kani.<hash>-cgu.0.rcgu.o`

**NixOS behavior**: buildRustPackage automatically adds metadata hashes for reproducibility

### Rustc Crate Resolution

When `--extern kani` (no explicit path) is specified:

1. **Search sysroot**: Look in `$KANI_HOME/kani-0.66.0/lib/`
2. **Find candidate**: Locate `libkani*.rlib` files
3. **Open archive**: Use `ar` to inspect contents
4. **Check metadata**: Read lib.rmeta for crate information
5. **Verify object files**: **Check if object file names match expected patterns**
6. **Resolution**: If checks pass, use this library

**Failure point**: Step 5 fails when object files have unexpected metadata hashes

---

## Known Limitations

### 1. HashMap/String Complexity
Some harnesses involving `HashMap` or `String` may timeout (60s limit):
- `proof_hashmap_basic`
- `proof_hashmap_string_keys`
- `proof_string_new_minimal`
- `proof_option_string_minimal`

**Status**: Harness-complexity limitation; track separately from the archive fix.
**Workaround**: Increase timeout or simplify harnesses
**Impact**: Does not affect fix correctness

### 2. Build Time Overhead
postFixup hook adds ~1-2 seconds to build time

**Impact**: Minimal (build takes several minutes total)

### 3. Architecture Assumption
Current implementation assumes:
- Single host architecture (x86_64-unknown-linux-gnu)
- Standard library locations

**Future**: May need adjustment for cross-compilation

---

## Future Considerations

### 1. Upstream Collaboration
Consider upstreaming this fix to:
- **nixpkgs kani package**: Share solution with broader community
- **Kani project**: Discuss NixOS compatibility in official docs

### 2. buildRustPackage Enhancement
Potential nixpkgs improvement:
```nix
# Hypothetical future API
buildRustPackage {
  metadataOnlyLibraries = [ "kani" ];
  # Auto-apply archive reconstruction for specified crates
}
```

### 3. Monitoring Kani Updates
Track Kani releases for potential build process changes:
- Version 0.67.0+: May change sysroot structure
- Monitor: <https://github.com/model-checking/kani/releases>

### 4. Alternative Build Methods
Explore:
- Building Kani with official `cargo bundle` in Nix
- Custom derivation mimicking official build process
- Hybrid approach: buildRustPackage + official bundle steps

---

## References

### Local Analysis

- [Problem and root cause](problem-and-root-cause.md)
- [Implemented fix and validation](implemented-fix-and-validation.md)

### Official Kani Sources
- `tools/build-kani/src/sysroot.rs` - Official build logic
- `tools/build-kani/src/main.rs` - Build entry point
- Kani 0.66.0 Release: <https://github.com/model-checking/kani/releases/tag/kani-0.66.0>

### Implementation
- `nix/kani/package.nix:586-651` - postFixup hook implementation

---

## Conclusion

The libkani.rlib metadata hash issue stemmed from a fundamental difference between NixOS `buildRustPackage` (which creates full libraries with hashed object files) and official Kani's build process (which creates metadata-only libraries).

The implemented postFixup hook successfully resolves this by rebuilding archives to match the official structure, enabling full Kani functionality on NixOS.

**Status**: ✅ **RESOLVED and VERIFIED**
- 4 harnesses tested
- 15 verification checks passed
- 0 failures
- Perfect archive structure match with official Kani

---
