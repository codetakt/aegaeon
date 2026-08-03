# HACL* Integration Documentation

Last updated: 2026-03-08

Status: current implementation baseline

Owner: Verification

Audience: verification contributors, maintainers

## Overview

This document describes the HACL\* cryptographic library integration with Aegaeon's F\* verification framework.

## Current Status

**Current posture (2026-03-08):**
- The modern verified allowlist is backed by HACL*/EverCrypt for the currently
  promoted paths (`HS256/384/512`, `EdDSA`, verified ChaCha20-Poly1305, and the
  associated verified bridges).
- Broad RSA/ECDSA interoperability still lives in the compat boundary.
- The promoted OIDC `RS256 Required Slice` / `RS256 Interop Slice` are
  explicit server-claim boundary exceptions; they do **not** reclassify broad
  RSA as part of the general HACL*/EverCrypt allowlist.
- For the canonical posture, always defer to `docs/verification/claims/crypto-allowlist.md`
  and `docs/verification/workplans/verification-boundary-roadmap.md`.

## Architecture

```text
┌──────────────────┐
│   Application    │
│    F* Modules    │
└────────┬─────────┘
         │
┌────────▼─────────┐
│  HACL_Wrapper    │  ← Verified interface layer
│   (F* module)    │
└────────┬─────────┘
         │
┌────────▼─────────┐
│    HACL* Libs    │  ← Actual HACL* implementation
│   (via Nix)      │     (current verified integration path)
└──────────────────┘
```

## Modules

### HACL_Wrapper.fst
Provides simplified, verified interfaces for:
- **ChaCha20-Poly1305 AEAD**
  - `chacha20poly1305_encrypt`: Authenticated encryption
  - `chacha20poly1305_decrypt`: Authenticated decryption
- **HMAC**
  - `hmac_sha256`: HMAC with SHA-256
  - `hmac_sha384`: HMAC with SHA-384
  - `hmac_sha512`: HMAC with SHA-512

### EverCrypt.Chacha20Poly1305.fst
- Uses `HACL_Wrapper` for AEAD operations
- Maintains EverCrypt API compatibility
- Provides buffer-based operations for C extraction

### EverCrypt.HMAC.fst
- Uses `HACL_Wrapper` for HMAC operations
- Integrates with `ConstTime` module for constant-time verification
- Supports multiple hash algorithms via `Spec.Hash.Definitions`

## Build Configuration

### Nix Environment
```bash
nix develop
# HACL* paths automatically set:
# HACL_FSTAR_PATH=/nix/store/.../share/hacl-star/fstar
# FSTAR_INCLUDE=/nix/store/.../share/hacl-star/fstar
```

### F* Makefile
```makefile
HACL_PATH ?= $(or $(HACL_FSTAR_PATH),$(FSTAR_INCLUDE))
ifneq ($(HACL_PATH),)
FSTAR_OPTS = --cache_dir .cache --cache_checked_modules --include $(HACL_PATH)
endif
```

## Verification

Run F* verification:
```bash
cd fstar
make verify
```

Expected output:
```text
Verifying HACL_Wrapper.fst...
Verified module: HACL_Wrapper
Verifying EverCrypt.Chacha20Poly1305.fst...
Verified module: EverCrypt.Chacha20Poly1305
Verifying EverCrypt.HMAC.fst...
Verified module: EverCrypt.HMAC
All F* files verified successfully
```

## Recommended Plan (Strong-Constraint)

### Phase 1 — Verified Crypto Path (F* + Extraction + Runtime)

**Goal:** Keep the verified-profile runtime aligned with HACL*/EverCrypt-backed
implementations, route promoted algorithms through extracted code, and keep broad
RSA/ECDSA compat-only unless a separate boundary-promotion decision is made.

1. **Algorithm inventory + allowlist**
   - Confirm verified allowlist includes **only** HACL*/EverCrypt-backed algs.
   - RSA-based algorithms remain compat-only unless verified implementations land.

2. **F\* implementations (remove `irreducible`)**
   - `Jose.Rsa_signatures.fst` — replace Ed25519 placeholder with EverCrypt impl.
   - `Jose.Jws.Verify.fst` — use verified signature verification + HMAC where
     applicable.
   - `Dpop.Signature.fst` — use verified signature verification.
   - `Jose.SdJwt.fst` — use verified hash/digest (SHA-256) for disclosures.
   - `Jose.Jwk_thumbprint_uri.fst` — use verified hash for thumbprints.

3. **Extraction + FFI**
   - KaRaMeL extract verified crypto into `c/` or `lib/`.
   - Provide a small, total FFI surface in `crates/ffi`.
   - In Rust, select FFI when the **verified allowlist** is active.

4. **Constant-time enforcement**
   - dudect tests for extracted primitives.
   - CI gates must fail-close on bypassing verified crypto.

### Phase 2 — RNG Boundary

**Goal:** Remove RNG `irreducible` models by making entropy explicit and using a
verified DRBG.

- Implement deterministic DRBG in F* using HMAC/SHA-256.
- Make entropy explicit input to `generate_secure_random` and
  `fresh_challenge_id`.
- Wire OS entropy in Rust only for the verified profile.

### Phase 3 — Hardened Interop (Optional)

- Add vectorized HACL* variants where safe.
- Evaluate AES-GCM in EverCrypt if needed for verified JWE.
- Keep compat profile for interop with external IdPs that require RSA.

## Benefits

1. **Verified Cryptography**: All cryptographic primitives are formally verified
2. **Constant-Time**: HACL* provides constant-time implementations
3. **Performance**: Optimized assembly implementations where available
4. **Modularity**: Clean separation between interface and implementation

## References

- [HACL* Repository](https://github.com/project-everest/hacl-star)
- [Project Everest](https://project-everest.github.io/)
- [F* Documentation](https://fstar-lang.org/)
- [KaRaMeL](https://github.com/FStarLang/karamel)
