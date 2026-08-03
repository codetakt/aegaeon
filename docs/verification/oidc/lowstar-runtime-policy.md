# OIDC Low\* Runtime Promotion Policy

Last updated: 2026-07-07

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, contributors

Current posture: the default compatibility profile remains Rust-first, but the
non-default `verified-claim` profile now promotes a narrow OIDC verification
slice into the active runtime path.

Rationale:

- The current OIDC server primarily issues *self-generated* ID Tokens. Security ROI is typically higher on
  externally supplied parsing/validation boundaries (JOSE header parsing, DCR inputs, DPoP proofs).
- The broader extracted `generated/lowstar/oidc/` tree is not generally
  promoted into the runtime path. The current source-managed exceptions are the
  `generated/lowstar/oidc/hash/` and `generated/lowstar/oidc/id_token/`
  subtrees, which we keep under version control so the strict hash path and the
  opt-in `idtoken_runtime` build stay reproducible.
- The runtime still uses Rust as the compatibility source of truth, and OIDC
  Low\* / EverParse integration remains **feature-gated** in `crates/ffi/build.rs`.

## What is linked today (default)

- EverParse structural schemas under `generated/everparse/` are linked and enforced by the build.
- JOSE Low\*/C artefacts under `generated/lowstar/jose/` are source-managed and linked where applicable.
- The extracted `generated/lowstar/oidc/id_token/` artefacts are now
  source-managed, but they are **not** linked by default and remain opt-in
  only.
- In the default compatibility profile, upstream OIDC `id_token` RS256
  required-slice verification treats the structural `check_id_token_jwt`
  precheck as **best-effort**; an unavailable local parser must not by itself
  break interoperability.
- In the default compatibility profile, OIDC `at_hash` / `c_hash`
  computation first tries the FFI helper but may still fall back to the Rust
  implementation when the native path is unavailable.

## What is linked today (`verified-claim`)

- The EverParse `IdTokenSchema` structure parser is part of the active runtime
  path and parser unavailability must fail closed.
- The source-managed extracted `HashComputation.Low` artefacts under
  `generated/lowstar/oidc/hash/` are part of the active runtime path for OIDC
  `at_hash` / `c_hash` computation.
- The remaining hand-written shim is narrowed to
  `c/hash_computation_runtime.c`, which now only supplies the host SHA
  primitive adapter and allocation helpers consumed by the extracted
  `HashComputation.Low` entrypoint.
- The extracted `generated/lowstar/oidc/id_token/IdToken_Low_Runtime.{c,h}`
  artefacts are **not** part of `verified-claim` today.
- In `verified-claim`, OIDC hash runtime unavailability or runtime failure must
  fail closed instead of falling back to the Rust implementation.
- `verify-jose` now compile-checks the opt-in
  `verified-claim,idtoken_runtime` combination so the source-managed extracted
  artefacts do not silently drift out of buildable shape.

## Opt-in modes (feature flags)

OIDC artefacts can be compiled into the Rust FFI path in opt-in configurations:

- `everparse_idtoken`: enables the generated `IdTokenSchema` EverParse entrypoints
- `lowstar_hash`: enables the source-managed extracted
  `HashComputation.Low` dispatcher/truncation artefacts plus the narrowed host
  SHA shim
- `idtoken_runtime`: links the source-managed `IdToken_Low_Runtime.c` opt-in
  layout/runtime artefact

`verified-claim` currently expands to `everparse_idtoken + lowstar_hash`. It
does **not** automatically enable `idtoken_runtime`.

See `crates/ffi/build.rs` for the exact feature gates and fail-closed checks.

## If/when promoting OIDC Low\* into runtime

Do it incrementally:

1. **Broaden source-management carefully**: today the `hash` and `id_token`
   subtrees are source-managed. Track additional `generated/lowstar/oidc/`
   artefacts in Git only when they are ready for reproducible extraction and
   review.
2. **Shadow mode**: compute both Low\* and Rust results, compare, and treat mismatches as failures only after sustained evidence.
3. **Bundle/runtime control**: ensure extracted C is self-contained and dependencies are explicit (e.g. `krml --bundle`).
4. **Claim update last**: only widen the strict-profile or released claim after
   the remaining model-to-runtime closure work replaces the current
   extracted-dispatch-plus-host-shim split with a proof-linked, source-managed
   closure.
