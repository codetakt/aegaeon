# Kani Verification (Status + How to Run)

Last updated: 2026-07-08

Status: current implementation baseline

Owner: Verification

Audience: verification reviewers, contributors

**Status**: Working with known ICE limitations (Updated 2026-05-31)
**Scope**: `crates/kani-harness`, `crates/server` (opt-in), and the Nix packaging under `nix/kani/`
**Kani Version**: 0.66.0 (Rust `nightly-2025-11-05`)

This document records the current Kani posture and the recommended entrypoints for Aegaeon.
For deeper RCA of the NixOS packaging fixes, see `docs/verification/kani/kani-nixos-fix/README.md`.

## Scope

- Kani package and sysroot posture
- local and CI-equivalent Kani entrypoints
- known Kani limitations and reproducer handling

## Canonical Documents

- `[index]` [Kani NixOS fix](kani-nixos-fix/README.md)
- `[reference]` [HashMap ICE reproducer](hashmap-ice-repro.md)
- `[runbook]` [Kani troubleshooting](troubleshooting.md)

## Reading Rule of Thumb

1. Use this README for current Kani posture and commands.
2. Treat ICE reproducer documents as diagnostics, not claim evidence.
3. Record claim-bearing Kani evidence in `../claims/` and `spec/compliance-matrix.yaml`.

## What was broken (fixed)

### 1) Sysroot panic strategy mismatch (`panic_abort` rejected)

Kani compiles user crates with `-C panic=abort`. The packaged sysroot was built with the default panic strategy (`unwind`), which makes the `panic_abort` runtime incompatible and causes Rust to fail at link-time selection:

```text
error: the crate `panic_abort` does not have the panic strategy `abort`
```

### 2) `libkani` built against the wrong `std` (E0460/E0463)

The sysroot forces a specific `std` via `--extern noprelude:std=...` (MIR-encoded `std`).
But `libkani*.rlib` was built against the toolchain `std` and then copied into the sysroot, making the `kani` runtime crate unusable under the sysroot and surfacing as:

- `E0460` (std mismatch), or
- `E0463` (“can’t find crate for kani”).

## Fix applied (repo changes)

- `nix/kani/package.nix`: build the MIR sysroot via `-Z build-std=panic_abort,std,test` with `-C panic=abort`
- Rebuild `kani_core`, `kani`, `kani_metadata` against the MIR sysroot (`--sysroot $KANI_SYSROOT`) with `-C panic=abort`
- Avoid copying duplicate `proc_macro`/`test` libs into the sysroot (MIR build-std output is the source of truth)
- Ensure wrapped `cargo-kani` relies on `setup-kani-env` for writable `KANI_HOME`/`RUSTUP_HOME` (avoid literal `'$HOME/…'` defaults that break sandboxed builds)

## How to run

Runner defaults (suite, timeouts, solver, etc.) live in `kani.toml`. Environment variables passed to `scripts/kani/run_kani.sh` override the file (CI does this to enable the regression suite + server harnesses).

### CI-equivalent (preferred)

```bash
nix build .#verify-kani -L
```

`verify-kani` runs `AEG_KANI_SUITE=regression` and `AEG_KANI_RUN_SERVER=1` by default (see `flake.nix`).

Note: `cargo-kani` uses its bundled Rust toolchain/sysroot (not your `rustup` toolchains). Prefer
the Nix entrypoints above for reproducibility.

### Local run (writes `artifacts/kani/*`)

```bash
# CI-equivalent local app; writes artifacts/kani/report.json and report.log.
nix run .#verify-kani

# Direct runner with an explicit Kani package in PATH.
nix build ".#kani'" --out-link result-kani
KANI_ROOT="$(readlink -f result-kani)"
PATH="$KANI_ROOT/bin:$KANI_ROOT/toolchain/bin:$PATH" \
  AEG_KANI_SUITE=regression \
  AEG_KANI_RUN_SERVER=1 \
  ./scripts/kani/run_kani.sh
```

## What is verified today

- Default (`scripts/kani/run_kani.sh`, `AEG_KANI_SUITE=smoke`): runs a small harness set in `crates/kani-harness` and writes:
  - `artifacts/kani/report.json`
  - `artifacts/kani/report.log`
- Regression (`AEG_KANI_SUITE=regression`): adds toolchain regression harnesses (`proof_string_*`, `proof_level*`, etc.) to detect Kani/Rust-nightly drift early.
- Server harnesses (opt-in): when `AEG_KANI_RUN_SERVER=1`, runs the `crates/server` harness shims and records results in the same report.

Best-effort note: Kani results are treated as **best-effort** until the upstream ICEs are resolved.
ICE-reproducer harnesses are kept for upstream reporting but excluded from CI gating.

The `crates/server/kani-reproducers/*.rs` files are retained outside Cargo's
integration-test target set as integration-style design inputs and reproducers.
They are not current claim evidence. CI-gated server properties should be converted into bounded
`crates/server/src/kani_test.rs` harnesses and listed in `kani.toml` before they are counted as
current Kani evidence.

Server Kani harnesses use explicit bounded models when the production data structure would be
impractical for Kani. Capacity harnesses therefore prove fail-closed overwrite behavior for the
bounded model. They are not a claim that the production `HashMap` runtime has the same fixed
capacity; runtime equivalence must be supported by ordinary Rust tests and by keeping the public
Kani-facing API free of sentinel success values.

### Soundness note (loop unwinding)

- The default flags in `kani.toml` keep Kani's default unwinding checks enabled:
  - `--unwind 16`
- Claim-bearing server Kani evidence must use those strict defaults or stricter flags.
- Diagnostic regression triage may override `KANI_EXTRA_FLAGS` to disable unwinding checks, but
  those runs are regression smoke evidence only and must not be cited as strict proof evidence.

## Known limitations

- HashMap-heavy harnesses can still trigger Kani ICEs (see `docs/verification/kani/hashmap-ice-repro.md`).
  Treat those harnesses as **reproducers**, not CI gates.
- Even when ICEs do not trigger, HashMap-heavy models are often impractical for CI due to
  state-space explosion. Prefer bounded array models plus unit tests for equivalence.
- Bounded model capacity properties must be described as model properties. They may support the
  server claim only when paired with runtime tests or type-level API checks that prevent
  sentinel values from being treated as successful runtime state.

## Recent Evidence

- 2026-08-04: `AEG_KANI_RUN_SERVER=1 cargo xtask kani` refreshed the
  artifact-producing runner on the initial-public-release tree.
  - `artifacts/kani/report.json` records `run_id=20260804T065437`,
    `status=success`, and `server_run_mode=enabled`.
  - All 9 `aegaeon-server` harnesses passed, including
    `verify_oidc_same_user_distinct_auth_sessions_have_distinct_sids`, after
    the session Kani model gained the async logout facades that production
    grew (`oidc/session/kani.rs`).
  - Repository evidence policy: only the latest run log
    (`artifacts/kani/run_20260804T065437.log`) is kept in the tree; earlier
    run logs referenced by the historical entries below were pruned at the
    initial public release and remain available in the private history.
- 2026-05-31: `AEG_KANI_SUITE=smoke AEG_KANI_RUN_SERVER=1 nix run .#verify-kani`
  refreshed the artifact-producing runner with the strict default unwinding-check posture.
  - `artifacts/kani/report.json` now records `run_id=20260531T115738`,
    `status=success`, and `server_run_mode=enabled`.
  - The smoke suite passed the two configured `crates/kani-harness` harnesses.
  - The `aegaeon-server` Kani harnesses all passed:
    `verify_client_assertion_replay_window_bounds`,
    `verify_oidc_logout_ttl_normalization_bounds`,
    `verify_oidc_logout_idempotent_jti`,
    `verify_oidc_logout_session_rotates_after_logout`,
    `verify_oidc_logout_session_ttl_prunes_logged_out_entries`, and
    `verify_oidc_logout_future_timestamp_prunes_fail_closed`,
    `verify_oidc_logout_capacity_fails_closed_without_overwrite` and
    `verify_oidc_logout_client_capacity_fails_closed_without_overwrite`.
  - The two capacity harnesses above are bounded-model evidence. They prove that the explicit
    Kani model fails closed without overwriting existing sessions/clients when full; they are not
    evidence for a fixed production `HashMap` capacity.
  - Runtime regression tests pair this bounded evidence with the public `OidcSessionStore`
    `try_*` APIs so failed session allocation or client association is not represented as a
    sentinel successful `sid`.
  - The detailed local log is `artifacts/kani/run_20260531T115738.log`.
- 2026-05-29: `nix run .#verify-kani` refreshed the local artifact-producing runner
  with the CI-equivalent regression suite and server harnesses enabled.
  - `artifacts/kani/report.json` now records `run_id=20260529T172759`,
    `status=success`, and `server_run_mode=enabled`.
  - The regression suite passed all 11 configured `crates/kani-harness`
    harnesses.
  - The `aegaeon-server` Kani harnesses all passed:
    `verify_oidc_logout_future_timestamp_prunes_fail_closed`,
    `verify_oidc_logout_idempotent_jti`,
    `verify_oidc_logout_session_rotates_after_logout`, and
    `verify_oidc_logout_session_ttl_prunes_logged_out_entries`.
  - The detailed local log is
    `artifacts/kani/run_20260529T172759.log`; it is a generated artifact and
    is referenced from the source-managed summary files.
- 2026-03-10: `nix build .#verify-kani -L` succeeded in the pinned Nix lane that
  backs the released server claim.
  - The authoritative evidence for product wording is the pinned `verify-kani`
    build, not ad-hoc direct `cargo-kani` invocations outside that wrapper.
  - Diagnostic post-build reruns in restricted sandboxes may fail to locate the
    Kani sysroot/runtime or may hit network restrictions; treat those as local
    environment issues rather than claim evidence.
  - `scripts/kani/run_kani.sh` was hardened on 2026-03-10 to fix repository-root
    resolution under nested / sandboxed invocation.

## History

Historical triage notes were consolidated into:

- `nix/kani/README.md` (quick checklist / operational notes)
- `docs/verification/kani/kani-nixos-fix/README.md` (deep RCA of the NixOS packaging fix)
