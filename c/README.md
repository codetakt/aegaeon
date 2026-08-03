# `c/`

This directory contains small, auditable C sources that are part of Aegaeon’s
build and verification pipeline.

## What lives here

- **FFI/runtime glue** compiled into the Rust FFI crate (see `crates/ffi/build.rs`).
- **Error helpers** used by generated parsers/extracted code (EverParse/Low*).
- **Test and verification harness code**, including constant‑time timing tests
  (see `tests/constant_time/run.sh`) and `dudect` support (used from `flake.nix`).

## What should NOT live here

- **Large generated artifacts**. Prefer `generated/` (EverParse outputs) or the
  dedicated extraction output directories.
- **Build outputs** (object files, archives, logs, etc.).
- **Secrets** or environment‑specific dumps.

## Notes for contributors

- Keep changes minimal and easy to review; this directory is security sensitive.
- If a file is tool‑generated, document its source and regeneration command and
  consider relocating it under `generated/` instead of `c/`.
