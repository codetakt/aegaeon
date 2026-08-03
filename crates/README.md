# `crates/`

This directory contains the Rust crates that make up the Aegaeon workspace.

## Workspace membership

The workspace is defined in the repository root `Cargo.toml`.

**Members** (built by default):

- `crates/server` — OAuth 2.0 / OIDC server implementation
- `crates/client` — client library / helpers used by tests and examples
- `crates/jose` — JOSE implementation (JWS/JWE/JWK, test vectors, etc.)
- `crates/ffi` — Rust FFI bindings to extracted/auxiliary C code
- `crates/observability` — telemetry/metrics/tracing support
- `crates/loadtest` — load-testing CLI and scenarios

**Excluded** (not built by default; used for verification or special workflows):

- `crates/pure` — minimal “pure” code used as a dependency for model checking
- `crates/kani-harness` — Kani harness crate (see `scripts/kani/run_kani.sh`)

## Notes

- Build outputs (`target/`) and local verification artefacts under `crates/*/artifacts/`
  are intentionally **ignored** by Git.
- If you add a new crate, update the workspace membership list in `Cargo.toml`
  and keep this document in sync.
