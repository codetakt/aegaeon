# DCR EverParse Runtime Posture (Self-Check)

Last updated: 2026-07-07

Status: current implementation baseline

Owner: Governance

Audience: contributors, maintainers

## Ownership
- Owner: Security/Verification
- Review by: Core/Server

## Summary

- The current EverParse DCR schema (`fstar/lowparse/DCR.3d`) validates a length-prefixed **binary structure**, not raw RFC 7591 JSON.
- Enabling EverParse at runtime therefore does **not** materially strengthen validation of the original JSON input received over the network.
- Instead we provide an optional defense-in-depth **self-check**: canonical binary encoding of already-decoded DCR fields -> EverParse validation (`policy.dcrEverparseRuntimeEnabled=true`).
- Any self-check failure is treated as an **internal bug or configuration/schema drift**, and is handled as 500 `server_error` (fail-close), not as a client error.

## Decision (2025-12-17)

- Do not use EverParse to validate raw RFC 7591 JSON at runtime.
- Provide an optional EverParse self-check of a canonical binary encoding derived from already-decoded DCR fields, gated by `policy.dcrEverparseRuntimeEnabled=true` in the active PostgreSQL-backed Environment policy.
- Treat self-check failures as internal errors (500 `server_error`), not as client errors.

## Background

- The current EverParse schema for DCR is defined in `fstar/lowparse/DCR.3d` and targets a length-prefixed binary representation.
- A “runtime EverParse path” therefore validates the server’s internal canonical encoding, not the original JSON text received over the network.
- The DCR self-check currently uses the `DCR.3d` entrypoints (`DcrCheck*` in `generated/everparse/DCRWrapper.c`) via `crates/ffi/src/dcr_parser.rs`.
- `DcrRegistration.3d` is generated and compiled (`generated/everparse/DcrRegistration*.c` are built in `crates/ffi/build.rs`) but is not invoked from Rust yet (no call path to `DcrRegistrationCheckDcrRegistrationPayload`).

## Rationale

- **Security claims must match reality**: “verified parsing of RFC 7591 JSON input” is not supported by the current schema and would require a different, verified JSON pipeline (separate epic).
- **Defense-in-depth still helps**: the self-check can catch encoder bugs, schema drift, or unexpected boundary mismatches before crossing FFI layers.
- **Operational safety**: keep the feature opt-in so production is not coupled to parser availability or build-time constraints.

## Implementation

- Toggle: `policy.dcrEverparseRuntimeEnabled=true` enables the self-check.
- Server integration:
  - Canonical encoder + entrypoint: `crates/server/src/dcr/everparse.rs` (`everparse_self_check_registration_with_runtime`)
  - Route hook: `crates/server/src/web/dcr_profile_validation/metadata.rs`
- EverParse wrapper entrypoints:
  - `crates/ffi/src/dcr_parser.rs` (`check_registration_request`, etc.)

## Operational Guidance

- Recommended default: **OFF** (`policy.dcrEverparseRuntimeEnabled=false`).
- Enable in CI/canary policies only if you want the additional drift detection.
- Note: the native EverParse parser is unavailable in `cfg(test)`, `cfg(kani)`, or `no_mbedtls` builds (`DcrParseError::ParserUnavailable`). With `policy.dcrEverparseRuntimeEnabled=true`, this is treated as a 500 internal error by design (fail-close).

## Future Work (Separate Epic)

- If the project wants to claim “verified parsing of RFC 7591 JSON input,” we need a verified JSON ingestion strategy (verified JSON parser and/or schema-level verification of the JSON representation), not the current binary self-check.
