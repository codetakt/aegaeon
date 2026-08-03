# JOSE Header Parser – Integration Plan

Last updated: 2026-07-07

Status: active plan

Owner: Program Management

Audience: maintainers, planning contributors

This document tracks the execution plan for completing the F*/EverParse → Low*/C → Rust pipeline.
The Rust TLV decoder has landed in `crates/jose/src/tlv.rs`; the remaining work is tracked as TODOs
below.

## 1. F* TLV parser implementation

- [x] Remove `assume parse_json_pairs` in `Jose.HeaderParser.fst` and implement TLV traversal using
  LowStar.Buffer.
  - [x] Express buffer bounds and length checks (`key_len`/`value_len`) as F* preconditions.
    - Implemented: `decode_all_entries_aux_result` validates bounds and enforces length checks.
  - [x] Add ASCII validation lemmas/helpers to guarantee `key` is ASCII-only.
    - Implemented: `string_of_ascii` / `ascii_byte` / `ascii_bytes_to_string`.
  - ⚠️ Note: round-trip lemmas for `string_of_ascii` / `list_of_string` are `assume`-based due to the
    F* standard library abstraction barrier. See `docs/verification/claims/assumptions/current-register.md`.
  - [x] Implement multi-byte UTF-8 encoder lemmas (`lemma_valid_{two,three,four}_byte_prefix`,
    `lemma_encode_utf8_scalar_valid`) to eliminate the ASCII-only constraint.
  - [x] Add canonical checks (`canonical_utf8_scalar`, length lemmas,
    `lemma_encode_utf8_scalar_canonical`) to prevent overlong encodings.
  - [x] Implement UTF-8 scalar decoder helpers (`decode_utf8_scalar_nat`,
    `lemma_decode_utf8_scalar_inverse`) and prove encoder/decoder round-trips.
  - [x] Completed the multi-byte UTF-8 decoder implementation and proofs. This plan is the canonical
    completed implementation record for the TLV decoder work.
- [x] Replace `parse_jwe_buffer` / `parse_jws_buffer` with the new implementation while preserving
  compatibility with existing `parse_jwe_micro` / `parse_jws_micro` call sites.
  - Implemented: `parse_jwe_buffer` / `parse_jws_buffer` call the micro-language parsers via
    `parse_with_tlv`.
  - Update: the `store_entries_into_buffer` VC resolution is documented in
    `docs/verification/fstar/store-entries-vc-resolution.md` (out of scope for this plan).
  - Commit: fce1e46 (extract `Jose.Utf8Lemmas` refactor)
- [x] Introduced `Jose.TlvResultSpec` and exposed a concrete implementation for
  `parse_tlv_entries_result`, duplicate-key elimination, and allowlist lemmas. `Jose.TlvInterface`
  is now a re-export of this module and the previous `assume` declarations were removed.
- [x] Updated `Jose.JsonHeaderSpec.lemma_parse_results_equiv_*` to align directly with the TLV-side
  invariants (`no_duplicate_keys` / `List.for_all key_allowed`) and the `Jose.TlvResultSpec`
  implementation.

## 2. Using EverParse generated artefacts

- [x] Call `JoseHeaderValidateJoseHeaderEntry` (C) / `JoseHeaderCheckJoseHeaderEntry` (wrapper),
  generated from `fstar/lowparse/JoseHeader.3d`, from F* to centralise TLV entry validation.
  - Interface: add a wrapper callable from `Jose.HeaderParser`, for example:
    `uint64_t JoseHeaderValidateJoseHeaderEntry(uint8_t *ctx, ErrFn, uint8_t *input, uint64_t len, uint64_t start)`,
    and make it switchable with the handwritten TLV path.
  - Update (2026-05-15): added `Jose.HeaderParser.Runtime` as a Stack-level bridge around the
    generated entry validator. The bridge calls a dedicated C symbol
    (`Jose_HeaderParser_Runtime_jose_header_entry_error_code`) that forwards to
    `JoseHeaderGetJoseHeaderEntryErrorCode`, preserving the coarse EverParse framing result inside
    the extracted Low*/C surface without reintroducing buffer reads into the pure seq parser.
  - Error mapping: align EverParse errors with Rust `JoseHeaderParseError` variants.
    Update (2026-05-15): the JOSE entry wrapper now surfaces EverParse error kinds to Rust instead
    of collapsing everything to a boolean. `EVERPARSE_ERROR_NOT_ENOUGH_DATA` maps to
    `JoseHeaderParseError::Truncated`; other EverParse entry-validator failures still fail closed as
    `EntryValidationFailed`. Non-ASCII / UTF-8 / trailing-byte enforcement remains in the
    handwritten TLV parser because the current `JoseHeader.3d` schema models framing only.
  - Note: EverParse3d `as_parser` (spec parser) cannot be executed directly from external modules via
    `LowParse.Spec.Base.parse` because `EverParse3d.Prelude.parser` is abstracted in a `.fsti`. For
    runtime integration, use either `validate__jose_header_entry` (Stack validator) or the extracted
    C validator (`JoseHeaderValidateJoseHeaderEntry`) as the entry point.
- [x] Rust: added `ffi::jose_header::check_jose_header_entry` so the `aegaeon-jose` TLV parser can
  run entry-level EverParse validation (B1) when `everparse_jose_header_entry` is enabled.
  - Update (2026-05-14): the exported `ffi` TLV bridge now applies the same
    entry-validator policy as `aegaeon-jose`; only `ParserUnavailable` is
    compat-tolerated, while validator rejection itself fails closed.
  - Update (2026-05-15): `ffi::jose_header::check_jose_header_entry` now calls
    the extracted `Jose_HeaderParser_Runtime_validate_entry_buffer` symbol
    rather than binding Rust directly to `JoseHeaderGetJoseHeaderEntryErrorCode`.
    This means the Rust TLV path and exported FFI TLV ABI now exercise the same
    generated Low*/C runtime bridge.
- [x] Implemented the FFI bridge (`crates/jose/src/ffi/tlv.rs`) and re-exported
  `parse_jose_header_tlv` via a C ABI (including safe wrappers around `decode_tlv_entries` and free
  functions). Rust unit tests cover both success and failure cases.
- [x] Added cbindgen wiring so extracted Low*/C artefacts and the Rust FFI stay connected (generates
  `aegaeon_tlv.h` via build-dependencies + build.rs).
  - [x] Make the EverParse-generated module usable from within `Jose.HeaderParser` for a runtime
    bridge while keeping the pure seq-based spec isolated.
    - Implemented as `Jose.HeaderParser.Runtime` plus a small C forwarding bridge compiled into the
      ffi/native build.
  - [x] Align the remaining F* runtime error paths with Rust for the non-framing checks
    (ASCII policy / UTF-8 / trailing bytes).
    - Update (2026-05-15): ASCII-key rejection is now aligned across the Low* JSON path, the
      compat fallback, and the `ffi_jose_header_tlv` normalization path.
    - Update (2026-05-15): direct Low* JSON-entry UTF-8 decode failures now report the same text as
      the handwritten TLV parser (`header key/value is not valid UTF-8`).
    - Update (2026-05-15): whole-stream trailing bytes are now classified explicitly on both
      surfaces. JSON header admission fails as
      `JsonError::TrailingBytes(\"trailing bytes after JOSE header JSON object\")`, and raw TLV /
      FFI parsing maps `JoseHeaderParseError::TrailingBytes` into the same top-level error class.

## 3. Low*/KaRaMeL extraction and scripts

- [x] Ensure `scripts/extraction/run_jose_lowstar.sh` does not stop due to unimplemented errors such
  as `Jose.Jwe_header.parse_b64` by adding the required F* stubs or C implementations.
  - Update (2026-05-15): the default verification-shell path now completes end-to-end again.
    Extraction now includes `Jose.LowStar.Json.Types`, so KaRaMeL emits the
    `json_parse_free_result{,_data}` helpers instead of warning about the unresolved
    `json_parse_result_c` type.
- [x] Once extraction succeeds, document the steps for wiring the generated artefacts under
  `generated/lowstar/jose/` into the Rust FFI build (build scripts + test cases).
  - Update (2026-05-15): `crates/ffi/build.rs` already consumes `generated/lowstar/jose/` as an
    include root, and the current extraction/spec docs plus `verify-jose` / `verify-lowstar`
    describe the supported test and drift-check entrypoints.

## 4. Rust FFI wiring and tests

- [x] Finalise the F* → C → Rust function signatures and add the new extern declarations plus safe
  wrappers to `crates/ffi`.
  - Update (2026-05-14): `crates/ffi/src/tlv.rs` now exposes
    `parse_jose_header_tlv_via_abi`, which owns the C result buffer, converts
    entries back into Rust strings, frees the ABI allocation on all paths, and
    maps ABI parse failures back into structured Rust errors.
- [x] Add a path in `crates/jose/src/jws.rs` to switch from the Rust-only TLV decoder to the FFI
  call (behind a feature flag).
  - Update (2026-05-14): added the opt-in `ffi_jose_header_tlv` feature in
    `crates/jose/Cargo.toml`; `crates/jose/src/jws.rs` and
    `crates/jose/src/jwe.rs` now normalize JOSE header JSON into internal TLV
    and route it through `ffi::tlv::parse_jose_header_tlv_via_abi` when the
    feature is enabled.
- [x] Ensure RFC 7520 vectors and the existing unit tests pass on both the native and extracted
  paths.
  - Update (2026-05-14): raw TLV parity between `aegaeon-jose` and the exported
    `ffi` ABI is covered by unit tests in `crates/jose/src/tlv.rs`, the
    existing `crates/jose/tests/tlv_parity.rs` integration suite remains green
    under `--features ffi_jose_header_tlv`, and
    `cargo test -p aegaeon-jose --test rfc7520_vectors --features ffi_jose_header_tlv`
    passes in the CI shell.
  - Update (2026-05-15): `crates/ffi/tests/jose_header_runtime_test.rs` now
    exercises the native `check_jose_header_entry(...)` bridge directly in the
    verification shell, covering valid framing, truncated entries, and the
    current framing-only scope of the EverParse schema.

## 5. CI / documentation updates

- [x] Update TODOs in `docs/program-management/initiatives/jose/parser/header-parser-spec.md` as the
  F* implementation and FFI wiring complete.
- [x] Ensure CI validates `scripts/extraction/run_jose_lowstar.sh` execution results and captures
  actionable diagnostics on failure.
  - Update (2026-05-15): `nix run .#verify-lowstar` is now the shared extraction gate used by the
    hosted verification/security lanes. It reruns `run_jose_lowstar.sh`, checks
    `generated/everparse`, `generated/lowstar`, and `artifacts/karamel` for drift, and fails on
    legacy EverParse wrapper aliases or missing `error_code` ABI parameters.

## 6. Recommended execution order (Updated 2025-11-10)

1. **EverParse integration** – prioritise the §2 wiring of `validate__jose_header_entry` and error
   mapping so TLV entry validation can run as an opt-in boundary defence (B1).
2. **Low*/KaRaMeL prep** – follow §3 to define the `Jose.LowStar` APIs, migrate to machine integers,
   and update extraction scripts so KaRaMeL does not fail.
3. **Rust FFI & tests** – follow §4 to add new externs, switch the production tests to the extracted
   path behind a feature flag, and keep RFC 7520/TLV parity green on both paths.
4. **CI & docs** – follow §5 to keep checklists up to date and continuously run
   `cargo test -p aegaeon-jose --test rfc7520_vectors` plus TLV sample checks in CI.

---
Update the checkboxes in each section in order. When a task completes, add links to the relevant
PR/commit and any associated artefacts.

## Ticket (hardening, out of DoD scope)

**Title:** Replace JOSE Header parser with verified EverParse pipeline

### Scope & Exit Criteria
- Wire EverParse-generated helpers into `Jose.HeaderParser` and Rust, with a switchable path against
  the handwritten TLV implementation.
- Align Rust error mapping with EverParse error codes (remove ambiguity between TLV/JSON paths).
- Keep existing tests and conformance checks green on both paths (TLV parity, RFC 7520, etc.).
- Ensure the extracted path runs reliably as opt-in (e.g. `GENERATE_EVERPARSE_LOWSTAR=1`).

### Constraints / Assumptions
- Keep the current handwritten TLV path until parity is confirmed (no regressions allowed).
- Extraction blockers such as BitFields/Warning26 are out of scope (handled in extraction-hardening).
- Keep IdToken/HashComputation verification-only (no changes to runtime FFI linkage).

### Diagnostics
- If extraction fails due to BitFields/Warning26, preserve the logs and hand off to a separate ticket.

### Artifacts
- Updated version of this document, test logs (both paths green), and any required CI changes.
## Dependency Overview
- Start Phase 2 (EverParse integration) after Phase 1 (F* TLV implementation) completes.
- Phase 2 complete → Phase 3 (extraction) → Phase 4 (Rust FFI) → Phase 5 (CI/docs).

### Note: store_entries_into_buffer VC resolution

Treat `docs/verification/fstar/store-entries-vc-resolution.md` as the primary source for the
resolution steps and common pitfalls.
