# Raw JSON Phase 1 Structural Parser Plan

Last updated: 2026-07-08

Status: historical record

Owner: Program Management

Audience: maintainers, planning contributors

This document turns Phase 1 of
`../../../initiatives/jose/raw-json-optimal-architecture-plan.md` into an execution-ready work
breakdown.

Use `raw-json-phase1-contract.md` as the authority for the concrete backend
name and structural ABI choices within this phase.

Phase 1 is intentionally limited:

- add a verified structural parser
- keep the released claim unchanged
- preserve the existing `raw_json` public contract through adapters
- prepare `jose-header` for Phase 2 promotion

It is not the phase where we claim end-to-end `raw-bytes` coverage for any
surface. That claim move happens only after a surface-specific typed decoder is
in place.

## Goal

Replace the current whole-object `serde_json` byte-level admission step for a
single selected surface path with a verified structural parser that proves:

- top-level object shape
- ordered member preservation
- duplicate-key preservation at admission
- whole first-object consumption
- trailing-byte classification
- per-member value-kind classification

The public Rust helper should still return the current duplicate-preserving
member representation until later phases replace the compatibility adapter.

## Out of Scope

- widening any surface from `top-level-object-members` to `raw-bytes`
- broad verified semantic decoding for Request Object, DCR, or federation
- removing `serde_json::Value` from all call sites
- promoting `generic-object`
- changing the current `verified-claim` release wording

## Preferred Phase 1 Contract

The preferred verified structural parser output is:

```text
raw bytes
  -> verified structural parse result
     - ordered top-level members
     - decoded key bytes
     - value kind tag
     - raw value span in the original input
     - consumed length / trailing-byte status
  -> Rust adapter
  -> current RawJsonObjectMember contract
```

### Why this contract

- It is smaller than a generic JSON AST.
- It preserves enough information for later typed decoders.
- It allows Phase 1 to keep the current public helper shape without claiming
  that broad semantic decoding is verified.
- It lets Phase 2 replace only the adapter for `jose-header`.

### Preferred Rust-side structural IR

The exact names may change, but the Phase 1 ABI should support a Rust wrapper
roughly equivalent to:

```rust
enum RawJsonStructuralValueKind {
    String,
    Null,
    Number,
    Bool,
    Object,
    Array,
}

struct RawJsonStructuralMember {
    key: Vec<u8>,
    value_kind: RawJsonStructuralValueKind,
    value_offset: u32,
    value_len: u32,
}

struct RawJsonStructuralParseResult {
    members: Vec<RawJsonStructuralMember>,
    consumed_len: u32,
}
```

Design notes:

- `key` should be decoded bytes, not a `serde_json::Value` key wrapper.
- `value_offset` / `value_len` should point into the original input so later
  typed decoders can operate directly on the raw surface bytes.
- `consumed_len` must let Rust classify trailing bytes without reparsing the
  whole object.

## Compatibility Adapter Rule

Phase 1 keeps the current Rust-facing helper contract:

- `parse_json_object_members_with_report_for_surface(...)`
- `deserialize_json_object_without_duplicate_keys_with_report_for_surface(...)`

That means the verified structural parser must initially sit *under* a
compatibility adapter.

The preferred adapter behavior is:

1. verified parser returns structural members plus value spans
2. Rust validates duplicate-key policy at the existing helper boundary
3. each raw value span is decoded individually only as needed for the current
   compatibility surface
4. broad whole-object `serde_json` admission is removed from the selected
   Phase 1 path

This still leaves semantic decoding on a compat footing, which is acceptable in
Phase 1 because the claim boundary remains `top-level-object-members`.

## Selected First Surface

Phase 1 should start with `jose-header` only.

Reasons:

- the downstream schema is narrow
- the parser already feeds a dedicated Low*/C policy-enforcement bridge
- the next phase can replace the compat adapter with a typed decoder without
  first solving open-ended JSON semantics

Do not start with:

- `generic-object`
- `request-object`
- `client-registration`

Those surfaces still rely too heavily on broad semantic decoding and create a
wider regression surface.

## Work Packages

### WP1. Freeze the Phase 1 backend contract

Deliverables:

- choose the new backend variant name in `RawJsonBackend`
- define the non-claim-bearing structural parser ABI
- define Rust-side structural wrapper types
- document how structural parse errors map into `RawJsonObjectError`

Preferred decisions:

- keep the new backend name versioned, e.g. `VerifiedStructuralV1`
- keep `current_claim_boundary_for_surface(...)` unchanged in Phase 1
- keep env/backend selection surface-specific

Exit criteria:

- backend name and ABI are documented
- no ambiguity remains about whether Phase 1 changes the released claim

### WP2. Add the verified structural parser spec and extraction entrypoint

Deliverables:

- F*/Low* spec for top-level object-member structural parsing
- extracted C entrypoint for the structural parser
- proof obligations for:
  - object-shape recognition
  - member ordering
  - consumed-length accounting
  - trailing-byte classification
  - value-kind tagging

Non-goals:

- full semantic decode of nested values
- typed JOSE header semantics

Exit criteria:

- the extracted entrypoint is callable from Rust
- proof and extraction artefacts are reproducible

### WP3. Add Rust FFI and structural wrapper types

Deliverables:

- `crates/ffi` externs and safe wrappers for the structural parser
- owned Rust wrapper types for structural members and parse result
- buffer lifetime / free-path tests

Preferred file targets:

- `crates/ffi/build.rs`
- `crates/ffi/src/lib.rs`
- `crates/ffi/src/...` (new raw JSON structural module if needed)

Exit criteria:

- Rust can call the extracted structural parser and free all outputs correctly

### WP4. Integrate the backend into `aegaeon_jose::raw_json`

Deliverables:

- `RawJsonBackend` grows the structural backend variant
- `raw_json_surface_metadata(...)` can select that backend for `jose-header`
- a compatibility adapter converts structural members into
  `Vec<RawJsonObjectMember>`

Rules:

- do not change `ALL_RAW_JSON_SURFACES`
- do not change `current_claim_boundary_for_surface(...)`
- do not change default claim wording

Preferred file targets:

- `crates/jose/src/raw_json.rs`
- `crates/jose/src/json_lowstar.rs`

Exit criteria:

- `jose-header` can run through the structural backend behind the existing
  helper boundary
- all other surfaces remain on `SerdeCompat`

### WP5. Add parity and regression evidence

Deliverables:

- structural parser vs compat helper parity tests for accepted/rejected
  top-level object cases
- tests for:
  - duplicate keys
  - trailing bytes
  - non-object top-level shapes
  - escaped strings
  - nested arrays / objects as member values
  - boundary-size cases
- fail-closed backend-selection tests for unsupported overrides

Preferred file targets:

- `crates/jose/src/raw_json.rs`
- `crates/jose/src/json_lowstar.rs`
- `crates/jose/tests/...` (new dedicated structural parity suite if needed)

Exit criteria:

- the structural backend produces the same current helper output for the
  Phase 1 surface on all covered cases

### WP6. Add CI / extraction gates

Deliverables:

- verification-shell command that exercises the structural parser path
- drift gate for any new generated artefacts
- targeted test lane for the structural backend

Preferred commands to support:

- `nix run .#verify-lowstar`
- `nix develop .#ci --command cargo test -p aegaeon-jose raw_json::tests:: --lib`
- a new targeted structural parser test command if a dedicated suite lands

Exit criteria:

- CI can detect structural parser drift and parity regressions before merge

## Suggested Commit Sequence

1. contract / ABI doc and backend naming
2. F* / extraction entrypoint
3. Rust FFI wrapper
4. `raw_json` backend plumbing
5. compatibility adapter
6. parity tests
7. CI / docs refresh

Each step should remain non-claim-bearing until the `jose-header` typed decoder
exists.

## Acceptance Checklist

- [x] structural backend exists but does not yet change released claim posture
- [x] `jose-header` is the only surface wired to the new backend in Phase 1
- [x] broad whole-object `serde_json` admission is gone from the selected
      Phase 1 byte-level path
- [x] compatibility adapter preserves current `RawJsonObjectMember` behaviour
- [x] duplicate/trailing/non-object regressions are covered
- [x] extraction and Rust FFI outputs are reproducible
- [x] CI runs the new structural parser evidence lane

Status note (2026-05-18):

- `aegaeon-jose --lib` passes with the structural adapter path enabled in-tree.
- `AEGAEON_RAW_JSON_BACKEND_JOSE_HEADER=verified-structural-v1` targeted tests
  pass and keep all non-`jose-header` surfaces fail-closed.
- `nix build .#server` and `nix build .#verifyJose` both succeed with the
  extracted structural parser artefacts and FFI/runtime bridge wired in.

## Phase 1 Exit Decision

Phase 1 is complete when the repository can truthfully say:

- we have a verified structural parser for the first selected surface path
- we still intentionally keep the released claim at
  `top-level-object-members`
- the next step is no longer "replace raw-byte admission", but
  "replace the compatibility adapter with a typed surface decoder"

That is the handoff into Phase 2 (`jose-header` promotion).

Current assessment (2026-05-18): this exit condition is now satisfied for the
Phase 1 scope defined in this document. The next implementation step is Phase 2
typed `jose-header` decoding/promotion rather than additional Phase 1 backend
plumbing.
