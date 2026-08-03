# Raw JSON Phase 1 Backend Contract

Last updated: 2026-07-08

Status: historical record

Owner: Program Management

Audience: maintainers, planning contributors

This note records the Phase 1 backend / ABI decisions that should remain stable
while the first verified structural parser is being implemented.

It narrows the broader work packages in
`raw-json-phase1-structural-parser-plan.md` down to the concrete contract
choices needed before extraction and FFI work begin.

## Decision Summary

### 1. Reserve the backend name `verified-structural-v1`

The first verified raw-byte backend should be named:

- Rust enum label: `VerifiedStructuralV1`
- string form: `verified-structural-v1`

Rationale:

- the name describes what Phase 1 actually provides: verified structural
  parsing, not end-to-end semantic decoding
- the `v1` suffix leaves room for future ABI-compatible or ABI-breaking parser
  upgrades without overloading one permanent "verified" label

### 2. Keep Phase 1 non-claim-bearing

Landing the Phase 1 backend does **not** by itself move any surface to
`RawJsonClaimBoundary::RawBytes`.

Why:

- Phase 1 still ends in a compatibility adapter
- later phases still need typed decoders before a surface can claim raw-byte
  verified semantics

Operational rule:

- `current_claim_boundary_for_surface(...)` stays unchanged through Phase 1
- the new backend may exist in code before any surface is allowed to publish a
  stronger claim posture

### 3. Keep the new backend narrowly selectable and non-claim-bearing

The structural backend is now selectable, but only for `jose-header`.

Why:

- Phase 1 is intentionally scoped to a single first surface.
- Other surfaces still rely on broader compatibility decoding and must remain
  fail-closed for this backend.
- Runtime selectability does not change the released claim boundary.

Current rule:

- `verified-structural-v1` may be selected for `jose-header`
- all non-`jose-header` surfaces must still reject
  `verified-structural-v1` fail-closed
- `current_claim_boundary_for_surface(...)` remains unchanged
- the default backend remains `SerdeCompat`

## Preferred Structural ABI

Phase 1 should expose a structural parse result that is smaller than a generic
JSON AST but rich enough for later typed decoders.

Preferred Rust-side shape:

```rust
enum RawJsonStructuralValueKind {
    String,
    Null,
    Number,
    Bool,
    Object,
    Array,
}

struct RawJsonStructuralSpan {
    offset: u32,
    len: u32,
}

struct RawJsonStructuralMember {
    key: Vec<u8>,
    value_kind: RawJsonStructuralValueKind,
    value_span: RawJsonStructuralSpan,
}

struct RawJsonStructuralParseResult {
    members: Vec<RawJsonStructuralMember>,
    consumed_len: u32,
}
```

Required semantics:

- `members` preserve top-level object order
- duplicate keys are preserved at admission
- `value_span` points at the original raw value bytes in the input
- `consumed_len` reports the end of the first fully consumed top-level object

Not required in Phase 1:

- typed semantic interpretation of member values
- recursive decoding of nested objects/arrays
- promotion of broad generic JSON semantics into the claim

## Error Mapping Contract

The Phase 1 structural parser should map into the existing `RawJsonObjectError`
taxonomy as follows:

- malformed JSON syntax / invalid string escaping / truncated input:
  `RawJsonObjectError::InvalidJson`
- non-object top-level shape:
  `RawJsonObjectError::InvalidShape`
- bytes after the first fully consumed object:
  `RawJsonObjectError::TrailingBytes`
- duplicate keys:
  still enforced at the existing helper boundary in Phase 1

This preserves outward behavior while the backend under the helper changes.

## Adapter Contract

Phase 1 keeps these public Rust helper contracts stable:

- `parse_json_object_members_with_report_for_surface(...)`
- `deserialize_json_object_without_duplicate_keys_with_report_for_surface(...)`

Therefore the first structural backend must initially feed a compatibility
adapter:

```text
verified structural parser
  -> structural member IR
  -> compat adapter
  -> RawJsonObjectMember / current deserialize helper
```

The adapter may still decode value spans with compatibility code, but the
selected Phase 1 byte-level admission path must no longer reparses the full
object through the old whole-object `serde_json` entrypoint.

## First Surface Rule

The first wired surface should be `jose-header`.

Why:

- narrow schema
- already paired with a dedicated Low*/C semantic validator
- provides the cleanest handoff into the typed-decoder work in Phase 2

Do not use this contract first for:

- `generic-object`
- `request-object`
- `client-registration`

## Landing Zones

Use these repository locations unless a later design note explicitly replaces
them:

- backend / claim selector:
  `crates/jose/src/raw_json.rs`
- structural Rust wrapper types:
  `crates/jose/src/raw_json_structural.rs`
- JOSE header structural adapter:
  `crates/jose/src/json_lowstar.rs`
- extracted parser bridge:
  `crates/ffi/src/...` plus generated Low*/C artefacts

## Acceptance Condition for WP1

WP1 is complete when all of the following are true:

- the backend name is fixed as `VerifiedStructuralV1`
- the Phase 1 structural ABI is source-managed
- the non-claim-bearing rule is explicit in docs
- the repository has a dedicated Rust-side structural IR module ready for FFI
  integration
- no unsupported surface can silently select `verified-structural-v1`
