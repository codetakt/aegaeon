# JOSE JSON ↔ TLV: Status & Open Items

Last updated: 2026-07-07

Status: active plan

Owner: Program Management

Audience: maintainers, planning contributors

This document tracks the remaining work required to keep JOSE header policy consistent
between the JSON (spec-mandated) and TLV (internal) representations. It deliberately
separates “verified policy enforcement” from “verified parsing”.

## Current posture

Last reviewed: 2026-04-23

### JSON path (network-facing)

- **JWS / JWE**
  - Raw JSON decoding: Rust `serde_json` tokenization with a duplicate-preserving
    object visitor (no intermediate `Value` object for JOSE headers)
  - Policy enforcement: extracted Low*/C bridge
    (`crates/jose/src/json_lowstar.rs::parse_json_header_lowstar`
    -> `ffi::parse_json_entries_safe`)
  - Header construction:
    - JWS: `crates/jose/src/jws.rs`
    - JWE: `crates/jose/src/jwe.rs`
  - Compatibility posture:
    - default build: `JsonError::ParserUnavailable` falls back to the local
      serde-based `(String, String)` extraction
    - `--features verified-claim`: `ParserUnavailable` fails closed and the
      local fallback is not used

### TLV path (internal / hardening)

- TLV decoding is available as an internal representation (`crates/jose/src/tlv.rs`).
- An **opt-in** EverParse entry-level validator can be enabled via the
  `everparse_jose_header_entry` feature (defence-in-depth; not a JSON parser).
- In `--features verified-claim`, `ParserUnavailable` from that entry-level
  validator is treated as fail-closed instead of being silently ignored.
- Validator rejection itself now fails closed across both compat and
  `verified-claim` profiles; only `ParserUnavailable` remains compat-tolerated.

## What this does *not* claim

- The runtime does not use a verified JSON parser on raw bytes: `serde_json` remains the first stage.
- The raw stage now preserves duplicate keys and string/null member shape for JOSE
  headers, but the tokenization itself is still not proof-linked.
- The `verified-claim` profile removes the local serde fallback, but it does **not**
  remove the raw-byte `serde_json` front-end yet.
- EverParse validation here is B1 (“self-check on internal TLV”), not a replacement for
  network-facing JSON verification.

## Open items worth keeping

1. **Optional raw-byte promotion prep**
   - The released claim boundary is already fixed at the duplicate-preserving
     `top-level-object-members` interface that feeds `parse_json_header_lowstar`.
   - If a future phase promotes the boundary to raw bytes, treat that as an
     optional enhancement with its own parser-selection decision, rollout plan,
     and CI / documentation evidence refresh.
   - Keep that optional track aligned with
     `docs/verification/claims/verification-maturity-status/gaps-and-promotion-work.md` and
     `docs/verification/workplans/verification-boundary-roadmap.md`.
   - Prep steps for that optional track:
     1. Choose the byte-level ingress contract: a verified parser that produces
        the existing duplicate-preserving top-level object-member representation,
        or a canonicalized intermediate representation whose invariants are
        proven equivalent before `parse_json_header_lowstar`.
     2. Specify surface-by-surface rollout rules for the shared
        `aegaeon_jose::raw_json` dispatch point (`generic-object`,
        `jose-header`, `request-object`, `client-registration`,
        `oidc-id-token-payload`, `jwt-access-token-header`,
        `jwt-access-token-payload`, `federation-entity-statement`,
        `federation-trust-mark`) so one ingress can move without widening the
        claim for every other consumer at the same time.
     3. Define the regression evidence required before any surface promotion:
        unit coverage for backend selection / env precedence, fail-closed tests
        for unsupported overrides, consumer-path tests for generic-object and
        HTTP error mapping, plus the existing JOSE JSON↔TLV parity lanes.
     4. Refresh the claim docs atomically with the code change: update
        `docs/verification/jose/raw-json-boundary.md`,
        `docs/verification/runbooks/runtime-linkage.md`, and the verification maturity /
        roadmap notes in the same change that promotes a surface.
   - Recommended default design if this optional track is ever started:
     - Prefer a verified parser that emits the existing duplicate-preserving
       top-level object-member representation rather than inventing a new
       consumer-facing intermediate shape. That keeps the current
       `aegaeon_jose::raw_json` dispatch point, downstream normalization code,
       and source-managed claim-boundary API stable while one surface is being
       promoted.
     - Treat a canonicalized intermediate representation as a fallback design
       only if the parser work can also prove equivalence back to the current
       top-level object-member contract and preserve the existing error
       taxonomy / fail-closed semantics.
   - Recommended rollout order if per-surface promotion ever begins:
     1. `jose-header`, `request-object`, `client-registration`
     2. `oidc-id-token-payload`, `jwt-access-token-header`,
        `jwt-access-token-payload`
     3. `federation-entity-statement`, `federation-trust-mark`
     4. `generic-object` last, because it still fans out into shared
        server-side consumers (software statements, DPoP nonce extraction,
        promoted `private_key_jwt`, JWT bearer assertions) and therefore
        carries the widest unrelated regression surface
2. **Keep JSON/TLV parity as CI evidence**
   - `crates/jose/tests/tlv_parity.rs`
   - `crates/jose/src/tlv.rs` unit tests comparing the handwritten TLV parser
     with `ffi::tlv::parse_jose_header_tlv_via_abi`
   - The opt-in `ffi_jose_header_tlv` feature, which normalizes JOSE header JSON
     into TLV before routing it through the ABI parser in `jws`/`jwe` flows
   - The opt-in `everparse_jose_header_entry` feature, which keeps the native
     TLV parser but turns on the entry-level EverParse framing validator
   - `crates/jose/tests/rfc7520_vectors.rs`
   - Run both suites in the default build and across the supported JOSE header
     parser profiles (`--features everparse_jose_header_entry`,
     `--features ffi_jose_header_tlv`, `--features verified-claim`, and
     `--features ffi_jose_header_tlv,verified-claim`) so compat and strict
     regressions are detected before merge.
3. **Keep JWS and JWE error behavior aligned**
   - Negative cases for `zip`, `crit`, unknown keys, invalid `kid`, and
     non-string values should continue to share the same policy contract.
4. **Track “verified JSON parsing” as a separate epic (if needed)**
   - Either adopt a verified JSON grammar/AST, or define a canonicalised representation with an
     EverParse schema.
   - Do not conflate this with the current Low*/C policy-enforcement bridge.
5. **Use the greenfield-optimal roadmap when the goal is end-state architecture**
   - `../raw-json-optimal-architecture-plan.md` describes the longer-horizon
     route toward a surface-first, typed, claim-bearing design.
   - Keep this document focused on the migration-friendly path from the current
     helper architecture unless and until the program explicitly chooses the
     longer redesign.

## Primary references

- `docs/verification/jose/phase4-verification-summary.md`
- `docs/verification/jose/json-lowstar-ffi-contracts.md`
- `docs/policies/jose-header-policy.md`
- `docs/program-management/initiatives/jose/parser/header-parser-spec.md`
