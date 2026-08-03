# JOSE Header Micro-language & EverParse Parser Plan

Last updated: 2026-07-07

Status: active plan

Owner: Program Management

Audience: maintainers, planning contributors

This document captures the contract that the forthcoming EverParse/LowParse-generated
parser must satisfy. It ties together the F* specification layer (`Jose.HeaderSpec`),
string micro-language (`Jose.HeaderMicro`), and the buffer-level entrypoints in
`Jose.HeaderParser`.

## Parsing Goals

We need a verified parser that accepts JOSE protected headers encoded in JSON and
returns the sanitised records defined in `Jose.HeaderSpec`:

| Variant | Sanitised fields |
| ------- | ---------------- |
| JWE     | `alg` (allow-listed string), `enc` (`A256GCM` only for now) |
| JWS     | `alg` (enum), `kid` (optional ASCII string, 1–255 chars) |

The parser must reject inputs that:

- Include unsupported `zip`, `crit`, or other extension members
- Violate the header length policy (`policy.joseHeaderMaxLen`)
- Use an algorithm outside `Jose.Alg_policy`
- Provide an invalid `kid` (non-ASCII, empty, or exceeding 255 chars)
- Contain duplicate header parameters or keys outside the recognised allow-list

Current claim-boundary note: the released server claim for shared raw JSON
admission does not start at JOSE header bytes. Today it starts at the
duplicate-preserving top-level object-member interface exported by
`aegaeon_jose::raw_json`; the raw-byte frontend that feeds that interface
remains `SerdeCompat` and is outside the current formal claim.

If a future phase promotes the `jose-header` surface to a verified raw-byte
parser, the preferred contract is still the existing duplicate-preserving
top-level object-member representation consumed by
`parse_json_header_lowstar`. In other words, the parser upgrade should replace
the byte-level admission step without forcing a new downstream normalization
shape for JOSE header consumers. A different intermediate representation is
acceptable only if it can be proven equivalent to the current member contract
and preserves the same fail-closed error taxonomy at the Rust boundary.

## JSON/TLV Policy Invariants

To keep the JSON and TLV entrypoints perfectly aligned, the verified parser must enforce
the following rules on both representations:

1. **Allow-listed keys only**
   - Recognised set: `alg`, `enc`, `kid`, `typ`, `cty`, `zip`, `crit`.
   - Any other key MUST be rejected with a policy error (TLV path already enforces this).
2. **Key uniqueness**
   - Each header parameter can appear at most once. A second occurrence is a hard failure
     (no “last value wins” behaviour).
3. **Value typing**
   - Recognised parameters must be strings. Inputs such as `null`, numbers, or nested
     structures are rejected as `InvalidFormat`.
   - TLV representation cannot encode `null`, so JSON validation must match that restriction.
4. **ASCII / UTF-8 guarantees**
   - Keys must be pure ASCII (consistent with TLV encoder).
   - Values must be canonical UTF-8; UTF-8 decoding errors propagate as `InvalidValueUtf8`.
5. **Critical/supplementary headers**
   - Reject `crit` and currently-unsupported `zip` immediately (policy forbids extensions). Align
     error mapping with the Rust taxonomy (e.g. `UnsupportedCriticalHeader`).
6. **Header length**
   - Combined header size is bounded by the active `JoseContext` / `policy.joseHeaderMaxLen`. TLV
     path already enforces this via buffer bounds.

These invariants become the shared contract for both the F* micro-language parser and the
Rust integration layer, avoiding divergence between JSON and TLV flows.

## Layering Overview

1. **Specification** – `fstar/jose/Jose.HeaderSpec.fst` defines sanitised records and helper
   functions `sanitize_jwe` / `sanitize_jws` / `parse_{jwe,jws}_sanitized`.
2. **Micro-language** – `fstar/jose/Jose.HeaderMicro.fst` introduces `parse_{jwe,jws}_micro`
   that operate on `list (string * string)` pairs, providing a convenient target for
   the generated parser.
3. **Buffer entrypoints** – `fstar/jose/Jose.HeaderParser.fst` declares
  `parse_{jwe,jws}_buffer` (TLV) and `parse_{jwe,jws}_json_members` (JSON). JSON
  normalisation is implemented via `JSON.parse_json_pairs_result` and surfaced to
  Rust via the extracted Low*/C bridge; there is no remaining `assume
  parse_json_pairs` dependency in the current codebase.
4. **Current extracted Low* surface** – `scripts/extraction/run_jose_lowstar.sh`
   now emits `Jose.LowStar.Json.Runtime`, `Jose.LowStar.Json.Types`,
   `Jose.LowStar.Json`, `Jose.Dcr`, and `Jose.LowStar` into
   `generated/lowstar/jose/`. The extraction gate is `nix run .#verify-lowstar`,
   which re-runs the script, checks generated artefacts for drift, and enforces
   the current EverParse wrapper ABI hygiene checks.

The EverParse specification will define the concrete binary layout and generate:

- Verified C parsers / validators for the chosen binary representation
- Rust/FFI entry points that can be used as opt-in runtime checks (defence in depth)

## EverParse Specification Skeleton

A new EverParse module will be added under `fstar/lowparse/JoseHeader.3d`. It will:

- Define ASCII string types bounded by 255 characters (for `kid`) and 16 characters
  (for `alg`/`enc`).
- Model a simple key-value micro-language with a fixed set of recognised keys (`alg`,
  `enc`, `kid`, `zip`, `crit`).
- Produce either a sanitised header structure or an error flag.

The resulting generated C code can be used as an opt-in runtime check, and later integrated
into the `Jose.HeaderParser` pipeline once the binary representation is fixed.

Current scope note: the `JoseHeader.3d` schema validates only TLV entry framing
(`key_len`, `key`, `value_len`, `value`). The handwritten TLV parser still owns
ASCII-key enforcement, UTF-8 decoding, allow-list checks, duplicate detection,
and whole-stream trailing-byte rejection. As of 2026-05-15, the C/Rust wrapper
preserves EverParse error kinds instead of collapsing them to a boolean, so
`EVERPARSE_ERROR_NOT_ENOUGH_DATA` is reported as `Truncated` while the remaining
entry-validator failures stay fail-closed as `EntryValidationFailed`. The
generated entry validator admits a single `jose_header_entry` prefix, so exact
whole-stream consumption remains the responsibility of the higher-level TLV
iterator.

The F* side now exposes a matching Stack-level bridge in
`fstar/jose/Jose.HeaderParser.Runtime.fst`. That module keeps the pure
`Jose.HeaderParser.Spec` pipeline unchanged and surfaces only the coarse entry
validator status (`Ok`, `Truncated`, `Failed`) for callers that already hold a
live buffer in `Low*`/KaRaMeL-extracted code.

As of 2026-05-15, the Rust-side `ffi::jose_header::check_jose_header_entry`
helper no longer binds directly to `JoseHeaderGetJoseHeaderEntryErrorCode`.
Instead it routes through the extracted
`Jose_HeaderParser_Runtime_validate_entry_buffer` bridge, so the Rust TLV path
and exported FFI TLV ABI both consume the generated Low*/C validator surface.
On the JSON side, ASCII-key rejection is now aligned across
`parse_json_header_lowstar`, the compat fallback, and the
`ffi_jose_header_tlv` normalization path: non-ASCII keys fail closed as
`InvalidKeyEncoding("header key must be ASCII")` before header sanitization.
Direct Low* JSON-entry decode failures now also report the same UTF-8 text as
the handwritten TLV parser (`header key/value is not valid UTF-8`), so the
handwritten TLV parser and JSON raw-admission now also align on trailing-byte
classification. JSON header payloads with non-whitespace bytes after the first
object fail closed as
`JsonError::TrailingBytes("trailing bytes after JOSE header JSON object")`,
while raw TLV / FFI parsing maps `JoseHeaderParseError::TrailingBytes` into the
same top-level error variant.

## Next Steps

1. Keep the extraction surface reproducible:
   `run_jose_lowstar.sh` should continue to emit stable `generated/everparse/`
   and `generated/lowstar/` trees, and `nix run .#verify-lowstar` should remain
   the hosted drift gate for those artefacts.
2. Keep the Rust TLV / FFI boundary green via parity tests:
   `crates/jose/tests/tlv_parity.rs`, `crates/jose/tests/rfc7520_vectors.rs`,
   and the opt-in `ffi_jose_header_tlv` profile matrix.
3. Treat the current released boundary as `top-level-object-members`. If a
   future phase promotes the boundary to raw bytes, replace the `serde_json`
   stage with a verified parser (or a canonicalised representation + EverParse
   schema). Until then, treat EverParse as an opt-in entry-level validator for
   internal TLV buffers.
