module Jose.HeaderParser.TLV

/// TLV parsing module-level compatibility layer.
///
/// The core parsing logic now lives in Jose.HeaderParser.Spec (pure, seq-based).
/// This module re-exports the Spec definitions so that existing `open`/`include`
/// references continue to resolve, and additionally provides the EverParse
/// validator reference and name aliases.
///
/// Current scope note: the generated `JoseHeader` validator models only the
/// TLV entry framing (`key_len`, `key`, `value_len`, `value`). ASCII key
/// policy, UTF-8 validation, allow-listing, duplicate detection, and
/// whole-stream consumption remain enforced by Jose.HeaderParser.Spec.
///
/// **Breaking API change (v0.9):** The buffer-based functions
/// (parse_jwe_buffer, parse_jws_buffer) have been intentionally removed.
/// `LowStar.Buffer.as_seq` is GTot, so a correct Tot-effect buffer wrapper
/// is impossible without an assume val — which is exactly what
/// `read_u8_safe` was.  The replacement is the seq-based API in
/// Jose.HeaderParser.Spec (parse_jwe_seq, parse_jws_seq).
/// Buffer holders in Stack context should snapshot the heap
/// (`let h = FStar.HyperStack.ST.get ()`) and project the ghost sequence
/// (`LowStar.Buffer.as_seq h b`) for use in specifications.

include Jose.HeaderParser.Spec

open Jose.HeaderMicro
open Jose.HeaderSpec
open FStar.UInt8
module EP = JoseHeader
module RT = Jose.HeaderParser.Runtime

noextract
let everparse_validate_jose_header_entry = EP.validate__jose_header_entry

/// Stack-level entry validator bridge backed by the generated EverParse C
/// wrapper. This reports only the coarse entry-framing status; ASCII/UTF-8 and
/// whole-stream checks remain in Jose.HeaderParser.Spec.
let validate_jose_header_entry_buffer = RT.validate_entry_buffer

let entry_validator_succeeded = RT.entry_validator_succeeded

/// Alias for backward compatibility: `parse_tlv_entries_result_spec` was
/// historically exported from this module.
let parse_tlv_entries_result_spec = Jose.HeaderParser.Spec.parse_tlv_entries_result
