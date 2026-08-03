module Jose.LowStar.Json.Structural.Types

open FStar.UInt8
open FStar.UInt32
open FStar.HyperStack.All
open LowStar.Buffer
open Jose.LowStar.Json.Structural.Runtime

module Buffer = LowStar.Buffer

type raw_json_structural_value_kind =
  | RawJsonStructuralValueString
  | RawJsonStructuralValueNull
  | RawJsonStructuralValueNumber
  | RawJsonStructuralValueBool
  | RawJsonStructuralValueObject
  | RawJsonStructuralValueArray

let raw_json_structural_value_kind_to_repr
  (kind:raw_json_structural_value_kind)
  : Tot UInt8.t
  =
  match kind with
  | RawJsonStructuralValueString -> 0uy
  | RawJsonStructuralValueNull -> 1uy
  | RawJsonStructuralValueNumber -> 2uy
  | RawJsonStructuralValueBool -> 3uy
  | RawJsonStructuralValueObject -> 4uy
  | RawJsonStructuralValueArray -> 5uy

type raw_json_structural_parse_error =
  | RawJsonStructuralParseOk
  | RawJsonStructuralParseErrorInvalidJson
  | RawJsonStructuralParseErrorInvalidShape
  | RawJsonStructuralParseErrorTrailingBytes
  | RawJsonStructuralParseErrorBufferTooLarge
  | RawJsonStructuralParseErrorInternal
  | RawJsonStructuralParseErrorParserUnavailable

let raw_json_structural_parse_error_to_status_code
  (err:raw_json_structural_parse_error)
  : Tot UInt32.t
  =
  match err with
  | RawJsonStructuralParseOk -> 0ul
  | RawJsonStructuralParseErrorInvalidJson -> 1ul
  | RawJsonStructuralParseErrorInvalidShape -> 2ul
  | RawJsonStructuralParseErrorTrailingBytes -> 3ul
  | RawJsonStructuralParseErrorBufferTooLarge -> 4ul
  | RawJsonStructuralParseErrorInternal -> 100ul
  | RawJsonStructuralParseErrorParserUnavailable -> 102ul

noeq type raw_json_structural_span = {
  span_offset: UInt32.t;
  span_len: UInt32.t
}

noeq type raw_json_structural_member = {
  structural_key: list UInt8.t;
  structural_value_kind: raw_json_structural_value_kind;
  structural_value_span: raw_json_structural_span
}

noeq type raw_json_structural_parse_result = {
  structural_members: list raw_json_structural_member;
  structural_consumed_len: UInt32.t
}

/// Concrete C-facing result record for the future structural parser entry
/// point. The parser owns the member array and the shared key-bytes buffer.
noeq type raw_json_structural_parse_result_c = {
  result_members: buffer raw_json_structural_member_out;
  result_member_count: UInt32.t;
  result_member_count_le: squash (UInt32.v result_member_count <= Buffer.length result_members);
  result_consumed_len: UInt32.t;
  result_error: raw_json_structural_parse_error;
  result_key_bytes: buffer UInt8.t;
  result_key_bytes_len: UInt32.t;
  result_key_bytes_len_le: squash (UInt32.v result_key_bytes_len <= Buffer.length result_key_bytes)
}

let raw_json_structural_parse_result_members_fit_buffers
  (result:raw_json_structural_parse_result_c)
  : GTot Type0
  =
  UInt32.v result.result_member_count <= Buffer.length result.result_members /\
  UInt32.v result.result_key_bytes_len <= Buffer.length result.result_key_bytes
