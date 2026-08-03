module Jose.LowStar.Json.Structural.Runtime

open FStar.UInt8
open FStar.UInt32
open FStar.HyperStack.All
module Buffer = LowStar.Buffer
open LowStar.Buffer

/// Output struct returned via the future raw JSON structural parser C ABI.
///
/// The parser returns member records plus a shared key-bytes buffer. Offsets
/// index into that shared buffer and into the original raw JSON input.
noeq type raw_json_structural_member_out = {
  member_key_offset: UInt32.t;
  member_key_len: UInt32.t;
  member_value_kind_repr: UInt8.t;
  member_reserved0: UInt8.t;
  member_reserved1: UInt8.t;
  member_reserved2: UInt8.t;
  member_value_offset: UInt32.t;
  member_value_len: UInt32.t
}

let raw_json_structural_member_reserved_zero
  (member:raw_json_structural_member_out)
  : GTot Type0
  =
  member.member_reserved0 = 0uy /\
  member.member_reserved1 = 0uy /\
  member.member_reserved2 = 0uy

let default_raw_json_structural_member_out : raw_json_structural_member_out = {
  member_key_offset = 0ul;
  member_key_len = 0ul;
  member_value_kind_repr = 0uy;
  member_reserved0 = 0uy;
  member_reserved1 = 0uy;
  member_reserved2 = 0uy;
  member_value_offset = 0ul;
  member_value_len = 0ul
}
