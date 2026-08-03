module Jose.HeaderParser.Runtime

/// Stack-level runtime bridge for the EverParse JOSE header entry validator.
///
/// This module intentionally keeps Jose.HeaderParser.Spec pure and seq-based.
/// Callers that already hold a live buffer can use this bridge to run the
/// generated entry-framing validator without re-introducing buffer reads into
/// the Tot parser.

open FStar.HyperStack.ST
open FStar.UInt8
open FStar.UInt32

module B = LowStar.Buffer
module U8 = FStar.UInt8
module U32 = FStar.UInt32

type entry_validator_status =
  | EntryValidatorOk
  | EntryValidatorTruncated
  | EntryValidatorFailed

let everparse_success_code : U32.t = 0ul
let everparse_error_not_enough_data_code : U32.t = 2ul

/// Low*/C bridge provided by c/jose_header_runtime.c.
///
/// The implementation delegates to the generated EverParse wrapper
/// JoseHeaderGetJoseHeaderEntryErrorCode and preserves its coarse error kind.
assume val jose_header_entry_error_code:
  input:B.buffer U8.t ->
  input_len:U32.t{U32.v input_len <= B.length input} ->
  Stack U32.t
    (requires fun h -> B.live h input)
    (ensures fun h0 _ h1 -> h0 == h1)

let classify_entry_error_code (code:U32.t) : Tot entry_validator_status =
  if code = everparse_success_code then EntryValidatorOk
  else if code = everparse_error_not_enough_data_code then EntryValidatorTruncated
  else EntryValidatorFailed

let validate_entry_buffer
  (input:B.buffer U8.t)
  (input_len:U32.t{U32.v input_len <= B.length input})
  : Stack entry_validator_status
    (requires fun h -> B.live h input)
    (ensures fun h0 _ h1 -> h0 == h1)
  =
    let code = jose_header_entry_error_code input input_len in
    classify_entry_error_code code

let entry_validator_succeeded (status:entry_validator_status) : Tot bool =
  match status with
  | EntryValidatorOk -> true
  | EntryValidatorTruncated
  | EntryValidatorFailed -> false
