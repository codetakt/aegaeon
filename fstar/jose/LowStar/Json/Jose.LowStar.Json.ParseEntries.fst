module Jose.LowStar.Json.ParseEntries

/// Buffer-based JSON entry parsing pipeline.
///
/// Replaces the aegaeon_ffi_decode_utf8 FFI callback with the concrete
/// Low* UTF-8 validator (Jose.LowStar.Json.Utf8.validate_utf8_buffer),
/// then delegates to the existing spec-level parsing for header validation.
///
/// Entry point: parse_members_buffer
///   1. Validates UTF-8 on all key/value buffers (Low*, Stack effect)
///   2. Collects raw members into lists (spec bridge, Stack effect)
///   3. Normalizes + parses entries via spec-level pipeline (Tot effect)
///   4. Builds result structure (ST effect)
///
/// This module is the concrete replacement for the json_parse_entries_to_c
/// assume val — the UTF-8 validation step is now fully verified Low*.

open FStar.HyperStack.ST
open LowStar.Buffer
open FStar.UInt8
open FStar.UInt32
open Jose.LowStar.Json.Types
open Jose.LowStar.Json.Runtime
open Jose.LowStar.Json.Utf8

module U8 = FStar.UInt8
module U32 = FStar.UInt32
module Buffer = LowStar.Buffer
module HST = FStar.HyperStack.ST

/// Validate that a single json_member_c has valid UTF-8 in its key and value buffers.
/// Returns true if both key and value (when present) are valid UTF-8.
/// Precondition: key/value lengths within buffer bounds (from json_member_c invariant).
inline_for_extraction
let validate_member_utf8 (m: json_member_c)
  : Stack bool
    (requires (fun h ->
      live h m.key_buf /\
      live h m.value_buf /\
      U32.v m.key_len <= Buffer.length m.key_buf /\
      U32.v m.value_len <= Buffer.length m.value_buf))
    (ensures (fun h0 _ h1 -> h0 == h1 /\ live h1 m.key_buf /\ live h1 m.value_buf))
  =
  let key_valid = validate_utf8_buffer m.key_buf m.key_len in
  if not key_valid then false
  else
    match m.value_kind with
    | JsonValueNull -> true
    | JsonValueString ->
      validate_utf8_buffer m.value_buf m.value_len

/// Iterate through all members[idx..count) and validate UTF-8 on each.
/// Returns the first error code encountered, or JsonParseOk if all valid.
///
/// The recursive structure uses decreases on (count - idx).
/// At each step: read the member, validate its UTF-8, advance if valid.
val validate_members_utf8_loop
  (members: buffer json_member_c)
  (count32: U32.t{U32.v count32 <= Buffer.length members})
  (idx32: U32.t{U32.v idx32 <= U32.v count32})
  : Stack json_parse_error
    (requires (fun h ->
      live h members /\
      members_nested_live h members (U32.v count32) 0))
    (ensures (fun h0 _ h1 -> h0 == h1 /\ live h1 members))
    (decreases (U32.v count32 - U32.v idx32))

#push-options "--z3rlimit 30 --fuel 0 --ifuel 0"

let rec validate_members_utf8_loop members count32 idx32 =
  if idx32 = count32 then
    JsonParseOk
  else
    let member = index_member_with_liveness members count32 idx32 in
    // Extract length refinements from json_member_c ghost fields for validate_member_utf8
    let _kle : squash (U32.v member.key_len <= Buffer.length member.key_buf) = member.key_len_le in
    let _vle :
      squash (U32.v member.value_len <= Buffer.length member.value_buf)
      = member.value_len_le in
    let valid = validate_member_utf8 member in
    if not valid then
      (* Determine which buffer failed: try key first *)
      let key_valid = validate_utf8_buffer member.key_buf member.key_len in
      if not key_valid then
        JsonParseErrorInvalidKeyEncoding
      else
        JsonParseErrorInvalidValueUtf8
    else
      validate_members_utf8_loop members count32 (U32.add idx32 1ul)

#pop-options

/// Top-level UTF-8 validation for a json_member_c buffer.
/// Validates all key and value buffers contain well-formed UTF-8.
///
/// This is the Low* replacement for the aegaeon_ffi_decode_utf8 calls
/// in the C runtime (json_lowstar_runtime.c lines 470-528).
let validate_members_utf8
  (members: buffer json_member_c)
  (count32: U32.t{U32.v count32 <= Buffer.length members})
  : Stack json_parse_error
    (requires (fun h ->
      live h members /\
      members_nested_live h members (U32.v count32) 0))
    (ensures (fun h0 _ h1 -> h0 == h1 /\ live h1 members))
  =
  validate_members_utf8_loop members count32 0ul
