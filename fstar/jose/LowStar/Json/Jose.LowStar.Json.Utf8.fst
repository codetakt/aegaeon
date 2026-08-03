module Jose.LowStar.Json.Utf8

/// Low* UTF-8 validator operating on buffers.
///
/// Validates that a buffer contains well-formed UTF-8 without decoding
/// to codepoints. Rejects overlong encodings, surrogates (U+D800–U+DFFF),
/// and codepoints > U+10FFFF — matching Jose.Utf8.Validity.valid_utf8_bytes.
///
/// Stack effect: no heap allocation, read-only on the input buffer.

open FStar.HyperStack.ST
open LowStar.Buffer
open FStar.UInt8
open FStar.UInt32

module U8 = FStar.UInt8
module U32 = FStar.UInt32
module Buffer = LowStar.Buffer

/// Helper: read a byte value as a UInt8 from the buffer at a given index.
/// Requires idx < Buffer.length buf and buf is live.
inline_for_extraction
let read_byte
  (buf: buffer U8.t)
  (idx: U32.t{U32.v idx < Buffer.length buf})
  : Stack U8.t
    (requires (fun h -> Buffer.live h buf))
    (ensures (fun h0 v h1 ->
      h0 == h1 /\
      Buffer.live h1 buf /\
      v == Seq.index (Buffer.as_seq h0 buf) (U32.v idx)))
  =
  Buffer.index buf idx

/// Check if a byte is a valid continuation byte (10xxxxxx: 0x80–0xBF).
inline_for_extraction
let is_continuation (b: U8.t) : Tot bool =
  U8.gte b 0x80uy && U8.lte b 0xBFuy

/// Validate that the buffer[pos..pos+len) contains valid UTF-8.
///
/// Recursive implementation with a decreasing clause on remaining bytes.
/// At each step, examines the lead byte to determine the sequence length
/// (1–4 bytes), then validates continuation bytes and rejects illegal ranges.
///
/// The logic mirrors Jose.Utf8.Validity.valid_utf8_bytes exactly:
///   - 1-byte: 0x00–0x7F
///   - 2-byte: 0xC2–0xDF + 1 continuation (rejects overlong 0xC0–0xC1)
///   - 3-byte: 0xE0–0xEF + 2 continuations
///       * 0xE0: second byte must be 0xA0–0xBF (reject overlong)
///       * 0xED: second byte must be 0x80–0x9F (reject surrogates)
///   - 4-byte: 0xF0–0xF4 + 3 continuations
///       * 0xF0: second byte must be 0x90–0xBF (reject overlong)
///       * 0xF4: second byte must be 0x80–0x8F (reject > U+10FFFF)
val validate_utf8_loop
  (buf: buffer U8.t)
  (len: U32.t{U32.v len <= Buffer.length buf})
  (pos: U32.t{U32.v pos <= U32.v len})
  : Stack bool
    (requires (fun h -> Buffer.live h buf))
    (ensures (fun h0 result h1 ->
      h0 == h1 /\
      Buffer.live h1 buf))
    (decreases (U32.v len - U32.v pos))

#push-options "--z3rlimit 40 --fuel 0 --ifuel 0"

let rec validate_utf8_loop buf len pos =
  if pos = len then
    true  (* All bytes consumed — valid *)
  else
    let remaining = U32.sub len pos in
    let b0 = read_byte buf pos in
    let v0 = U8.v b0 in

    (* 1-byte sequence: 0x00–0x7F *)
    if U8.lte b0 0x7Fuy then
      validate_utf8_loop buf len (U32.add pos 1ul)

    (* 2-byte sequence: 0xC2–0xDF *)
    else if U8.gte b0 0xC2uy && U8.lte b0 0xDFuy then
      if U32.lt remaining 2ul then false
      else
        let b1 = read_byte buf (U32.add pos 1ul) in
        if is_continuation b1 then
          validate_utf8_loop buf len (U32.add pos 2ul)
        else false

    (* 3-byte sequence: 0xE0–0xEF *)
    else if U8.gte b0 0xE0uy && U8.lte b0 0xEFuy then
      if U32.lt remaining 3ul then false
      else
        let b1 = read_byte buf (U32.add pos 1ul) in
        let b2 = read_byte buf (U32.add pos 2ul) in
        (* Check second-byte constraints based on lead byte *)
        let b1_ok =
          if U8.eq b0 0xE0uy then
            (* Reject overlong: second byte must be 0xA0–0xBF *)
            U8.gte b1 0xA0uy && U8.lte b1 0xBFuy
          else if U8.eq b0 0xEDuy then
            (* Reject surrogates: second byte must be 0x80–0x9F *)
            U8.gte b1 0x80uy && U8.lte b1 0x9Fuy
          else
            (* General continuation range *)
            is_continuation b1
        in
        if b1_ok && is_continuation b2 then
          validate_utf8_loop buf len (U32.add pos 3ul)
        else false

    (* 4-byte sequence: 0xF0–0xF4 *)
    else if U8.gte b0 0xF0uy && U8.lte b0 0xF4uy then
      if U32.lt remaining 4ul then false
      else
        let b1 = read_byte buf (U32.add pos 1ul) in
        let b2 = read_byte buf (U32.add pos 2ul) in
        let b3 = read_byte buf (U32.add pos 3ul) in
        (* Check second-byte constraints based on lead byte *)
        let b1_ok =
          if U8.eq b0 0xF0uy then
            (* Reject overlong: second byte must be 0x90–0xBF *)
            U8.gte b1 0x90uy && U8.lte b1 0xBFuy
          else if U8.eq b0 0xF4uy then
            (* Reject > U+10FFFF: second byte must be 0x80–0x8F *)
            U8.gte b1 0x80uy && U8.lte b1 0x8Fuy
          else
            (* General continuation range *)
            is_continuation b1
        in
        if b1_ok && is_continuation b2 && is_continuation b3 then
          validate_utf8_loop buf len (U32.add pos 4ul)
        else false

    (* Invalid lead byte (0x80–0xBF, 0xC0–0xC1, 0xF5–0xFF) *)
    else false

#pop-options

/// Top-level validator: checks that buf[0..len) is valid UTF-8.
/// Stack effect — no heap allocation, read-only on input.
val validate_utf8_buffer
  (buf: buffer U8.t)
  (len: U32.t{U32.v len <= Buffer.length buf})
  : Stack bool
    (requires (fun h -> Buffer.live h buf))
    (ensures (fun h0 result h1 ->
      h0 == h1 /\
      Buffer.live h1 buf))

let validate_utf8_buffer buf len =
  validate_utf8_loop buf len 0ul
