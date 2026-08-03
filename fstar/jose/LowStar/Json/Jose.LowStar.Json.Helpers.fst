module Jose.LowStar.Json.Helpers

open FStar.List.Tot
open FStar.Math.Lemmas
open FStar.UInt
open FStar.UInt32
open FStar.HyperStack.All
open FStar.HyperStack.ST
open LowStar.Buffer
open Jose.Policy
open Jose.Utf8Lemmas
open Jose.Arith.Bounds

module List = FStar.List.Tot
module U32 = FStar.UInt32
module Buffer = LowStar.Buffer

// Proof-only helper; nat arithmetic is not extracted.
noextract
val four_times : nat -> nat
noextract
let four_times (n:nat) : nat = Prims.op_Multiply 4 n

/// Helper lemmas and utilities shared by Jose.LowStar.Json and Json.Stack.
/// Proofs will be filled in as admit() sites are eliminated.

let lemma_buffer_length_within_uint32 (buf:buffer 'a)
  : Lemma (Buffer.length buf < pow2 32)
  =
    lemma_buffer_length_bounded buf

let lemma_u32_succ_within_bound
  (idx32:UInt32.t)
  (len32:UInt32.t{UInt32.v idx32 < UInt32.v len32})
  : Lemma (UInt32.v (UInt32.add idx32 1ul) <= UInt32.v len32)
  =
    let idx = UInt32.v idx32 in
    let len = UInt32.v len32 in
    lemma_lt_implies_le_succ idx len;
    ()

let lemma_u32_measure_lt
  (len32:UInt32.t)
  (idx32:UInt32.t{UInt32.v idx32 < UInt32.v len32})
  : Lemma (UInt32.v len32 - UInt32.v (UInt32.add idx32 1ul) <
           UInt32.v len32 - UInt32.v idx32)
  =
    let len = UInt32.v len32 in
    let idx = UInt32.v idx32 in
    lemma_measure_lt len idx;
    ()

let lemma_nat_le_buffer_implies_lt_pow2
  (#a:Type)
  (buf:buffer a)
  (n:nat{n <= Buffer.length buf})
  : Lemma (ensures n < pow2 32)
  =
    let len = Buffer.length buf in
    lemma_buffer_length_within_uint32 buf;
    lemma_length_transitive n len (pow2 32);
    ()

/// UTF-8 encoding length fits in UInt32 under the JOSE policy string bound.
///
/// Rationale:
/// - In Jose parsing paths we enforce small inputs (e.g., header_max_length = 4096),
///   so the worst-case UTF-8 expansion (4 bytes per char) still fits in UInt32.
let lemma_utf8_bytes_length_bound (s:string)
  : Lemma
      (requires FStar.String.length s <= header_max_length)
      (ensures List.length (encode_utf8_bytes s) < pow2 32)
  =
    lemma_encode_utf8_bytes_length_bound s;
    let bytes_len = List.length (encode_utf8_bytes s) in
    let max_bytes = four_times header_max_length in
    assert (bytes_len <= four_times (FStar.String.length s));
    assert (four_times (FStar.String.length s) <= max_bytes);
    assert (bytes_len <= max_bytes);
    assert (max_bytes < pow2 32);
    lemma_length_transitive bytes_len max_bytes (pow2 32);
    ()

/// Same as lemma_utf8_bytes_length_bound, but for C strings (trailing NUL).
let lemma_utf8_bytes_cstring_length_bound (s:string)
  : Lemma
      (requires FStar.String.length s <= header_max_length)
      (ensures List.length (encode_utf8_bytes s) + 1 < pow2 32)
  =
    lemma_encode_utf8_bytes_length_bound s;
    let bytes_len = List.length (encode_utf8_bytes s) in
    let max_bytes = four_times header_max_length + 1 in
    assert (bytes_len <= four_times (FStar.String.length s));
    assert (bytes_len + 1 <= four_times (FStar.String.length s) + 1);
    assert (four_times (FStar.String.length s) + 1 <= max_bytes);
    assert (bytes_len + 1 <= max_bytes);
    assert (max_bytes < pow2 32);
    lemma_length_transitive (bytes_len + 1) max_bytes (pow2 32);
    ()
