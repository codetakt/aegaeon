module Jose.Arith.Bounds

open FStar.UInt32
open FStar.String
open FStar.Math.Lemmas
open Jose.Context
open Jose.UInt32Bounds

/// This module provides arithmetic lemmas and boundary proofs needed for
/// safe conversion between nat/String.length and UInt32 in Low* extraction.

/// Lemma: If a string length is bounded by a context limit, it fits in UInt32.
val lemma_string_length_bounded_by_context :
  ctx:jose_context ->
  s:string ->
  Lemma (requires String.length s <= header_max_length_nat ctx)
        (ensures String.length s < pow2 32)
let lemma_string_length_bounded_by_context ctx s =
  lemma_context_header_max_length_u32_safe ctx;
  // header_max_length_nat ctx < pow2 32 (from context type)
  // String.length s <= header_max_length_nat ctx (from requires)
  // Therefore: String.length s < pow2 32 (by transitivity)
  ()

/// Lemma: If a nat is less than context limit, it fits in UInt32.
val lemma_nat_bounded_by_context :
  ctx:jose_context ->
  n:nat ->
  Lemma (requires n <= header_max_length_nat ctx)
        (ensures n < pow2 32)
let lemma_nat_bounded_by_context ctx n =
  lemma_context_header_max_length_u32_safe ctx;
  ()

/// Safe conversion of string length to UInt32 given context bounds.
val string_length_to_u32 :
  ctx:jose_context ->
  s:string{String.length s <= header_max_length_nat ctx} ->
  UInt32.t
let string_length_to_u32 ctx s =
  lemma_string_length_bounded_by_context ctx s;
  UInt32.uint_to_t (String.length s)

/// Lemma: Round-trip property for string_length_to_u32.
val lemma_string_length_u32_roundtrip :
  ctx:jose_context ->
  s:string{String.length s <= header_max_length_nat ctx} ->
  Lemma (ensures UInt32.v (string_length_to_u32 ctx s) = String.length s)
let lemma_string_length_u32_roundtrip ctx s =
  lemma_string_length_bounded_by_context ctx s;
  ()

/// Safe conversion of bounded nat to UInt32.
val nat_to_u32_bounded :
  ctx:jose_context ->
  n:nat{n <= header_max_length_nat ctx} ->
  UInt32.t
let nat_to_u32_bounded ctx n =
  lemma_nat_bounded_by_context ctx n;
  UInt32.uint_to_t n

/// Lemma: Round-trip property for nat_to_u32_bounded.
val lemma_nat_u32_roundtrip :
  ctx:jose_context ->
  n:nat{n <= header_max_length_nat ctx} ->
  Lemma (ensures UInt32.v (nat_to_u32_bounded ctx n) = n)
let lemma_nat_u32_roundtrip ctx n =
  lemma_nat_bounded_by_context ctx n;
  ()

/// Lemma: Transitivity helper for length comparisons.
val lemma_length_transitive :
  a:nat -> b:nat -> c:nat ->
  Lemma (requires a <= b /\ b < c)
        (ensures a < c)
let lemma_length_transitive a b c = ()

/// Lemma: Addition preserves UInt32 bounds under context limits.
/// Useful for buffer offset calculations.
val lemma_add_bounded_u32 :
  ctx:jose_context ->
  a:nat{a <= header_max_length_nat ctx} ->
  b:nat{b <= header_max_length_nat ctx /\ a + b < pow2 32} ->
  Lemma (ensures a + b < pow2 32)
let lemma_add_bounded_u32 ctx a b = ()

/// Lemma: Subtraction safety for non-negative results.
val lemma_sub_bounded :
  a:nat -> b:nat ->
  Lemma (requires a >= b)
        (ensures a - b >= 0)
let lemma_sub_bounded a b = ()

// ============================================================================
// General arithmetic and transitivity lemmas for KaRaMeL extraction
// ============================================================================

/// Lemma: pow2 32 is positive.
val lemma_pow2_32_positive : unit -> Lemma (ensures 0 < pow2 32)
let lemma_pow2_32_positive () = ()

/// Lemma: Transitivity of < for index bounds.
/// If idx < count and count < pow2 32, then idx < pow2 32.
val lemma_idx_lt_pow2 :
  idx:nat -> count:nat ->
  Lemma (requires idx < count /\ count < pow2 32)
        (ensures idx < pow2 32)
let lemma_idx_lt_pow2 idx count = ()

/// Lemma: Transitivity mixing < and <=.
/// If i < n and n <= m, then i < m.
val lemma_lt_trans_le :
  i:nat -> n:nat -> m:nat ->
  Lemma (requires i < n /\ n <= m)
        (ensures i < m)
let lemma_lt_trans_le i n m = ()

/// Lemma: If i < n, then i + 1 <= n.
val lemma_lt_implies_le_succ :
  i:nat -> n:nat ->
  Lemma (requires i < n)
        (ensures i + 1 <= n)
let lemma_lt_implies_le_succ i n = ()

/// Lemma: Every natural number is less than its successor.
val lemma_lt_succ :
  idx:nat ->
  Lemma (ensures idx < idx + 1)
let lemma_lt_succ idx = ()

/// Lemma: Measure decreases for loop termination.
/// Used in recursive functions to prove termination via decreases clause.
val lemma_measure_lt :
  count:nat ->
  idx:nat{idx < count} ->
  Lemma (ensures count - (idx + 1) < count - idx)
let lemma_measure_lt count idx = ()

// ============================================================================
// Buffer-related bounds (LowStar.Buffer integration)
// ============================================================================

open LowStar.Buffer

/// Lemma: Buffer.length is always within UInt32 range.
/// This is fundamental for KaRaMeL extraction since LowStar.Buffer defines
/// length in terms of UInt32 bounds.
val lemma_buffer_length_bounded :
  #a:Type -> buf:buffer a ->
  Lemma (ensures LowStar.Buffer.length buf < pow2 32)
let lemma_buffer_length_bounded #a buf =
  // LowStar.Buffer.length is defined as U32.v (len buf) where len : U32.t
  // UInt32.t is refined to {n:nat | n < pow2 32}, so the bound holds
  ()

/// Lemma: Transitivity for idx < len <= Buffer.length buf.
/// Combines index bound with buffer length bound to prove idx < pow2 32.
val lemma_idx_lt_pow2_via_buffer :
  #a:Type -> buf:buffer a -> len:nat -> idx:nat ->
  Lemma (requires len <= LowStar.Buffer.length buf /\ idx < len)
        (ensures idx < pow2 32)
let lemma_idx_lt_pow2_via_buffer #a buf len idx =
  lemma_buffer_length_bounded buf;
  lemma_idx_lt_pow2 idx (LowStar.Buffer.length buf)

/// Lemma: If idx < len and len <= Buffer.length buf, then idx < Buffer.length buf.
val lemma_idx_lt_buffer_length :
  #a:Type -> buf:buffer a -> len:nat -> idx:nat ->
  Lemma (requires idx < len /\ len <= LowStar.Buffer.length buf)
        (ensures idx < LowStar.Buffer.length buf)
let lemma_idx_lt_buffer_length #a buf len idx =
  lemma_lt_trans_le idx len (LowStar.Buffer.length buf)

// ============================================================================
// Phase 1: UInt32 arithmetic lemmas for Warning 15 mitigation
// ============================================================================
//
// These lemmas support UInt32-based Stack functions without nat conversions.
// See: docs/program-management/initiatives/jose/lowstar/warning15-machine-integer.md

/// Lemma: UInt32 addition preserves bounds when sum is within pow2 32.
/// Useful for buffer offset calculations: offset + length < buffer_size.
val lemma_u32_add_within_pow2 :
  a:UInt32.t ->
  b:UInt32.t ->
  Lemma (requires UInt32.v a + UInt32.v b < pow2 32)
        (ensures UInt32.v (UInt32.add a b) == UInt32.v a + UInt32.v b)
let lemma_u32_add_within_pow2 a b =
  // UInt32.add is defined as: uint_to_t ((v a + v b) % pow2 32)
  // When v a + v b < pow2 32, the modulo is identity
  FStar.Math.Lemmas.modulo_lemma (UInt32.v a + UInt32.v b) (pow2 32)

/// Lemma: If idx < count (as UInt32), then idx + 1 <= count.
/// Supports loop termination proofs in UInt32-based iteration.
val lemma_u32_succ_within_bound :
  idx:UInt32.t ->
  count:UInt32.t ->
  Lemma (requires UInt32.v idx < UInt32.v count)
        (ensures UInt32.v idx + 1 <= UInt32.v count)
let lemma_u32_succ_within_bound idx count = ()

/// Lemma: Index validity for Buffer.index with UInt32 index.
/// If idx32 < len32 and len32 <= Buffer.length buf, then idx32 is valid for indexing.
val lemma_idx_u32_lt_buffer_from_len :
  #a:Type -> buf:buffer a -> len32:UInt32.t -> idx32:UInt32.t ->
  Lemma (requires UInt32.v len32 <= LowStar.Buffer.length buf /\ UInt32.v idx32 < UInt32.v len32)
        (ensures UInt32.v idx32 < LowStar.Buffer.length buf)
let lemma_idx_u32_lt_buffer_from_len #a buf len32 idx32 =
  lemma_idx_lt_buffer_length buf (UInt32.v len32) (UInt32.v idx32)

/// Lemma: If idx <= count <= length(buf) and idx ≠ count, then idx < length(buf).
let lemma_idx_u32_lt_buffer_from_le_neq
  #a
  (buf:buffer a)
  (count:UInt32.t)
  (idx:UInt32.t{UInt32.v idx <= UInt32.v count})
  : Lemma (requires UInt32.v count <= LowStar.Buffer.length buf /\ UInt32.eq idx count = false)
          (ensures UInt32.v idx < LowStar.Buffer.length buf)
  =
    lemma_eq_false_implies_v_neq idx count;
    lemma_le_and_neq_implies_lt idx count;
    lemma_idx_u32_lt_buffer_from_len #a buf count idx

/// Lemma: Measure decreases for UInt32-based loops.
/// Proves that (count - (idx + 1)) < (count - idx) for termination.
val lemma_u32_measure_lt :
  count:UInt32.t ->
  idx:UInt32.t ->
  Lemma (requires UInt32.v idx < UInt32.v count)
        (ensures UInt32.v count - (UInt32.v idx + 1) < UInt32.v count - UInt32.v idx)
let lemma_u32_measure_lt count idx =
  lemma_measure_lt (UInt32.v count) (UInt32.v idx)

/// Helper: natural difference between two UInt32 values (requires idx <= count).
let u32_diff
  (count:UInt32.t)
  (idx:UInt32.t{UInt32.v idx <= UInt32.v count})
  : nat
  = UInt32.v count - UInt32.v idx

/// If idx < count, then u32_diff decreases by one when idx is incremented.
let lemma_u32_diff_step
  (count:UInt32.t)
  (idx:UInt32.t{UInt32.v idx < UInt32.v count})
  : Lemma (
      u32_diff count idx =
      u32_diff count (UInt32.add idx UInt32.one) + 1
    )
  =
    let count_v = UInt32.v count in
    let idx_v = UInt32.v idx in
    assert (UInt32.v (UInt32.add idx UInt32.one) = idx_v + 1);
    assert (u32_diff count idx == count_v - idx_v);
    assert (u32_diff count (UInt32.add idx UInt32.one) == count_v - (idx_v + 1));
    ()
