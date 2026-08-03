module Jose.LowStar.Json.Stack

/// Minimal Stack-layer module for KaRaMeL extraction (Option B)
///
/// This module contains only the types and functions needed for Phase 3.2.4
/// C runtime integration, with minimal dependencies to avoid the deep
/// dependency chain issues identified in the KaRaMeL extraction investigation.
///
/// Dependencies: Only FStar.* and LowStar.Buffer (no Jose.* modules)
///
/// See: docs/verification/fstar/troubleshooting.md

open FStar.List.Tot
open FStar.UInt8
open FStar.UInt32
open FStar.HyperStack.All
open FStar.HyperStack.ST
open LowStar.Buffer
open Jose.LowStar.Json.Helpers

module List = FStar.List.Tot
module U32 = FStar.UInt32
module Buffer = LowStar.Buffer
module HS = FStar.HyperStack

// ============================================================================
// Core types (minimal, no dependencies)
// ============================================================================

type json_value_kind =
  | JsonValueString
  | JsonValueNull

noeq
type json_member_c = {
  key_buf: buffer UInt8.t;
  key_len: UInt32.t;
  key_len_le: UInt32.v key_len <= Buffer.length key_buf;
  value_kind: json_value_kind;
  value_buf: buffer UInt8.t;
  value_len: UInt32.t;
  value_len_le: UInt32.v value_len <= Buffer.length value_buf
}

/// A bytes block with machine-integer length, suitable for Stack allocation.
/// This type avoids Prims.list and nat, using only UInt32 and buffer.
noeq
type bytes_block = {
  buf: buffer UInt8.t;
  len: UInt32.t;
  len_bound: squash (UInt32.v len <= LowStar.Buffer.length buf)
}

noeq
type bytes_block_option =
  | BytesBlockNone
  | BytesBlockSome of bytes_block

/// Stack-friendly JSON member representation using bytes_block.
noeq
type json_member_u32 = {
  u32_key: bytes_block;
  u32_value_kind: json_value_kind;
  u32_value: bytes_block_option
}

// ============================================================================
// Ghost predicates (local, no Jose.* dependencies)
// ============================================================================

/// All nested key_buf/value_buf in members[idx..count-1] are live.
/// Local duplicate of Jose.LowStar.Json.Types.members_nested_live to
/// maintain the "no Jose.* dependencies" invariant for KaRaMeL extraction.
let rec members_nested_live
  (h:FStar.HyperStack.mem)
  (members:buffer json_member_c)
  (count:nat{count <= Buffer.length members})
  (idx:nat{idx <= count})
  : GTot Type0
  (decreases count - idx)
  =
  if idx = count then True
  else
    let s = Buffer.as_seq h members in
    let m = Seq.index s idx in
    live h m.key_buf /\ live h m.value_buf /\
    members_nested_live h members count (idx + 1)

/// Extract liveness at a specific index from the members_nested_live predicate.
let rec lemma_members_nested_live_at
  (h:FStar.HyperStack.mem)
  (members:buffer json_member_c)
  (count:nat{count <= Buffer.length members})
  (start:nat{start <= count})
  (target:nat{target >= start /\ target < count})
  : Lemma (requires members_nested_live h members count start)
          (ensures (let s = Buffer.as_seq h members in
                    let m = Seq.index s target in
                    live h m.key_buf /\ live h m.value_buf))
  (decreases target - start)
  = if start = target then ()
    else lemma_members_nested_live_at h members count (start + 1) target

/// All members in members[idx..count-1] have valid key/value lengths
/// (key_len > 0, and if value_kind = String then value_len > 0).
let rec members_valid_lengths
  (members:buffer json_member_c)
  (h:FStar.HyperStack.mem)
  (count:nat{count <= Buffer.length members})
  (idx:nat{idx <= count})
  : GTot Type0
  (decreases count - idx)
  =
  if idx = count then True
  else
    let s = Buffer.as_seq h members in
    let m = Seq.index s idx in
    FStar.UInt32.v m.key_len > 0 /\
    (m.value_kind = JsonValueString ==> FStar.UInt32.v m.value_len > 0) /\
    members_valid_lengths members h count (idx + 1)

/// Step members_nested_live from idx to idx+1 when idx < count.
let lemma_members_nested_live_step
  (h:FStar.HyperStack.mem)
  (members:buffer json_member_c)
  (count:nat{count <= Buffer.length members})
  (idx:nat{idx < count})
  : Lemma (requires members_nested_live h members count idx)
          (ensures members_nested_live h members count (idx + 1))
  = ()

/// Step members_valid_lengths from idx to idx+1 when idx < count.
let lemma_members_valid_lengths_step
  (members:buffer json_member_c)
  (h:FStar.HyperStack.mem)
  (count:nat{count <= Buffer.length members})
  (idx:nat{idx < count})
  : Lemma (requires members_valid_lengths members h count idx)
          (ensures members_valid_lengths members h count (idx + 1))
  = ()

/// Extract validity at a specific index.
let rec lemma_members_valid_lengths_at
  (members:buffer json_member_c)
  (h:FStar.HyperStack.mem)
  (count:nat{count <= Buffer.length members})
  (start:nat{start <= count})
  (target:nat{target >= start /\ target < count})
  : Lemma (requires members_valid_lengths members h count start)
          (ensures (let s = Buffer.as_seq h members in
                    let m = Seq.index s target in
                    FStar.UInt32.v m.key_len > 0 /\
                    (m.value_kind = JsonValueString ==> FStar.UInt32.v m.value_len > 0)))
  (decreases target - start)
  = if start = target then ()
    else lemma_members_valid_lengths_at members h count (start + 1) target

// ============================================================================
// FFI functions (assume val - implemented in C)
// ============================================================================

/// Heap allocator for byte buffers.
/// Concrete implementation via LowStar.Buffer.malloc (replaces FFI assume val).
/// This is intentionally duplicated from Jose.BytesBlock.malloc_bytes
/// to maintain the "no Jose.* dependencies" invariant required for
/// clean KaRaMeL extraction of this module.
val malloc_bytes
  : len:FStar.UInt32.t{FStar.UInt32.v len > 0}
  -> ST (buffer UInt8.t)
        (requires (fun _ -> True))
        (ensures (fun h0 buf h1 ->
          live h1 buf /\
          Buffer.length buf = FStar.UInt32.v len /\
          modifies loc_none h0 h1 /\
          Buffer.freeable buf /\
          Buffer.unused_in buf h0))

let malloc_bytes len = Buffer.malloc HS.root 0uy len

// ============================================================================
// Helper lemmas (simplified, no Jose.* dependencies)
// ============================================================================

// ============================================================================
// Stack layer functions (Low* compatible)
// ============================================================================

/// Copy bytes from source to destination buffer (recursive helper)
let rec copy_bytes_u32_aux
  (src:buffer UInt8.t)
  (dst:buffer UInt8.t)
  (len32:UInt32.t)
  (idx32:UInt32.t{UInt32.v idx32 <= UInt32.v len32})
  : Stack unit
      (requires (fun h ->
        live h src /\
        live h dst /\
        UInt32.v len32 <= Buffer.length src /\
        UInt32.v len32 <= Buffer.length dst /\
        loc_disjoint (loc_buffer src) (loc_buffer dst)))
      (ensures (fun h0 _ h1 ->
        modifies (loc_buffer dst) h0 h1 /\
        live h1 src /\
        live h1 dst))
  (decreases UInt32.v len32 - UInt32.v idx32)
  =
    if UInt32.lt idx32 len32 then begin
      let byte = Buffer.index src idx32 in
      Buffer.upd dst idx32 byte;
      lemma_u32_succ_within_bound idx32 len32;
      lemma_u32_measure_lt len32 idx32;
      copy_bytes_u32_aux src dst len32 (UInt32.add idx32 1ul)
    end else ()

/// Read bytes from buffer into new bytes_block
val read_bytes_with_bound_u32
  : buf:buffer UInt8.t
  -> len32:UInt32.t{FStar.UInt32.v len32 > 0 /\ FStar.UInt32.v len32 <= Buffer.length buf}
  -> ST bytes_block
      (requires (fun h -> live h buf))
      (ensures (fun h0 result h1 ->
        live h1 buf /\
        live h1 result.buf /\
        Buffer.length result.buf == FStar.UInt32.v len32 /\
        FStar.UInt32.v result.len == FStar.UInt32.v len32 /\
        Buffer.freeable result.buf /\
        Buffer.unused_in result.buf h0 /\
        modifies (loc_buffer result.buf) h0 h1))

let read_bytes_with_bound_u32 buf len32 =
    let h0 = FStar.HyperStack.ST.get () in
    let dst = malloc_bytes len32 in
    // dst is freshly allocated (unused_in h0), buf is live in h0 => disjoint
    copy_bytes_u32_aux buf dst len32 0ul;
    { buf = dst; len = len32; len_bound = () }

/// Lemma: members_nested_live is preserved when the heap is modified only
/// at a location that was unused_in h0 (i.e., freshly allocated).
/// This is the core frame lemma for the collect_members_u32_stack_aux proof.
///
/// Key insight: if buf was unused_in h0, then modifies (loc_buffer buf) h0 h1
/// preserves liveness of all buffers that were live in h0, because unused_in
/// implies loc_disjoint from all live locations.
let rec lemma_members_nested_live_preserved
  (h0 h1:FStar.HyperStack.mem)
  (members:buffer json_member_c)
  (count:nat{count <= Buffer.length members})
  (idx:nat{idx <= count})
  (fresh_buf:buffer UInt8.t)
  : Lemma
      (requires
        live h0 members /\
        live h1 members /\
        Buffer.unused_in fresh_buf h0 /\
        modifies (loc_buffer fresh_buf) h0 h1 /\
        members_nested_live h0 members count idx)
      (ensures members_nested_live h1 members count idx)
  (decreases count - idx)
  =
  if idx = count then ()
  else begin
    // modifies (loc_buffer fresh_buf) h0 h1 where fresh_buf unused_in h0
    // => Buffer.as_seq h0 members == Buffer.as_seq h1 members
    //    (members was live in h0, disjoint from fresh_buf)
    // => Seq.index at idx is the same in both heaps
    // For nested bufs: they were live h0, disjoint from fresh_buf => live h1
    lemma_members_nested_live_preserved h0 h1 members count (idx + 1) fresh_buf
  end

/// Lemma: members_valid_lengths is preserved when the heap is modified only
/// at a freshly allocated location.
let rec lemma_members_valid_lengths_preserved
  (h0 h1:FStar.HyperStack.mem)
  (members:buffer json_member_c)
  (count:nat{count <= Buffer.length members})
  (idx:nat{idx <= count})
  (fresh_buf:buffer UInt8.t)
  : Lemma
      (requires
        live h0 members /\
        Buffer.unused_in fresh_buf h0 /\
        modifies (loc_buffer fresh_buf) h0 h1 /\
        members_valid_lengths members h0 count idx)
      (ensures members_valid_lengths members h1 count idx)
  (decreases count - idx)
  =
  if idx = count then ()
  else
    lemma_members_valid_lengths_preserved h0 h1 members count (idx + 1) fresh_buf

/// Read json_member_c and convert to json_member_u32
val read_member_u32_stack
  : m:json_member_c{FStar.UInt32.v m.key_len > 0 /\
                     (m.value_kind = JsonValueString ==> FStar.UInt32.v m.value_len > 0)}
  -> ST json_member_u32
      (requires (fun h -> live h m.key_buf /\ live h m.value_buf))
      (ensures (fun h0 result h1 ->
        live h1 m.key_buf /\
        live h1 m.value_buf /\
        live h1 result.u32_key.buf /\
        (match result.u32_value with
         | BytesBlockSome v -> live h1 v.buf
         | BytesBlockNone -> True)))

let read_member_u32_stack m =
    let _ = m.key_len_le in  // bring key_len <= length key_buf into context
    let key_len32 = m.key_len in
    let u32_key = read_bytes_with_bound_u32 m.key_buf key_len32 in
    match m.value_kind with
    | JsonValueNull ->
        { u32_key = u32_key;
          u32_value_kind = JsonValueNull;
          u32_value = BytesBlockNone }
    | JsonValueString ->
        let _ = m.value_len_le in  // bring value_len <= length value_buf into context
        let value_len32 = m.value_len in
        let u32_value_block = read_bytes_with_bound_u32 m.value_buf value_len32 in
        { u32_key = u32_key;
          u32_value_kind = JsonValueString;
          u32_value = BytesBlockSome u32_value_block }

/// Collect members into list json_member_u32 (recursive helper).
/// Concrete implementation replacing former assume val.
/// Effect is ST (not Stack) because read_bytes_with_bound_u32 allocates via malloc.
///
/// Strategy: inline the read_bytes_with_bound_u32 calls directly so that
/// the modifies/unused_in postconditions are available for proving that
/// members_nested_live and members_valid_lengths are preserved for the
/// recursive call at idx+1. Each branch (Null/String) independently
/// steps the predicates and makes the recursive call.
let rec collect_members_u32_stack_aux
  (members:buffer json_member_c)
  (count32:UInt32.t{UInt32.v count32 <= Buffer.length members})
  (idx32:UInt32.t{UInt32.v idx32 <= UInt32.v count32})
  : ST (list json_member_u32)
      (requires (fun h ->
        live h members /\
        members_nested_live h members (UInt32.v count32) (UInt32.v idx32) /\
        members_valid_lengths members h (UInt32.v count32) (UInt32.v idx32)))
      (ensures (fun h0 _ h1 -> live h1 members))
  (decreases UInt32.v count32 - UInt32.v idx32)
  =
    if UInt32.lt idx32 count32 then begin
      let h0 = FStar.HyperStack.ST.get () in
      let idx = UInt32.v idx32 in
      let count = UInt32.v count32 in
      // Extract liveness and validity for this index
      lemma_members_nested_live_at h0 members count idx idx;
      lemma_members_valid_lengths_at members h0 count idx idx;
      let m = Buffer.index members idx32 in
      let _ = m.key_len_le in
      // -- Read key bytes --
      let u32_key = read_bytes_with_bound_u32 m.key_buf m.key_len in
      let h1 = FStar.HyperStack.ST.get () in
      // u32_key.buf was unused_in h0 => modifies only fresh location =>
      // all pre-existing liveness preserved
      lemma_members_nested_live_preserved h0 h1 members count idx u32_key.buf;
      lemma_members_valid_lengths_preserved h0 h1 members count idx u32_key.buf;
      // -- Branch on value kind, recurse in each branch --
      match m.value_kind with
      | JsonValueNull ->
          let converted = { u32_key = u32_key;
                            u32_value_kind = JsonValueNull;
                            u32_value = BytesBlockNone } in
          // Step predicates from idx to idx+1
          lemma_members_nested_live_step h1 members count idx;
          lemma_members_valid_lengths_step members h1 count idx;
          lemma_u32_succ_within_bound idx32 count32;
          lemma_u32_measure_lt count32 idx32;
          let rest = collect_members_u32_stack_aux members count32 (UInt32.add idx32 1ul) in
          converted :: rest
      | JsonValueString ->
          let _ = m.value_len_le in
          let h_pre = FStar.HyperStack.ST.get () in
          let u32_val = read_bytes_with_bound_u32 m.value_buf m.value_len in
          let h_post = FStar.HyperStack.ST.get () in
          lemma_members_nested_live_preserved h_pre h_post members count idx u32_val.buf;
          lemma_members_valid_lengths_preserved h_pre h_post members count idx u32_val.buf;
          let converted = { u32_key = u32_key;
                            u32_value_kind = JsonValueString;
                            u32_value = BytesBlockSome u32_val } in
          // Step predicates from idx to idx+1
          lemma_members_nested_live_step h_post members count idx;
          lemma_members_valid_lengths_step members h_post count idx;
          lemma_u32_succ_within_bound idx32 count32;
          lemma_u32_measure_lt count32 idx32;
          let rest = collect_members_u32_stack_aux members count32 (UInt32.add idx32 1ul) in
          converted :: rest
    end else []

/// Collect members into list json_member_u32 (main entry point)
let collect_members_u32_stack
  (members:buffer json_member_c)
  (count32:UInt32.t{UInt32.v count32 <= Buffer.length members})
  : ST (list json_member_u32)
      (requires (fun h ->
        live h members /\
        members_nested_live h members (UInt32.v count32) 0 /\
        members_valid_lengths members h (UInt32.v count32) 0))
      (ensures (fun h0 _ h1 -> live h1 members))
  =
    collect_members_u32_stack_aux members count32 0ul
