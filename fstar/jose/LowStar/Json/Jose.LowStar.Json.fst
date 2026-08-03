module Jose.LowStar.Json

open FStar.List.Tot
open FStar.String
open FStar.Math.Lemmas
open FStar.UInt8
open FStar.UInt32
open FStar.HyperStack.All
open FStar.HyperStack.ST
open FStar.Seq
open FStar.Calc
open FStar.UInt
open LowStar.Buffer
open Jose.JsonHeaderSpec
open Jose.HeaderParser
open Jose.HeaderSpec
open Jose.Utf8Lemmas
open Jose.Arith.Bounds
open Jose.BufferListLemmas
open Jose.BytesBlock
open Jose.LowStar.Json.Helpers
open Jose.LowStar.Json.Runtime
open Jose.LowStar.Json.Types
open Jose.LowStar.Json.Utf8
open Jose.LowStar.Json.ParseEntries
open Jose.LowStar.Json.Spec

module List = FStar.List.Tot
module U32 = FStar.UInt32
module Buffer = LowStar.Buffer
module HST = FStar.HyperStack.ST

type decode_error = Jose.Utf8Lemmas.decode_error

noeq
type bytes_block_option =
  | BytesBlockNone
  | BytesBlockSome of bytes_block

// ============================================================================
// Phase 2: UInt32-based types for KaRaMeL extraction (Step 2: extractable)
// ============================================================================
//
// These types are designed for KaRaMeL extraction without mathematical integers.
// Migrating Stack functions from list-based to bytes_block-based representation.
// See: docs/program-management/initiatives/jose/lowstar/warning15-machine-integer.md

/// Stack-friendly JSON member representation using bytes_block.
/// Replaces raw_json_member for Stack layer functions.
/// Field names prefixed with `u32_` to distinguish from json_member_c.
noeq
type json_member_u32 = {
  u32_key: bytes_block;
  u32_value_kind: json_value_kind;
  u32_value: bytes_block_option
}

// Phase 2 Step 2.4: UInt32-based member indexing for KaRaMeL extraction
// Buffer.index requires UInt32.t index, so we provide UInt32 version.
let index_member_u32
  (members:buffer json_member_c)
  (count32:UInt32.t{UInt32.v count32 <= Buffer.length members})
  (idx32:UInt32.t{UInt32.v idx32 < UInt32.v count32})
  : Stack json_member_c
      (requires (fun h -> live h members))
      (ensures (fun h0 member h1 ->
                  h0 == h1 /\
                  live h1 members))
  =
    lemma_idx_u32_lt_buffer_from_len members count32 idx32;
    Buffer.index members idx32

// index_member_with_liveness: now in Jose.LowStar.Json.Types

// UTF-8 encoding runtime function
//
// This is marked noextract because it operates on F* strings (spec-level).
// The actual implementation uses encode_utf8_bytes_runtime_correct as the
// interface to Low* code, which operates on buffers.
//
// The assume here represents that the runtime correctly implements UTF-8
// encoding according to the spec-level encode_utf8_bytes definition.
// (Documented in docs/verification/jose/json-lowstar-ffi-contracts.md.)

///////////////////////////////////////////////////////////////////////////////
// C ABI Wrappers
///////////////////////////////////////////////////////////////////////////////

// json_parse_error: now in Jose.LowStar.Json.Types

// Predicate: a single entry's buffers are live
let entry_buffers_live (h:FStar.HyperStack.mem) (entry:json_entry_out) : GTot Type0 =
  live h entry.entry_key_ptr /\ live h entry.entry_value_ptr

// Predicate: all entries' buffers from idx to count-1 are live
let rec entries_buffers_live
  (h:FStar.HyperStack.mem)
  (entries:buffer json_entry_out)
  (count:U32.t{U32.v count <= Buffer.length entries})
  (idx:U32.t{U32.v idx <= U32.v count})
  : GTot Type0
  (decreases U32.v count - U32.v idx)
  =
  if U32.v idx = U32.v count then True
  else
    (let entries_seq = Buffer.as_seq h entries in
     let entry = Seq.index entries_seq (U32.v idx) in
     entry_buffers_live h entry) /\
    entries_buffers_live h entries count (U32.add idx U32.one)

// Predicate: all entries' buffers are pairwise disjoint
// This is the key allocator invariant: distinct entries have disjoint nested buffers
let rec entries_buffers_disjoint
  (h:FStar.HyperStack.mem)
  (entries:buffer json_entry_out)
  (count:U32.t{U32.v count <= Buffer.length entries})
  (idx:U32.t{U32.v idx <= U32.v count})
  : GTot Type0
  (decreases U32.v count - U32.v idx)
  =
  if U32.v idx = U32.v count then True
  else
    (let entries_seq = Buffer.as_seq h entries in
     let entry = Seq.index entries_seq (U32.v idx) in
     // entry's buffers are disjoint from all subsequent entries' buffers
     ((forall (j:nat{U32.v idx < j /\ j < U32.v count}).
       let other = Seq.index entries_seq j in
       loc_disjoint (loc_buffer entry.entry_key_ptr) (loc_buffer other.entry_key_ptr) /\
       loc_disjoint (loc_buffer entry.entry_key_ptr) (loc_buffer other.entry_value_ptr) /\
       loc_disjoint (loc_buffer entry.entry_value_ptr) (loc_buffer other.entry_key_ptr) /\
       loc_disjoint (loc_buffer entry.entry_value_ptr) (loc_buffer other.entry_value_ptr)) /\
     entries_buffers_disjoint h entries count (U32.add idx U32.one)))

// Predicate: entries buffer is disjoint from all nested buffers
// This is part of the FFI contract: the Rust allocator must ensure the entries
// array buffer does not overlap with any of the nested key/value buffers
let rec entries_buffer_disjoint_from_nested
  (h:FStar.HyperStack.mem)
  (entries:buffer json_entry_out)
  (count:U32.t{U32.v count <= Buffer.length entries})
  (idx:U32.t{U32.v idx <= U32.v count})
  : GTot Type0
  (decreases U32.v count - U32.v idx)
  =
  if U32.v idx = U32.v count then True
  else
    (let entries_seq = Buffer.as_seq h entries in
     let entry = Seq.index entries_seq (U32.v idx) in
     loc_disjoint (loc_buffer entries) (loc_buffer entry.entry_key_ptr) /\
     loc_disjoint (loc_buffer entries) (loc_buffer entry.entry_value_ptr) /\
     entries_buffer_disjoint_from_nested h entries count (U32.add idx U32.one))

// entries_buffers_freeable: now in Jose.LowStar.Json.Runtime
// entries_key_value_self_disjoint: now in Jose.LowStar.Json.Runtime

// Lemma: entries buffer remains unchanged when only nested buffers are freed.
// Uses loc_addr_of_buffer (from Buffer.free) instead of loc_buffer.
// freeable_disjoint' bridges loc_buffer disjointness to loc_addr_of_buffer disjointness.
/// Helper: extract entry at a given index from a buffer.
/// Proves the Seq.index bound explicitly (U32.v idx < U32.v count <= Buffer.length entries
/// => U32.v idx < Seq.length (as_seq h entries)).
/// Needed because my Spec.fst additions pollute Z3's context, making it unable to
/// derive this trivial arithmetic bound automatically.
#push-options "--z3rlimit 20 --fuel 0 --ifuel 0"
let entry_at_idx
  (h:FStar.HyperStack.mem)
  (entries:buffer json_entry_out)
  (count:U32.t{U32.v count <= Buffer.length entries})
  (idx:U32.t{U32.v idx < U32.v count})
  : Ghost json_entry_out
    (requires live h entries)
    (ensures fun entry -> entry == Seq.index (Buffer.as_seq h entries) (U32.v idx))
  =
  Seq.index (Buffer.as_seq h entries) (U32.v idx)
#pop-options

#push-options "--z3rlimit 200 --fuel 1 --ifuel 1 --z3refresh"
let lemma_entries_buffer_preserved
  (entries:buffer json_entry_out)
  (count:U32.t{U32.v count <= Buffer.length entries})
  (idx:U32.t{U32.v idx < U32.v count})
  (freed_key:buffer UInt8.t)
  (freed_value:buffer UInt8.t)
  (h0 h1:FStar.HyperStack.mem)
  : Lemma (requires live h0 entries /\
                     Buffer.freeable freed_key /\
                     Buffer.freeable freed_value /\
                     Buffer.length entries > 0 /\
                     entries_buffer_disjoint_from_nested h0 entries count idx /\
                     modifies (loc_union (loc_addr_of_buffer freed_key) (loc_addr_of_buffer freed_value)) h0 h1 /\
                     (let entry = entry_at_idx h0 entries count idx in
                      freed_key == entry.entry_key_ptr /\
                      freed_value == entry.entry_value_ptr))
          (ensures Buffer.as_seq h0 entries == Buffer.as_seq h1 entries /\ live h1 entries)
  =
  // Extract entry via helper (handles Seq.index bound proof in isolation)
  let entry = entry_at_idx h0 entries count idx in
  // Step 1: Extract disjointness from predicate (loc_buffer level).
  // Need to unfold entries_buffer_disjoint_from_nested once at idx.
  // idx < count => idx <= count (trivial, but help Z3)
  assert (U32.v idx <= U32.v count);
  // The predicate at idx gives:
  //   loc_disjoint (loc_buffer entries) (loc_buffer entry.entry_key_ptr) /\
  //   loc_disjoint (loc_buffer entries) (loc_buffer entry.entry_value_ptr)
  // Step 2: Symmetry + freeable_disjoint' to get loc_addr_of_buffer disjointness.
  // entry.entry_key_ptr == freed_key (from requires)
  loc_disjoint_sym (loc_buffer entries) (loc_buffer freed_key);
  loc_disjoint_sym (loc_buffer entries) (loc_buffer freed_value);
  // Now: loc_disjoint (loc_buffer freed_key) (loc_buffer entries) etc.
  // freeable_disjoint': freeable b1 /\ live h b2 /\ loc_disjoint (loc_buffer b1) (loc_buffer b2)
  //                     => loc_disjoint (loc_addr_of_buffer b1) (loc_addr_of_buffer b2)
  Buffer.freeable_disjoint' freed_key entries;
  Buffer.freeable_disjoint' freed_value entries;
  // Step 3: Narrow from loc_addr_of_buffer entries to loc_buffer entries
  loc_disjoint_includes (loc_addr_of_buffer freed_key) (loc_addr_of_buffer entries)
                        (loc_addr_of_buffer freed_key) (loc_buffer entries);
  loc_disjoint_includes (loc_addr_of_buffer freed_value) (loc_addr_of_buffer entries)
                        (loc_addr_of_buffer freed_value) (loc_buffer entries);
  // Step 4: Combine into union disjointness
  loc_disjoint_union_r (loc_buffer entries) (loc_addr_of_buffer freed_key) (loc_addr_of_buffer freed_value);
  // Step 5: modifies_buffer_elim fires via SMT → as_seq preserved + live h1
  ()
#pop-options

// Lemma: entries_buffer_disjoint_from_nested preserved across heap transitions when buffer sequence unchanged
let rec lemma_entries_buffer_disjoint_from_nested_preserved
  (entries:buffer json_entry_out)
  (count:U32.t{U32.v count <= Buffer.length entries})
  (idx:U32.t{U32.v idx <= U32.v count})
  (h0 h1:FStar.HyperStack.mem)
  : Lemma (requires entries_buffer_disjoint_from_nested h0 entries count idx /\
                     Buffer.as_seq h0 entries == Buffer.as_seq h1 entries)
          (ensures entries_buffer_disjoint_from_nested h1 entries count idx)
          (decreases U32.v count - U32.v idx)
  =
  if U32.v idx = U32.v count then ()
  else (
    // Unfold predicates in both heaps
    let entries_seq_h0 = Buffer.as_seq h0 entries in
    let entries_seq_h1 = Buffer.as_seq h1 entries in
    let entry_h0 = Seq.index entries_seq_h0 (U32.v idx) in
    let entry_h1 = Seq.index entries_seq_h1 (U32.v idx) in
    // Since sequences are equal, entries are equal
    assert (entry_h0 == entry_h1);
    // loc_disjoint is structural, doesn't depend on heap contents
    assert (loc_disjoint (loc_buffer entries) (loc_buffer entry_h0.entry_key_ptr));
    assert (loc_disjoint (loc_buffer entries) (loc_buffer entry_h0.entry_value_ptr));
    // Recurse for remaining entries
    lemma_entries_buffer_disjoint_from_nested_preserved entries count (U32.add idx 1ul) h0 h1
  )

// Lemma: unfolding the recursive predicate for next index
let lemma_entries_buffers_live_next
  (h:FStar.HyperStack.mem)
  (entries:buffer json_entry_out)
  (count:U32.t{U32.v count <= Buffer.length entries})
  (idx:U32.t{U32.v idx < U32.v count})
  : Lemma (requires entries_buffers_live h entries count idx)
          (ensures entries_buffers_live h entries count (U32.add idx U32.one))
  = ()

let lemma_entries_buffers_freeable_next
  (h:FStar.HyperStack.mem)
  (entries:buffer json_entry_out)
  (count:U32.t{U32.v count <= Buffer.length entries})
  (idx:U32.t{U32.v idx < U32.v count})
  : Lemma (requires entries_buffers_freeable h entries count idx)
          (ensures entries_buffers_freeable h entries count (U32.add idx U32.one))
  = ()

let lemma_entries_key_value_self_disjoint_next
  (h:FStar.HyperStack.mem)
  (entries:buffer json_entry_out)
  (count:U32.t{U32.v count <= Buffer.length entries})
  (idx:U32.t{U32.v idx < U32.v count})
  : Lemma (requires entries_key_value_self_disjoint h entries count idx)
          (ensures entries_key_value_self_disjoint h entries count (U32.add idx U32.one))
  = ()

// Lemma: disjoint buffers preserve liveness after modification
// If buffer b is modified and buffer c is disjoint from b, then c remains live
let lemma_disjoint_preserves_liveness
  (#a:Type)
  (b:buffer a)
  (c:buffer a)
  (h0 h1:FStar.HyperStack.mem)
  : Lemma (requires live h0 c /\
                     loc_disjoint (loc_buffer b) (loc_buffer c) /\
                     modifies (loc_buffer b) h0 h1)
          (ensures live h1 c)
  = ()

// Lemma: stepping the disjointness predicate to next index
let lemma_entries_buffers_disjoint_next
  (h:FStar.HyperStack.mem)
  (entries:buffer json_entry_out)
  (count:U32.t{U32.v count <= Buffer.length entries})
  (idx:U32.t{U32.v idx < U32.v count})
  : Lemma (requires entries_buffers_disjoint h entries count idx)
          (ensures entries_buffers_disjoint h entries count (U32.add idx U32.one))
  = ()

// Lemma: disjointness is preserved across heap transitions (it's a structural property)
let rec lemma_entries_buffers_disjoint_preserved
  (entries:buffer json_entry_out)
  (count:U32.t{U32.v count <= Buffer.length entries})
  (idx:U32.t{U32.v idx <= U32.v count})
  (h0 h1:FStar.HyperStack.mem)
  : Lemma (requires entries_buffers_disjoint h0 entries count idx /\
                     Buffer.as_seq h0 entries == Buffer.as_seq h1 entries)
          (ensures entries_buffers_disjoint h1 entries count idx)
          (decreases U32.v count - U32.v idx)
  = if U32.v idx = U32.v count then ()
    else lemma_entries_buffers_disjoint_preserved entries count (U32.add idx U32.one) h0 h1

let rec lemma_entries_buffers_freeable_preserved
  (entries:buffer json_entry_out)
  (count:U32.t{U32.v count <= Buffer.length entries})
  (idx:U32.t{U32.v idx <= U32.v count})
  (h0 h1:FStar.HyperStack.mem)
  : Lemma (requires entries_buffers_freeable h0 entries count idx /\
                     Buffer.as_seq h0 entries == Buffer.as_seq h1 entries)
          (ensures entries_buffers_freeable h1 entries count idx)
          (decreases U32.v count - U32.v idx)
  = if U32.v idx = U32.v count then ()
    else lemma_entries_buffers_freeable_preserved entries count (U32.add idx 1ul) h0 h1

let rec lemma_entries_key_value_self_disjoint_preserved
  (entries:buffer json_entry_out)
  (count:U32.t{U32.v count <= Buffer.length entries})
  (idx:U32.t{U32.v idx <= U32.v count})
  (h0 h1:FStar.HyperStack.mem)
  : Lemma (requires entries_key_value_self_disjoint h0 entries count idx /\
                     Buffer.as_seq h0 entries == Buffer.as_seq h1 entries)
          (ensures entries_key_value_self_disjoint h1 entries count idx)
          (decreases U32.v count - U32.v idx)
  = if U32.v idx = U32.v count then ()
    else lemma_entries_key_value_self_disjoint_preserved entries count (U32.add idx 1ul) h0 h1

// Lemma: helper for proving single entry buffers remain live after freeing disjoint buffers.
// Uses loc_addr_of_buffer modifies + freeable for SMT bridging via freeable_disjoint'.
#push-options "--z3rlimit 100 --fuel 0 --ifuel 0 --z3refresh"
let lemma_entry_buffers_live_preserved
  (entry:json_entry_out)
  (freed_key:buffer UInt8.t{Buffer.freeable freed_key})
  (freed_value:buffer UInt8.t{Buffer.freeable freed_value})
  (h0 h1:FStar.HyperStack.mem)
  : Lemma (requires entry_buffers_live h0 entry /\
                     Buffer.freeable entry.entry_key_ptr /\
                     Buffer.freeable entry.entry_value_ptr /\
                     loc_disjoint (loc_buffer freed_key) (loc_buffer entry.entry_key_ptr) /\
                     loc_disjoint (loc_buffer freed_key) (loc_buffer entry.entry_value_ptr) /\
                     loc_disjoint (loc_buffer freed_value) (loc_buffer entry.entry_key_ptr) /\
                     loc_disjoint (loc_buffer freed_value) (loc_buffer entry.entry_value_ptr) /\
                     modifies (loc_union (loc_addr_of_buffer freed_key) (loc_addr_of_buffer freed_value)) h0 h1)
          (ensures entry_buffers_live h1 entry)
  =
  // Lift loc_buffer disjointness to loc_addr_of_buffer disjointness via freeable_disjoint'.
  Buffer.freeable_disjoint' freed_key entry.entry_key_ptr;
  Buffer.freeable_disjoint' freed_key entry.entry_value_ptr;
  Buffer.freeable_disjoint' freed_value entry.entry_key_ptr;
  Buffer.freeable_disjoint' freed_value entry.entry_value_ptr;
  // Narrow to loc_buffer level for modifies_buffer_elim.
  loc_disjoint_includes (loc_addr_of_buffer freed_key) (loc_addr_of_buffer entry.entry_key_ptr)
                        (loc_addr_of_buffer freed_key) (loc_buffer entry.entry_key_ptr);
  loc_disjoint_includes (loc_addr_of_buffer freed_key) (loc_addr_of_buffer entry.entry_value_ptr)
                        (loc_addr_of_buffer freed_key) (loc_buffer entry.entry_value_ptr);
  loc_disjoint_includes (loc_addr_of_buffer freed_value) (loc_addr_of_buffer entry.entry_key_ptr)
                        (loc_addr_of_buffer freed_value) (loc_buffer entry.entry_key_ptr);
  loc_disjoint_includes (loc_addr_of_buffer freed_value) (loc_addr_of_buffer entry.entry_value_ptr)
                        (loc_addr_of_buffer freed_value) (loc_buffer entry.entry_value_ptr);
  // Combine into union disjointness and let modifies_buffer_elim fire.
  loc_disjoint_union_r (loc_buffer entry.entry_key_ptr)
                       (loc_addr_of_buffer freed_key) (loc_addr_of_buffer freed_value);
  loc_disjoint_union_r (loc_buffer entry.entry_value_ptr)
                       (loc_addr_of_buffer freed_key) (loc_addr_of_buffer freed_value);
  ()
#pop-options

// Lemma: recursive helper for frame condition (loc_addr_of_buffer version).
let rec lemma_free_preserves_remaining_entries_aux
  (entries:buffer json_entry_out)
  (count:U32.t{U32.v count <= Buffer.length entries})
  (idx:U32.t{U32.v idx < U32.v count})
  (curr:U32.t{U32.v idx < U32.v curr /\ U32.v curr <= U32.v count})
  (entry:json_entry_out)
  (h0 h1:FStar.HyperStack.mem)
  : Lemma (requires entries_buffers_live h0 entries count curr /\
                     entries_buffers_freeable h0 entries count curr /\
                     entries_buffers_disjoint h0 entries count idx /\
                     Buffer.freeable entry.entry_key_ptr /\
                     Buffer.freeable entry.entry_value_ptr /\
                     entry == Seq.index (Buffer.as_seq h0 entries) (U32.v idx) /\
                     Buffer.as_seq h0 entries == Buffer.as_seq h1 entries /\
                     modifies (loc_union (loc_addr_of_buffer entry.entry_key_ptr)
                                        (loc_addr_of_buffer entry.entry_value_ptr)) h0 h1)
          (ensures entries_buffers_live h1 entries count curr)
          (decreases U32.v count - U32.v curr)
  =
  if U32.v curr = U32.v count then ()
  else
    let entries_seq = Buffer.as_seq h0 entries in
    let current_entry = Seq.index entries_seq (U32.v curr) in
    lemma_entry_buffers_live_preserved current_entry
      entry.entry_key_ptr entry.entry_value_ptr h0 h1;
    lemma_free_preserves_remaining_entries_aux entries count idx (U32.add curr 1ul) entry h0 h1

// Lemma: frame condition for entries_buffers_live (loc_addr_of_buffer version).
// When freeing entry[idx]'s buffers via Buffer.free, if all entries are disjoint and freeable,
// then entries[idx+1..count]'s buffers remain live and the entries array is unchanged.
let lemma_free_preserves_remaining_entries
  (entries:buffer json_entry_out)
  (count:U32.t{U32.v count <= Buffer.length entries})
  (idx:U32.t{U32.v idx < U32.v count})
  (entry:json_entry_out)
  (h0 h1:FStar.HyperStack.mem)
  : Lemma (requires live h0 entries /\
                     Buffer.length entries > 0 /\
                     entries_buffers_live h0 entries count (U32.add idx U32.one) /\
                     entries_buffers_freeable h0 entries count (U32.add idx U32.one) /\
                     entries_buffers_disjoint h0 entries count idx /\
                     entries_buffer_disjoint_from_nested h0 entries count idx /\
                     Buffer.freeable entry.entry_key_ptr /\
                     Buffer.freeable entry.entry_value_ptr /\
                     entry == Seq.index (Buffer.as_seq h0 entries) (U32.v idx) /\
                     modifies (loc_union (loc_addr_of_buffer entry.entry_key_ptr)
                                        (loc_addr_of_buffer entry.entry_value_ptr)) h0 h1)
          (ensures entries_buffers_live h1 entries count (U32.add idx U32.one) /\
                   Buffer.as_seq h0 entries == Buffer.as_seq h1 entries /\
                   live h1 entries)
  =
  lemma_entries_buffer_preserved entries count idx
    entry.entry_key_ptr entry.entry_value_ptr h0 h1;
  lemma_free_preserves_remaining_entries_aux entries count idx (U32.add idx 1ul) entry h0 h1

let lemma_store_pre (#a:Type) (idx:nat) (x:a) (xs:list a) (buf_len:nat)
  : Lemma (requires idx + List.length (x :: xs) <= buf_len)
          (ensures idx + 1 + List.length xs <= buf_len /\ idx < buf_len)
  =
    let len_cons = List.length (x :: xs) in
    let len_tail = List.length xs in
    assert (len_cons = len_tail + 1);
    assert (idx + 1 + len_tail = idx + len_cons);
    assert (idx + 1 + len_tail <= buf_len);
    assert (len_cons > 0);
    assert (idx < idx + len_cons);
    lemma_lt_trans_le idx (idx + len_cons) buf_len

let lemma_bound_drop_one
  (idx:nat)
  (rest_len:nat)
  (buf_len:nat)
  : Lemma (requires idx + (rest_len + 1) <= buf_len)
          (ensures idx + rest_len <= buf_len)
  =
    assert (idx + rest_len <= buf_len);
    ()

let lemma_length_cons_split_eq (#a:Type) (x:a) (xs:list a) (len:nat)
  : Lemma (requires List.length (x :: xs) = len)
          (ensures List.length xs + 1 = len)
  =
    let tail_len = List.length xs in
    assert (List.length (x :: xs) = tail_len + 1);
    assert (tail_len + 1 = len);
    ()

let lemma_store_bounds
  (idx:nat)
  (entry:json_entry_out)
  (rest:list json_entry_out)
  (buf_len:nat)
  : Lemma
      (requires idx + List.length (entry :: rest) <= buf_len)
      (ensures idx < buf_len /\
               idx + List.length rest < buf_len /\
               idx + 1 + List.length rest <= buf_len)
  =
    let rest_len = List.length rest in
    let total_len = List.length (entry :: rest) in
    lemma_length_cons_split_eq entry rest total_len;
    assert (rest_len + 1 = total_len);
    lemma_store_pre idx entry rest buf_len;
    lemma_bound_drop_one idx rest_len buf_len;
    lemma_lt_succ (idx + rest_len);
    assert (idx + rest_len + 1 = idx + 1 + rest_len);
    assert (idx + rest_len + 1 <= buf_len);
    lemma_lt_trans_le (idx + rest_len) (idx + rest_len + 1) buf_len;
    ()

// write_entry_at_u32: now in Jose.LowStar.Json.Types
// json_parse_result_c: now in Jose.LowStar.Json.Types

///////////////////////////////////////////////////////////////////////////////
// Lift lemmas: convert list-based predicates + content linking into
// buffer-indexed predicates (entries_buffers_live, etc.)
///////////////////////////////////////////////////////////////////////////////

/// Convert entry_disjoint_from_list structural to index-based.
/// Given entry_disjoint_from_list entry entries, we can extract disjointness
/// for any specific entry at index k in the list.
let rec lemma_disjoint_from_list_at_index
  (entry:json_entry_out) (entries:list json_entry_out) (k:nat{k < List.length entries})
  : Lemma (requires entry_disjoint_from_list entry entries)
    (ensures (let other = List.index entries k in
      loc_disjoint (loc_buffer entry.entry_key_ptr) (loc_buffer other.entry_key_ptr) /\
      loc_disjoint (loc_buffer entry.entry_key_ptr) (loc_buffer other.entry_value_ptr) /\
      loc_disjoint (loc_buffer entry.entry_value_ptr) (loc_buffer other.entry_key_ptr) /\
      loc_disjoint (loc_buffer entry.entry_value_ptr) (loc_buffer other.entry_value_ptr)))
    (decreases k)
  = match entries with
    | hd :: tl ->
      if k = 0 then ()
      else lemma_disjoint_from_list_at_index entry tl (k - 1)

/// Extract liveness at a specific index from entry_list_buffers_live.
let rec lemma_entry_list_live_at_index
  (h:FStar.HyperStack.mem) (entries:list json_entry_out) (k:nat{k < List.length entries})
  : Lemma (requires entry_list_buffers_live h entries)
    (ensures (let e = List.index entries k in live h e.entry_key_ptr /\ live h e.entry_value_ptr))
    (decreases k)
  = match entries with
    | hd :: tl ->
      if k = 0 then ()
      else lemma_entry_list_live_at_index h tl (k - 1)

/// Lift entry_list_buffers_live to entries_buffers_live (buffer-indexed).
/// Content linking is from index 0: forall i < count. buf[i] == entries[i].
/// This is invariant across recursion (idx increases but the linking covers all indices).
#push-options "--z3rlimit 80 --fuel 2 --ifuel 1"
let rec lemma_lift_live_aux
  (h:FStar.HyperStack.mem)
  (buf:buffer json_entry_out)
  (count:U32.t{U32.v count <= Buffer.length buf})
  (idx:U32.t{U32.v idx <= U32.v count})
  (entries:list json_entry_out)
  : Lemma
    (requires
      live h buf /\
      List.length entries = U32.v count /\
      entry_list_buffers_live h entries /\
      (forall (i:nat{i < List.length entries}).
        Seq.index (Buffer.as_seq h buf) i == List.index entries i))
    (ensures entries_buffers_live h buf count idx)
    (decreases U32.v count - U32.v idx)
  = if U32.v idx = U32.v count then ()
    else begin
      // buf[idx] == entries[idx] by content linking (i = U32.v idx)
      let seq = Buffer.as_seq h buf in
      assert (Seq.index seq (U32.v idx) == List.index entries (U32.v idx));
      // entries[idx] has live buffers (from list predicate)
      lemma_entry_list_live_at_index h entries (U32.v idx);
      // Recurse for idx+1 (content linking still holds for all indices)
      lemma_lift_live_aux h buf count (U32.add idx U32.one) entries
    end
#pop-options

/// Extract freeability at a specific index from entry_list_buffers_freeable.
let rec lemma_entry_list_freeable_at_index
  (entries:list json_entry_out) (k:nat{k < List.length entries})
  : Lemma (requires entry_list_buffers_freeable entries)
    (ensures (let e = List.index entries k in Buffer.freeable e.entry_key_ptr /\ Buffer.freeable e.entry_value_ptr))
    (decreases k)
  = match entries with
    | hd :: tl ->
      if k = 0 then ()
      else lemma_entry_list_freeable_at_index tl (k - 1)

/// Lift entry_list_buffers_freeable to entries_buffers_freeable (buffer-indexed).
#push-options "--z3rlimit 80 --fuel 2 --ifuel 1"
let rec lemma_lift_freeable_aux
  (h:FStar.HyperStack.mem)
  (buf:buffer json_entry_out)
  (count:U32.t{U32.v count <= Buffer.length buf})
  (idx:U32.t{U32.v idx <= U32.v count})
  (entries:list json_entry_out)
  : Lemma
    (requires
      live h buf /\
      List.length entries = U32.v count /\
      entry_list_buffers_freeable entries /\
      (forall (i:nat{i < List.length entries}).
        Seq.index (Buffer.as_seq h buf) i == List.index entries i))
    (ensures entries_buffers_freeable h buf count idx)
    (decreases U32.v count - U32.v idx)
  = if U32.v idx = U32.v count then ()
    else begin
      let seq = Buffer.as_seq h buf in
      assert (Seq.index seq (U32.v idx) == List.index entries (U32.v idx));
      lemma_entry_list_freeable_at_index entries (U32.v idx);
      lemma_lift_freeable_aux h buf count (U32.add idx U32.one) entries
    end
#pop-options

/// Extract self-disjointness at a specific index from entry_list_key_value_self_disjoint.
let rec lemma_entry_list_self_disjoint_at_index
  (entries:list json_entry_out) (k:nat{k < List.length entries})
  : Lemma (requires entry_list_key_value_self_disjoint entries)
    (ensures (let e = List.index entries k in
      loc_disjoint (loc_buffer e.entry_key_ptr) (loc_buffer e.entry_value_ptr)))
    (decreases k)
  = match entries with
    | hd :: tl ->
      if k = 0 then ()
      else lemma_entry_list_self_disjoint_at_index tl (k - 1)

/// Lift entry_list_key_value_self_disjoint to entries_key_value_self_disjoint (buffer-indexed).
#push-options "--z3rlimit 80 --fuel 2 --ifuel 1"
let rec lemma_lift_self_disjoint_aux
  (h:FStar.HyperStack.mem)
  (buf:buffer json_entry_out)
  (count:U32.t{U32.v count <= Buffer.length buf})
  (idx:U32.t{U32.v idx <= U32.v count})
  (entries:list json_entry_out)
  : Lemma
    (requires
      live h buf /\
      List.length entries = U32.v count /\
      entry_list_key_value_self_disjoint entries /\
      (forall (i:nat{i < List.length entries}).
        Seq.index (Buffer.as_seq h buf) i == List.index entries i))
    (ensures entries_key_value_self_disjoint h buf count idx)
    (decreases U32.v count - U32.v idx)
  = if U32.v idx = U32.v count then ()
    else begin
      let seq = Buffer.as_seq h buf in
      assert (Seq.index seq (U32.v idx) == List.index entries (U32.v idx));
      lemma_entry_list_self_disjoint_at_index entries (U32.v idx);
      lemma_lift_self_disjoint_aux h buf count (U32.add idx U32.one) entries
    end
#pop-options

/// Get the tail of a list after index k (i.e., elements at positions k+1, k+2, ...).
let rec list_tail_after (#a:Type) (xs:list a) (k:nat{k < List.length xs})
  : Tot (list a) (decreases k)
  = match xs with
    | _ :: tl ->
      if k = 0 then tl
      else list_tail_after tl (k - 1)

/// list_tail_after has the right length.
let rec lemma_tail_after_length (#a:Type) (xs:list a) (k:nat{k < List.length xs})
  : Lemma (ensures List.length (list_tail_after xs k) = List.length xs - k - 1)
    (decreases k)
  = match xs with
    | _ :: tl ->
      if k = 0 then ()
      else lemma_tail_after_length tl (k - 1)

/// Indexing into list_tail_after: (list_tail_after xs k)[i] == xs[k + 1 + i].
let rec lemma_tail_index (#a:Type) (xs:list a) (k:nat{k < List.length xs})
  (i:nat{i < List.length xs - k - 1})
  : Lemma (ensures (lemma_tail_after_length xs k;
      List.index (list_tail_after xs k) i == List.index xs (k + 1 + i)))
    (decreases k)
  = lemma_tail_after_length xs k;
    match xs with
    | _ :: tl ->
      if k = 0 then ()
      else begin
        lemma_tail_after_length tl (k - 1);
        lemma_tail_index tl (k - 1) i
      end

/// Extract pairwise disjoint at a specific index: entries[k] is disjoint from entries[k+1..].
let rec lemma_pairwise_disjoint_at_index
  (entries:list json_entry_out) (k:nat{k < List.length entries})
  : Lemma (requires entry_list_pairwise_disjoint entries)
    (ensures entry_disjoint_from_list (List.index entries k) (list_tail_after entries k))
    (decreases k)
  = match entries with
    | _ :: tl ->
      if k = 0 then ()
      else lemma_pairwise_disjoint_at_index tl (k - 1)

/// Lift entry_list_pairwise_disjoint to entries_buffers_disjoint (buffer-indexed).
/// The Json.fst version uses FORWARD-ONLY: U32.v idx < j (not j <> idx).
/// We use entry_list_pairwise_disjoint which gives: for each entry, it is
/// disjoint from all entries that come AFTER it in the list.
/// The buffer predicate at idx quantifies over j where idx < j < count.
/// entry at buf[idx] == entries[idx], entry at buf[j] == entries[j].
/// pairwise_disjoint at entries[idx] says: entry_disjoint_from_list entries[idx] entries[idx+1..].
/// entries[j] for j > idx is at position (j - idx - 1) in entries[idx+1..] = tail after idx.
/// We use lemma_disjoint_from_list_at_index to extract the specific j.
#push-options "--z3rlimit 120 --fuel 2 --ifuel 1"
let rec lemma_lift_disjoint_aux
  (h:FStar.HyperStack.mem)
  (buf:buffer json_entry_out)
  (count:U32.t{U32.v count <= Buffer.length buf})
  (idx:U32.t{U32.v idx <= U32.v count})
  (entries:list json_entry_out)
  : Lemma
    (requires
      live h buf /\
      List.length entries = U32.v count /\
      entry_list_pairwise_disjoint entries /\
      (forall (i:nat{i < List.length entries}).
        Seq.index (Buffer.as_seq h buf) i == List.index entries i))
    (ensures entries_buffers_disjoint h buf count idx)
    (decreases U32.v count - U32.v idx)
  = if U32.v idx = U32.v count then ()
    else begin
      let seq = Buffer.as_seq h buf in
      let entry = Seq.index seq (U32.v idx) in
      assert (entry == List.index entries (U32.v idx));
      // entries[idx] has entry_disjoint_from_list entries[idx] (tail after idx)
      lemma_pairwise_disjoint_at_index entries (U32.v idx);
      let idx_v = U32.v idx in
      let count_v = U32.v count in
      let tail = list_tail_after entries idx_v in
      // Introduce the universal: for each j with idx < j < count
      let aux (j:nat{idx_v < j /\ j < count_v}) : Lemma
        (let other = Seq.index seq j in
         loc_disjoint (loc_buffer entry.entry_key_ptr) (loc_buffer other.entry_key_ptr) /\
         loc_disjoint (loc_buffer entry.entry_key_ptr) (loc_buffer other.entry_value_ptr) /\
         loc_disjoint (loc_buffer entry.entry_value_ptr) (loc_buffer other.entry_key_ptr) /\
         loc_disjoint (loc_buffer entry.entry_value_ptr) (loc_buffer other.entry_value_ptr))
        = // buf[j] == entries[j] by content linking
          assert (Seq.index seq j == List.index entries j);
          // entries[j] is at position (j - idx_v - 1) in tail
          lemma_tail_after_length entries idx_v;
          lemma_tail_index entries idx_v (j - idx_v - 1);
          // Now: List.index tail (j - idx_v - 1) == List.index entries j
          // and entry_disjoint_from_list entry tail
          lemma_disjoint_from_list_at_index entry tail (j - idx_v - 1)
      in
      FStar.Classical.forall_intro aux;
      // Recurse for idx+1
      lemma_lift_disjoint_aux h buf count (U32.add idx U32.one) entries
    end
#pop-options

/// Extract disjoint-from-buf at a specific index.
let rec lemma_entry_list_disjoint_from_buf_at_index
  (entries:list json_entry_out) (buf:buffer json_entry_out)
  (k:nat{k < List.length entries})
  : Lemma (requires entry_list_disjoint_from_buf entries buf)
    (ensures (let e = List.index entries k in
      loc_disjoint (loc_buffer buf) (loc_buffer e.entry_key_ptr) /\
      loc_disjoint (loc_buffer buf) (loc_buffer e.entry_value_ptr)))
    (decreases k)
  = match entries with
    | _ :: tl ->
      if k = 0 then ()
      else lemma_entry_list_disjoint_from_buf_at_index tl buf (k - 1)

/// Lift entry_list_disjoint_from_buf to entries_buffer_disjoint_from_nested.
/// buf was unused_in when entries were live => disjoint from all entry buffers.
/// After store_entries_into_buffer, buf's content changed but the buffer identity didn't.
#push-options "--z3rlimit 80 --fuel 2 --ifuel 1"
let rec lemma_lift_disjoint_from_nested_aux
  (h:FStar.HyperStack.mem)
  (buf:buffer json_entry_out)
  (count:U32.t{U32.v count <= Buffer.length buf})
  (idx:U32.t{U32.v idx <= U32.v count})
  (entries:list json_entry_out)
  : Lemma
    (requires
      live h buf /\
      List.length entries = U32.v count /\
      entry_list_disjoint_from_buf entries buf /\
      (forall (i:nat{i < List.length entries}).
        Seq.index (Buffer.as_seq h buf) i == List.index entries i))
    (ensures entries_buffer_disjoint_from_nested h buf count idx)
    (decreases U32.v count - U32.v idx)
  = if U32.v idx = U32.v count then ()
    else begin
      let seq = Buffer.as_seq h buf in
      assert (Seq.index seq (U32.v idx) == List.index entries (U32.v idx));
      lemma_entry_list_disjoint_from_buf_at_index entries buf (U32.v idx);
      lemma_lift_disjoint_from_nested_aux h buf count (U32.add idx U32.one) entries
    end
#pop-options

/// Prove entry_list_disjoint_from_buf from unused_in + live.
/// If buf is unused_in h and all entry buffers are live in h, then buf is
/// disjoint from all entry buffers (unused_in + live => disjoint).
let rec lemma_unused_in_implies_disjoint_from_buf
  (h:FStar.HyperStack.mem)
  (entries:list json_entry_out)
  (buf:buffer json_entry_out)
  : Lemma
    (requires Buffer.unused_in buf h /\ entry_list_buffers_live h entries)
    (ensures entry_list_disjoint_from_buf entries buf)
    (decreases entries)
  = match entries with
    | [] -> ()
    | hd :: tl ->
      // hd.entry_key_ptr is live h, buf is unused_in h => disjoint
      // hd.entry_value_ptr is live h, buf is unused_in h => disjoint
      lemma_unused_in_implies_disjoint_from_buf h tl buf

/// Prove that entry_list_disjoint_from_buf is preserved across modifications
/// that only affect the buffer (store_entries_into_buffer modifies loc_buffer buf).
/// entry_list_disjoint_from_buf is a structural property (loc_disjoint) — it does
/// not depend on heap contents, only on buffer identity.
let lemma_entry_list_disjoint_from_buf_structural
  (entries:list json_entry_out)
  (buf:buffer json_entry_out)
  (h0 h1:FStar.HyperStack.mem)
  : Lemma
    (requires entry_list_disjoint_from_buf entries buf)
    (ensures entry_list_disjoint_from_buf entries buf)
  = ()

/// Lift entry_list_buffers_live with a simplified interface for the 0-based case.
let lemma_lift_live
  (h:FStar.HyperStack.mem)
  (buf:buffer json_entry_out)
  (count:U32.t{U32.v count <= Buffer.length buf})
  (entries:list json_entry_out)
  : Lemma
    (requires
      live h buf /\
      List.length entries = U32.v count /\
      entry_list_buffers_live h entries /\
      (forall (i:nat{i < List.length entries}).
        Seq.index (Buffer.as_seq h buf) i == List.index entries i))
    (ensures entries_buffers_live h buf count 0ul)
  = // Content linking adjustment: need forall i. buf[0 + i] == entries[i]
    // which is the same as forall i. buf[i] == entries[i]
    lemma_lift_live_aux h buf count 0ul entries

let lemma_lift_freeable
  (h:FStar.HyperStack.mem)
  (buf:buffer json_entry_out)
  (count:U32.t{U32.v count <= Buffer.length buf})
  (entries:list json_entry_out)
  : Lemma
    (requires
      live h buf /\
      List.length entries = U32.v count /\
      entry_list_buffers_freeable entries /\
      (forall (i:nat{i < List.length entries}).
        Seq.index (Buffer.as_seq h buf) i == List.index entries i))
    (ensures entries_buffers_freeable h buf count 0ul)
  = lemma_lift_freeable_aux h buf count 0ul entries

let lemma_lift_self_disjoint
  (h:FStar.HyperStack.mem)
  (buf:buffer json_entry_out)
  (count:U32.t{U32.v count <= Buffer.length buf})
  (entries:list json_entry_out)
  : Lemma
    (requires
      live h buf /\
      List.length entries = U32.v count /\
      entry_list_key_value_self_disjoint entries /\
      (forall (i:nat{i < List.length entries}).
        Seq.index (Buffer.as_seq h buf) i == List.index entries i))
    (ensures entries_key_value_self_disjoint h buf count 0ul)
  = lemma_lift_self_disjoint_aux h buf count 0ul entries

let lemma_lift_disjoint
  (h:FStar.HyperStack.mem)
  (buf:buffer json_entry_out)
  (count:U32.t{U32.v count <= Buffer.length buf})
  (entries:list json_entry_out)
  : Lemma
    (requires
      live h buf /\
      List.length entries = U32.v count /\
      entry_list_pairwise_disjoint entries /\
      (forall (i:nat{i < List.length entries}).
        Seq.index (Buffer.as_seq h buf) i == List.index entries i))
    (ensures entries_buffers_disjoint h buf count 0ul)
  = lemma_lift_disjoint_aux h buf count 0ul entries

let lemma_lift_disjoint_from_nested
  (h:FStar.HyperStack.mem)
  (buf:buffer json_entry_out)
  (count:U32.t{U32.v count <= Buffer.length buf})
  (entries:list json_entry_out)
  : Lemma
    (requires
      live h buf /\
      List.length entries = U32.v count /\
      entry_list_disjoint_from_buf entries buf /\
      (forall (i:nat{i < List.length entries}).
        Seq.index (Buffer.as_seq h buf) i == List.index entries i))
    (ensures entries_buffer_disjoint_from_nested h buf count 0ul)
  = lemma_lift_disjoint_from_nested_aux h buf count 0ul entries

/// Helper: entry_list_buffers_live is preserved across heap transitions
/// when the modification is disjoint from all entry buffers.
/// (Entries are UInt8 buffers; disjointness from a json_entry_out buffer
/// is tracked via entry_list_disjoint_from_buf.)
let rec lemma_entry_list_live_frame
  (entries:list json_entry_out)
  (h0 h1:FStar.HyperStack.mem)
  (l:loc)
  : Lemma
    (requires
      entry_list_buffers_live h0 entries /\
      entry_list_disjoint_from_buf entries (Buffer.null #json_entry_out) /\
      modifies l h0 h1 /\
      (forall (b:buffer UInt8.t). {:pattern (Buffer.live h0 b)}
        Buffer.live h0 b ==> Buffer.live h1 b))
    (ensures entry_list_buffers_live h1 entries)
    (decreases entries)
  = match entries with
    | [] -> ()
    | _ :: tl -> lemma_entry_list_live_frame tl h0 h1 l

/// Simpler frame lemma: if all entries are live in h0, and the frame condition
/// from allocate_entry_list holds (forall b. live h0 b ==> live h1 b),
/// then all entries are still live in h1.
let rec lemma_entry_list_live_frame_simple
  (entries:list json_entry_out)
  (h0 h1:FStar.HyperStack.mem)
  : Lemma
    (requires
      entry_list_buffers_live h0 entries /\
      (forall (b:buffer UInt8.t). {:pattern (Buffer.live h0 b)}
        Buffer.live h0 b ==> Buffer.live h1 b))
    (ensures entry_list_buffers_live h1 entries)
    (decreases entries)
  = match entries with
    | [] -> ()
    | _ :: tl -> lemma_entry_list_live_frame_simple tl h0 h1

/// Frame for entry liveness across modifies loc_none transitions.
/// modifies loc_none means no existing buffers are affected.
let rec lemma_entry_list_live_loc_none_frame
  (entries:list json_entry_out)
  (h0 h1:FStar.HyperStack.mem)
  : Lemma
    (requires
      entry_list_buffers_live h0 entries /\
      modifies loc_none h0 h1)
    (ensures entry_list_buffers_live h1 entries)
    (decreases entries)
  = match entries with
    | [] -> ()
    | hd :: tl ->
      // modifies loc_none => loc_disjoint loc_none (loc_buffer hd.entry_key_ptr)
      // => live h0 hd.entry_key_ptr => live h1 hd.entry_key_ptr
      // (and similarly for value_ptr)
      lemma_entry_list_live_loc_none_frame tl h0 h1

/// Preserve entries_buffers_live across heap transition where:
/// (1) buf's sequence is unchanged (entries are the same)
/// (2) all nested UInt8 buffers that were live stay live
let rec lemma_entries_buffers_live_preserved_with_frame
  (entries:buffer json_entry_out)
  (count:U32.t{U32.v count <= Buffer.length entries})
  (idx:U32.t{U32.v idx <= U32.v count})
  (h0 h1:FStar.HyperStack.mem)
  : Lemma
    (requires
      entries_buffers_live h0 entries count idx /\
      Buffer.as_seq h0 entries == Buffer.as_seq h1 entries /\
      (forall (b:buffer UInt8.t). {:pattern (Buffer.live h0 b)}
        Buffer.live h0 b ==> Buffer.live h1 b))
    (ensures entries_buffers_live h1 entries count idx)
    (decreases U32.v count - U32.v idx)
  = if U32.v idx = U32.v count then ()
    else
      lemma_entries_buffers_live_preserved_with_frame entries count (U32.add idx U32.one) h0 h1

/// Frame lemma using disjointness from a json_entry_out buffer.
/// If entries are live and disjoint from buf, and only buf was modified,
/// then entries are still live.
let rec lemma_entry_list_live_disjoint_frame
  (entries:list json_entry_out)
  (buf:buffer json_entry_out)
  (h0 h1:FStar.HyperStack.mem)
  : Lemma
    (requires
      entry_list_buffers_live h0 entries /\
      entry_list_disjoint_from_buf entries buf /\
      modifies (loc_buffer buf) h0 h1)
    (ensures entry_list_buffers_live h1 entries)
    (decreases entries)
  = match entries with
    | [] -> ()
    | hd :: tl ->
      // hd.entry_key_ptr: loc_disjoint (loc_buffer buf) (loc_buffer hd.entry_key_ptr)
      // + live h0 hd.entry_key_ptr + modifies (loc_buffer buf) => live h1
      // (SMT pattern for modifies_buffer_elim should fire)
      lemma_entry_list_live_disjoint_frame tl buf h0 h1

///////////////////////////////////////////////////////////////////////////////
// build_success_result_full: inlined allocation pipeline, zero assume statements.
///////////////////////////////////////////////////////////////////////////////

/// Success-path wrapper: inlines the allocation pipeline and proves all 5
/// buffer-indexed predicates plus the members frame condition.
///
/// Pipeline:
///   1. allocate_entry_list: list with all list predicates, all_unused_in h_orig
///   2. malloc_entry_array: fresh buffer (unused_in h_after_entries)
///   3. store_entries_into_buffer: content linking buf[i] == entries[i]
///   4. Lift lemmas: convert list predicates to buffer predicates
///   5. allocate_empty_bytes: fresh error message buffer
///
/// All 6 former assume statements are eliminated by the lift lemma proofs.
#push-options "--z3rlimit 300 --fuel 2 --ifuel 1 --z3refresh --split_queries always"
private noextract
let build_success_result_full
  (members:buffer json_member_c)
  (pairs:list (string * string))
  : ST json_parse_result_c
      (requires (fun h ->
        live h members /\
        List.Tot.for_all utf8_pair_within_u32 pairs /\
        List.length pairs < pow2 32))
      (ensures (fun h0 res h1 ->
        live h1 members /\
        live h1 res.result_entries /\
        Buffer.freeable res.result_entries /\
        Buffer.length res.result_entries > 0 /\
        live h1 res.result_error_message /\
        U32.v res.result_entry_count <= Buffer.length res.result_entries /\
        entries_buffers_live h1 res.result_entries res.result_entry_count 0ul /\
        entries_buffers_freeable h1 res.result_entries res.result_entry_count 0ul /\
        entries_buffers_disjoint h1 res.result_entries res.result_entry_count 0ul /\
        entries_key_value_self_disjoint h1 res.result_entries res.result_entry_count 0ul /\
        entries_buffer_disjoint_from_nested h1 res.result_entries res.result_entry_count 0ul))
  =
    let h_orig = HST.get () in
    let count_nat = list_length pairs in
    let _ = lemma_list_length pairs in

    if count_nat = 0 then begin
      // Zero entries: all 5 buffer predicates are True (base case: idx = count = 0).
      let buf = malloc_entry_array 1ul in
      let empty_msg = allocate_empty_bytes () in
      let h_final = HST.get () in
      // members frame: buf was unused_in h_orig (from malloc_entry_array),
      // empty_msg was unused_in at its allocation point.
      // malloc_entry_array modifies loc_none => members still live.
      // allocate_empty_bytes modifies only its own buffer => members still live
      // (because its buffer was unused_in => disjoint from members).
      { result_entries = buf;
        result_entry_count = 0ul;
        result_error = JsonParseOk;
        result_error_message = empty_msg.bytes_ptr;
        result_error_message_len = empty_msg.bytes_len32 }
    end else begin
      // Help Z3 with basic arithmetic that context pollution hides.
      assert (count_nat > 0);
      assert (count_nat = List.length pairs);
      assert (count_nat < pow2 32);
      let count32 = U32.uint_to_t count_nat in
      assert (U32.v count32 = count_nat);
      assert (U32.v count32 > 0);

      // Step 1: Allocate entry list (list-based predicates).
      let entries = allocate_entry_list pairs in
      let h_after_entries = HST.get () in
      assert (List.length entries = List.length pairs);
      assert (List.length entries = count_nat);
      assert (live h_after_entries members);

      // Step 2: Allocate entries buffer.
      let buf = malloc_entry_array count32 in
      let h_after_buf = HST.get () in
      assert (Buffer.length buf = count_nat);
      assert (U32.v count32 <= Buffer.length buf);
      assert (live h_after_buf buf);
      assert (Buffer.freeable buf);
      assert (Buffer.unused_in buf h_after_entries);
      assert (modifies loc_none h_after_entries h_after_buf);
      // entries still live: malloc modifies loc_none => all live buffers preserved
      lemma_entry_list_live_loc_none_frame entries h_after_entries h_after_buf;
      assert (entry_list_buffers_live h_after_buf entries);
      assert (live h_after_buf members);

      // Step 3: Store entries into buffer (content linking).
      store_entries_into_buffer buf 0 entries;
      let h_after_store = HST.get () in
      assert (modifies (loc_buffer buf) h_after_buf h_after_store);
      assert (live h_after_store buf);
      assert (forall (i:nat{i < List.length entries}).
        Seq.index (Buffer.as_seq h_after_store buf) (0 + i) ==
        List.index entries i);

      // Entries' nested buffers are disjoint from buf.
      lemma_unused_in_implies_disjoint_from_buf h_after_entries entries buf;
      assert (entry_list_disjoint_from_buf entries buf);

      // Entry list liveness preserved across store.
      lemma_entry_list_live_disjoint_frame entries buf h_after_buf h_after_store;
      assert (entry_list_buffers_live h_after_store entries);

      // Content linking for lift lemmas: normalize 0 + i to i.
      assert (forall (i:nat{i < List.length entries}).
        Seq.index (Buffer.as_seq h_after_store buf) i ==
        List.index entries i);

      // Step 4: Lift list predicates to buffer predicates.
      lemma_lift_live h_after_store buf count32 entries;
      lemma_lift_freeable h_after_store buf count32 entries;
      lemma_lift_self_disjoint h_after_store buf count32 entries;
      lemma_lift_disjoint h_after_store buf count32 entries;
      lemma_lift_disjoint_from_nested h_after_store buf count32 entries;

      // Confirm 5 buffer predicates hold at h_after_store.
      assert (entries_buffers_live h_after_store buf count32 0ul);
      assert (entries_buffers_freeable h_after_store buf count32 0ul);
      assert (entries_buffers_disjoint h_after_store buf count32 0ul);
      assert (entries_key_value_self_disjoint h_after_store buf count32 0ul);
      assert (entries_buffer_disjoint_from_nested h_after_store buf count32 0ul);

      // Step 5: Allocate empty error message.
      let empty_msg = allocate_empty_bytes () in
      let h_final = HST.get () in

      // Preserve buffer sequence across empty_msg allocation.
      assert (Buffer.as_seq h_after_store buf == Buffer.as_seq h_final buf);
      // Structural predicates preserved via as_seq invariance:
      lemma_entries_buffers_disjoint_preserved buf count32 0ul h_after_store h_final;
      lemma_entries_buffer_disjoint_from_nested_preserved buf count32 0ul h_after_store h_final;
      lemma_entries_buffers_freeable_preserved buf count32 0ul h_after_store h_final;
      lemma_entries_key_value_self_disjoint_preserved buf count32 0ul h_after_store h_final;
      // Liveness: nested UInt8 buffers frame.
      assert (forall (b:buffer UInt8.t). {:pattern (Buffer.live h_after_store b)}
        Buffer.live h_after_store b ==> Buffer.live h_final b);
      lemma_entries_buffers_live_preserved_with_frame buf count32 0ul h_after_store h_final;

      // members frame through entire pipeline.
      assert (live h_final members);

      // Confirm all postcondition components.
      assert (live h_final buf);
      assert (Buffer.freeable buf);
      assert (Buffer.length buf > 0);
      assert (live h_final empty_msg.bytes_ptr);
      assert (U32.v count32 <= Buffer.length buf);

      { result_entries = buf;
        result_entry_count = count32;
        result_error = JsonParseOk;
        result_error_message = empty_msg.bytes_ptr;
        result_error_message_len = empty_msg.bytes_len32 }
    end
#pop-options

// JSON parsing entry point with C ABI
//
// Concrete implementation replacing the former assume val.
// Pipeline:
//   1. Validates UTF-8 on all key/value buffers (Low* — Jose.LowStar.Json.Utf8)
//   2. Collects raw members from C structures (Jose.LowStar.Json.Spec)
//   3. Normalizes + parses JSON entries (spec-level)
//   4. Allocates and populates result structure (Jose.LowStar.Json.Spec)
//
// Precondition strengthened: requires members_nested_live (always held by C runtime).
// Postcondition: 11 conjuncts for safe deallocation via free_entry_array_contents.
//
// All inline assumes eliminated: error paths proved directly (count=0 base case
// + frame reasoning from build_error_result's modifies postcondition via
// modifies_liveness_insensitive_buffer_weak SMTPat);
// success path delegates to build_success_result_full (assumes consolidated there).
// UTF-8 pair bounds (A2a) converted to runtime guard. Length bound (A2b) proved
// via lemma_pipeline_length_bound.
//
// noextract: uses spec-level functions (decode_utf8, normalize_json_members).
// C runtime bridge: c/json_lowstar_runtime.c still provides the KaRaMeL-extractable
// entry point; this concrete F* function verifies the specification.
#push-options "--z3rlimit 60 --fuel 1 --ifuel 1"

noextract
let json_parse_entries_to_c
  (members:buffer json_member_c)
  (count32:UInt32.t{UInt32.v count32 <= Buffer.length members})
  : ST json_parse_result_c
      (requires (fun h -> live h members /\
                          members_nested_live h members (U32.v count32) 0))
      (ensures (fun h0 res h1 ->
        live h1 members /\
        live h1 res.result_entries /\
        Buffer.freeable res.result_entries /\
        Buffer.length res.result_entries > 0 /\
        live h1 res.result_error_message /\
        U32.v res.result_entry_count <= Buffer.length res.result_entries /\
        entries_buffers_live h1 res.result_entries res.result_entry_count 0ul /\
        entries_buffers_freeable h1 res.result_entries res.result_entry_count 0ul /\
        entries_buffers_disjoint h1 res.result_entries res.result_entry_count 0ul /\
        entries_key_value_self_disjoint h1 res.result_entries res.result_entry_count 0ul /\
        entries_buffer_disjoint_from_nested h1 res.result_entries res.result_entry_count 0ul))
  =
  // Step 1: Validate UTF-8 on all member buffers using Low* validator
  // validate_members_utf8: Stack effect (h0 == h1), heap unchanged.
  let utf8_err = validate_members_utf8 members count32 in
  match utf8_err with
  | JsonParseErrorInvalidKeyEncoding ->
    // Error path: build_error_result allocates to address-liveness-insensitive locs.
    // result_entry_count = 0 → all 5 recursive predicates are True (base case).
    // Frame: modifies_liveness_insensitive_buffer_weak SMTPat preserves live h1 members.
    build_error_result InvalidKeyEncoding
  | JsonParseErrorInvalidValueUtf8 ->
    build_error_result InvalidValueUtf8
  | _ ->
    // utf8_err = JsonParseOk (only possible non-error return)
    // Step 2: Collect raw members into lists (spec bridge)
    // collect_raw_members_stack: Stack (h0 == h1), |raw_members| = count_nat.
    let count_nat = U32.v count32 in
    let raw_members = collect_raw_members_stack members count_nat 0 in
    // Step 3: Normalize UTF-8 and parse entries (spec-level, Tot — no heap change)
    (match normalise_raw_members raw_members with
    | Error err ->
      build_error_result err
    | Ok json_members ->
      (match parse_json_entries json_members with
      | Error err ->
        build_error_result err
      | Ok pairs ->
        // Step 4: Build success result — allocate entries array
        // A2b: |pairs| < pow2 32 (pipeline preserves length, proved by lemma)
        lemma_pipeline_length_bound raw_members count_nat;
        // A2a: UTF-8 pair bounds — conservative runtime guard.
        // The UTF-8 roundtrip property (decode ∘ encode = id) should ensure
        // re-encoded bytes fit in UInt32, but threading this through the full
        // pipeline requires deeper engineering. Runtime check catches any edge case.
        if not (List.Tot.for_all utf8_pair_within_u32 pairs) then
          build_error_result BufferTooShort
        else
          // Success path: all preconditions satisfied, delegate to wrapper
          // which consolidates allocator invariant assumes.
          build_success_result_full members pairs))

#pop-options

// Lemma: stepping entries_buffer_disjoint_from_nested to next index
let lemma_entries_buffer_disjoint_from_nested_next
  (h:FStar.HyperStack.mem)
  (entries:buffer json_entry_out)
  (count:U32.t{U32.v count <= Buffer.length entries})
  (idx:U32.t{U32.v idx < U32.v count})
  : Lemma (requires entries_buffer_disjoint_from_nested h entries count idx)
          (ensures entries_buffer_disjoint_from_nested h entries count (U32.add idx U32.one))
  = ()

/// Concrete free for entry key/value buffers via Buffer.free.
/// Replaces the former FFI assume val free_bytes_ffi.
/// Callers must ensure buffers are freeable (allocated via Buffer.malloc or equivalent).
#push-options "--z3rlimit 200 --fuel 2 --ifuel 2 --z3refresh --split_queries always"
let rec free_entry_array_contents
  (entries:buffer json_entry_out)
  (count:U32.t{U32.v count <= Buffer.length entries})
  (idx:U32.t{U32.v idx <= U32.v count})
  : ST unit
      (requires (fun h -> live h entries /\
                          Buffer.length entries > 0 /\
                          entries_buffers_live h entries count idx /\
                          entries_buffers_freeable h entries count idx /\
                          entries_buffers_disjoint h entries count idx /\
                          entries_key_value_self_disjoint h entries count idx /\
                          entries_buffer_disjoint_from_nested h entries count idx))
      (ensures (fun _ _ h1 -> live h1 entries))
      (decreases U32.v count - U32.v idx)
  =
    if idx = count then
      ()
    else
      let h0 = HST.get () in
      let entry = Buffer.index entries idx in
      // Establish freeable and disjointness BEFORE any free (in h0's context).
      assert (Buffer.freeable entry.entry_key_ptr);
      assert (Buffer.freeable entry.entry_value_ptr);
      assert (live h0 entry.entry_key_ptr);
      assert (live h0 entry.entry_value_ptr);
      assert (loc_disjoint (loc_buffer entry.entry_key_ptr) (loc_buffer entry.entry_value_ptr));
      // Free key, then prove value_ptr is still live.
      Buffer.free entry.entry_key_ptr;
      let h_mid = HST.get () in
      // entry.key_ptr and entry.value_ptr are disjoint and both freeable:
      //   freeable_disjoint' gives loc_disjoint at loc_addr_of_buffer level.
      //   Buffer.free modifies loc_addr_of_buffer, so value_ptr stays live.
      Buffer.freeable_disjoint' entry.entry_key_ptr entry.entry_value_ptr;
      loc_disjoint_includes (loc_addr_of_buffer entry.entry_key_ptr) (loc_addr_of_buffer entry.entry_value_ptr)
                            (loc_addr_of_buffer entry.entry_key_ptr) (loc_buffer entry.entry_value_ptr);
      assert (live h_mid entry.entry_value_ptr);
      Buffer.free entry.entry_value_ptr;
      let h1 = HST.get () in
      // Step predicates and apply frame lemmas
      lemma_entries_buffers_live_next h0 entries count idx;
      lemma_entries_buffers_freeable_next h0 entries count idx;
      lemma_free_preserves_remaining_entries entries count idx entry h0 h1;
      lemma_entries_buffers_disjoint_next h0 entries count idx;
      lemma_entries_buffer_disjoint_from_nested_next h0 entries count idx;
      lemma_entries_key_value_self_disjoint_next h0 entries count idx;
      // Preserve structural predicates across heap transition
      lemma_entries_buffers_disjoint_preserved entries count (U32.add idx 1ul) h0 h1;
      lemma_entries_buffer_disjoint_from_nested_preserved entries count (U32.add idx 1ul) h0 h1;
      lemma_entries_buffers_freeable_preserved entries count (U32.add idx 1ul) h0 h1;
      lemma_entries_key_value_self_disjoint_preserved entries count (U32.add idx 1ul) h0 h1;
      free_entry_array_contents entries count (U32.add idx 1ul)
#pop-options

#push-options "--z3rlimit 100 --fuel 0 --ifuel 0 --z3refresh"
inline_for_extraction let json_parse_free_result_data (res:json_parse_result_c)
  : ST unit
      (requires (fun h ->
                   Buffer.freeable res.result_entries /\
                   Buffer.length res.result_entries > 0 /\
                   live h res.result_entries /\
                   U32.v res.result_entry_count <= Buffer.length res.result_entries /\
                   entries_buffers_live h res.result_entries res.result_entry_count 0ul /\
                   entries_buffers_freeable h res.result_entries res.result_entry_count 0ul /\
                   entries_buffers_disjoint h res.result_entries res.result_entry_count 0ul /\
                   entries_key_value_self_disjoint h res.result_entries res.result_entry_count 0ul /\
                   entries_buffer_disjoint_from_nested h res.result_entries res.result_entry_count 0ul))
      (ensures (fun _ _ _ -> True))
  =
    // Free nested contents first (ST via Buffer.free per entry),
    // then free the entries array last (ST via Buffer.free).
    // Error message is not freed here (aligned with C runtime behavior:
    // json_parse_free_result just nulls error_message without freeing).
    free_entry_array_contents res.result_entries res.result_entry_count 0ul;
    free_entry_array res.result_entries
#pop-options

#push-options "--z3rlimit 100 --fuel 0 --ifuel 0 --z3refresh"
inline_for_extraction let json_parse_free_result
  (res:buffer json_parse_result_c)
  : ST unit
      (requires (fun h ->
                   live h res /\
                   Buffer.length res >= 1 /\
                   (let result_value = Seq.index (Buffer.as_seq h res) 0 in
                    Buffer.freeable result_value.result_entries /\
                    Buffer.length result_value.result_entries > 0 /\
                    live h result_value.result_entries /\
                    U32.v result_value.result_entry_count <= Buffer.length result_value.result_entries /\
                    entries_buffers_live h result_value.result_entries result_value.result_entry_count 0ul /\
                    entries_buffers_freeable h result_value.result_entries result_value.result_entry_count 0ul /\
                    entries_buffers_disjoint h result_value.result_entries result_value.result_entry_count 0ul /\
                    entries_key_value_self_disjoint h result_value.result_entries result_value.result_entry_count 0ul /\
                    entries_buffer_disjoint_from_nested h result_value.result_entries result_value.result_entry_count 0ul)))
      (ensures (fun _ _ _ -> True))
  =
    let result_value = Buffer.index res 0ul in
    json_parse_free_result_data result_value
#pop-options
