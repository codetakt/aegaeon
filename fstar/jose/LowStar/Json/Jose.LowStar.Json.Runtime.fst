module Jose.LowStar.Json.Runtime

open FStar.UInt8
open FStar.HyperStack.All
open FStar.HyperStack.ST
open FStar.UInt32
module Buffer = LowStar.Buffer
open LowStar.Buffer
open Jose.BytesBlock

module HS = FStar.HyperStack

/// Output struct returned to Rust via C FFI.
noeq type json_entry_out = {
  entry_key_ptr: Buffer.buffer UInt8.t;
  entry_key_len: UInt32.t;
  entry_value_ptr: Buffer.buffer UInt8.t;
  entry_value_len: UInt32.t
}

/// Predicate: a single entry's buffers are live.
let entry_buffers_live (h:FStar.HyperStack.mem) (entry:json_entry_out) : GTot Type0 =
  Buffer.live h entry.entry_key_ptr /\ Buffer.live h entry.entry_value_ptr

/// All entries' buffers from idx .. count-1 are live.
let rec entries_buffers_live
  (h:FStar.HyperStack.mem)
  (entries:Buffer.buffer json_entry_out)
  (count:UInt32.t{UInt32.v count <= Buffer.length entries})
  (idx:UInt32.t{UInt32.v idx <= UInt32.v count})
  : GTot Type0
  (decreases UInt32.v count - UInt32.v idx)
  =
  if UInt32.v idx = UInt32.v count then True
  else
    (let entries_seq = Buffer.as_seq h entries in
     let entry = Seq.index entries_seq (UInt32.v idx) in
     entry_buffers_live h entry) /\
    entries_buffers_live h entries count (UInt32.add idx UInt32.one)

/// All entries' buffers are pairwise disjoint.
let rec entries_buffers_disjoint
  (h:FStar.HyperStack.mem)
  (entries:Buffer.buffer json_entry_out)
  (count:UInt32.t{UInt32.v count <= Buffer.length entries})
  (idx:UInt32.t{UInt32.v idx <= UInt32.v count})
  : GTot Type0
  (decreases UInt32.v count - UInt32.v idx)
  =
  if UInt32.v idx = UInt32.v count then True
  else
    let entries_seq = Buffer.as_seq h entries in
    let entry = Seq.index entries_seq (UInt32.v idx) in
    (forall (j:nat{j <> UInt32.v idx /\ j < UInt32.v count}).
       let entry_j = Seq.index entries_seq j in
       loc_disjoint (loc_buffer entry.entry_key_ptr) (loc_buffer entry_j.entry_key_ptr) /\
       loc_disjoint (loc_buffer entry.entry_key_ptr) (loc_buffer entry_j.entry_value_ptr) /\
       loc_disjoint (loc_buffer entry.entry_value_ptr) (loc_buffer entry_j.entry_key_ptr) /\
       loc_disjoint (loc_buffer entry.entry_value_ptr) (loc_buffer entry_j.entry_value_ptr)) /\
    entries_buffers_disjoint h entries count (UInt32.add idx UInt32.one)

/// Entries buffers are disjoint from nested buffers (value pointers).
let rec entries_buffer_disjoint_from_nested
  (h:FStar.HyperStack.mem)
  (entries:Buffer.buffer json_entry_out)
  (count:UInt32.t{UInt32.v count <= Buffer.length entries})
  (idx:UInt32.t{UInt32.v idx <= UInt32.v count})
  : GTot Type0
  (decreases UInt32.v count - UInt32.v idx)
  =
  if UInt32.v idx = UInt32.v count then True
  else
    let entries_seq = Buffer.as_seq h entries in
    let entry = Seq.index entries_seq (UInt32.v idx) in
    loc_disjoint (loc_buffer entries) (loc_buffer entry.entry_key_ptr) /\
    loc_disjoint (loc_buffer entries) (loc_buffer entry.entry_value_ptr) /\
    entries_buffer_disjoint_from_nested h entries count (UInt32.add idx UInt32.one)

/// All entries' key/value buffers are freeable (allocated via Buffer.malloc).
/// Required for replacing free_bytes_ffi with concrete Buffer.free.
let rec entries_buffers_freeable
  (h:FStar.HyperStack.mem)
  (entries:Buffer.buffer json_entry_out)
  (count:UInt32.t{UInt32.v count <= Buffer.length entries})
  (idx:UInt32.t{UInt32.v idx <= UInt32.v count})
  : GTot Type0
  (decreases UInt32.v count - UInt32.v idx)
  =
  if UInt32.v idx = UInt32.v count then True
  else
    (let entries_seq = Buffer.as_seq h entries in
     let entry = Seq.index entries_seq (UInt32.v idx) in
     Buffer.freeable entry.entry_key_ptr /\
     Buffer.freeable entry.entry_value_ptr) /\
    entries_buffers_freeable h entries count (UInt32.add idx UInt32.one)

/// Each entry's key buffer is disjoint from its value buffer.
/// Required for sequential Buffer.free of key then value within the same entry.
let rec entries_key_value_self_disjoint
  (h:FStar.HyperStack.mem)
  (entries:Buffer.buffer json_entry_out)
  (count:UInt32.t{UInt32.v count <= Buffer.length entries})
  (idx:UInt32.t{UInt32.v idx <= UInt32.v count})
  : GTot Type0
  (decreases UInt32.v count - UInt32.v idx)
  =
  if UInt32.v idx = UInt32.v count then True
  else
    (let entries_seq = Buffer.as_seq h entries in
     let entry = Seq.index entries_seq (UInt32.v idx) in
     loc_disjoint (loc_buffer entry.entry_key_ptr) (loc_buffer entry.entry_value_ptr)) /\
    entries_key_value_self_disjoint h entries count (UInt32.add idx UInt32.one)

/// Default json_entry_out for Buffer.malloc initialization.
private let default_entry_out : json_entry_out = {
  entry_key_ptr = Buffer.null;
  entry_key_len = 0ul;
  entry_value_ptr = Buffer.null;
  entry_value_len = 0ul
}

/// Allocator for json_entry_out arrays.
/// Concrete implementation via LowStar.Buffer.malloc (replaces FFI assume val).
val malloc_entry_array
  : len32:UInt32.t{UInt32.v len32 > 0}
  -> ST (Buffer.buffer json_entry_out)
        (requires (fun _ -> True))
        (ensures (fun h0 buf h1 ->
                    Buffer.live h1 buf /\
                    Buffer.length buf = UInt32.v len32 /\
                    modifies loc_none h0 h1 /\
                    Buffer.freeable buf /\
                    Buffer.unused_in buf h0))

let malloc_entry_array len32 = Buffer.malloc HS.root default_entry_out len32

/// Free for json_entry_out arrays (container only).
/// Concrete implementation via LowStar.Buffer.free.
/// Paired with concrete malloc_entry_array which produces freeable buffers.
/// Callers reordered: free_entry_array is called last so the ST effect
/// (which loses equal_domains) does not break downstream liveness proofs.
val free_entry_array
  : buf:Buffer.buffer json_entry_out{Buffer.freeable buf}
  -> ST unit
        (requires (fun h -> Buffer.live h buf))
        (ensures (fun h0 _ h1 -> True))

let free_entry_array buf = Buffer.free buf

/// Lemma: advance disjoint-from-nested predicate.
let lemma_entries_buffer_disjoint_from_nested_next
  (h:FStar.HyperStack.mem)
  (entries:Buffer.buffer json_entry_out)
  (count:UInt32.t{UInt32.v count <= Buffer.length entries})
  (idx:UInt32.t{UInt32.v idx < UInt32.v count})
  : Lemma (requires entries_buffer_disjoint_from_nested h entries count idx)
          (ensures entries_buffer_disjoint_from_nested h entries count (UInt32.add idx UInt32.one))
  = ()

/// free_entry_array_contents: concrete implementation provided in
/// Jose.LowStar.Json.fst (replaces former assume val).
/// Recursively frees nested key/value buffers using disjointness lemmas.
