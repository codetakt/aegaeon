module Jose.BytesBlock

open FStar.UInt8
open FStar.UInt32
open FStar.HyperStack.All
open FStar.HyperStack.ST
module Buffer = LowStar.Buffer
module HS = FStar.HyperStack
open LowStar.Buffer
open Jose.Arith.Bounds

/// Heap allocator for byte buffers.
/// Concrete implementation via LowStar.Buffer.malloc (replaces FFI assume val).
/// Pre: len > 0.
/// Post: returned buffer is live, freeable, with exactly `len` bytes allocated.
/// Note: Same implementation as Jose.LowStar.Json.Stack.malloc_bytes (intentional
///       duplication to avoid Jose.* dependency in the Stack extraction layer).
val malloc_bytes
  : len:FStar.UInt32.t{FStar.UInt32.v len > 0}
  -> ST (Buffer.buffer UInt8.t)
        (requires (fun _ -> True))
        (ensures (fun h0 buf h1 ->
          Buffer.live h1 buf /\
          Buffer.length buf = FStar.UInt32.v len /\
          modifies loc_none h0 h1 /\
          Buffer.freeable buf /\
          Buffer.unused_in buf h0))

let malloc_bytes len = Buffer.malloc HS.root 0uy len

/// Heap deallocator for byte buffers.
/// Concrete implementation via LowStar.Buffer.free (replaces FFI assume val).
/// Pre: buffer must be live and freeable in the current memory.
/// Post: modifies the buffer's address region.
/// Note: No corresponding function in Jose.LowStar.Json.Stack because
///       that module does not perform deallocation.
val free_bytes
  : buf:Buffer.buffer UInt8.t
  -> ST unit
        (requires (fun h -> Buffer.live h buf /\ Buffer.freeable buf))
        (ensures (fun h0 _ h1 -> modifies (loc_addr_of_buffer buf) h0 h1))

let free_bytes buf = Buffer.free buf

/// Machine-integer-sized byte slice used by Low* Stack routines.
noeq type bytes_block = {
  buf: Buffer.buffer UInt8.t;
  len: UInt32.t;
  len_bound: squash (UInt32.v len <= Buffer.length buf)
}

/// Copy bytes from `src` into `dst` with UInt32 indexing.
let rec copy_bytes_u32_aux
  (src:Buffer.buffer UInt8.t)
  (dst:Buffer.buffer UInt8.t)
  (len32:UInt32.t)
  (idx32:UInt32.t{UInt32.v idx32 <= UInt32.v len32})
  : Stack unit
      (requires (fun h ->
        Buffer.live h src /\
        Buffer.live h dst /\
        UInt32.v len32 <= Buffer.length src /\
        UInt32.v len32 <= Buffer.length dst /\
        loc_disjoint (loc_buffer src) (loc_buffer dst)))
      (ensures (fun h0 _ h1 ->
        modifies (loc_buffer dst) h0 h1 /\
        Buffer.live h1 src /\
        Buffer.live h1 dst))
  (decreases UInt32.v len32 - UInt32.v idx32)
  =
    if UInt32.lt idx32 len32 then begin
      let byte = Buffer.index src idx32 in
      Buffer.upd dst idx32 byte;
      lemma_u32_succ_within_bound idx32 len32;
      lemma_u32_measure_lt len32 idx32;
      copy_bytes_u32_aux src dst len32 (UInt32.add idx32 1ul)
    end else ()

/// Read `len32` bytes from buffer into a freshly allocated bytes_block.
val read_bytes_with_bound_u32
  : buf:Buffer.buffer UInt8.t
  -> len32:UInt32.t{FStar.UInt32.v len32 > 0 /\ FStar.UInt32.v len32 <= Buffer.length buf}
  -> ST bytes_block
      (requires (fun h -> Buffer.live h buf))
      (ensures (fun h0 result h1 ->
        Buffer.live h1 buf /\
        Buffer.live h1 result.buf /\
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

/// Free the underlying buffer of a bytes_block.
val free_bytes_block
  : bb:bytes_block
  -> ST unit
      (requires (fun h -> Buffer.live h bb.buf /\ Buffer.freeable bb.buf))
      (ensures (fun h0 _ h1 -> modifies (loc_addr_of_buffer bb.buf) h0 h1))

let free_bytes_block bb =
    free_bytes bb.buf
