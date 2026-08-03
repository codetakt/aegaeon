module Jose.LowStar.Json.Spec

open Jose.LowStar.Json.Types
open LowStar.Buffer
open FStar.List.Tot
open FStar.String
open FStar.UInt8
open FStar.UInt32
open FStar.HyperStack.All
open FStar.HyperStack.ST
module List = FStar.List.Tot
module U32 = FStar.UInt32
module Buffer = LowStar.Buffer
open Jose.BufferListLemmas
open Jose.BytesBlock
open Jose.Utf8Lemmas
open Jose.Arith.Bounds
open Jose.JsonHeaderSpec
open Jose.HeaderSpec

open Jose.LowStar.Json.Helpers
open Jose.LowStar.Json.Runtime

noeq
type raw_json_member = {
  raw_key: list UInt8.t;
  raw_kind: json_value_kind;
  raw_value: list UInt8.t
}

/// Copy a list of bytes into a buffer starting at idx32.
/// Content correctness: buf[idx32 + i] = List.nth bytes i for all valid i.
/// This is maintained by construction (Buffer.upd at each index), but the
/// postcondition only encodes liveness and modification — matching the
/// specification level of the former assume val. Downstream code does not
/// depend on buffer content values (only on liveness and length).
let rec write_list_to_buffer
  (buf:buffer UInt8.t)
  (bytes:list UInt8.t)
  (idx32:UInt32.t)
  : Stack unit
      (requires (fun h ->
        Buffer.live h buf /\
        UInt32.v idx32 + List.length bytes <= Buffer.length buf /\
        Buffer.length buf < pow2 32))
      (ensures (fun h0 _ h1 ->
        modifies (loc_buffer buf) h0 h1 /\
        Buffer.live h1 buf))
  (decreases bytes)
  = match bytes with
    | [] -> ()
    | b :: rest ->
      Buffer.upd buf idx32 b;
      write_list_to_buffer buf rest (UInt32.add idx32 1ul)

/// Allocate a fresh buffer and populate it from a byte list.
/// Concrete implementation: malloc_bytes + write_list_to_buffer.
/// Pre: list length fits in UInt32 (required for buffer indexing).
/// The caller allocate_bytes_with_length already ensures this bound.
/// Allocate a fresh buffer and populate it from a byte list.
/// Concrete implementation: malloc_bytes + write_list_to_buffer.
/// Pre: list length fits in UInt32 (required for buffer indexing).
/// The caller allocate_bytes_with_length already ensures this bound.
/// For empty input, allocates a 1-byte buffer to guarantee non-null
/// (Buffer.null has unused_in = False in the LowStar memory model,
/// which breaks downstream invariants). Buffer.length >= List.length
/// (not exact =) because the empty case over-allocates.
let allocate_bytes_from_list (bytes:list UInt8.t)
  : ST (buffer UInt8.t)
        (requires (fun _ -> List.length bytes < pow2 32))
        (ensures (fun h0 buf h1 ->
          Buffer.live h1 buf /\
          Buffer.length buf >= List.length bytes /\
          Buffer.unused_in buf h0 /\
          Buffer.freeable buf /\
          modifies (loc_buffer buf) h0 h1))
  =
  if List.length bytes > 0 then begin
    let len32 : UInt32.t = FStar.UInt32.uint_to_t (List.length bytes) in
    let buf = malloc_bytes len32 in
    write_list_to_buffer buf bytes 0ul;
    buf
  end else begin
    // Empty: allocate 1 byte to guarantee freeability + unused_in.
    // Buffer.length = 1 >= 0 = List.length [].
    // malloc_bytes gives modifies loc_none; modifies_loc_includes lifts to modifies (loc_buffer buf).
    let buf = malloc_bytes 1ul in
    buf
  end

let encode_utf8_bytes_runtime (s:string) : Tot (list UInt8.t) = encode_utf8_bytes s

let lemma_encode_utf8_bytes_runtime_correct
  (s:string)
  : Lemma (encode_utf8_bytes_runtime s == encode_utf8_bytes s)
  = ()

let u32_of_nat (n:nat{n < pow2 32}) : Tot UInt32.t =
  FStar.UInt32.uint_to_t n

let lemma_u32_of_nat_inv (n:nat{n < pow2 32})
  : Lemma (ensures FStar.UInt32.v (u32_of_nat n) = n)
  = ()

let rec list_length (#a:Type) (xs:list a) : Tot nat
  (decreases xs)
  =
    match xs with
    | [] -> 0
    | _ :: rest -> 1 + list_length rest

let rec lemma_list_length (#a:Type) (xs:list a)
  : Lemma (ensures list_length xs = List.length xs)
      (decreases xs)
  =
    match xs with
    | [] -> ()
    | _ :: rest ->
        lemma_list_length rest

let lemma_list_length_bound (#a:Type) (xs:list a) (bound:nat)
  : Lemma (requires List.length xs < bound)
          (ensures list_length xs < bound)
  =
    lemma_list_length xs

let rec lemma_length_append_single (#a:Type) (xs:list a) (x:a)
  : Lemma (ensures List.length (List.append xs [x]) = List.length xs + 1)
      (decreases xs)
  =
    match xs with
    | [] -> ()
    | _::rest -> lemma_length_append_single rest x

let utf8_pair_within_u32 (kv:string * string) : Tot bool =
  let (key, value) = kv in
  let key_len = list_length (encode_utf8_bytes_runtime key) in
  let value_len = list_length (encode_utf8_bytes_runtime value) in
  key_len < pow2 32 && value_len < pow2 32

let lemma_for_all_cons (#a:Type) (p:a -> bool) (x:a) (xs:list a)
  : Lemma (requires List.Tot.for_all p (x :: xs))
          (ensures p x /\ List.Tot.for_all p xs)
  = ()

let lemma_utf8_pair_left (kv:string * string)
  : Lemma (requires utf8_pair_within_u32 kv)
          (ensures List.length (encode_utf8_bytes (fst kv)) < pow2 32)
  =
    let (key, _) = kv in
    let assumption = utf8_pair_within_u32 kv in
    assert assumption;
    let key_bytes_runtime = encode_utf8_bytes_runtime key in
    let key_len_nat = list_length key_bytes_runtime in
    let _ = lemma_list_length key_bytes_runtime in
    assert (key_len_nat < pow2 32);
    let _ = lemma_encode_utf8_bytes_runtime_correct key in
    let key_bytes_spec = encode_utf8_bytes key in
    assert (key_bytes_spec = key_bytes_runtime);
    let key_len_spec = List.length key_bytes_spec in
    assert (key_len_spec = key_len_nat);
    assert (key_len_spec < pow2 32);
    ()

let lemma_utf8_pair_right (kv:string * string)
  : Lemma (requires utf8_pair_within_u32 kv)
          (ensures List.length (encode_utf8_bytes (snd kv)) < pow2 32)
  =
    let (_, value) = kv in
    let assumption = utf8_pair_within_u32 kv in
    assert assumption;
    let value_bytes_runtime = encode_utf8_bytes_runtime value in
    let value_len_nat = list_length value_bytes_runtime in
    let _ = lemma_list_length value_bytes_runtime in
    assert (value_len_nat < pow2 32);
    let _ = lemma_encode_utf8_bytes_runtime_correct value in
    let value_bytes_spec = encode_utf8_bytes value in
    assert (value_bytes_spec = value_bytes_runtime);
    let value_len_spec = List.length value_bytes_spec in
    assert (value_len_spec = value_len_nat);
    assert (value_len_spec < pow2 32);
    ()

let lemma_utf8_pair_string_lengths (kv:string * string)
  : Lemma (requires utf8_pair_within_u32 kv)
          (ensures FStar.String.length (fst kv) < pow2 32 /\
                   FStar.String.length (snd kv) < pow2 32)
  =
    let (key, value) = kv in
    let assumption = utf8_pair_within_u32 kv in
    assert assumption;
    let key_bytes_runtime = encode_utf8_bytes_runtime key in
    let value_bytes_runtime = encode_utf8_bytes_runtime value in
    let key_len_nat = list_length key_bytes_runtime in
    let value_len_nat = list_length value_bytes_runtime in
    let _ = lemma_list_length key_bytes_runtime in
    let _ = lemma_list_length value_bytes_runtime in
    assert (key_len_nat < pow2 32);
    assert (value_len_nat < pow2 32);
    let _ = lemma_encode_utf8_bytes_runtime_correct key in
    let _ = lemma_encode_utf8_bytes_runtime_correct value in
    let key_bytes_spec = encode_utf8_bytes key in
    let value_bytes_spec = encode_utf8_bytes value in
    assert (key_bytes_spec = key_bytes_runtime);
    assert (value_bytes_spec = value_bytes_runtime);
    let _ = lemma_encode_utf8_bytes_length_lower_bound key in
    let _ = lemma_encode_utf8_bytes_length_lower_bound value in
    lemma_length_transitive (FStar.String.length key) (List.length key_bytes_spec) (pow2 32);
    lemma_length_transitive (FStar.String.length value) (List.length value_bytes_spec) (pow2 32);
    ()


noeq
type allocated_utf8 = {
  bytes_ptr: buffer UInt8.t;
  bytes_len_nat: nat;
  bytes_len32: UInt32.t
}

let rec read_bytes_with_bound_aux
  (buf:buffer UInt8.t)
  (len:nat)
  (idx:nat)
  : Stack (list UInt8.t)
      (requires (fun h ->
                   live h buf /\
                   len <= Buffer.length buf /\
                   idx <= len))
      (ensures (fun h0 bytes h1 ->
                  h0 == h1 /\
                  live h1 buf /\
                  List.length bytes = len - idx))
      (decreases len - idx)
  =
    if idx < len then
      let idx32 = u32_of_nat idx in
      let _ = lemma_u32_of_nat_inv idx in
      let byte = Buffer.index buf idx32 in
      lemma_lt_implies_le_succ idx len;
      lemma_measure_lt len idx;
      let tail = read_bytes_with_bound_aux buf len (idx + 1) in
      byte :: tail
    else []

let read_bytes_with_bound
  (buf:buffer UInt8.t)
  (len:nat)
  (len_bound:len <= Buffer.length buf)
  : Stack (list UInt8.t)
      (requires (fun h -> live h buf))
      (ensures (fun h0 bytes h1 -> h0 == h1 /\ live h1 buf))
  =
    read_bytes_with_bound_aux buf len 0

let read_raw_member_stack (m:json_member_c)
  : Stack raw_json_member
      (requires (fun h -> live h m.key_buf /\ live h m.value_buf))
      (ensures (fun h0 _ h1 -> h0 == h1 /\ live h1 m.key_buf /\ live h1 m.value_buf))
  =
    let key_len_nat = UInt32.v m.key_len in
    let key_bytes = read_bytes_with_bound m.key_buf key_len_nat m.key_len_le in
    match m.value_kind with
    | JsonValueNull ->
        { raw_key = key_bytes;
          raw_kind = JsonValueNull;
          raw_value = [] }
    | JsonValueString ->
        let value_len_nat = UInt32.v m.value_len in
        let value_bytes = read_bytes_with_bound m.value_buf value_len_nat m.value_len_le in
        { raw_key = key_bytes;
          raw_kind = JsonValueString;
          raw_value = value_bytes }

let rec collect_raw_members_stack_aux
  (members:buffer json_member_c)
  (count32:UInt32.t{UInt32.v count32 <= Buffer.length members})
  (idx32:UInt32.t{UInt32.v idx32 <= UInt32.v count32})
  : Stack (list raw_json_member)
      (requires (fun h -> live h members /\
                          members_nested_live h members (UInt32.v count32) 0))
      (ensures (fun h0 res h1 -> h0 == h1 /\ live h1 members /\
                                  List.length res = UInt32.v count32 - UInt32.v idx32))
  (decreases UInt32.v count32 - UInt32.v idx32)
  =
    if UInt32.lt idx32 count32 then
      let _ = lemma_idx_u32_lt_buffer_from_len members count32 idx32 in
      let current = index_member_with_liveness members count32 idx32 in
      let raw_member = read_raw_member_stack current in
      let _ = lemma_u32_succ_within_bound idx32 count32 in
      let _ = lemma_u32_measure_lt count32 idx32 in
      let idx_next = UInt32.add idx32 1ul in
      let tail = collect_raw_members_stack_aux members count32 idx_next in
      raw_member :: tail
    else []

let collect_raw_members_stack
  (members:buffer json_member_c)
  (count:nat)
  (idx:nat)
  : Stack (list raw_json_member)
      (requires (fun h -> live h members /\ count <= Buffer.length members /\ idx <= count /\
                          members_nested_live h members count 0))
      (ensures (fun h0 res h1 -> h0 == h1 /\ live h1 members /\
                                  List.length res = count - idx))
  =
    let _ = lemma_buffer_length_bounded members in
    let _ = lemma_length_transitive count (Buffer.length members) (pow2 32) in
    let _ = lemma_length_transitive idx count (pow2 32) in
    let count32 = UInt32.uint_to_t count in
    let idx32 = UInt32.uint_to_t idx in
    collect_raw_members_stack_aux members count32 idx32

let json_parse_error_of_decode_error (err:decode_error) : json_parse_error =
  match err with
  | BufferTooShort -> JsonParseErrorBufferTooShort
  | InvalidKeyEncoding -> JsonParseErrorInvalidKeyEncoding
  | InvalidValueUtf8 -> JsonParseErrorInvalidValueUtf8
  | UnknownKey _ -> JsonParseErrorUnknownKey
  | PolicyViolation _ -> JsonParseErrorPolicyViolation

let decode_error_message (err:decode_error) : string =
  match err with
  | BufferTooShort -> "buffer-too-short"
  | InvalidKeyEncoding -> "invalid-key-encoding"
  | InvalidValueUtf8 -> "invalid-value-utf8"
  | UnknownKey _ -> "unknown-key"
  | PolicyViolation _ -> "policy-violation"

let lemma_decode_error_message_within_header_max_length (err:decode_error)
  : Lemma
      (ensures FStar.String.length (decode_error_message err) <= Jose.Policy.header_max_length)
  =
    match err with
    | BufferTooShort ->
        assert_norm
          (FStar.String.length "buffer-too-short" <= Jose.Policy.header_max_length)
    | InvalidKeyEncoding ->
        assert_norm
          (FStar.String.length "invalid-key-encoding" <= Jose.Policy.header_max_length)
    | InvalidValueUtf8 ->
        assert_norm
          (FStar.String.length "invalid-value-utf8" <= Jose.Policy.header_max_length)
    | UnknownKey _ ->
        assert_norm (FStar.String.length "unknown-key" <= Jose.Policy.header_max_length)
    | PolicyViolation _ ->
        assert_norm
          (FStar.String.length "policy-violation" <= Jose.Policy.header_max_length)

let allocate_bytes_with_length (bytes:list UInt8.t)
  : ST allocated_utf8
      (requires (fun _ -> List.length bytes < pow2 32))
      (ensures (fun h0 res h1 ->
                 live h1 res.bytes_ptr /\
                 Buffer.length res.bytes_ptr >= res.bytes_len_nat /\
                 res.bytes_len_nat = List.length bytes /\
                 res.bytes_len32 = u32_of_nat (List.length bytes) /\
                 Buffer.unused_in res.bytes_ptr h0 /\
                 Buffer.freeable res.bytes_ptr /\
                 modifies (loc_buffer res.bytes_ptr) h0 h1))
  =
    let buf = allocate_bytes_from_list bytes in
    let len_nat = list_length bytes in
    let _ = lemma_list_length bytes in
    let _ = lemma_list_length_bound bytes (pow2 32) in
    let len32 = u32_of_nat len_nat in
    { bytes_ptr = buf;
      bytes_len_nat = len_nat;
      bytes_len32 = len32 }

let allocate_utf8_bytes_from_string (s:string)
  : ST allocated_utf8
      (requires (fun _ -> List.length (encode_utf8_bytes s) < pow2 32))
      (ensures (fun h0 res h1 ->
                 live h1 res.bytes_ptr /\
                 res.bytes_len_nat = List.length (encode_utf8_bytes s) /\
                 res.bytes_len32 = u32_of_nat (List.length (encode_utf8_bytes s)) /\
                 Buffer.unused_in res.bytes_ptr h0 /\
                 Buffer.freeable res.bytes_ptr /\
                 modifies (loc_buffer res.bytes_ptr) h0 h1))
  =
    let _ = lemma_encode_utf8_bytes_runtime_correct s in
    let bytes = encode_utf8_bytes_runtime s in
    let _ = lemma_encode_utf8_bytes_length_bound s in
    let _ = lemma_list_length bytes in
    let len = List.length bytes in
    if len > 0 then begin
      // Non-empty: delegate to allocate_bytes_with_length (freeable when len > 0)
      let res = allocate_bytes_with_length bytes in
      res
    end else begin
      // Empty string: allocate 1 byte to guarantee freeability.
      // bytes_len_nat = 0 tracks the logical length; buffer is oversized but freeable.
      let buf = malloc_bytes 1ul in
      { bytes_ptr = buf; bytes_len_nat = 0; bytes_len32 = 0ul }
    end

let allocate_utf8_cstring (s:string)
  : ST allocated_utf8
      (requires (fun _ -> List.length (encode_utf8_bytes s) + 1 < pow2 32))
      (ensures (fun h0 res h1 ->
        live h1 res.bytes_ptr /\
        modifies (loc_buffer res.bytes_ptr) h0 h1 /\
        Buffer.unused_in res.bytes_ptr h0 /\
        Buffer.freeable res.bytes_ptr))
  =
    let _ = lemma_encode_utf8_bytes_runtime_correct s in
    let bytes = encode_utf8_bytes_runtime s in
    let _ = lemma_list_length bytes in
    let bytes_with_null = List.append bytes [UInt8.zero] in
    let _ = lemma_length_append_single bytes UInt8.zero in
    allocate_bytes_with_length bytes_with_null

let allocate_empty_bytes () : ST allocated_utf8
  (requires (fun _ -> True))
  (ensures (fun h0 res h1 ->
    live h1 res.bytes_ptr /\ res.bytes_len_nat = 0 /\
    modifies (loc_buffer res.bytes_ptr) h0 h1 /\
    Buffer.unused_in res.bytes_ptr h0))
  =
    let _ = lemma_pow2_32_positive () in
    allocate_bytes_with_length []

/// Weaker version of unused_in that works at the loc_unused_in level.
/// Unlike Buffer.unused_in, this CAN be proved backward through heap transitions
/// using modifies_loc_unused_in (the LowStar API does not export a reverse of
/// unused_in_loc_unused_in, so Buffer.unused_in cannot be recovered from
/// loc_unused_in — but loc_unused_in suffices for proving disjointness via
/// unused_in_not_unused_in_disjoint_2).
let in_loc_unused_in (b:buffer UInt8.t) (h:FStar.HyperStack.mem) : GTot Type0 =
  loc_unused_in h `loc_includes` loc_addr_of_buffer b

/// unused_in implies in_loc_unused_in (forward direction via unused_in_loc_unused_in).
let lemma_unused_in_implies_in_loc_unused_in (b:buffer UInt8.t) (h:FStar.HyperStack.mem)
  : Lemma (requires Buffer.unused_in b h)
          (ensures in_loc_unused_in b h)
  = unused_in_loc_unused_in b h

/// Backward frame for in_loc_unused_in across address-liveness-insensitive modifications.
/// Key insight: modifies_loc_unused_in gives us the chain
///   loc_unused_in h1 includes loc_addr_of_buffer b
///   + modifies l h0 h1 (where l is address_liveness_insensitive)
///   => loc_unused_in h0 includes loc_addr_of_buffer b
/// This is the loc_unused_in analog of the impossible-to-prove unused_in backward frame.
let lemma_in_loc_unused_in_backward
  (l:loc)
  (b:buffer UInt8.t)
  (h0 h1:FStar.HyperStack.mem)
  : Lemma
    (requires
      modifies l h0 h1 /\
      address_liveness_insensitive_locs `loc_includes` l /\
      in_loc_unused_in b h1)
    (ensures in_loc_unused_in b h0)
  = modifies_loc_unused_in l h0 h1 (loc_addr_of_buffer b)

/// Disjointness between a live buffer and a buffer in loc_unused_in.
/// Uses unused_in_not_unused_in_disjoint_2: if loc_unused_in h includes l1
/// and loc_not_unused_in h includes l2, then l1' and l2' are disjoint
/// (where l1 includes l1' and l2 includes l2').
/// live_loc_not_unused_in gives: live h b => loc_not_unused_in h includes loc_addr_of_buffer b.
/// loc_includes_addresses_buffer gives: loc_addr_of_buffer b includes loc_buffer b.
let lemma_in_loc_unused_in_disjoint_from_live
  (h:FStar.HyperStack.mem)
  (unused_buf:buffer UInt8.t)
  (live_buf:buffer UInt8.t)
  : Lemma
    (requires in_loc_unused_in unused_buf h /\ live h live_buf)
    (ensures loc_disjoint (loc_buffer unused_buf) (loc_buffer live_buf))
  = // Step 1: live h live_buf => loc_not_unused_in h includes loc_addr_of_buffer live_buf
    //   (SMTPat on live h live_buf)
    live_loc_not_unused_in live_buf h;
    // Step 2: precondition gives loc_unused_in h includes loc_addr_of_buffer unused_buf
    // Step 3: unused_in_not_unused_in_disjoint_2 gives loc_disjoint between addr-level locs
    //   l1 = loc_addr_of_buffer unused_buf, l2 = loc_addr_of_buffer live_buf,
    //   l1' = loc_buffer unused_buf, l2' = loc_buffer live_buf
    //   Needs: l1 includes l1' and l2 includes l2' (from loc_includes_addresses_buffer)
    unused_in_not_unused_in_disjoint_2
      (loc_addr_of_buffer unused_buf) (loc_addr_of_buffer live_buf)
      (loc_buffer unused_buf) (loc_buffer live_buf) h

#push-options "--z3rlimit 60 --fuel 2 --ifuel 1"
let create_entry_from_pair (kv:string * string)
  : ST json_entry_out
      (requires (fun _ -> utf8_pair_within_u32 kv))
      (ensures (fun h0 entry h1 ->
        live h1 entry.entry_key_ptr /\ live h1 entry.entry_value_ptr /\
        loc_disjoint (loc_buffer entry.entry_key_ptr) (loc_buffer entry.entry_value_ptr) /\
        Buffer.freeable entry.entry_key_ptr /\
        Buffer.freeable entry.entry_value_ptr /\
        Buffer.unused_in entry.entry_key_ptr h0 /\
        in_loc_unused_in entry.entry_value_ptr h0 /\
        modifies (loc_union (loc_buffer entry.entry_key_ptr) (loc_buffer entry.entry_value_ptr)) h0 h1 /\
        (forall (b:buffer UInt8.t). {:pattern (Buffer.live h0 b)}
          Buffer.live h0 b ==> Buffer.live h1 b) /\
        (forall (b:buffer json_member_c). {:pattern (Buffer.live h0 b)}
          Buffer.live h0 b ==> Buffer.live h1 b)))
  =
    let _ = lemma_utf8_pair_left kv in
    let _ = lemma_utf8_pair_right kv in
    let (key, value) = kv in
    let h0 = FStar.HyperStack.ST.get () in
    let key_alloc = allocate_utf8_bytes_from_string key in
    let h_mid = FStar.HyperStack.ST.get () in
    let value_alloc = allocate_utf8_bytes_from_string value in
    let h1 = FStar.HyperStack.ST.get () in
    // key: live h_mid, freeable, unused_in h0, modifies (loc_buffer key) h0 h_mid
    // value: live h1, freeable, unused_in h_mid, modifies (loc_buffer value) h_mid h1

    // value in_loc_unused_in h0: chain through key allocation via modifies_loc_unused_in
    // unused_in value h_mid => in_loc_unused_in value h_mid
    // modifies (loc_buffer key) h0 h_mid + address_liveness_insensitive => backward
    lemma_unused_in_implies_in_loc_unused_in value_alloc.bytes_ptr h_mid;
    address_liveness_insensitive_buffer key_alloc.bytes_ptr;
    lemma_in_loc_unused_in_backward (loc_buffer key_alloc.bytes_ptr) value_alloc.bytes_ptr h0 h_mid;

    // modifies: compose the two allocations
    modifies_trans (loc_buffer key_alloc.bytes_ptr) h0 h_mid
                   (loc_buffer value_alloc.bytes_ptr) h1;

    { entry_key_ptr = key_alloc.bytes_ptr;
      entry_key_len = key_alloc.bytes_len32;
      entry_value_ptr = value_alloc.bytes_ptr;
      entry_value_len = value_alloc.bytes_len32 }
#pop-options

module HST = FStar.HyperStack.ST

///////////////////////////////////////////////////////////////////////////////
// List-based intermediate predicates for allocation invariant tracking.
// Simpler than buffer-indexed predicates (no content linking needed).
// Used in allocate_entry_list proofs, then lifted to buffer predicates.
///////////////////////////////////////////////////////////////////////////////

let rec entry_list_buffers_live (h:FStar.HyperStack.mem) (entries:list json_entry_out)
  : GTot Type0 (decreases entries) =
  match entries with
  | [] -> True
  | entry :: rest ->
    live h entry.entry_key_ptr /\ live h entry.entry_value_ptr /\
    entry_list_buffers_live h rest

let rec entry_list_buffers_freeable (entries:list json_entry_out)
  : GTot Type0 (decreases entries) =
  match entries with
  | [] -> True
  | entry :: rest ->
    Buffer.freeable entry.entry_key_ptr /\ Buffer.freeable entry.entry_value_ptr /\
    entry_list_buffers_freeable rest

let rec entry_list_key_value_self_disjoint (entries:list json_entry_out)
  : GTot Type0 (decreases entries) =
  match entries with
  | [] -> True
  | entry :: rest ->
    loc_disjoint (loc_buffer entry.entry_key_ptr) (loc_buffer entry.entry_value_ptr) /\
    entry_list_key_value_self_disjoint rest

/// Helper: one entry's buffers are disjoint from all entries in a list.
let rec entry_disjoint_from_list (entry:json_entry_out) (entries:list json_entry_out)
  : GTot Type0 (decreases entries) =
  match entries with
  | [] -> True
  | other :: rest ->
    loc_disjoint (loc_buffer entry.entry_key_ptr) (loc_buffer other.entry_key_ptr) /\
    loc_disjoint (loc_buffer entry.entry_key_ptr) (loc_buffer other.entry_value_ptr) /\
    loc_disjoint (loc_buffer entry.entry_value_ptr) (loc_buffer other.entry_key_ptr) /\
    loc_disjoint (loc_buffer entry.entry_value_ptr) (loc_buffer other.entry_value_ptr) /\
    entry_disjoint_from_list entry rest

let rec entry_list_pairwise_disjoint (entries:list json_entry_out)
  : GTot Type0 (decreases entries) =
  match entries with
  | [] -> True
  | entry :: rest ->
    entry_disjoint_from_list entry rest /\
    entry_list_pairwise_disjoint rest

let rec entry_list_all_unused_in (h:FStar.HyperStack.mem) (entries:list json_entry_out)
  : GTot Type0 (decreases entries) =
  match entries with
  | [] -> True
  | entry :: rest ->
    Buffer.unused_in entry.entry_key_ptr h /\ Buffer.unused_in entry.entry_value_ptr h /\
    entry_list_all_unused_in h rest

/// Weaker list predicate using in_loc_unused_in instead of unused_in.
/// Can be proved backward through heap transitions (unlike entry_list_all_unused_in).
let rec entry_list_all_in_loc_unused_in (h:FStar.HyperStack.mem) (entries:list json_entry_out)
  : GTot Type0 (decreases entries) =
  match entries with
  | [] -> True
  | entry :: rest ->
    in_loc_unused_in entry.entry_key_ptr h /\ in_loc_unused_in entry.entry_value_ptr h /\
    entry_list_all_in_loc_unused_in h rest

let rec entry_list_disjoint_from_buf (entries:list json_entry_out) (buf:buffer json_entry_out)
  : GTot Type0 (decreases entries) =
  match entries with
  | [] -> True
  | entry :: rest ->
    loc_disjoint (loc_buffer buf) (loc_buffer entry.entry_key_ptr) /\
    loc_disjoint (loc_buffer buf) (loc_buffer entry.entry_value_ptr) /\
    entry_list_disjoint_from_buf rest buf

/// Footprint of all entry buffers in a list (union of all key/value loc_buffers).
let rec entry_list_loc (entries:list json_entry_out)
  : GTot loc (decreases entries) =
  match entries with
  | [] -> loc_none
  | entry :: rest ->
    loc_union (loc_union (loc_buffer entry.entry_key_ptr) (loc_buffer entry.entry_value_ptr))
              (entry_list_loc rest)

///////////////////////////////////////////////////////////////////////////////
// Lemmas for list-based predicates
///////////////////////////////////////////////////////////////////////////////

/// unused_in entries at h + live buffer at h -> entry is disjoint from that buffer.
let rec lemma_unused_in_implies_disjoint_from_list
  (h:FStar.HyperStack.mem)
  (entry:json_entry_out)
  (entries:list json_entry_out)
  : Lemma (requires
      entry_list_all_unused_in h entries /\
      live h entry.entry_key_ptr /\ live h entry.entry_value_ptr)
    (ensures entry_disjoint_from_list entry entries)
    (decreases entries)
  = match entries with
    | [] -> ()
    | _ :: rest ->
      lemma_unused_in_implies_disjoint_from_list h entry rest

/// Disjointness from in_loc_unused_in list predicate + live entry buffers.
/// Uses lemma_in_loc_unused_in_disjoint_from_live for each entry in the list.
let rec lemma_in_loc_unused_in_implies_disjoint_from_list
  (h:FStar.HyperStack.mem)
  (entry:json_entry_out)
  (entries:list json_entry_out)
  : Lemma (requires
      entry_list_all_in_loc_unused_in h entries /\
      live h entry.entry_key_ptr /\ live h entry.entry_value_ptr)
    (ensures entry_disjoint_from_list entry entries)
    (decreases entries)
  = match entries with
    | [] -> ()
    | other :: rest ->
      // other.key is in_loc_unused_in h, entry.key is live h => disjoint
      lemma_in_loc_unused_in_disjoint_from_live h other.entry_key_ptr entry.entry_key_ptr;
      lemma_in_loc_unused_in_disjoint_from_live h other.entry_key_ptr entry.entry_value_ptr;
      lemma_in_loc_unused_in_disjoint_from_live h other.entry_value_ptr entry.entry_key_ptr;
      lemma_in_loc_unused_in_disjoint_from_live h other.entry_value_ptr entry.entry_value_ptr;
      loc_disjoint_sym (loc_buffer other.entry_key_ptr) (loc_buffer entry.entry_key_ptr);
      loc_disjoint_sym (loc_buffer other.entry_key_ptr) (loc_buffer entry.entry_value_ptr);
      loc_disjoint_sym (loc_buffer other.entry_value_ptr) (loc_buffer entry.entry_key_ptr);
      loc_disjoint_sym (loc_buffer other.entry_value_ptr) (loc_buffer entry.entry_value_ptr);
      lemma_in_loc_unused_in_implies_disjoint_from_list h entry rest

/// Backward frame for entry_list_all_in_loc_unused_in across address-liveness-insensitive
/// modifications. Each entry's in_loc_unused_in is preserved backward by modifies_loc_unused_in.
let rec lemma_entry_list_in_loc_unused_in_backward
  (l:loc)
  (entries:list json_entry_out)
  (h0 h1:FStar.HyperStack.mem)
  : Lemma
    (requires
      modifies l h0 h1 /\
      address_liveness_insensitive_locs `loc_includes` l /\
      entry_list_all_in_loc_unused_in h1 entries)
    (ensures entry_list_all_in_loc_unused_in h0 entries)
    (decreases entries)
  = match entries with
    | [] -> ()
    | entry :: rest ->
      lemma_in_loc_unused_in_backward l entry.entry_key_ptr h0 h1;
      lemma_in_loc_unused_in_backward l entry.entry_value_ptr h0 h1;
      lemma_entry_list_in_loc_unused_in_backward l rest h0 h1

/// Liveness preserved for list entries across heap transitions where
/// modification is to unused_in buffers (fresh allocations).
let rec lemma_entry_list_live_preserved
  (entries:list json_entry_out)
  (l:loc)
  (h0 h1:FStar.HyperStack.mem)
  : Lemma (requires
      entry_list_buffers_live h0 entries /\
      entry_list_all_unused_in h0 entries /\
      modifies l h0 h1 /\
      (forall (b:buffer UInt8.t). Buffer.live h0 b ==> Buffer.live h1 b))
    (ensures entry_list_buffers_live h1 entries)
    (decreases entries)
  = match entries with
    | [] -> ()
    | entry :: rest ->
      lemma_entry_list_live_preserved rest l h0 h1

#push-options "--z3rlimit 100 --fuel 2 --ifuel 1"
let rec allocate_entry_list
  (pairs:list (string * string))
  : ST (list json_entry_out)
      (requires (fun _ -> List.Tot.for_all utf8_pair_within_u32 pairs))
      (ensures (fun h0 res h1 ->
        List.length res = List.length pairs /\
        entry_list_buffers_live h1 res /\
        entry_list_buffers_freeable res /\
        entry_list_key_value_self_disjoint res /\
        entry_list_pairwise_disjoint res /\
        entry_list_all_in_loc_unused_in h0 res /\
        (forall (b:buffer UInt8.t). {:pattern (Buffer.live h0 b)}
          Buffer.live h0 b ==> Buffer.live h1 b) /\
        (forall (b:buffer json_member_c). {:pattern (Buffer.live h0 b)}
          Buffer.live h0 b ==> Buffer.live h1 b)))
  (decreases pairs)
  =
    match pairs with
    | [] -> []
    | pair::rest ->
        let _ = lemma_for_all_cons utf8_pair_within_u32 pair rest in
        let h0 = HST.get () in
        let entry = create_entry_from_pair pair in
        let h_mid = HST.get () in
        let tail = allocate_entry_list rest in
        let h1 = HST.get () in

        // IH gives: entry_list_all_in_loc_unused_in h_mid tail
        //   + all list predicates at h1
        //   + frame: forall b. live h_mid b ==> live h1 b

        // (A) Pairwise disjoint: entry's buffers are live at h_mid,
        //     IH gives entry_list_all_in_loc_unused_in h_mid tail.
        lemma_in_loc_unused_in_implies_disjoint_from_list h_mid entry tail;

        // (B) entry_list_all_in_loc_unused_in h0 (entry :: tail):
        // (B1) entry.key: unused_in h0 => in_loc_unused_in h0
        lemma_unused_in_implies_in_loc_unused_in entry.entry_key_ptr h0;
        // (B2) entry.value: in_loc_unused_in h0 (from create_entry_from_pair postcondition)
        // (B3) tail: backward frame from h_mid to h0
        //     create_entry_from_pair: modifies (loc_union key_loc value_loc) h0 h_mid
        //     Both loc_buffer's are address_liveness_insensitive (SMTPat)
        //     => address_liveness_insensitive_locs includes the union (SMTPat via loc_includes_union_r')
        address_liveness_insensitive_buffer entry.entry_key_ptr;
        address_liveness_insensitive_buffer entry.entry_value_ptr;
        let entry_mod = loc_union (loc_buffer entry.entry_key_ptr) (loc_buffer entry.entry_value_ptr) in
        lemma_entry_list_in_loc_unused_in_backward entry_mod tail h0 h_mid;

        entry :: tail
#pop-options

/// Wrapper for write_entry_at_u32 with Seq.upd postcondition.
/// The Seq.upd fact is needed locally in store_entries_into_buffer_aux for
/// content linking, but exported from Types.fst's write_entry_at_u32 it causes
/// Z3 encoding issues in unrelated lemmas (lemma_entries_buffer_preserved).
/// Keeping the stronger postcondition local avoids the global SMT context pollution.
let write_entry_at_u32_with_seq
  (buf:buffer json_entry_out)
  (idx32:UInt32.t)
  (entry:json_entry_out)
  : Stack unit
      (requires (fun h ->
                   live h buf /\
                   UInt32.v idx32 < Buffer.length buf /\
                   Buffer.length buf <= pow2 32))
      (ensures (fun h0 _ h1 ->
                   modifies (loc_buffer buf) h0 h1 /\
                   live h1 buf /\
                   Buffer.as_seq h1 buf == Seq.upd (Buffer.as_seq h0 buf) (UInt32.v idx32) entry))
  =
    Buffer.upd buf idx32 entry

/// Helper lemma for store_entries_into_buffer_aux: compose write + IH content linking.
/// After write_entry_at_u32 at idx_v (giving Seq.upd), the IH for rest at idx_v+1
/// composes to give content linking for entry::rest at idx_v.
let lemma_store_compose_content_linking
  (buf:buffer json_entry_out)
  (idx_v:nat)
  (entry:json_entry_out)
  (rest:list json_entry_out)
  (h0 h_mid h1:FStar.HyperStack.mem)
  : Lemma
    (requires
      live h0 buf /\ live h_mid buf /\ live h1 buf /\
      idx_v + 1 + List.length rest <= Buffer.length buf /\
      Buffer.length buf < pow2 32 /\
      // write: buf_mid = upd buf_0 idx_v entry
      Buffer.as_seq h_mid buf == Seq.upd (Buffer.as_seq h0 buf) idx_v entry /\
      // IH content linking: forall j < |rest|. buf_1[idx_v+1+j] == rest[j]
      (forall (j:nat{j < List.length rest}).
        Seq.index (Buffer.as_seq h1 buf) (idx_v + 1 + j) ==
        List.index rest j) /\
      // IH frame: forall k outside [idx_v+1, idx_v+1+|rest|). buf_1[k] == buf_mid[k]
      (forall (k:nat{k < Buffer.length buf}).
        (k < idx_v + 1 \/ k >= idx_v + 1 + List.length rest) ==>
        Seq.index (Buffer.as_seq h1 buf) k ==
        Seq.index (Buffer.as_seq h_mid buf) k))
    (ensures
      // Composed content linking: forall i < |entry::rest|. buf_1[idx_v+i] == (entry::rest)[i]
      (forall (i:nat{i < List.length (entry :: rest)}).
        Seq.index (Buffer.as_seq h1 buf) (idx_v + i) ==
        List.index (entry :: rest) i) /\
      // Composed frame: forall k outside [idx_v, idx_v+|entry::rest|). buf_1[k] == buf_0[k]
      (forall (k:nat{k < Buffer.length buf}).
        (k < idx_v \/ k >= idx_v + List.length (entry :: rest)) ==>
        Seq.index (Buffer.as_seq h1 buf) k ==
        Seq.index (Buffer.as_seq h0 buf) k))
  =
    let seq0 = Buffer.as_seq h0 buf in
    let seq_mid = Buffer.as_seq h_mid buf in
    let seq1 = Buffer.as_seq h1 buf in
    let entries = entry :: rest in
    let n = List.length entries in
    // Content linking for i = 0: buf_1[idx_v] == entry
    // IH frame: idx_v < idx_v + 1, so buf_1[idx_v] == buf_mid[idx_v]
    // write: buf_mid = upd buf_0 idx_v entry, so buf_mid[idx_v] == entry
    assert (Seq.index seq1 idx_v == Seq.index seq_mid idx_v);
    assert (seq_mid == Seq.upd seq0 idx_v entry);
    assert (Seq.index (Seq.upd seq0 idx_v entry) idx_v == entry);
    assert (Seq.index seq1 idx_v == entry);
    assert (List.index entries 0 == entry);
    // Content linking for i > 0: buf_1[idx_v + i] == entries[i] = rest[i-1]
    // IH: buf_1[(idx_v + 1) + (i-1)] == rest[i-1] = entries[i]
    let aux_content (i:nat{i < n}) : Lemma
      (Seq.index seq1 (idx_v + i) == List.index entries i)
      = if i = 0 then ()
        else begin
          // i > 0: idx_v + i = (idx_v + 1) + (i - 1), entries[i] = rest[i-1]
          assert (idx_v + i = (idx_v + 1) + (i - 1));
          assert (List.index entries i == List.index rest (i - 1))
        end
    in
    FStar.Classical.forall_intro aux_content;
    // Frame: for k outside [idx_v, idx_v + n)
    let aux_frame (k:nat{k < Buffer.length buf})
      : Lemma (requires k < idx_v \/ k >= idx_v + n)
              (ensures Seq.index seq1 k == Seq.index seq0 k)
      = // k outside [idx_v, idx_v+n) => k outside [idx_v+1, idx_v+1+|rest|) or k = idx_v
        // Case 1: k < idx_v => k < idx_v + 1 => IH frame gives seq1[k] = seq_mid[k]
        //   write: k <> idx_v so seq_mid[k] = seq0[k]
        // Case 2: k >= idx_v + n => k >= idx_v + 1 + |rest| => IH frame gives seq1[k] = seq_mid[k]
        //   write: k <> idx_v (since k >= idx_v + n >= idx_v + 1) so seq_mid[k] = seq0[k]
        if k < idx_v + 1 then begin
          // k < idx_v + 1 means k <= idx_v, combined with k < idx_v (from hypothesis)
          assert (Seq.index seq1 k == Seq.index seq_mid k);
          assert (k <> idx_v);
          Seq.lemma_index_upd2 seq0 idx_v entry k
        end else begin
          assert (k >= idx_v + 1 + List.length rest);
          assert (Seq.index seq1 k == Seq.index seq_mid k);
          assert (k <> idx_v);
          Seq.lemma_index_upd2 seq0 idx_v entry k
        end
    in
    FStar.Classical.forall_intro (FStar.Classical.move_requires aux_frame)

#push-options "--z3rlimit 200 --fuel 2 --ifuel 1"
let rec store_entries_into_buffer_aux
  (buf:buffer json_entry_out)
  (idx32:UInt32.t)
  (entries:list json_entry_out)
  : Stack unit
      (requires (fun h ->
                   live h buf /\
                   UInt32.v idx32 + List.length entries <= Buffer.length buf /\
                   Buffer.length buf < pow2 32))
      (ensures (fun h0 _ h1 ->
                   modifies (loc_buffer buf) h0 h1 /\
                   live h1 buf /\
                   // Content linking: buf[idx32+i] == entries[i]
                   (forall (i:nat{i < List.length entries}).
                     Seq.index (Buffer.as_seq h1 buf) (UInt32.v idx32 + i) ==
                     List.index entries i) /\
                   // Frame: indices outside written range are unchanged
                   (forall (i:nat{i < Buffer.length buf}).
                     (i < UInt32.v idx32 \/ i >= UInt32.v idx32 + List.length entries) ==>
                     Seq.index (Buffer.as_seq h1 buf) i ==
                     Seq.index (Buffer.as_seq h0 buf) i)))
  (decreases (List.length entries))
  =
    match entries with
    | [] -> ()
    | entry::rest ->
        let idx_v = UInt32.v idx32 in
        let idx_next = UInt32.add idx32 1ul in
        let h0 = FStar.HyperStack.ST.get () in
        write_entry_at_u32_with_seq buf idx32 entry;
        let h_mid = FStar.HyperStack.ST.get () in
        store_entries_into_buffer_aux buf idx_next rest;
        let h1 = FStar.HyperStack.ST.get () in
        lemma_store_compose_content_linking buf idx_v entry rest h0 h_mid h1
#pop-options

let store_entries_into_buffer
  (buf:buffer json_entry_out)
  (idx:nat)
  (entries:list json_entry_out)
  : Stack unit
      (requires (fun h ->
                   live h buf /\
                   idx + List.length entries <= Buffer.length buf))
      (ensures (fun h0 _ h1 ->
                   modifies (loc_buffer buf) h0 h1 /\
                   live h1 buf /\
                   (forall (i:nat{i < List.length entries}).
                     Seq.index (Buffer.as_seq h1 buf) (idx + i) ==
                     List.index entries i) /\
                   (forall (i:nat{i < Buffer.length buf}).
                     (i < idx \/ i >= idx + List.length entries) ==>
                     Seq.index (Buffer.as_seq h1 buf) i ==
                     Seq.index (Buffer.as_seq h0 buf) i)))
  =
    let _ = lemma_buffer_length_bounded buf in
    let _ = lemma_length_transitive idx (idx + List.length entries) (pow2 32) in
    let idx32 = UInt32.uint_to_t idx in
    store_entries_into_buffer_aux buf idx32 entries

let lemma_entries_length_bound
  (entries:list json_entry_out)
  (pairs:list (string * string))
  (count:nat)
  : Lemma (requires List.length entries = List.length pairs /\ count = List.length pairs)
          (ensures List.length entries <= count)
  =
    assert (List.length entries = count);
    ()

let allocate_entries_array
  (pairs:list (string * string))
  : ST (buffer json_entry_out)
      (requires (fun _ ->
                   List.Tot.for_all utf8_pair_within_u32 pairs /\
                   List.length pairs < pow2 32))
      (ensures (fun h0 buf h1 -> live h1 buf /\ Buffer.length buf >= List.length pairs /\
                                  Buffer.freeable buf /\ Buffer.length buf > 0))
  =
    let count = list_length pairs in
    let _ = lemma_list_length pairs in
    if count = 0 then
      // Buffer.malloc requires v > 0; allocate 1 element for empty input.
      malloc_entry_array 1ul
    else begin
      let count32 = U32.uint_to_t count in
      // Allocate entries first (ST effect — may invalidate prior heap state).
      // Then malloc_entry_array (also ST now — uses Buffer.malloc).
      let entries = allocate_entry_list pairs in
      let _ = lemma_entries_length_bound entries pairs count in
      let buf = malloc_entry_array count32 in
      let _ = store_entries_into_buffer buf 0 entries in
      buf
    end

let build_success_result (pairs:list (string * string))
  : ST json_parse_result_c
      (requires (fun _ ->
                   List.Tot.for_all utf8_pair_within_u32 pairs /\
                   List.length pairs < pow2 32))
      (ensures (fun h0 res h1 ->
        live h1 res.result_entries /\
        Buffer.freeable res.result_entries /\
        Buffer.length res.result_entries > 0 /\
        live h1 res.result_error_message /\
        U32.v res.result_entry_count <= Buffer.length res.result_entries))
  =
    let entries_buf = allocate_entries_array pairs in
    let count_nat = list_length pairs in
    let _ = lemma_list_length pairs in
    let count32 = u32_of_nat count_nat in
    let empty_msg = allocate_empty_bytes () in
    // entries_buf: live (allocate_entries_array), freeable, length > 0, length >= |pairs|
    // empty_msg: allocate_empty_bytes returns Buffer.null (length 0, modifies loc_none)
    //   so entries_buf stays live (heap unchanged by null allocation)
    // count32 = |pairs| <= length entries_buf (from allocate_entries_array)
    { result_entries = entries_buf;
      result_entry_count = count32;
      result_error = JsonParseOk;
      result_error_message = empty_msg.bytes_ptr;
      result_error_message_len = empty_msg.bytes_len32 }

#push-options "--z3rlimit 60 --fuel 1 --ifuel 1"
let build_error_result (err:decode_error)
  : ST json_parse_result_c
      (requires (fun _ -> True))
      (ensures (fun h0 res h1 ->
        live h1 res.result_entries /\
        Buffer.freeable res.result_entries /\
        Buffer.length res.result_entries > 0 /\
        live h1 res.result_error_message /\
        U32.v res.result_entry_count = 0 /\
        U32.v res.result_entry_count <= Buffer.length res.result_entries /\
        // modifies clause: both result buffers are address-liveness-insensitive,
        // so modifies_liveness_insensitive_buffer_weak (SMTPat) preserves liveness
        // of any buffer that was live in h0 — callers get frame for free.
        modifies (loc_union (loc_buffer res.result_entries)
                            (loc_buffer res.result_error_message)) h0 h1))
  =
    let h0 = FStar.HyperStack.ST.get () in
    // Allocate 1-element buffer (Buffer.malloc requires v > 0).
    // result_entry_count = 0 means no entries are used; the buffer
    // is freed by free_entry_array without accessing any entries.
    let entries_buf = malloc_entry_array 1ul in
    let h_mid = FStar.HyperStack.ST.get () in
    // entries_buf: live h_mid, freeable, length=1, modifies loc_none h0 h_mid
    // unused_in entries_buf h0

    let msg = decode_error_message err in
    let _ = lemma_decode_error_message_within_header_max_length err in
    let _ = lemma_utf8_bytes_cstring_length_bound msg in
    let msg_alloc = allocate_utf8_cstring msg in
    let h1 = FStar.HyperStack.ST.get () in
    // msg_alloc.bytes_ptr: live h1, freeable, unused_in h_mid
    // modifies (loc_buffer msg_alloc.bytes_ptr) h_mid h1

    // (1) entries_buf still live h1: entries_buf was live h_mid, and
    //     msg_alloc.bytes_ptr was unused_in h_mid => disjoint from entries_buf
    //     => modifies (loc_buffer msg_alloc) doesn't affect entries_buf.
    //     (SMT derives this from unused_in + modifies frame.)

    // (2) modifies composition:
    //     malloc_entry_array: modifies loc_none h0 h_mid
    //     modifies_loc_includes (SMTPat) + loc_includes_none (SMTPat):
    //       modifies loc_none h0 h_mid => modifies (loc_buffer entries_buf) h0 h_mid
    //     allocate_utf8_cstring: modifies (loc_buffer msg_alloc.bytes_ptr) h_mid h1
    //     modifies_trans gives: modifies (loc_union entries msg) h0 h1
    modifies_trans (loc_buffer entries_buf) h0 h_mid
                   (loc_buffer msg_alloc.bytes_ptr) h1;

    { result_entries = entries_buf;
      result_entry_count = U32.zero;
      result_error = json_parse_error_of_decode_error err;
      result_error_message = msg_alloc.bytes_ptr;
      result_error_message_len = msg_alloc.bytes_len32 }
#pop-options

let decode_bytes_to_string (bytes:list UInt8.t)
  : Tot (decode_result string)
  = decode_utf8 bytes

let normalise_raw_member (raw:raw_json_member)
  : Tot (decode_result json_member)
  =
    match decode_bytes_to_string raw.raw_key with
    | Error err -> Error err
    | Ok key_str ->
        match raw.raw_kind with
        | JsonValueNull -> Ok { key = key_str; value = JsonNull }
        | JsonValueString ->
            match decode_bytes_to_string raw.raw_value with
            | Error err -> Error err
            | Ok value_str -> Ok { key = key_str; value = JsonString value_str }

let rec normalise_raw_members
  (members:list raw_json_member)
  : Tot (decode_result (list json_member))
  =
    match members with
    | [] -> Ok []
    | m :: rest ->
        match normalise_raw_member m with
        | Error err -> Error err
        | Ok member ->
            match normalise_raw_members rest with
            | Error err -> Error err
            | Ok tail -> Ok (member :: tail)

let parse_json_entries
  (members:list json_member)
  : decode_result (list (string * string))
  = parse_json_pairs_result members

/// Lemma: normalise_raw_members preserves list length when successful.
let rec lemma_normalise_raw_members_length (members:list raw_json_member)
  : Lemma (ensures (match normalise_raw_members members with
                    | Ok result -> List.length result = List.length members
                    | Error _ -> True))
          (decreases members)
  = match members with
    | [] -> ()
    | m :: rest ->
      match normalise_raw_member m with
      | Error _ -> ()
      | Ok _ ->
        lemma_normalise_raw_members_length rest

/// Lemma: keys_of_members has the same length as the input list.
let rec lemma_keys_of_members_length (members:list json_member)
  : Lemma (ensures List.length (keys_of_members members) = List.length members)
          (decreases members)
  = match members with
    | [] -> ()
    | _ :: rest -> lemma_keys_of_members_length rest

/// Lemma: List.map fst preserves length (for keys_of_entries).
let rec lemma_map_fst_length (#a #b:Type) (xs:list (a * b))
  : Lemma (ensures List.length (List.map #(a * b) #a (fun p -> match p with | (k, _) -> k) xs) = List.length xs)
          (decreases xs)
  = match xs with
    | [] -> ()
    | _ :: rest -> lemma_map_fst_length rest

/// Lemma: normalize_json_members preserves list length when successful.
/// Follows from keys_of_entries output = keys_of_members input.
let lemma_normalize_json_members_length (members:list json_member)
  : Lemma (ensures (match normalize_json_members members with
                    | Ok entries -> List.length entries = List.length members
                    | Error _ -> True))
  = match normalize_json_members members with
    | Ok entries ->
      // normalize_json_members ensures: keys_of_entries entries = keys_of_members members
      lemma_map_fst_length entries;
      lemma_keys_of_members_length members;
      // keys_of_entries entries = List.map fst entries, so |keys_of_entries entries| = |entries|
      // |keys_of_members members| = |members|
      // keys_of_entries entries = keys_of_members members (from normalize_json_members postcondition)
      // Therefore |entries| = |members|
      ()
    | Error _ -> ()

/// Lemma: parse_json_entries preserves list length when successful.
let lemma_parse_json_entries_length (members:list json_member)
  : Lemma (ensures (match parse_json_entries members with
                    | Ok pairs -> List.length pairs = List.length members
                    | Error _ -> True))
  = lemma_normalize_json_members_length members

/// Lemma: full pipeline length bound.
/// If count < pow2 32 and the pipeline succeeds, |pairs| < pow2 32.
let lemma_pipeline_length_bound
  (raw_members:list raw_json_member)
  (count:nat)
  : Lemma (requires List.length raw_members = count /\ count < pow2 32)
          (ensures (match normalise_raw_members raw_members with
                   | Error _ -> True
                   | Ok json_members ->
                     (match parse_json_entries json_members with
                      | Error _ -> True
                      | Ok pairs -> List.length pairs < pow2 32)))
  = lemma_normalise_raw_members_length raw_members;
    match normalise_raw_members raw_members with
    | Error _ -> ()
    | Ok json_members ->
      lemma_parse_json_entries_length json_members

/// FFI entry point: parse JSON entries from a C-allocated json_member_c buffer.
/// Pre: members buffer is live AND all nested key_buf/value_buf are live.
/// The members_nested_live precondition is an explicit FFI contract:
/// the C JSON parser must allocate all nested buffers before calling this.
let parse_json_entries_from_c
  (members:buffer json_member_c)
  (count:nat{count <= Buffer.length members})
  : Stack (decode_result (list (string * string)))
      (requires (fun h -> live h members /\
                          members_nested_live h members count 0))
      (ensures (fun _ _ _ -> True))
  =
    let raw_members = collect_raw_members_stack members count 0 in
    match normalise_raw_members raw_members with
    | Error err -> Error err
    | Ok json_members -> parse_json_entries json_members
