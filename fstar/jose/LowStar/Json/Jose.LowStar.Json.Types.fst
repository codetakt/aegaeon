module Jose.LowStar.Json.Types

/// Shared type definitions for the Jose.LowStar.Json module family.
///
/// Extracted from Jose.LowStar.Json.fst to break the layer inversion
/// where Jose.LowStar.Json.Spec depended on the full implementation.
///
/// Dependency chain: Runtime → Types → {Spec, Jose.LowStar.Json}

open FStar.UInt8
open FStar.UInt32
open FStar.HyperStack.All
open FStar.HyperStack.ST
open LowStar.Buffer
open Jose.LowStar.Json.Runtime

module Buffer = LowStar.Buffer

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

type json_parse_error =
  | JsonParseOk
  | JsonParseErrorUnknownKey
  | JsonParseErrorInvalidKeyEncoding
  | JsonParseErrorInvalidValueUtf8
  | JsonParseErrorPolicyViolation
  | JsonParseErrorBufferTooShort
  | JsonParseErrorInternal

noeq
type json_parse_result_c = {
  result_entries: buffer json_entry_out;
  result_entry_count: UInt32.t;
  result_error: json_parse_error;
  result_error_message: buffer UInt8.t;
  result_error_message_len: UInt32.t
}

/// Predicate: all nested key_buf/value_buf in members[idx..count-1] are live.
/// FFI callers (C JSON parser) must ensure this invariant when passing
/// a json_member_c buffer into F* verification code.
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

/// Concrete implementation of buffer indexing with nested liveness proof.
/// Replaces the former assume val: now uses Buffer.index with an explicit
/// members_nested_live precondition that callers (FFI boundary) must satisfy.
noextract
let index_member_with_liveness
  (members:buffer json_member_c)
  (count32:UInt32.t{UInt32.v count32 <= Buffer.length members})
  (idx32:UInt32.t{UInt32.v idx32 < UInt32.v count32})
  : Stack json_member_c
      (requires (fun h -> live h members /\
                          members_nested_live h members (UInt32.v count32) 0))
      (ensures (fun h0 member h1 ->
                  h0 == h1 /\
                  live h1 members /\
                  live h1 member.key_buf /\
                  live h1 member.value_buf))
  =
  let h = FStar.HyperStack.ST.get () in
  lemma_members_nested_live_at h members (UInt32.v count32) 0 (UInt32.v idx32);
  Buffer.index members idx32

/// Phase 2 Step 3.2: UInt32-based buffer write for KaRaMeL extraction
let write_entry_at_u32
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
                   live h1 buf))
  =
    Buffer.upd buf idx32 entry
