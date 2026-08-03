module Jose.HeaderParser.Spec

/// Pure (Tot) TLV header parser operating on `FStar.Seq.seq UInt8.t`.
///
/// This module mirrors Jose.HeaderParser.TLV but replaces the
/// `buffer UInt8.t` + `read_u8_safe` (assume val) approach with
/// `Seq.index` on an immutable sequence.  All functions are Tot;
/// no assume vals, no Stack effect.
///
/// Buffer-level callers should convert via `Buffer.as_seq` in Stack
/// context, then call these pure functions.

open Jose.HeaderMicro
open Jose.HeaderSpec
open FStar.UInt8
open FStar.String
open FStar.Char
open FStar.Pervasives
open FStar.Math.Lemmas
open FStar.List.Tot
open JoseNatLemmas
module SL = Jose.StringLemmas
open Jose.StringLemmas
open Jose.Utf8Lemmas
open Jose.TlvLemmas
open Jose.HeaderKeyLemmas
module JSON = Jose.JsonHeaderSpec
module Policy = Jose.HeaderPolicy
module List = FStar.List.Tot
module Seq = FStar.Seq

///////////////////////////////////////////////////////////////////////////////
// TLV scaffolding (seq-based)
///////////////////////////////////////////////////////////////////////////////

let entry_min_size : nat = 2

/// Safe addition lemma for UInt8 payload lengths
val lemma_length_sum_safe : a:UInt8.t -> b:UInt8.t ->
  Lemma (requires (UInt8.v a + UInt8.v b + entry_min_size < pow2_8))
        (ensures True)
let lemma_length_sum_safe a b = ()

let option_of_result
  (#a:Type0)
  (#e:Type0)
  (r:jlresult a e)
  : option a
  = match r with
    | Ok v -> Some v
    | Error _ -> None

type entry_record = {
  key_start: nat;
  key_len: nat;
  value_len: nat;
  value_start: nat;
  new_offset: nat;
  key_text: string;
  value_text: string;
}

/// Gather `count` bytes starting at `idx` from a sequence.
/// Replaces the buffer-based `gather_bytes` that used `read_u8_safe`.
let rec gather_bytes
  (s:Seq.seq UInt8.t)
  (len:nat{len <= Seq.length s})
  (idx:nat{idx <= len})
  (count:nat{idx + count <= len})
  : Tot (list UInt8.t)
  (decreases count)
  =
    if count = 0 then []
    else
      let _ = assert (idx < len) in
      let _ = assert (idx < Seq.length s) in
      let byte = Seq.index s idx in
      byte :: gather_bytes s len (idx + 1) (count - 1)

val lemma_gather_bytes_length :
  s:Seq.seq UInt8.t ->
  len:nat{len <= Seq.length s} ->
  idx:nat{idx <= len} ->
  count:nat{idx + count <= len} ->
  Lemma (ensures List.length (gather_bytes s len idx count) = count)
  (decreases count)
let rec lemma_gather_bytes_length s len idx count =
  if count = 0 then ()
  else lemma_gather_bytes_length s len (idx + 1) (count - 1)

let known_header_keys : list string = Policy.allow_list

val decode_entry_raw :
  s:Seq.seq UInt8.t ->
  offset:nat ->
  len:nat{offset + entry_min_size <= len /\ len <= Seq.length s} ->
  Tot (option entry_record)

/// Helper returning structured information about a TLV entry with error reporting
let decode_entry_raw_result
  (s:Seq.seq UInt8.t)
  (offset:nat)
  (len:nat{offset + entry_min_size <= len /\ len <= Seq.length s})
  : Tot (decode_result entry_record)
  =
    let key_len_u8 = Seq.index s offset in
    let key_len = byte_val key_len_u8 in
    if key_len = 0 then Error InvalidKeyEncoding
    else
      let key_start = offset + 1 in
      if key_start + key_len >= len then Error BufferTooShort
      else
        let key_bytes = gather_bytes s len key_start key_len in
        match string_of_ascii key_bytes with
        | None -> Error InvalidKeyEncoding
        | Some key_str ->
            if not (Policy.key_allowed key_str) then Error (UnknownKey key_str)
            else
              let value_len_pos = key_start + key_len in
              let value_len_u8 = Seq.index s value_len_pos in
              let value_len = byte_val value_len_u8 in
              let value_start = value_len_pos + 1 in
              if value_start + value_len > len then Error BufferTooShort
              else
                let value_bytes = gather_bytes s len value_start value_len in
                match decode_utf8 value_bytes with
                | Error e -> Error e
                | Ok value_str ->
                    let new_offset = value_start + value_len in
                    let _ = assert (offset < new_offset) in
                    let _ = assert (new_offset <= len) in
                    Ok {
                      key_start = key_start;
                      key_len = key_len;
                      value_len = value_len;
                      value_start = value_start;
                      new_offset = new_offset;
                      key_text = key_str;
                      value_text = value_str;
                    }

/// Helper returning structured information about a TLV entry (legacy option)
let decode_entry_raw
  (s:Seq.seq UInt8.t)
  (offset:nat)
  (len:nat{offset + entry_min_size <= len /\ len <= Seq.length s})
  : Tot (option entry_record)
  = option_of_result (decode_entry_raw_result s offset len)

let lemma_decode_entry_raw_bounds
  (s:Seq.seq UInt8.t)
  (offset:nat)
  (len:nat{offset + entry_min_size <= len /\ len <= Seq.length s})
  (r:entry_record)
  : Lemma
      (requires decode_entry_raw s offset len == Some r)
      (ensures r.key_start = offset + 1 /\
               r.key_start + r.key_len < len /\
               r.value_start = r.key_start + r.key_len + 1 /\
               r.value_start + r.value_len <= len /\
               r.new_offset = r.value_start + r.value_len)
  =
    match decode_entry_raw s offset len with
    | None -> ()
    | Some entry ->
        let _ = assert (entry == r) in
        assert (entry.key_start == offset + 1);
        assert (entry.key_start + entry.key_len < len);
        assert (entry.value_start == entry.key_start + entry.key_len + 1);
        assert (entry.value_start + entry.value_len <= len);
        assert (entry.new_offset == entry.value_start + entry.value_len)

/// Public decoder returning key/value pair with error reporting
let decode_entry_result
  (s:Seq.seq UInt8.t)
  (offset:nat)
  (len:nat{offset + entry_min_size <= len /\ len <= Seq.length s})
  : Tot (decode_result ((string * string) * nat))
  =
    match decode_entry_raw_result s offset len with
    | Ok r -> Ok ((r.key_text, r.value_text), r.new_offset)
    | Error e -> Error e

/// Public decoder returning key/value pair (legacy option)
let decode_entry
  (s:Seq.seq UInt8.t)
  (offset:nat)
  (len:nat{offset + entry_min_size <= len /\ len <= Seq.length s})
  : Tot (option ((string * string) * nat))
  = option_of_result (decode_entry_result s offset len)

let rec decode_all_entries_aux_result
  (s:Seq.seq UInt8.t)
  (offset:nat)
  (len:nat{offset <= len /\ len <= Seq.length s})
  (acc:list (string * string))
  (seen:list string)
  : Pure (decode_result (list (string * string) * nat))
         (requires seen = keys_of_entries acc /\
                   no_duplicate_keys seen /\
                   List.for_all Policy.key_allowed seen = true)
         (ensures fun r ->
           match r with
           | Ok (result, final_offset) ->
               no_duplicate_keys (keys_of_entries result) /\
               List.for_all Policy.key_allowed (keys_of_entries result) = true /\
                offset <= final_offset /\ final_offset <= len
           | Error _ -> True)
         (decreases (len - offset))
  =
    if offset = len then (
      lemma_rev_preserves_no_duplicates seen;
      lemma_policy_for_all_rev seen;
      lemma_keys_of_entries_rev acc;
      assert (keys_of_entries (List.rev acc) = List.rev (keys_of_entries acc));
      assert (keys_of_entries (List.rev acc) = List.rev seen);
      assert (no_duplicate_keys (keys_of_entries (List.rev acc)));
      lemma_policy_for_all_eq (keys_of_entries (List.rev acc)) (List.rev seen);
      Ok (List.rev acc, offset)
    )
    else if offset + entry_min_size > len then
      Error BufferTooShort
    else
      match decode_entry_raw_result s offset len with
      | Error e -> Error e
      | Ok r ->
          let k = r.key_text in
          let v = r.value_text in
          let new_offset = r.new_offset in
          assert (decode_entry_raw s offset len = Some r);
          lemma_decode_entry_raw_bounds s offset len r;
          assert (new_offset <= len);
          if string_in_list k seen then Error (PolicyViolation Policy.duplicate_key_msg)
          else (
            lemma_seen_acc_consistency acc seen k v;
            lemma_no_duplicate_seen acc seen k v;
            assert (Policy.key_allowed k = true);
            lemma_policy_for_all_cons k seen;
            lemma_policy_for_all_eq (keys_of_entries ((k, v) :: acc)) (k :: seen);
            decode_all_entries_aux_result s new_offset len ((k, v) :: acc) (k :: seen)
          )

let decode_all_entries_aux
  (s:Seq.seq UInt8.t)
  (offset:nat)
  (len:nat{offset <= len /\ len <= Seq.length s})
  (acc:list (string * string))
  (seen:list string)
  : Pure (option (list (string * string) * nat))
       (requires seen = keys_of_entries acc /\
                 no_duplicate_keys seen /\
                 List.for_all Policy.key_allowed seen = true)
       (ensures fun r ->
         match r with
         | Some (result, final_offset) ->
             no_duplicate_keys (keys_of_entries result) /\
             List.for_all Policy.key_allowed (keys_of_entries result) = true /\
             offset <= final_offset /\ final_offset <= len
         | None -> True)
  = option_of_result (decode_all_entries_aux_result s offset len acc seen)

/// Recursive decoder exposed with error reporting
let decode_all_entries_result
  (s:Seq.seq UInt8.t)
  (offset:nat)
  (len:nat{offset <= len /\ len <= Seq.length s})
  : Tot (decode_result (list (string * string) * nat))
    (decreases (len - offset))
  = decode_all_entries_aux_result s offset len [] []

/// TLV parse helper that discards the final offset on success.
let parse_tlv_entries_result
  (s:Seq.seq UInt8.t)
  (len:nat{len <= Seq.length s})
  : Tot (decode_result (list (string * string)))
  =
    match decode_all_entries_result s 0 len with
    | Ok (entries, consumed) ->
        if consumed = len then Ok entries
        else Error (PolicyViolation "partial-read")
    | Error err -> Error err

/// Legacy option wrapper for recursive decoder
let decode_all_entries
  (s:Seq.seq UInt8.t)
  (offset:nat)
  (len:nat{offset <= len /\ len <= Seq.length s})
  : Tot (option (list (string * string) * nat))
    (decreases (len - offset))
  = option_of_result (decode_all_entries_result s offset len)

/// Option-based helper for TLV parsing.
let parse_tlv_entries
  (s:Seq.seq UInt8.t)
  (len:nat{len <= Seq.length s})
  : Tot (option (list (string * string)))
  = option_of_result (parse_tlv_entries_result s len)

///////////////////////////////////////////////////////////////////////////////
// TLV-first parsing with JSON fallback (seq-based)
///////////////////////////////////////////////////////////////////////////////

let parse_with_tlv
  (#a:Type)
  (s:Seq.seq UInt8.t)
  (len:nat{len <= Seq.length s})
  (micro:list (string * string) -> Tot (option a))
  : Tot (option a)
  =
    match parse_tlv_entries s len with
    | Some entries ->
        micro entries
    | None ->
        None

/// JWE parser (seq-based).
val parse_jwe_seq:
  s:Seq.seq UInt8.t ->
  len:nat{len <= Seq.length s} ->
  Tot (option sanitized_jwe)
let parse_jwe_seq s len =
  parse_with_tlv s len parse_jwe_micro

/// JWS parser (seq-based).
val parse_jws_seq:
  s:Seq.seq UInt8.t ->
  len:nat{len <= Seq.length s} ->
  Tot (option sanitized_jws)
let parse_jws_seq s len =
  parse_with_tlv s len parse_jws_micro

/// Context-based JWE parser (seq-based).
val parse_jwe_seq_with_context:
  ctx:Jose.Context.jose_context ->
  s:Seq.seq UInt8.t ->
  len:nat{len <= Seq.length s /\
          len <= Jose.Context.header_max_length_nat ctx} ->
  Tot (option sanitized_jwe)
let parse_jwe_seq_with_context ctx s len =
  parse_with_tlv s len parse_jwe_micro

/// Context-based JWS parser (seq-based).
val parse_jws_seq_with_context:
  ctx:Jose.Context.jose_context ->
  s:Seq.seq UInt8.t ->
  len:nat{len <= Seq.length s /\
          len <= Jose.Context.header_max_length_nat ctx} ->
  Tot (option sanitized_jws)
let parse_jws_seq_with_context ctx s len =
  parse_with_tlv s len parse_jws_micro

///////////////////////////////////////////////////////////////////////////////
// JSON normalization interface (unchanged — no buffer dependency)
///////////////////////////////////////////////////////////////////////////////

let parse_json_entries_result
  (members:list JSON.json_member)
  : decode_result (list (string * string))
  = JSON.parse_json_pairs_result members

let parse_jwe_json_members
  (members:list JSON.json_member)
  : decode_result (option sanitized_jwe)
  =
    match JSON.parse_json_pairs_result members with
    | Ok entries -> Ok (parse_jwe_micro entries)
    | Error err -> Error err

let parse_jws_json_members
  (members:list JSON.json_member)
  : decode_result (option sanitized_jws)
  =
    match JSON.parse_json_pairs_result members with
    | Ok entries -> Ok (parse_jws_micro entries)
    | Error err -> Error err
