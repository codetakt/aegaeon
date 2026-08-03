module Jose.HeaderParser.Proofs

/// Standalone correctness lemmas for the TLV header parser.
///
/// These lemmas prove properties about the pure (seq-based) parsing
/// functions defined in Jose.HeaderParser.Spec.

open FStar.UInt8
open Jose.HeaderMicro
open Jose.HeaderSpec
open Jose.Utf8Lemmas
open Jose.HeaderKeyLemmas
open Jose.HeaderParser.Spec
module Policy = Jose.HeaderPolicy
module List = FStar.List.Tot
module Seq = FStar.Seq

let lemma_decode_entry_bounds
  (s:Seq.seq UInt8.t)
  (offset:nat)
  (len:nat{offset + entry_min_size <= len /\ len <= Seq.length s})
  (result:(string * string) * nat)
  : Lemma
      (requires decode_entry s offset len = Some result)
      (ensures (let ((_, _), new_offset) = result in offset < new_offset /\ new_offset <= len))
  =
    match decode_entry s offset len with
    | None -> ()
    | Some ((_, _), new_offset) ->
        match decode_entry_raw s offset len with
        | None -> ()
        | Some r ->
            lemma_decode_entry_raw_bounds s offset len r;
            assert (r.new_offset == new_offset);
            assert (offset < new_offset);
            assert (new_offset <= len)

let lemma_decode_all_unique
  (s:Seq.seq UInt8.t)
  (offset:nat)
  (len:nat{offset <= len /\ len <= Seq.length s})
  (acc:list (string * string))
  (seen:list string)
  (result:list (string * string))
  (final_offset:nat)
  : Lemma
      (requires seen = keys_of_entries acc /\
                no_duplicate_keys seen /\
                List.for_all Policy.key_allowed seen = true /\
                decode_all_entries_aux s offset len acc seen = Some (result, final_offset))
      (ensures no_duplicate_keys (keys_of_entries result))
  =
    match decode_all_entries_aux s offset len acc seen with
    | Some (r, f) ->
        assert (r = result);
        assert (f = final_offset);
        assert (no_duplicate_keys (keys_of_entries r))
    | None -> ()

let lemma_decode_all_allow_list
  (s:Seq.seq UInt8.t)
  (offset:nat)
  (len:nat{offset <= len /\ len <= Seq.length s})
  (acc:list (string * string))
  (seen:list string)
  (result:list (string * string))
  (final_offset:nat)
  : Lemma
      (requires seen = keys_of_entries acc /\
                no_duplicate_keys seen /\
                List.for_all Policy.key_allowed seen = true /\
                decode_all_entries_aux s offset len acc seen = Some (result, final_offset))
      (ensures List.for_all Policy.key_allowed (keys_of_entries result) = true)
  =
    match decode_all_entries_aux s offset len acc seen with
    | Some (r, f) ->
        assert (r = result);
        assert (f = final_offset);
        assert (List.for_all Policy.key_allowed (keys_of_entries r) = true)
    | None -> ()

let lemma_parse_tlv_entries_invariants
  (s:Seq.seq UInt8.t)
  (len:nat{len <= Seq.length s})
  (entries:list (string * string))
  : Lemma
      (requires parse_tlv_entries_result s len = Ok entries)
      (ensures no_duplicate_keys (keys_of_entries entries) /\
               List.for_all Policy.key_allowed (keys_of_entries entries) = true)
  =
    match parse_tlv_entries_result s len with
    | Ok parsed_entries ->
        assert (parsed_entries = entries);
        begin
          match decode_all_entries_result s 0 len with
          | Ok (decoded_entries, consumed) ->
              if consumed = len then (
                assert (decoded_entries = entries);
                assert (no_duplicate_keys (keys_of_entries decoded_entries));
                assert (List.for_all Policy.key_allowed (keys_of_entries decoded_entries) = true)
              ) else ()
          | Error _ -> ()
        end
    | Error _ -> ()

let lemma_parse_with_tlv_preserves
  (#a:eqtype)
  (s:Seq.seq UInt8.t)
  (len:nat{len <= Seq.length s})
  (micro:list (string * string) -> Tot (option a))
  (entries:list (string * string))
  : Lemma
      (requires decode_all_entries s 0 len = Some (entries, len))
      (ensures parse_with_tlv s len micro = micro entries)
  =
    let res = decode_all_entries_result s 0 len in
    match res with
    | Ok (decoded, consumed) ->
        assert (option_of_result res = Some (decoded, consumed));
        assert (decode_all_entries s 0 len = option_of_result res);
        assert (Some (decoded, consumed) = Some (entries, len));
        assert (decoded = entries);
        assert (consumed = len);
        assert (parse_tlv_entries_result s len = Ok decoded);
        assert (parse_tlv_entries s len = Some decoded);
        assert (parse_with_tlv s len micro = micro decoded);
        assert (parse_with_tlv s len micro = micro entries);
        ()
    | Error err ->
        assert (option_of_result res = None);
        assert (decode_all_entries s 0 len = None);
        assert False;
        ()

let lemma_tlv_decode_preserves_semantics_jwe
  (s:Seq.seq UInt8.t)
  (len:nat{len <= Seq.length s})
  (entries:list (string * string))
  : Lemma
      (requires decode_all_entries s 0 len = Some (entries, len))
      (ensures parse_jwe_seq s len = parse_jwe_micro entries)
  =
    lemma_parse_with_tlv_preserves s len parse_jwe_micro entries

let lemma_tlv_decode_preserves_semantics_jws
  (s:Seq.seq UInt8.t)
  (len:nat{len <= Seq.length s})
  (entries:list (string * string))
  : Lemma
      (requires decode_all_entries s 0 len = Some (entries, len))
      (ensures parse_jws_seq s len = parse_jws_micro entries)
  =
    lemma_parse_with_tlv_preserves s len parse_jws_micro entries
