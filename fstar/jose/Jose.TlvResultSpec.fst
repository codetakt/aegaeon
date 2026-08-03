module Jose.TlvResultSpec

open FStar.UInt8
open Jose.Utf8Lemmas
open Jose.HeaderKeyLemmas
module Spec = Jose.HeaderParser.Spec
module Policy = Jose.HeaderPolicy
module List = FStar.List.Tot
module Seq = FStar.Seq

let parse_tlv_entries_result_spec = Spec.parse_tlv_entries_result

let lemma_tlv_result_unique_keys
  (s:Seq.seq UInt8.t)
  (len:nat{len <= Seq.length s})
  (tlv_pairs:list (string * string))
  : Lemma
      (requires parse_tlv_entries_result_spec s len = Ok tlv_pairs)
      (ensures no_duplicate_keys (keys_of_entries tlv_pairs))
  =
    Jose.HeaderParser.Proofs.lemma_parse_tlv_entries_invariants s len tlv_pairs;
    ()

let lemma_tlv_result_keys_in_allow_list
  (s:Seq.seq UInt8.t)
  (len:nat{len <= Seq.length s})
  (tlv_pairs:list (string * string))
  : Lemma
      (requires parse_tlv_entries_result_spec s len = Ok tlv_pairs)
      (ensures List.for_all Policy.key_allowed (keys_of_entries tlv_pairs) = true)
  =
    Jose.HeaderParser.Proofs.lemma_parse_tlv_entries_invariants s len tlv_pairs;
    ()
