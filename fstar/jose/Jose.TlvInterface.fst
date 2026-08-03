module Jose.TlvInterface

open FStar.UInt8
open Jose.Utf8Lemmas
open Jose.TlvLemmas
open Jose.StringLemmas
open Jose.HeaderKeyLemmas
open FStar.List.Tot
module Policy = Jose.HeaderPolicy
module ResultSpec = Jose.TlvResultSpec

let key_allowed_tlv (k:string) : Tot bool =
  Policy.key_allowed k

let parse_tlv_entries_result_spec = ResultSpec.parse_tlv_entries_result_spec

let lemma_tlv_result_keys_in_allow_list = ResultSpec.lemma_tlv_result_keys_in_allow_list

let lemma_tlv_result_unique_keys = ResultSpec.lemma_tlv_result_unique_keys
