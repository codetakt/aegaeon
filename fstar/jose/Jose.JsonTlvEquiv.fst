module Jose.JsonTlvEquiv

open FStar.List.Tot
open FStar.UInt8
open Prims
open Jose.JsonHeaderSpec
open Jose.Utf8Lemmas
open Jose.HeaderParser.Spec
module HM = Jose.HeaderMicro
module HS = Jose.HeaderSpec
module TLV = Jose.TlvInterface
module Seq = FStar.Seq

let lemma_parse_tlv_result_spec_some
  (s:Seq.seq UInt8.t)
  (len:nat{len <= Seq.length s})
  (entries:list (string * string))
  (pf:TLV.parse_tlv_entries_result_spec s len = Ok entries)
  : Lemma (parse_tlv_entries s len = Some entries)
  =
    match TLV.parse_tlv_entries_result_spec s len with
    | Ok entries' ->
        (match pf with
         | () ->
             assert (entries' = entries);
             assert (parse_tlv_entries_result s len = Ok entries');
             assert (parse_tlv_entries s len = Some entries');
             assert (parse_tlv_entries s len = Some entries);
             ())
    | Error _ -> ()

let lemma_parse_tlv_result_spec_none
  (s:Seq.seq UInt8.t)
  (len:nat{len <= Seq.length s})
  (err:decode_error)
  (pf:TLV.parse_tlv_entries_result_spec s len = Error err)
  : Lemma (parse_tlv_entries s len = None)
  =
    match TLV.parse_tlv_entries_result_spec s len with
    | Ok _ -> ()
    | Error err' ->
        (match pf with
         | () ->
             assert (err' = err);
             assert (parse_tlv_entries_result s len = Error err');
             assert (parse_tlv_entries s len = None);
             ())

let lemma_json_pairs_equiv_tlv_success
  (members:list json_member)
  (entries:list (string * string))
  (s:Seq.seq UInt8.t)
  (len:nat{len <= Seq.length s})
  (pf_json:parse_json_pairs_result members = Ok entries)
  (pf_tlv:TLV.parse_tlv_entries_result_spec s len = Ok entries)
  : Lemma
      (ensures
        parse_jwe_seq s len = HS.parse_jwe_sanitized (members_to_json members) /\
        parse_jws_seq s len = HS.parse_jws_sanitized (members_to_json members))
  =
    lemma_parse_json_pairs_result_jwe members entries pf_json;
    lemma_parse_json_pairs_result_jws members entries pf_json;
    lemma_parse_tlv_result_spec_some s len entries pf_tlv;
    let _ = assert (parse_tlv_entries s len = Some entries) in
    let _ = assert (HS.parse_jwe_sanitized (members_to_json members) = HM.parse_jwe_micro entries) in
    let _ = assert (HS.parse_jws_sanitized (members_to_json members) = HM.parse_jws_micro entries) in
    (match parse_tlv_entries s len with
     | Some entries' ->
         assert (entries' = entries);
         assert (parse_jwe_seq s len = HM.parse_jwe_micro entries);
         assert (parse_jws_seq s len = HM.parse_jws_micro entries);
         ()
     | None -> ());
    assert (parse_jwe_seq s len = HS.parse_jwe_sanitized (members_to_json members));
    assert (parse_jws_seq s len = HS.parse_jws_sanitized (members_to_json members));
    ()

let lemma_json_pairs_equiv_tlv_error
  (members:list json_member)
  (s:Seq.seq UInt8.t)
  (len:nat{len <= Seq.length s})
  (err:decode_error)
  (pf_json:parse_json_pairs_result members = Error err)
  (pf_tlv:TLV.parse_tlv_entries_result_spec s len = Error err)
  : Lemma
      (ensures parse_jwe_seq s len = None /\
               parse_jws_seq s len = None)
  =
    (match pf_json with
     | () -> ());
    lemma_parse_tlv_result_spec_none s len err pf_tlv;
    let _ = assert (parse_tlv_entries s len = None) in
    assert (parse_jwe_seq s len = None);
    assert (parse_jws_seq s len = None);
    ()
