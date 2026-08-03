module TestJoseHeaderMicro

open Jose.HeaderMicro
open Jose.HeaderSpec
open FStar.List.Tot
open FStar.String

val lemma_parse_jwe_micro_matches_spec :
  fields:list (string * string) ->
  Lemma (parse_jwe_micro fields == parse_jwe_sanitized (map (fun (k,v) -> (k, FStar.Json.String v)) fields))
let lemma_parse_jwe_micro_matches_spec _ = ()

val lemma_parse_jws_micro_matches_spec :
  fields:list (string * string) ->
  Lemma (parse_jws_micro fields == parse_jws_sanitized (map (fun (k,v) -> (k, FStar.Json.String v)) fields))
let lemma_parse_jws_micro_matches_spec _ = ()
