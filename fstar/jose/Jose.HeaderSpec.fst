module Jose.HeaderSpec

open Jose.Alg_policy
module Policy = Jose.Policy
module JWE = Jose.Jwe_header
module JWS = Jose.Jws_header
open FStar.String
open FStar.List.Tot
open FStar.Json

type sanitized_jwe = {
  alg: string;
  enc: string
}

type sanitized_jws = {
  alg: alg;
  kid: option string
}

val sanitize_jwe : h:JWE.jwe_header -> Tot (option sanitized_jwe)
let sanitize_jwe h =
  if is_supported_alg h.alg && JWE.enc_allowed h.enc then
    let r:sanitized_jwe = { alg = h.alg; enc = h.enc } in
    Some r
  else
    None

val sanitize_jws : h:JWS.jws_header -> Tot (option sanitized_jws)
let sanitize_jws h =
  if allowed h.alg then
    match h.kid with
    | Some k ->
        if JWS.valid_kid_string k then
          let r:sanitized_jws = { alg = h.alg; kid = Some k } in
          Some r
        else None
    | None ->
        let r:sanitized_jws = { alg = h.alg; kid = None } in
        Some r
  else
    None

val parse_jwe_sanitized : fields:list (string * json) -> Tot (option sanitized_jwe)
let parse_jwe_sanitized fields =
  match JWE.parse_json_spec (Object fields) with
  | Some h ->
      let _ = JWE.lemma_parse_guards fields h in
      sanitize_jwe h
  | None -> None

val parse_jws_sanitized : fields:list (string * json) -> Tot (option sanitized_jws)
let parse_jws_sanitized fields =
  match JWS.parse_json_spec (Object fields) with
  | Some h ->
      let _ = JWS.lemma_parse_valid fields h in
      sanitize_jws h
  | None -> None
