module Jose.HeaderMicro

open Jose.HeaderSpec
open FStar.Json
open FStar.List.Tot

let string_fields_to_json (fields:list (string * string)) : list (string * json) =
  map (fun (k,v) -> (k, String v)) fields

val parse_jwe_micro : list (string * string) -> Tot (option sanitized_jwe)
let parse_jwe_micro fields =
  parse_jwe_sanitized (string_fields_to_json fields)

val parse_jws_micro : list (string * string) -> Tot (option sanitized_jws)
let parse_jws_micro fields =
  parse_jws_sanitized (string_fields_to_json fields)
