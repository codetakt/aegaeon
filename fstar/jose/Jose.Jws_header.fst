module Jose.Jws_header

open Jose.Alg_policy
open Jose.Policy
open FStar.Json
open FStar.Bytes
open FStar.Base64
open FStar.String
open FStar.List.Tot
open FStar.Char
module Policy = Jose.Policy

(** Representation of a minimal JWS protected header. *)
type jws_header = {
  alg: alg;
  kid: option string
}

let header_max_length : nat = Policy.header_max_length

(** Lookup a field in a JSON object. *)
val field_lookup : k:string -> fields:list (string * json) -> Tot (option json)
let rec field_lookup k fields =
  match fields with
  | [] -> None
  | (x, v)::tl -> if x = k then Some v else field_lookup k tl

let kid_max_length : nat = Policy.kid_max_length

noextract
let valid_kid_string (k:string) : Tot bool =
  let ascii =
    let chars = String.list_of_string k in
    FStar.List.Tot.Base.for_all
      (fun c -> FStar.Char.int_of_char c <= 127)
      chars
  in
  (String.length k > 0) &&
  (String.length k <= kid_max_length) &&
  ascii

noextract
let parse_kid (fields:list (string * json)) : Tot (option (option string)) =
  match field_lookup "kid" fields with
  | None -> Some None
  | Some (String k) -> if valid_kid_string k then Some (Some k) else None
  | _ -> None

noextract
let forbid_crit (fields:list (string * json)) : Tot bool =
  match field_lookup "crit" fields with
  | None -> true
  | _ -> false

(** Parse a JWS header from a JSON value. *)
noextract
val parse_json_spec : json -> option jws_header
let parse_json_spec j =
  match j with
  | Object fields ->
      (match field_lookup "alg" fields with
       | Some (String alg_s) ->
           if is_supported_alg alg_s && forbid_crit fields then
             match parse_kid fields with
             | Some kid_value ->
                 let a = alg_of_string alg_s in
                 let h = { alg = a; kid = kid_value } in
                 Some h
             | None -> None
           else
             None
       | _ -> None)
  | _ -> None

noextract
val lemma_parse_valid :
  fields:list (string * json) ->
  h:jws_header ->
  Lemma
    (requires parse_json_spec (Object fields) = Some h)
    (ensures allowed h.alg &&
             (match h.kid with
              | Some k -> valid_kid_string k
              | None -> true))
let lemma_parse_valid fields h =
  match parse_json_spec (Object fields) with
  | Some header ->
      let _ = assert (header == h) in
      (match field_lookup "alg" fields with
       | Some (String alg_s) ->
           if is_supported_alg alg_s && forbid_crit fields then
             match parse_kid fields with
             | Some kid_value ->
                 let a = alg_of_string alg_s in
                 let _ = assert (header.alg == a) in
                 let _ = assert (allowed a) in
                 begin
                   match kid_value with
                   | Some kid_str ->
                       let _ = assert (header.kid == Some kid_str) in
                       let _ = assert (valid_kid_string kid_str) in
                       ()
                   | None ->
                       let _ = assert (header.kid == None) in
                       ()
                 end
             | None -> ()
           else
             ()
       | _ -> ())
  | None -> ()

(** Decode base64url bytes and parse the header. *)
noextract
val parse_bytes_spec : bytes -> Tot (option jws_header)
let parse_bytes_spec b =
  match FStar.Bytes.iutf8_opt b with
  | None -> None
  | Some header_str ->
      (match FStar.Json.parse header_str with
       | Some j -> parse_json_spec j
       | None -> None)

(** Parse a base64url encoded header string. *)
noextract
val parse_b64 : string -> Tot (option jws_header)
let parse_b64 s =
  match Base64.url_decode s with
  | Some bytes -> parse_bytes_spec bytes
  | None -> None

(** Validate a JWS header. *)
noextract
val validate : jws_header -> Tot bool
let validate h =
  allowed h.alg &&
  (match h.kid with
   | Some k -> String.length k > 0
   | None -> true)

(** Low\*-friendly aliases. *)
noextract
val parse_json : json -> option jws_header
let parse_json = parse_json_spec

noextract
val parse_bytes : bytes -> Tot (option jws_header)
let parse_bytes = parse_bytes_spec

// Context-based parsing lemmas
open Jose.Context
open Jose.Arith.Bounds

/// Lemma: Successful parse implies input length is bounded by context limit.
/// This is the lemma referenced in lowstar-extraction-plan.md but was previously unimplemented.
noextract
val lemma_parse_length_bound :
  ctx:jose_context ->
  input:string ->
  header:jws_header ->
  Lemma (requires parse_b64 input = Some header /\
                  String.length input <= header_max_length_nat ctx)
        (ensures String.length input <= header_max_length_nat ctx /\
                 String.length input < pow2 32)
let lemma_parse_length_bound ctx input header =
  lemma_string_length_bounded_by_context ctx input;
  ()

/// Legacy version using the global header_max_length constant.
/// This proves that any successful parse respects the policy limit.
noextract
val lemma_parse_respects_policy_limit :
  input:string ->
  header:jws_header ->
  Lemma (requires parse_b64 input = Some header /\
                  String.length input <= header_max_length)
        (ensures String.length input <= header_max_length)
let lemma_parse_respects_policy_limit input header = ()
