module Jose.Jwt_claims

open FStar.Json
open FStar.Bytes
open FStar.Base64
open FStar.String
open FStar.List.Tot

(** Representation of common JWT claims as per RFC 7519. All fields are
    optional and represented as `option` values. The audience claim is
    represented as a list of strings and is empty when not present. *)
type jwt_claims = {
  iss: option string;
  sub: option string;
  aud: list string;
  exp: option int;
  nbf: option int;
  iat: option int;
  jti: option string
}

(** Lookup a field in a JSON object. *)
val field_lookup: k:string -> fields:list (string * json) -> Tot (option json)
let rec field_lookup k fields =
  match fields with
  | [] -> None
  | (x, v)::tl -> if x = k then Some v else field_lookup k tl

(** Helper to parse an optional string field. *)
let parse_opt_string fields name =
  match field_lookup name fields with
  | Some (String s) -> Some s
  | _ -> None

(** Helper to parse an optional numeric field. *)
let parse_opt_int fields name =
  match field_lookup name fields with
  | Some (Number n) -> Some n
  | _ -> None

(** Helper to parse the audience claim which may be a single string or
    an array of strings. *)
let rec collect_aud arr =
  match arr with
  | [] -> []
  | hd::tl ->
      let rest = collect_aud tl in
      (match hd with | String s -> s::rest | _ -> rest)

let parse_aud fields =
  match field_lookup "aud" fields with
  | Some (String s) -> [s]
  | Some (Array arr) -> collect_aud arr
  | _ -> []

(** Parse JWT claims from a JSON value. *)
val parse_json : json -> option jwt_claims
let parse_json j =
  match j with
  | Object fields ->
      let claims = {
        iss = parse_opt_string fields "iss";
        sub = parse_opt_string fields "sub";
        aud = parse_aud fields;
        exp = parse_opt_int fields "exp";
        nbf = parse_opt_int fields "nbf";
        iat = parse_opt_int fields "iat";
        jti = parse_opt_string fields "jti"
      } in
      Some claims
  | _ -> None

(** Decode base64url bytes and parse the claims. *)
val parse_bytes : bytes -> Tot (option jwt_claims)
let parse_bytes b =
  match FStar.Bytes.iutf8_opt b with
  | None -> None
  | Some s ->
      (match FStar.Json.parse s with
       | Some j -> parse_json j
       | None -> None)

(** Parse a base64url encoded claim string. *)
val parse_b64 : string -> Tot (option jwt_claims)
let parse_b64 s =
  match Base64.url_decode s with
  | Some bytes -> parse_bytes bytes
  | None -> None
