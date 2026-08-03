module Jose.LowStar

open Jose.Jwe_header
open Jose.Jws_header
open Jose.Alg_policy
open Jose.Policy
open Jose.Jwe_aad
open Jose.JsonHeaderSpec
open Jose.HeaderParser
open Jose.Utf8Lemmas
open Jose.Context
open Jose.Arith.Bounds
open FStar.UInt32
open FStar.String
open FStar.UInt8
open LowStar.Buffer

module HS = Jose.HeaderSpec

type jwe_header_result =
  | JweHeaderMissing
  | JweHeaderFound: string -> string -> jwe_header_result

type jws_kid =
  | KidMissing
  | KidPresent: string -> jws_kid

type jws_header_result =
  | JwsHeaderMissing
  | JwsHeaderFound: alg -> jws_kid -> jws_header_result

type aad_parameter =
  | AadMissing
  | AadPresent: string -> aad_parameter

/// Context-based JWE header parser (new API).
/// Accepts a jose_context to enable per-request header length limits.
noextract
let jwe_parse_header_with_context
  (ctx:jose_context)
  (input:string)
  (len:UInt32.t{FStar.String.length input = UInt32.v len})
  (within_limit:bool{
    within_limit <==>
    UInt32.v len <= UInt32.v (context_header_max_length_u32 ctx)
  })
  : Tot jwe_header_result
  =
  if within_limit then
    match Jose.Jwe_header.parse_b64 input with
    | None -> JweHeaderMissing
    | Some header -> JweHeaderFound header.alg header.enc
  else
    JweHeaderMissing

/// Legacy JWE header parser (backward compatibility wrapper).
/// Uses the global default context (4096 character limit).
noextract
let jwe_parse_header
  (input:string)
  (len:UInt32.t{FStar.String.length input = UInt32.v len})
  (within_limit:bool{within_limit <==> UInt32.v len <= header_max_length})
  : Tot jwe_header_result
  =
  jwe_parse_header_with_context default_context input len within_limit

noextract
let jwe_compute_aad (protected_b64:string) (aad_opt:aad_parameter) =
  match aad_opt with
  | AadMissing -> compute protected_b64 None
  | AadPresent aad -> compute protected_b64 (Some aad)

/// Context-based JWS header parser (new API).
/// Accepts a jose_context to enable per-request header length limits.
noextract
let jws_parse_header_with_context
  (ctx:jose_context)
  (input:string)
  (len:UInt32.t{FStar.String.length input = UInt32.v len})
  (within_limit:bool{
    within_limit <==>
    UInt32.v len <= UInt32.v (context_header_max_length_u32 ctx)
  })
  : Tot jws_header_result
  =
  if within_limit then
    match Jose.Jws_header.parse_b64 input with
    | None -> JwsHeaderMissing
    | Some header ->
        let kid_repr =
          match header.kid with
          | None -> KidMissing
          | Some value -> KidPresent value
        in
        JwsHeaderFound header.alg kid_repr
  else
    JwsHeaderMissing

/// Legacy JWS header parser (backward compatibility wrapper).
/// Uses the global default context (4096 character limit).
noextract
let jws_parse_header
  (input:string)
  (len:UInt32.t{FStar.String.length input = UInt32.v len})
  (within_limit:bool{within_limit <==> UInt32.v len <= header_max_length})
  : Tot jws_header_result
  =
  jws_parse_header_with_context default_context input len within_limit

type decode_error = Jose.Utf8Lemmas.decode_error

type json_result 'a = decode_result 'a

let of_option
  (#a:Type0)
  (opt:option a)
  (err:decode_error)
  : json_result a
  =
    match opt with
    | None -> Error err
    | Some v -> Ok v

noextract
let parse_json_entries
  (members:list json_member)
  : json_result (list (string * string))
  = parse_json_entries_result members

noextract
let parse_jwe_json
  (members:list json_member)
  : json_result HS.sanitized_jwe
  =
    match parse_jwe_json_members members with
    | Ok opt -> of_option opt (PolicyViolation "invalid jwe header type")
    | Error err -> Error err

noextract
let parse_jws_json
  (members:list json_member)
  : json_result HS.sanitized_jws
  =
    match parse_jws_json_members members with
    | Ok opt -> of_option opt (PolicyViolation "invalid jws header type")
    | Error err -> Error err
