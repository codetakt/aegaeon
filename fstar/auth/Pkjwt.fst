module Pkjwt

open FStar.All
open FStar.List.Tot
open FStar.String

module List = FStar.List.Tot
module Str = FStar.String

type alg = string
type audience = string

let nonempty (s:string) : Tot bool = Str.length s > 0

// -----------------------------------------------------------------------------
// RFC 7523 claim/header invariants (modeled as pure predicates)
// -----------------------------------------------------------------------------

let pkjwt_requires_iss (iss:option string) : Tot bool =
  match iss with
  | Some _ -> true
  | None -> false

let pkjwt_requires_sub (sub:option string) : Tot bool =
  match sub with
  | Some _ -> true
  | None -> false

let pkjwt_subject_is_client_id (sub:option string) (client_id:string) : Tot bool =
  sub = Some client_id

let pkjwt_issuer_is_client_id (iss:option string) (client_id:string) : Tot bool =
  iss = Some client_id

let pkjwt_audience_matches_expected (aud:list audience) (expected:audience) : Tot bool =
  List.mem expected aud

let pkjwt_requires_exp (exp:option int) : Tot bool =
  match exp with
  | Some _ -> true
  | None -> false

let pkjwt_time_window_enforced
  (now:int)
  (leeway:int)
  (exp:option int)
  (nbf:option int)
  (iat:option int)
  : Tot bool =
  // exp is required for client assertions; accept within leeway.
  (match exp with
   | None -> false
   | Some e -> now <= e + leeway) &&
  // nbf/iat are optional but enforced when present.
  (match nbf with
   | None -> true
   | Some n -> now + leeway >= n) &&
  (match iat with
   | None -> true
   | Some i -> now + leeway >= i)

let pkjwt_kid_policy_ok (require_kid:bool) (kid:option string) : Tot bool =
  if require_kid
  then match kid with
       | Some k -> nonempty k
       | None -> false
  else true

let pkjwt_alg_allowed (allowed:list alg) (alg:alg) : Tot bool =
  List.mem alg allowed

let pkjwt_signature_verified_and_alg_allowed
  (signature_ok:bool)
  (allowed:list alg)
  (alg:alg)
  : Tot bool =
  signature_ok && pkjwt_alg_allowed allowed alg

// pkjwt-specific JTI replay store (separate from DPoP)
type pkjwt_store = { consumed: list string }
inline_for_extraction let empty_store : unit -> pkjwt_store =
  fun _ -> { consumed = [] }

let rec contains (x:string) (l:list string) : Tot bool =
  match l with
  | [] -> false
  | y::ys -> if x = y then true else contains x ys

let jti_fresh s j = not (contains j s.consumed)

val consume_jti: s:pkjwt_store -> j:string -> Pure pkjwt_store
  (requires (jti_fresh s j))
  (ensures  (fun s' -> not (jti_fresh s' j)))
let consume_jti s j = { consumed = j :: s.consumed }

let pkjwt_jti_single_use_within_window (store:pkjwt_store) (jti:option string) : Tot bool =
  match jti with
  | None -> true
  | Some j -> jti_fresh store j

// Specification-level validator over extracted JWT claims and header fields.
// This is a *pure* model of the runtime's private_key_jwt checks.
val validate_pkjwt:
  store:pkjwt_store ->
  require_kid:bool ->
  allowed_algs:list alg ->
  expected_aud:audience ->
  client_id:string ->
  kid:option string ->
  alg:alg ->
  iss:option string ->
  sub:option string ->
  aud:list audience ->
  exp:option int ->
  nbf:option int ->
  iat:option int ->
  jti:option string ->
  now:int ->
  leeway:int ->
  signature_ok:bool ->
  Tot (pkjwt_store * bool)
let validate_pkjwt store require_kid allowed_algs expected_aud client_id kid alg iss sub aud exp nbf iat jti now leeway signature_ok =
  let base_ok =
    pkjwt_signature_verified_and_alg_allowed signature_ok allowed_algs alg &&
    pkjwt_kid_policy_ok require_kid kid &&
    pkjwt_issuer_is_client_id iss client_id &&
    pkjwt_subject_is_client_id sub client_id &&
    pkjwt_audience_matches_expected aud expected_aud &&
    pkjwt_time_window_enforced now leeway exp nbf iat
  in
  match jti with
  | None -> (store, base_ok)
  | Some j ->
      if base_ok && jti_fresh store j
      then (consume_jti store j, true)
      else (store, false)

// Proven effect: consuming a JTI makes it non-fresh
let lemma_consume_jti_not_fresh (s:pkjwt_store) (j:string) : Lemma
  (requires (jti_fresh s j))
  (ensures  (not (jti_fresh (consume_jti s j) j))) = ()

// -----------------------------------------------------------------------------
// RFC 7523 JWT Bearer authorization grant (urn:ietf:params:oauth:grant-type:jwt-bearer)
// -----------------------------------------------------------------------------

let jwt_bearer_subject_nonempty (sub:option string) : Tot bool =
  match sub with
  | None -> false
  | Some s -> nonempty s

let jwt_bearer_subject_and_audience_profile
  (allow_client_subject:bool)
  (sub:option string)
  (client_id:string)
  (aud:list audience)
  (token_endpoint_aud:audience)
  (issuer_aud:audience)
  : Tot bool =
  match sub with
  | None -> false
  | Some s ->
      if s = client_id
      then nonempty s &&
           allow_client_subject &&
           pkjwt_audience_matches_expected aud issuer_aud &&
           not (pkjwt_audience_matches_expected aud token_endpoint_aud)
      else nonempty s &&
           pkjwt_audience_matches_expected aud token_endpoint_aud

let jwt_bearer_issuer_is_client_id (iss:option string) (client_id:string) : Tot bool =
  iss = Some client_id

let jwt_bearer_audience_matches_expected (aud:list audience) (expected:audience) : Tot bool =
  pkjwt_audience_matches_expected aud expected

let jwt_bearer_time_window_enforced
  (now:int)
  (leeway:int)
  (exp:option int)
  (nbf:option int)
  (iat:option int)
  : Tot bool =
  pkjwt_time_window_enforced now leeway exp nbf iat

let jwt_bearer_assertion_valid
  (signature_ok:bool)
  (allowed_algs:list alg)
  (alg:alg)
  (require_kid:bool)
  (kid:option string)
  (iss:option string)
  (client_id:string)
  (sub:option string)
  (aud:list audience)
  (token_endpoint_aud:audience)
  (issuer_aud:audience)
  (allow_client_subject:bool)
  (now:int)
  (leeway:int)
  (exp:option int)
  (nbf:option int)
  (iat:option int)
  : Tot bool =
  pkjwt_signature_verified_and_alg_allowed signature_ok allowed_algs alg &&
  pkjwt_kid_policy_ok require_kid kid &&
  jwt_bearer_issuer_is_client_id iss client_id &&
  jwt_bearer_subject_and_audience_profile allow_client_subject sub client_id aud token_endpoint_aud issuer_aud &&
  jwt_bearer_time_window_enforced now leeway exp nbf iat

let jwt_bearer_jti_key (client_id:string) (jti:string) : Tot string =
  client_id ^ ":" ^ jti

let jwt_bearer_jti_single_use_within_window
  (store:pkjwt_store)
  (client_id:string)
  (jti:option string)
  : Tot bool =
  match jti with
  | None -> true
  | Some j -> jti_fresh store (jwt_bearer_jti_key client_id j)

val validate_jwt_bearer_grant:
  store:pkjwt_store ->
  require_kid:bool ->
  allowed_algs:list alg ->
  token_endpoint_aud:audience ->
  issuer_aud:audience ->
  allow_client_subject:bool ->
  client_id:string ->
  kid:option string ->
  alg:alg ->
  iss:option string ->
  sub:option string ->
  aud:list audience ->
  exp:option int ->
  nbf:option int ->
  iat:option int ->
  jti:option string ->
  now:int ->
  leeway:int ->
  signature_ok:bool ->
  Tot (pkjwt_store * option string)
let validate_jwt_bearer_grant store require_kid allowed_algs token_endpoint_aud issuer_aud allow_client_subject client_id kid alg iss sub aud exp nbf iat jti now leeway signature_ok =
  let base_ok =
    jwt_bearer_assertion_valid
      signature_ok allowed_algs alg require_kid kid iss client_id sub aud token_endpoint_aud issuer_aud allow_client_subject now leeway exp nbf iat
  in
  match sub with
  | None -> (store, None)
  | Some subject ->
      match jti with
      | None ->
          if base_ok
          then (store, Some subject)
          else (store, None)
      | Some j ->
          let key = jwt_bearer_jti_key client_id j in
          if base_ok && jti_fresh store key
          then (consume_jti store key, Some subject)
          else (store, None)
