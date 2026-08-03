module Introspection

open FStar.UInt32
open Jose.UInt32Bounds

(* RFC 7662: OAuth 2.0 Token Introspection *)

(* Token introspection response claims *)
noeq type introspection_response = {
  active: bool;
  scope: list UInt32.t;  (* List of scope IDs *)
  client_id: UInt32.t;
  username: UInt32.t;    (* User identifier *)
  token_type: UInt32.t;  (* 0=Bearer, 1=DPoP *)
  exp: UInt32.t;         (* Expiration time *)
  iat: UInt32.t;         (* Issued at time *)
  nbf: UInt32.t;         (* Not before time *)
  sub: UInt32.t;         (* Subject identifier *)
  aud: list UInt32.t;    (* Audience list *)
  iss: UInt32.t;         (* Issuer identifier *)
  jti: UInt32.t;         (* JWT ID for DPoP tokens *)
}

(* Token database entry *)
noeq type token_entry = {
  token_id: UInt32.t;
  active: bool;
  expires_at: UInt32.t;
  issued_at: UInt32.t;
  client_id: UInt32.t;
  subject: UInt32.t;
  scopes: list UInt32.t;
  token_type: UInt32.t;
  audience: list UInt32.t;
  issuer: UInt32.t;
}

(* Default inactive response *)
val inactive_response : unit -> introspection_response
let inactive_response () = {
  active = false;
  scope = [];
  client_id = 0ul;
  username = 0ul;
  token_type = 0ul;
  exp = 0ul;
  iat = 0ul;
  nbf = 0ul;
  sub = 0ul;
  aud = [];
  iss = 0ul;
  jti = 0ul;
}

(* Check if token is expired *)
val is_expired : token:token_entry -> now:UInt32.t -> bool
let is_expired token now =
  UInt32.gte now token.expires_at

(* Build introspection response from token entry *)
val build_response : token:token_entry -> now:UInt32.t -> Pure introspection_response
  (requires True)
  (ensures fun r ->
    let expired = is_expired token now in
    if expired || not token.active then
      r == inactive_response ()
    else
      r.active == true /\
      r.scope == token.scopes /\
      r.client_id == token.client_id /\
      r.username == token.subject /\
      r.token_type == token.token_type /\
      r.exp == token.expires_at /\
      r.iat == token.issued_at /\
      r.nbf == token.issued_at /\
      r.sub == token.subject /\
      r.aud == token.audience /\
      r.iss == token.issuer /\
      r.jti == token.token_id)
let build_response token now =
  let expired = is_expired token now in
  if expired || not token.active then
    inactive_response ()
  else {
    active = true;
    scope = token.scopes;
    client_id = token.client_id;
    username = token.subject;  (* Simplified: using subject as username *)
    token_type = token.token_type;
    exp = token.expires_at;
    iat = token.issued_at;
    nbf = token.issued_at;  (* Simplified: nbf = iat *)
    sub = token.subject;
    aud = token.audience;
    iss = token.issuer;
    jti = token.token_id;  (* Using token_id as jti *)
  }

(* Introspect a token *)
val introspect : token_id:UInt32.t -> token:token_entry -> now:UInt32.t
  -> Pure introspection_response
  (requires True)
  (ensures fun r ->
    if UInt32.eq token_id token.token_id then
      r == build_response token now
    else
      r == inactive_response ())
let introspect token_id token now =
  if UInt32.eq token_id token.token_id then
    build_response token now
  else
    inactive_response ()

(* Validate introspection response schema *)
val validate_schema : resp:introspection_response -> bool
let validate_schema resp =
  if not resp.active then
    UInt32.eq resp.exp 0ul
  else
    UInt32.gt resp.exp 0ul &&
    UInt32.gt resp.iat 0ul &&
    UInt32.gt resp.client_id 0ul

val lemma_validate_schema_inactive :
  resp:introspection_response ->
  Lemma (requires validate_schema resp = true /\ resp.active = false)
        (ensures UInt32.eq resp.exp 0ul = true)
let lemma_validate_schema_inactive resp =
  if resp.active then ()
  else
    let _ = assert (validate_schema resp = true) in
    assert_norm (validate_schema resp);
    ()

val lemma_validate_schema_active :
  resp:introspection_response ->
  Lemma (requires validate_schema resp = true /\ resp.active = true)
        (ensures (UInt32.gt resp.exp 0ul &&
                  UInt32.gt resp.iat 0ul &&
                  UInt32.gt resp.client_id 0ul) = true)
let lemma_validate_schema_active resp =
  if resp.active then
    let _ = assert (validate_schema resp = true) in
    assert_norm (validate_schema resp);
    ()
  else ()

(* Client authentication check for introspection *)
val can_introspect : client_id:UInt32.t -> token:token_entry -> bool
let can_introspect client_id token =
  UInt32.eq client_id token.client_id

let eq_can_introspect client_id token : Lemma (can_introspect client_id token = UInt32.eq client_id token.client_id) = ()

val lemma_can_introspect_owner :
  token:token_entry ->
  Lemma (ensures can_introspect token.client_id token = true)
let lemma_can_introspect_owner token =
  assert_norm (can_introspect token.client_id token);
  ()

val lemma_can_introspect_not_owner :
  client_id:UInt32.t -> token:token_entry ->
  Lemma (requires can_introspect client_id token = false)
        (ensures UInt32.eq client_id token.client_id = false)
let lemma_can_introspect_not_owner client_id token =
  Jose.UInt32Bounds.lemma_eq_false_implies_neq client_id token.client_id;
  ()

(* Caching hint calculation *)
val cache_duration : resp:introspection_response -> now:UInt32.t -> Pure UInt32.t
  (requires resp.active ==> UInt32.v resp.exp > UInt32.v now)
  (ensures fun r ->
    (* Cache duration is time until expiration or 0 *)
    (if resp.active && UInt32.v resp.exp > UInt32.v now then
      UInt32.v r = UInt32.v resp.exp - UInt32.v now
    else
      UInt32.v r = 0))
let cache_duration resp now =
  if resp.active && UInt32.gt resp.exp now then
    UInt32.sub resp.exp now
  else
    0ul

val no_implicit_ion : resp:introspection_response -> now:UInt32.t -> Tot bool
let no_implicit_ion resp now =
  if resp.active then
    UInt32.gt resp.exp now
  else
    UInt32.eq (cache_duration resp now) 0ul

val lemma_cache_duration_active :
  resp:introspection_response -> now:UInt32.t ->
  Lemma
    (requires resp.active = true /\
              validate_schema resp = true /\
              UInt32.gt resp.exp now = true)
    (ensures UInt32.add (cache_duration resp now) now == resp.exp /\
             UInt32.gt (cache_duration resp now) 0ul = true)
let lemma_cache_duration_active resp now =
  if resp.active && UInt32.gt resp.exp now then begin
    let diff = cache_duration resp now in
    let _ = assert (diff == UInt32.sub resp.exp now) in
    let _ = lemma_sub_add_cancel_eq resp.exp now in
    let _ = lemma_sub_positive_if_gt resp.exp now in
    ()
  end else ()

val lemma_cache_duration_activ :
  resp:introspection_response -> now:UInt32.t ->
  Lemma
    (requires resp.active = true /\
              validate_schema resp = true /\
              UInt32.gt resp.exp now = true)
    (ensures UInt32.add (cache_duration resp now) now == resp.exp /\
             UInt32.gt (cache_duration resp now) 0ul = true)
let lemma_cache_duration_activ resp now =
  lemma_cache_duration_active resp now

val lemma_cache_duration_inactive :
  resp:introspection_response -> now:UInt32.t ->
  Lemma
    (requires resp.active = false)
    (ensures cache_duration resp now = 0ul)
let lemma_cache_duration_inactive resp now =
  if resp.active then ()
  else
    assert (cache_duration resp now == 0ul);
    ()
