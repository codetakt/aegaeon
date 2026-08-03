module Logout.Spec

open FStar.String
module List = FStar.List.Tot
open FStar.Option

open IdToken.Spec

(** OpenID Connect Logout (RP-initiated + Back-channel)

This module captures the F* specification surface needed to reason about:
  - RP-initiated logout validation of `id_token_hint` (issuer/exp/nbf/aud/azp)
  - Exact-match whitelisting of post-logout redirect URIs
  - Back-channel logout token claim shape
  - Idempotent retry semantics via stable per-session `jti`

It is intentionally standards-first and fail-closed: malformed or ambiguous
inputs yield `Error`.
*)

let non_empty (s:string) : Tot bool =
  String.length s > 0

let nbf_allows_use (token:id_token_claims) (now:timestamp) : Tot bool =
  match token.nbf with
  | None -> true
  | Some nbf -> now >= nbf

val client_id_from_id_token_hint : claims:id_token_claims -> Tot (result string)
let client_id_from_id_token_hint claims =
  match claims.aud with
  | Single client_id ->
      if non_empty client_id
      then Ok client_id
      else Error "invalid aud claim in id_token_hint"
  | Multiple _ ->
      match claims.azp with
      | Some azp ->
          if non_empty azp
          then Ok azp
          else Error "azp is required when aud contains multiple audiences"
      | None ->
          Error "azp is required when aud contains multiple audiences"

type rp_logout_id_token_prop
  (token:id_token_claims)
  (client_id:string)
  (issuer:string)
  (now:timestamp)
  = {
    wf: well_formed_id_token_prop token client_id;
    issuer_match: fact (token.iss = issuer);
    not_expired: fact (now < token.exp);
    nbf_ok: fact (nbf_allows_use token now);
  }

val rp_logout_validate_id_token_hint:
  token:id_token_claims ->
  issuer:string ->
  now:timestamp ->
  Tot (result (client_id:string & rp_logout_id_token_prop token client_id issuer now))
let rp_logout_validate_id_token_hint token issuer now =
  match client_id_from_id_token_hint token with
  | Error msg -> Error msg
  | Ok client_id ->
      match build_well_formed_id_token_prop token client_id with
      | None ->
          Error "malformed id_token_hint"
      | Some wf ->
          if not (token.iss = issuer) then
            Error "id_token_hint issuer mismatch"
          else if not (now < token.exp) then
            Error "id_token_hint is expired"
          else if not (nbf_allows_use token now) then
            Error "id_token_hint is not yet valid"
          else
            let packed : rp_logout_id_token_prop token client_id issuer now = {
              wf = wf;
              issuer_match = ();
              not_expired = ();
              nbf_ok = ();
            } in
            let out :
              (client_id':string & rp_logout_id_token_prop token client_id' issuer now)
              = Mkdtuple2 client_id packed
            in
            Ok out

(* Exact-match allow-list for post-logout redirect URIs. *)
let exact_redirect_whitelist (allowed:list string) (uri:string) : Tot bool =
  List.mem uri allowed

(* Back-channel logout token (claim-level model; signature/JWS encoding is out of scope). *)
let backchannel_logout_event_uri : string =
  "http://schemas.openid.net/event/backchannel-logout"

noeq type backchannel_logout_token_claims = {
  iss: string;
  aud: string;
  iat: timestamp;
  jti: string;
  sid: string;
  sub: option string;
  events: list string;
}

let backchannel_logout_required_claims
  (token:backchannel_logout_token_claims)
  : Tot bool
  =
    is_https_url token.iss
    && non_empty token.aud
    && non_empty token.jti
    && non_empty token.sid
    && List.mem backchannel_logout_event_uri token.events
    && (match token.sub with
        | None -> true
        | Some sub -> non_empty sub)

type backchannel_logout_token_prop (token:backchannel_logout_token_claims) = {
  required: fact (backchannel_logout_required_claims token);
}

val build_backchannel_logout_token_claims:
  issuer:string ->
  client_id:string ->
  sid:string ->
  user_id:string ->
  include_sub:bool ->
  jti:string ->
  now:timestamp ->
  Tot (result (token:backchannel_logout_token_claims & backchannel_logout_token_prop token))
let build_backchannel_logout_token_claims issuer client_id sid user_id include_sub jti now =
  if not (is_https_url issuer) then
    Error "issuer must be https"
  else if not (non_empty client_id) then
    Error "client_id must not be blank"
  else if not (non_empty sid) then
    Error "sid must not be blank"
  else if not (non_empty jti) then
    Error "jti must not be blank"
  else
    let sub = if include_sub then Some user_id else None in
    if include_sub && not (non_empty user_id) then
      Error "sub must not be blank"
    else
      let claims:backchannel_logout_token_claims = {
        iss = issuer;
        aud = client_id;
        iat = now;
        jti = jti;
        sid = sid;
        sub = sub;
        events = [backchannel_logout_event_uri];
      } in
      let prop:backchannel_logout_token_prop claims = {
        required = ();
      } in
      let out :
        (token':backchannel_logout_token_claims & backchannel_logout_token_prop token')
        = Mkdtuple2 claims prop
      in
      Ok out

(* Stable per-session `jti` is the core idempotency property needed for safe retries. *)
type logout_jti_state = option string

val get_or_set_logout_jti:
  state:logout_jti_state ->
  fresh:string ->
  Pure (logout_jti_state * string)
  (requires True)
  (ensures fun (st', jti) ->
     st' = Some jti /\
     (match state with
      | Some old -> jti = old
      | None -> jti = fresh))
let get_or_set_logout_jti state fresh =
  match state with
  | Some jti -> (Some jti, jti)
  | None -> (Some fresh, fresh)

val lemma_logout_jti_idempotent:
  state:logout_jti_state ->
  jti1:string ->
  jti2:string ->
  Lemma
    (ensures (
      let st1, out1 = get_or_set_logout_jti state jti1 in
      let _, out2 = get_or_set_logout_jti st1 jti2 in
      out1 = out2))
let lemma_logout_jti_idempotent state jti1 jti2 =
  let st1, out1 = get_or_set_logout_jti state jti1 in
  let _, out2 = get_or_set_logout_jti st1 jti2 in
  match state with
  | Some _ -> ()
  | None -> ()
