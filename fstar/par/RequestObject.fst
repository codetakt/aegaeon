module RequestObject

(** Request Object (JAR) parameter precedence model.

    This module models the security-critical precedence rule used by the server:
    when a Request Object is present, its parameters win over the outer request
    parameters for all fields that are required to be bound.
*)

type authz_params = {
  client_id: string;
  redirect_uri: string;
  response_type: string;
  scope: string;
  state: option string;
  nonce: option string;
  code_challenge: string;
  code_challenge_method: string;
  jti: string;
}

type request_object_claims = {
  aud: string;
  exp: nat;
  nbf: nat;
  client_id: string;
  redirect_uri: string;
  response_type: string;
  scope: string;
  state: option string;
  nonce: option string;
  code_challenge: string;
  code_challenge_method: string;
  response_mode: option string;
  jti: string;
}

let merge_params (outer:authz_params) (ro:request_object_claims) : Tot authz_params =
  {
    client_id = ro.client_id;
    redirect_uri = ro.redirect_uri;
    response_type = ro.response_type;
    scope = ro.scope;
    state = (match ro.state with | Some s -> Some s | None -> outer.state);
    nonce = (match ro.nonce with | Some n -> Some n | None -> outer.nonce);
    code_challenge = ro.code_challenge;
    code_challenge_method = ro.code_challenge_method;
    jti = ro.jti;
  }

let lemma_merge_request_object_wins (outer:authz_params) (ro:request_object_claims) : Lemma
  (ensures
    (merge_params outer ro).client_id == ro.client_id /\
    (merge_params outer ro).redirect_uri == ro.redirect_uri /\
    (merge_params outer ro).response_type == ro.response_type /\
    (merge_params outer ro).scope == ro.scope /\
    (merge_params outer ro).code_challenge == ro.code_challenge /\
    (merge_params outer ro).code_challenge_method == ro.code_challenge_method /\
    (merge_params outer ro).jti == ro.jti)
= ()

let lemma_merge_optional_state (outer:authz_params) (ro:request_object_claims) : Lemma
  (ensures (match ro.state with
            | Some s -> (merge_params outer ro).state == Some s
            | None -> (merge_params outer ro).state == outer.state))
= ()

let lemma_merge_optional_nonce (outer:authz_params) (ro:request_object_claims) : Lemma
  (ensures (match ro.nonce with
            | Some n -> (merge_params outer ro).nonce == Some n
            | None -> (merge_params outer ro).nonce == outer.nonce))
= ()
