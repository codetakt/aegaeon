module AuthCode.Types

open FStar.String

(* RFC 6749 Authorization Code types *)

type client_id = string
type redirect_uri = string
type user_id = string
type scope = string
type state = string
type nonce = string

(* Authorization Code with security properties *)
noeq type authorization_code = {
  code: string;
  client_id: client_id;
  user_id: user_id;
  redirect_uri: redirect_uri;
  scope: option scope;
  state: option state;
  nonce: option nonce;
  code_challenge: option string;  (* RFC 7636 PKCE *)
  expires_at: nat;
  used: bool;  (* Single-use enforcement *)
}

(* Bearer Token per RFC 6750 *)
noeq type access_token = {
  token: string;
  token_type: string;  (* Always "Bearer" *)
  client_id: client_id;
  user_id: user_id;
  scope: option scope;
  expires_in: nat;
  created_at: nat;
}

noeq type refresh_token = {
  token: string;
  client_id: client_id;
  user_id: user_id;
  scope: option scope;
  expires_at: nat;
  rotated: bool;  (* RFC 9700 rotation tracking *)
}

(* Authorization Request per RFC 6749 *)
noeq type authorization_request = {
  response_type: string;
  client_id: client_id;
  redirect_uri: option redirect_uri;
  scope: option scope;
  state: option state;
  nonce: option nonce;
  code_challenge: option string;
  code_challenge_method: option string;
}

(* Token Request *)
noeq type token_request = {
  grant_type: string;
  code: option string;
  redirect_uri: option redirect_uri;
  client_id: client_id;
  client_secret: option string;
  refresh_token: option string;
  code_verifier: option string;  (* PKCE *)
}

(* Token Response *)
noeq type token_response =
  | TokenSuccess:
      access_token: string ->
      token_type: string ->
      expires_in: nat ->
      refresh_token: option string ->
      scope: option string ->
      token_response
  | TokenError:
      error: string ->
      error_description: option string ->
      token_response

(* Security predicates *)
let is_expired (expires_at: nat) (current_time: nat) : Tot bool =
  current_time >= expires_at

let is_valid_state (req_state: option state) (resp_state: option state) : Tot bool =
  match req_state, resp_state with
  | Some s1, Some s2 -> s1 = s2
  | None, None -> true
  | _ -> false

let is_valid_nonce (req_nonce: option nonce) (token_nonce: option nonce) : Tot bool =
  match req_nonce, token_nonce with
  | Some n1, Some n2 -> n1 = n2
  | None, None -> true
  | _ -> false
