module AuthCode.Flow

open FStar.Bytes
open FStar.String
open FStar.Seq
open FStar.Seq.Properties
open FStar.List.Tot
open AuthCode.Types
open AuthCode.Store
open Pkce.Verification
open Pkce.Verifier
open Pkce.Challenge
open Pkce.Method_selection
open Random
open Drbg.HmacSha256

(* RFC 6749 Authorization Code Flow with RFC 9700 security enhancements *)

(* Recursive helper: lookup code_challenge by code string *)
let rec lookup_code_challenge_helper
  (codes: seq authorization_code) (code_str: string) (i: nat)
  : Tot (option string)
  (decreases (Seq.length codes - i))
  = if i >= Seq.length codes then None
    else let c = Seq.index codes i in
         if c.code = code_str then c.code_challenge
         else lookup_code_challenge_helper codes code_str (i + 1)

val lookup_code_challenge:
  store:auth_store -> code_str:string -> Tot (option string)
let lookup_code_challenge store code_str =
  lookup_code_challenge_helper store.codes code_str 0

(* Generate authorization code — now Tot with explicit entropy *)
val generate_auth_code:
  entropy:bytes{Bytes.length entropy = 32} ->
  Tot (r:string{String.length r >= 32})  (* RFC 6749 recommends high entropy *)
let generate_auth_code entropy = generate_secure_random entropy 32

(* Generate access token — now Tot with explicit entropy *)
val generate_access_token:
  entropy:bytes{Bytes.length entropy = 32} ->
  Tot (r:string{String.length r >= 32})
let generate_access_token entropy = generate_secure_random entropy 32

(* Authorization endpoint - Issue authorization code.
   Inlined store operations to preserve full postconditions
   (store_auth_code ensures is too weak to prove Seq.length growth).
   Now Tot: entropy replaces the ST CSPRNG state access. *)
#push-options "--z3rlimit 50 --fuel 1 --ifuel 1"
val authorize:
  store:auth_store ->
  req:authorization_request{
    (match req.state with | Some s -> is_state_unique store s | None -> true) /\
    (match req.nonce with | Some n -> is_nonce_unique store n | None -> true) /\
    req.code_challenge <> None /\
    Some? req.code_challenge_method} ->
  user:user_id ->
  entropy:bytes{Bytes.length entropy = 32} ->
  Tot (p:(auth_store * (authorization_code * redirect_uri)){
    Seq.length (fst p).codes = Seq.length store.codes + 1 /\
    (fst (snd p)).state = req.state /\
    (fst (snd p)).nonce = req.nonce /\
    not (fst (snd p)).used /\
    (fst (snd p)).expires_at = store.current_time + 300 /\
    (fst (snd p)).code_challenge = req.code_challenge})
let authorize store req user entropy =
  let code_str = generate_auth_code entropy in
  let redirect = (match req.redirect_uri with | Some r -> r | None -> "") in
  let auth_code : authorization_code = {
    code = code_str;
    client_id = req.client_id;
    user_id = user;
    redirect_uri = redirect;
    scope = req.scope;
    state = req.state;
    nonce = req.nonce;
    code_challenge = req.code_challenge;
    expires_at = store.current_time + 300;
    used = false;
  } in
  let new_codes = Seq.snoc store.codes auth_code in
  let new_states = (match req.state with
    | Some s -> Seq.snoc store.states s
    | None -> store.states) in
  let new_nonces = (match req.nonce with
    | Some n -> Seq.snoc store.nonces n
    | None -> store.nonces) in
  let new_store : auth_store = { store with
    codes = new_codes;
    states = new_states;
    nonces = new_nonces
  } in
  lemma_len_append store.codes (Seq.create 1 auth_code);
  (new_store, (auth_code, redirect))
#pop-options

(* Helper function for issuing tokens.
   Inlined store_access_token to preserve postconditions.
   Now Tot: entropy replaces the ST CSPRNG state access. *)
#push-options "--z3rlimit 40 --fuel 1 --ifuel 1"
val issue_tokens_helper:
  store:auth_store ->
  code:authorization_code ->
  entropy:bytes{Bytes.length entropy = 32} ->
  Tot (p:(auth_store * token_response){
    (match snd p with
     | TokenSuccess _ _ _ _ _ -> True
     | TokenError _ _ -> False)})
let issue_tokens_helper store code entropy =
  let at_str = generate_access_token entropy in
  let at : access_token = {
    token = at_str;
    token_type = "Bearer";
    client_id = code.client_id;
    user_id = code.user_id;
    scope = code.scope;
    expires_in = 3600;
    created_at = store.current_time;
  } in
  let new_store = { store with
    access_tokens = Seq.snoc store.access_tokens at
  } in
  (new_store, TokenSuccess at_str "Bearer" 3600 None code.scope)
#pop-options

(* Token endpoint - Exchange code for tokens.
   Inlined use_auth_code logic (find_code_index + Seq.upd) to preserve
   postconditions across the full operation.
   Now Tot: entropy replaces the ST CSPRNG state access. *)
#push-options "--z3rlimit 80 --fuel 2 --ifuel 2"
val token_exchange:
  store:auth_store ->
  req:token_request{
    req.grant_type = "authorization_code" /\
    req.code <> None} ->
  entropy:bytes{Bytes.length entropy = 32} ->
  Tot (p:(auth_store * token_response){
    (match snd p with
     | TokenSuccess _ _ _ _ _ -> True
     | TokenError error _ ->
         error = "invalid_grant" \/ error = "invalid_request")})
let token_exchange store req entropy =
  let code_str = (match req.code with | Some c -> c | None -> "") in
  match find_code_index store.codes code_str 0 with
  | None ->
    (store, TokenError "invalid_grant" (Some "Code not found or already used"))
  | Some idx ->
    let found_code = Seq.index store.codes idx in
    let marked = { found_code with used = true } in
    let new_codes = Seq.upd store.codes idx marked in
    let store_after_use = { store with codes = new_codes } in
    (match found_code.code_challenge, req.code_verifier with
    | Some challenge, Some verifier ->
      if (String.length verifier >= 43) && (String.length verifier <= 128)
         && (String.length challenge = 43) then
        let v : code_verifier = verifier in
        let c : code_challenge = challenge in
        if verify_pkce v c S256 then
          issue_tokens_helper store_after_use found_code entropy
        else
          (store_after_use, TokenError "invalid_request" (Some "PKCE verification failed"))
      else
        (store_after_use, TokenError "invalid_request" (Some "Invalid PKCE parameter lengths"))
    | Some _, None ->
      (store_after_use, TokenError "invalid_request" (Some "Code verifier required"))
    | None, _ ->
      issue_tokens_helper store_after_use found_code entropy)
#pop-options

(** A stored PKCE challenge requires a verifier at token exchange. *)
#push-options "--z3rlimit 80 --fuel 2 --ifuel 2"
val lemma_verifier_required_when_challenge_present:
  store:auth_store ->
  req:token_request{
    req.grant_type = "authorization_code" /\
    req.code <> None} ->
  entropy:bytes{Bytes.length entropy = 32} ->
  Lemma
    (requires
      req.code_verifier = None /\
      (let code_str = (match req.code with | Some c -> c | None -> "") in
       match find_code_index store.codes code_str 0 with
       | Some idx -> Some? (Seq.index store.codes idx).code_challenge
       | None -> false))
    (ensures
      (match snd (token_exchange store req entropy) with
       | TokenError error _ -> error = "invalid_request"
       | TokenSuccess _ _ _ _ _ -> false))
let lemma_verifier_required_when_challenge_present store req entropy = ()
#pop-options
