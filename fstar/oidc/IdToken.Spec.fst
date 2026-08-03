module IdToken.Spec
open HashComputation
open HashComputation.Model

open FStar.String
open FStar.Bytes
open FStar.Error
open FStar.Pervasives
open FStar.List.Tot
open FStar.Option
open Jose.False

type fact (p:bool) = u:unit{p}

(* Result type for error handling *)
type result (a:Type) =
  | Ok: v:a -> result a
  | Error: msg:string -> result a

let https_prefix = "https://"

let is_https_url (s:string) : Tot bool =
  let len = String.length https_prefix in
  String.length s >= len && String.sub s 0 len = https_prefix

let has_scope (scopes:list string) (scope:string) : Tot bool =
  List.mem scope scopes

(* ID Token Claims with type-level constraints per OIDC Core 1.0 *)

(* Time constraints *)
type timestamp = nat
type valid_expiry (iat:timestamp) (exp:timestamp) =
  b:bool{b = true <==> exp > iat}

(* Audience constraints *)
type audience =
  | Single: string -> audience
  | Multiple: list string -> audience

type valid_audience (aud:audience) (client_id:string) =
  b:bool{b = true <==> (match aud with
    | Single s -> s = client_id
    | Multiple lst -> List.mem client_id lst)}

(* Required claims per OIDC Core 1.0 Section 2 *)
type id_token_claims = {
  (* REQUIRED claims *)
  iss: string;          (* Issuer - MUST be https URL *)
  sub: string;          (* Subject - unique identifier *)
  aud: audience;        (* Audience - client_id *)
  exp: timestamp;       (* Expiration time *)
  iat: timestamp;       (* Issued at time *)

  (* REQUIRED when using implicit flow (we don't but model it) *)
  nonce: option string; (* Nonce for replay prevention *)

  (* OPTIONAL but we enforce for security *)
  nbf: option timestamp;      (* Not before *)
  auth_time: option timestamp; (* Authentication time *)
  azp: option string;         (* Authorized party (when multiple audiences) *)

  (* Authentication context *)
  acr: option string;         (* Authentication Context Reference *)
  amr: option (list string);  (* Authentication Methods References *)

  (* Hash claims for hybrid flow *)
  at_hash: option bytes;      (* Access Token hash *)
  c_hash: option bytes;       (* Code hash *)

  (* Session *)
  sid: option string;         (* Session ID *)
}

type userinfo_profile = {
  profile_sub: string;
  profile_name: string;
  profile_preferred_username: string;
  profile_email: string;
  profile_email_verified: bool;
  profile_address: option string;
  profile_phone_number: option string;
  profile_updated_at: option timestamp;
}

type userinfo_claims = {
  sub: string;
  name: option string;
  preferred_username: option string;
  email: option string;
  email_verified: option bool;
  address: option string;
  phone_number: option string;
  updated_at: option timestamp;
}

let option_is_some #a (o:option a) : Tot bool =
  match o with
  | None -> false
  | Some _ -> true

let lemma_bool_true_of_requires (p:bool)
  : Lemma (requires p) (ensures p = true)
  =
    match p with
    | true -> ()
    | false -> ()

let nonce_ok (nonce_required:bool) (nonce:option string) : Tot bool =
  if nonce_required then option_is_some nonce else true

let verify_optional_hash
  (hash_fun:(string -> bytes -> Tot (option bytes)))
  (alg:string)
  (source:option bytes)
  (provided:option bytes)
  : Tot bool =
  match source, provided with
  | None, _ -> true
  | Some _, None -> false
  | Some raw, Some expected -> hash_fun alg raw = Some expected

(* Hash computation per OIDC Core 1.0 Section 3.1.3.6 and 3.3.2.11 *)
val compute_at_hash: alg:string -> access_token:bytes -> Tot (option bytes)
let compute_at_hash alg access_token =
  let res = HashComputation.Model.compute_oidc_hash_bytes_tot alg access_token in
  if res.success then Some res.digest else None

val compute_c_hash: alg:string -> code:bytes -> Tot (option bytes)
let compute_c_hash alg code =
  let res = HashComputation.Model.compute_oidc_hash_bytes_tot alg code in
  if res.success then Some res.digest else None

let at_hash_ok (alg:string) (access_token:option bytes) (hash:option bytes) : Tot bool =
  verify_optional_hash compute_at_hash alg access_token hash

let nbf_not_after_iat (token:id_token_claims) : Tot bool =
  match token.nbf with
  | None -> true
  | Some nbf -> nbf <= token.iat

let auth_time_not_after_iat (token:id_token_claims) : Tot bool =
  match token.auth_time with
  | None -> true
  | Some auth_time -> auth_time <= token.iat

let audience_contains_client (token:id_token_claims) (client_id:string) : Tot bool =
  match token.aud with
  | Single s -> s = client_id
  | Multiple lst -> List.mem client_id lst

let azp_consistent_with_audience
  (token:id_token_claims)
  (client_id:string)
  : Tot bool =
  match token.aud, token.azp with
  | Multiple _, None -> false
  | Multiple _, Some azp -> azp = client_id
  | Single _, Some _ -> false
  | Single _, None -> true

type well_formed_id_token_prop (token:id_token_claims) (client_id:string) = {
  exp_gt_iat: fact (token.exp > token.iat);
  nbf_not_after_iat: fact (nbf_not_after_iat token);
  auth_time_not_after_iat: fact (auth_time_not_after_iat token);
  audience_has_client: fact (audience_contains_client token client_id);
  azp_consistent: fact (azp_consistent_with_audience token client_id);
  issuer_is_https: fact (is_https_url token.iss);
}

let build_well_formed_id_token_prop
  (token:id_token_claims)
  (client_id:string)
  : Tot (option (well_formed_id_token_prop token client_id))
  =
    if not (token.exp > token.iat) then None else
    let exp_fact : fact (token.exp > token.iat) = () in
    if not (nbf_not_after_iat token) then None else
    let nbf_fact : fact (nbf_not_after_iat token) = () in
    if not (auth_time_not_after_iat token) then None else
    let auth_time_fact : fact (auth_time_not_after_iat token) = () in
    if not (audience_contains_client token client_id) then None else
    let aud_fact : fact (audience_contains_client token client_id) = () in
    if not (azp_consistent_with_audience token client_id) then None else
    let azp_fact : fact (azp_consistent_with_audience token client_id) = () in
    if not (is_https_url token.iss) then None else
    let issuer_fact : fact (is_https_url token.iss) = () in
    Some {
      exp_gt_iat = exp_fact;
      nbf_not_after_iat = nbf_fact;
      auth_time_not_after_iat = auth_time_fact;
      audience_has_client = aud_fact;
      azp_consistent = azp_fact;
      issuer_is_https = issuer_fact;
    }

(* Well-formed ID Token constraints *)
(* NOTE: upstream Rust canonicalizes ID Tokens into the JWS Compact form before
 * feeding bytes into EverParse. That layer enforces:
 *   - exactly three non-empty base64url segments
 *   - each segment <= MAX_JWT_SEGMENT_BYTES (see crates/ffi/src/id_token.rs)
 * Those guards are the canonical source of truth; proofs in this module assume
 * the canonicalizer ran successfully. *)
let well_formed_id_token (token:id_token_claims) (client_id:string) : bool =
  Option.isSome (build_well_formed_id_token_prop token client_id)

let lemma_wf_build_none
  (token:id_token_claims)
  (client_id:string)
  (pf:build_well_formed_id_token_prop token client_id = None)
  : Lemma (well_formed_id_token token client_id = false)
  =
    match pf with
    | () ->
        assert_norm (well_formed_id_token token client_id = false);
        ()

type oidc_token_prop
  (token:id_token_claims)
  (client_id:string)
  (nonce_required:bool)
  (alg:string)
  (access_token:option bytes)
  (code:option bytes)
  = {
    core: well_formed_id_token_prop token client_id;
    nonce_ok_fact: fact (nonce_ok nonce_required token.nonce);
    at_hash_ok_fact: fact (at_hash_ok alg access_token token.at_hash);
    c_hash_ok_fact: fact (verify_optional_hash compute_c_hash alg code token.c_hash);
  }

let oidc_token_prop_core
  (token:id_token_claims)
  (client_id:string)
  (nonce_required:bool)
  (alg:string)
  (access_token:option bytes)
  (code:option bytes)
  (facts:oidc_token_prop token client_id nonce_required alg access_token code)
  : well_formed_id_token_prop token client_id = facts.core

let oidc_token_prop_nonce_ok
  (token:id_token_claims)
  (client_id:string)
  (nonce_required:bool)
  (alg:string)
  (access_token:option bytes)
  (code:option bytes)
  (facts:oidc_token_prop token client_id nonce_required alg access_token code)
  : Lemma (ensures nonce_ok nonce_required token.nonce)
  = let _ = facts.nonce_ok_fact in ()

let oidc_token_prop_at_hash_ok
  (token:id_token_claims)
  (client_id:string)
  (nonce_required:bool)
  (alg:string)
  (access_token:option bytes)
  (code:option bytes)
  (facts:oidc_token_prop token client_id nonce_required alg access_token code)
  : Lemma (ensures at_hash_ok alg access_token token.at_hash)
  = let _ = facts.at_hash_ok_fact in ()

let oidc_token_prop_c_hash_ok
  (token:id_token_claims)
  (client_id:string)
  (nonce_required:bool)
  (alg:string)
  (access_token:option bytes)
  (code:option bytes)
  (facts:oidc_token_prop token client_id nonce_required alg access_token code)
  : Lemma (ensures verify_optional_hash compute_c_hash alg code token.c_hash)
  = let _ = facts.c_hash_ok_fact in ()

let build_oidc_well_formed_id_token_prop
  (token:id_token_claims)
  (client_id:string)
  (nonce_required:bool)
  (alg:string)
  (access_token:option bytes)
  (code:option bytes)
  : Tot (option (oidc_token_prop token client_id nonce_required alg access_token code))
  =
    match build_well_formed_id_token_prop token client_id with
    | None -> None
    | Some core_wf ->
        if not (nonce_ok nonce_required token.nonce) then None else
        let nonce_fact : fact (nonce_ok nonce_required token.nonce) = () in
        if not (at_hash_ok alg access_token token.at_hash) then None else
        let at_hash_fact : fact (at_hash_ok alg access_token token.at_hash) = () in
        if not (verify_optional_hash compute_c_hash alg code token.c_hash) then None else
        let c_hash_fact : fact (verify_optional_hash compute_c_hash alg code token.c_hash) = () in
        Some {
          core = core_wf;
          nonce_ok_fact = nonce_fact;
          at_hash_ok_fact = at_hash_fact;
          c_hash_ok_fact = c_hash_fact;
        }

let pack_oidc_token_prop
  (token:id_token_claims)
  (client_id:string)
  (nonce_required:bool)
  (alg:string)
  (access_token:option bytes)
  (code:option bytes)
  (facts:oidc_token_prop token client_id nonce_required alg access_token code)
  : (token':id_token_claims &
      oidc_token_prop token' client_id nonce_required alg access_token code)
  = Mkdtuple2 token facts

let require_well_formed_id_token_prop
  (token:id_token_claims)
  (client_id:string)
  : Pure (well_formed_id_token_prop token client_id)
      (requires well_formed_id_token token client_id)
      (ensures (fun _ -> True))
  =
    match build_well_formed_id_token_prop token client_id with
    | Some pf -> pf
    | None ->
        let pf_true = lemma_bool_true_of_requires (well_formed_id_token token client_id) in
        let pf_false =
          lemma_wf_build_none token client_id ()
        in
        bool_conflict_elim
          (well_formed_id_token token client_id)
          pf_true
          pf_false

let optional_claim_requires_scope (#a:Type) (value:option a) (scopes:list string) (scope:string)
  : Tot bool =
  match value with
  | None -> true
  | Some _ -> has_scope scopes scope

let valid_userinfo_for_scopes (claims:userinfo_claims) (scopes:list string) : Tot bool =
  claims.sub <> "" &&
  optional_claim_requires_scope claims.name scopes "profile" &&
  optional_claim_requires_scope claims.preferred_username scopes "profile" &&
  optional_claim_requires_scope claims.email scopes "email" &&
  optional_claim_requires_scope claims.email_verified scopes "email" &&
  optional_claim_requires_scope claims.address scopes "address" &&
  optional_claim_requires_scope claims.phone_number scopes "phone" &&
  optional_claim_requires_scope claims.updated_at scopes "profile"

let build_userinfo (profile:userinfo_profile) (scopes:list string) : userinfo_claims =
  {
    sub = profile.profile_sub;
    name = if has_scope scopes "profile" then Some profile.profile_name else None;
    preferred_username =
      if has_scope scopes "profile" then Some profile.profile_preferred_username else None;
    email = if has_scope scopes "email" then Some profile.profile_email else None;
    email_verified =
      if has_scope scopes "email" then Some profile.profile_email_verified else None;
    address = if has_scope scopes "address" then profile.profile_address else None;
    phone_number = if has_scope scopes "phone" then profile.profile_phone_number else None;
    updated_at =
      if has_scope scopes "profile" then profile.profile_updated_at else None;
  }

let verify_userinfo (claims:userinfo_claims) (scopes:list string) : Tot bool =
  valid_userinfo_for_scopes claims scopes

(* ID Token issuance with validation *)
type id_token_issuance_params = {
  issuer: string;
  subject: string;
  client_id: string;
  nonce: option string;
  auth_time: timestamp;
  acr_values: option string;
  amr_values: option (list string);
  access_token: option bytes;
  auth_code: option bytes;
  alg: string;
  ttl_seconds: nat;
}

val compute_at_hash_bytes: alg:string -> tok:bytes -> Tot bytes
let compute_at_hash_bytes alg tok =
  match alg with
  | "RS256" | "HS256" | "ES256" -> Bytes.create 16ul 0uy
  | "RS384" | "HS384" | "ES384" -> Bytes.create 24ul 0uy
  | _ -> Bytes.create 32ul 0uy

let verify_optional_hash_bytes (expected:bytes) (candidate:option bytes) : Tot bool =
  match candidate with
  | None -> true
  | Some v -> v = expected

let oidc_well_formed_id_token
  (token:id_token_claims)
  (client_id:string)
  (nonce_required:bool)
  (alg:string)
  (access_token:option bytes)
  (code:option bytes)
  : Tot bool =
  Option.isSome (build_oidc_well_formed_id_token_prop token client_id nonce_required alg access_token code)

let lemma_oidc_wf_build_none
  (token:id_token_claims)
  (client_id:string)
  (nonce_required:bool)
  (alg:string)
  (access_token:option bytes)
  (code:option bytes)
  (pf:build_oidc_well_formed_id_token_prop token client_id nonce_required alg access_token code = None)
  : Lemma (oidc_well_formed_id_token token client_id nonce_required alg access_token code = false)
  =
    match pf with
    | () ->
        assert_norm (oidc_well_formed_id_token token client_id nonce_required alg access_token code = false);
        ()

let require_oidc_well_formed_id_token_prop
  (token:id_token_claims)
  (client_id:string)
  (nonce_required:bool)
  (alg:string)
  (access_token:option bytes)
  (code:option bytes)
  : Pure (oidc_token_prop token client_id nonce_required alg access_token code)
      (requires oidc_well_formed_id_token token client_id nonce_required alg access_token code)
      (ensures (fun _ -> True))
  =
    match build_oidc_well_formed_id_token_prop token client_id nonce_required alg access_token code with
    | Some pf -> pf
    | None ->
        let pf_true =
          lemma_bool_true_of_requires
            (oidc_well_formed_id_token token client_id nonce_required alg access_token code)
        in
        let pf_false =
          lemma_oidc_wf_build_none token client_id nonce_required alg access_token code ()
        in
        bool_conflict_elim
          (oidc_well_formed_id_token token client_id nonce_required alg access_token code)
          pf_true
          pf_false

(* -------------------------------------------------------------------------- *)
(* Lemmas derived from well_formed_id_token constraints                       *)
(* -------------------------------------------------------------------------- *)

let lemma_multiple_audience_requires_azp
  (token:id_token_claims)
  (client_id:string)
  (wf:well_formed_id_token_prop token client_id)
  : Lemma
      (requires (exists lst. token.aud == Multiple lst))
      (ensures token.azp == Some client_id)
  =
    match token.aud, token.azp with
    | Multiple lst, Some azp ->
        let _ = wf.audience_has_client in
        assert (List.mem client_id lst);
        let _ = wf.azp_consistent in
        assert (azp = client_id)
    | Multiple _, None ->
        let _ = wf.azp_consistent in
        ()
    | Single _ , _ -> ()

let lemma_single_audience_forbids_azp
  (token:id_token_claims)
  (client_id:string)
  (wf:well_formed_id_token_prop token client_id)
  : Lemma
      (requires token.aud == Single client_id)
    (ensures token.azp == None)
  =
    match token.aud, token.azp with
    | Single _, None -> ()
    | Single _, Some _ ->
        let _ = wf.azp_consistent in
        ()
    | Multiple _, _ -> ()

let lemma_issuer_is_https
  (token:id_token_claims)
  (client_id:string)
  (wf:well_formed_id_token_prop token client_id)
  : Lemma (ensures is_https_url token.iss)
  =
    let _ = wf.issuer_is_https in
    ()

let lemma_oidc_nonce_required
  (token:id_token_claims)
  (client_id:string)
  (alg:string)
  (access_token:option bytes)
  (code:option bytes)
  (facts:oidc_token_prop token client_id true alg access_token code)
  : Lemma (ensures token.nonce <> None)
  =
    let _ = facts.nonce_ok_fact in
    match token.nonce with
    | Some _ -> ()
    | None -> assert false

let lemma_verify_optional_hash_some
  (expected:bytes)
  (actual:bytes)
  : Lemma
      (requires verify_optional_hash_bytes expected (Some actual))
      (ensures actual = expected)
  =
    let _ = assert (verify_optional_hash_bytes expected (Some actual)) in ()

let lemma_oidc_at_hash_matches_access_token
  (token:id_token_claims)
  (client_id:string)
  (alg:string)
  (tok:bytes)
  (code:option bytes)
  (facts:oidc_token_prop token client_id false alg (Some tok) code)
  : Lemma
      (ensures at_hash_ok alg (Some tok) token.at_hash)
  =
    let _ = facts.at_hash_ok_fact in
    ()

let lemma_oidc_c_hash_matches_code
  (token:id_token_claims)
  (client_id:string)
  (alg:string)
  (code:bytes)
  (access_token:option bytes)
  (facts:oidc_token_prop token client_id false alg access_token (Some code))
  : Lemma
      (ensures verify_optional_hash compute_c_hash alg (Some code) token.c_hash)
  =
    let _ = facts.c_hash_ok_fact in
    ()

val issue_id_token:
  params:id_token_issuance_params ->
  current_time:timestamp ->
  Tot (
    result (
      token:id_token_claims &
      oidc_token_prop token params.client_id (option_is_some params.nonce) params.alg params.access_token params.auth_code
    )
  )
let issue_id_token params current_time =
  (* Validate issuer *)
  if not (is_https_url params.issuer) then
    Error "Issuer must be HTTPS URL"
  else
    let exp_time = current_time + params.ttl_seconds in
    let at_hash = match params.access_token with
      | None -> None
      | Some token -> compute_at_hash params.alg token in
    let c_hash = match params.auth_code with
      | None -> None
      | Some code -> compute_c_hash params.alg code in

    let claims = {
      iss = params.issuer;
      sub = params.subject;
      aud = Single params.client_id;
      exp = exp_time;
      iat = current_time;
      nonce = params.nonce;
      nbf = Some current_time;
      auth_time = Some params.auth_time;
      azp = None; (* Single audience, no AZP needed *)
      acr = params.acr_values;
      amr = params.amr_values;
      at_hash = at_hash;
      c_hash = c_hash;
      sid = None; (* Session management not implemented yet *)
    } in

    let nonce_required = option_is_some params.nonce in
    match build_oidc_well_formed_id_token_prop claims params.client_id nonce_required params.alg params.access_token params.auth_code with
    | Some (wf:oidc_token_prop claims params.client_id nonce_required params.alg params.access_token params.auth_code) ->
        let packed =
          pack_oidc_token_prop claims params.client_id nonce_required params.alg params.access_token params.auth_code wf
        in
        Ok packed
    | None ->
        Error "Invalid ID token claims"

(* ID Token verification *)
type verification_context = {
  expected_issuer: string;
  expected_client_id: string;
  expected_nonce: option string;
  nonce_required: bool;
  current_time: timestamp;
  max_age: option nat; (* Maximum authentication age *)
  access_token_for_hash: option bytes;
  code_for_hash: option bytes;
  alg: string;
}

let verify_max_age (token:id_token_claims) (ctx:verification_context) : Tot bool =
  match ctx.max_age with
  | None -> true
  | Some window ->
      (match token.auth_time with
       | None -> false
       | Some t -> ctx.current_time <= t + window)

val verify_id_token:
  token:id_token_claims ->
  ctx:verification_context ->
  Tot (result (oidc_token_prop token ctx.expected_client_id ctx.nonce_required ctx.alg ctx.access_token_for_hash ctx.code_for_hash))
let verify_id_token token ctx =
  match build_well_formed_id_token_prop token ctx.expected_client_id with
  | None -> Error "Malformed ID token"
  | Some wf ->
      (* Check issuer *)
      if not (token.iss = ctx.expected_issuer) then
        Error "Invalid issuer"

      (* Check expiration *)
      else if not (ctx.current_time < token.exp) then
        Error "Token expired"

      (* Check not-before if present *)
      else if (match token.nbf with
               | Some nbf -> ctx.current_time < nbf
               | None -> false) then
        Error "Token not yet valid"

      (* Check nonce if required *)
      else if (match ctx.expected_nonce, token.nonce with
               | Some exp_nonce, Some tok_nonce -> not (exp_nonce = tok_nonce)
               | Some _, None -> true
               | None, _ -> false) then
        Error "Invalid nonce"

      else if not (verify_max_age token ctx) then
        Error "Authentication too old"

      else if not (at_hash_ok ctx.alg ctx.access_token_for_hash token.at_hash) then
        Error "Invalid at_hash"

      else if not (verify_optional_hash compute_c_hash ctx.alg ctx.code_for_hash token.c_hash) then
        Error "Invalid c_hash"

      else
        match build_oidc_well_formed_id_token_prop token ctx.expected_client_id ctx.nonce_required ctx.alg ctx.access_token_for_hash ctx.code_for_hash with
        | Some facts -> Ok facts
        | None -> Error "Malformed ID token"

(* Lemmas for security properties *)

(* Lemma: Well-formed tokens have valid temporal ordering *)
val lemma_temporal_ordering:
  token:id_token_claims ->
  client_id:string ->
  wf:well_formed_id_token_prop token client_id ->
  Lemma
    (ensures token.exp > token.iat /\
             (match token.nbf with None -> true | Some nbf -> nbf <= token.iat) /\
             (match token.auth_time with None -> true | Some at -> at <= token.iat))
let lemma_temporal_ordering token client_id wf =
  let _ = wf.exp_gt_iat in
  let _ = wf.nbf_not_after_iat in
  let _ = wf.auth_time_not_after_iat in
  ()

(* Lemma: Issued tokens are always well-formed *)
