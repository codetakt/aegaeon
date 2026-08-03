module JwtIntrospection

(** RFC 9701: JWT Introspection Response — Formal Specification.

    Models the security properties of JWT-encoded introspection responses:

    JI-1  aud_binding         — JWT `aud` must match the requesting resource server
    JI-2  short_exp           — JWT `exp` ≤ `iat` + MAX_EXP (60 seconds)
    JI-4  distinct_typ        — JWT `typ` = "token-introspection+jwt" (not "at+jwt" or "JWT")
    JI-5  revocation_window   — exp - iat ≤ 60s bounds staleness of revocation info
    JI-6  cross_tenant        — JWT `iss` prevents cross-tenant confusion

    Production code reference:
      `crates/server/src/web/mod.rs` — build_jwt_introspection_response, sign_jwt_introspection
      `crates/server/src/config.rs`  — enable_jwt_introspection, jwt_introspection_exp_secs

    Tamarin companion: proofs/tamarin/introspection/jwt_introspection_security.spthy *)

open FStar.UInt32
open Jose.UInt32Bounds

(* =========================================================================
   Constants
   ========================================================================= *)

(** Maximum JWT introspection response lifetime in seconds (JI-2). *)
let max_exp_secs : nat = 60

(** The required JOSE `typ` header value (JI-4). *)
let required_typ : string = "token-introspection+jwt"

(** Content-Type for JWT introspection responses. *)
let content_type : string = "application/token-introspection+jwt"

(* =========================================================================
   Types
   ========================================================================= *)

(** JWT introspection response wrapper claims (outer JWT).
    These are the AS-issued claims that wrap the introspection result. *)
noeq type jwt_introspection_wrapper = {
  ji_iss : string;             (** AS issuer identifier *)
  ji_aud : option string;      (** requesting RS client_id — JI-1 *)
  ji_iat : nat;                (** issued-at epoch seconds *)
  ji_exp : nat;                (** expiration epoch seconds *)
  ji_jti : string;             (** unique JWT ID *)
  ji_typ : string;             (** JOSE typ header value *)
}

(** The inner introspection claims (token_introspection object). *)
noeq type introspection_claims = {
  ic_active    : bool;
  ic_client_id : option string;
  ic_scope     : option string;
  ic_exp       : option nat;
  ic_token_type: option string;
}

(** A complete JWT introspection response = wrapper + inner claims. *)
noeq type jwt_introspection_response = {
  wrapper : jwt_introspection_wrapper;
  claims  : introspection_claims;
}

(* =========================================================================
   Well-formedness predicates
   ========================================================================= *)

(** JI-2 + JI-5: exp must be within MAX_EXP_SECS of iat. *)
val exp_within_bound : w:jwt_introspection_wrapper -> bool
let exp_within_bound w =
  w.ji_exp > w.ji_iat &&
  w.ji_exp <= w.ji_iat + max_exp_secs

(** JI-4: typ header must be the distinct introspection type. *)
val has_distinct_typ : w:jwt_introspection_wrapper -> bool
let has_distinct_typ w =
  w.ji_typ = required_typ

(** JI-6: iss must be non-empty (prevents cross-tenant confusion). *)
val has_issuer : w:jwt_introspection_wrapper -> bool
let has_issuer w =
  String.length w.ji_iss > 0

(** JI-1: aud binding — if present, must be non-empty. *)
val has_aud_binding : w:jwt_introspection_wrapper -> bool
let has_aud_binding w =
  match w.ji_aud with
  | Some aud -> String.length aud > 0
  | None -> true  (* absent is acceptable but less secure *)

(** Complete well-formedness: all security properties hold. *)
val is_well_formed : r:jwt_introspection_response -> bool
let is_well_formed r =
  exp_within_bound r.wrapper &&
  has_distinct_typ r.wrapper &&
  has_issuer r.wrapper &&
  has_aud_binding r.wrapper

(* =========================================================================
   Construction
   ========================================================================= *)

(** Build a JWT introspection response with enforced security properties.

    Pre-conditions:
      - iss is non-empty
      - configured_exp_secs > 0

    Post-conditions (verified):
      - JI-2: exp ≤ iat + 60
      - JI-4: typ = "token-introspection+jwt"
      - JI-5: exp - iat ≤ 60
      - JI-6: iss is present *)
val build_jwt_introspection :
  iss:string{String.length iss > 0} ->
  aud:option string{match aud with Some s -> String.length s > 0 | None -> true} ->
  now:nat ->
  configured_exp_secs:nat{configured_exp_secs > 0} ->
  jti:string ->
  active:bool ->
  Pure jwt_introspection_response
    (requires True)
    (ensures fun r ->
      r.wrapper.ji_iss = iss /\
      r.wrapper.ji_iat = now /\
      r.wrapper.ji_typ = required_typ /\
      r.wrapper.ji_exp <= now + max_exp_secs /\
      r.wrapper.ji_exp > now /\
      r.claims.ic_active = active /\
      is_well_formed r)
let build_jwt_introspection iss aud now configured_exp_secs jti active =
  let clamped_exp : nat = if configured_exp_secs <= max_exp_secs
                          then configured_exp_secs
                          else max_exp_secs in
  let exp_val : nat = now + clamped_exp in
  let wrapper = {
    ji_iss = iss;
    ji_aud = aud;
    ji_iat = now;
    ji_exp = exp_val;
    ji_jti = jti;
    ji_typ = required_typ;
  } in
  let claims = {
    ic_active     = active;
    ic_client_id  = None;
    ic_scope      = None;
    ic_exp        = None;
    ic_token_type = None;
  } in
  { wrapper = wrapper; claims = claims }

(* =========================================================================
   Security Lemmas
   ========================================================================= *)

(** JI-2: The JWT expiration is always bounded by max_exp_secs. *)
val lemma_exp_bounded :
  iss:string{String.length iss > 0} ->
  now:nat ->
  cfg_exp:nat{cfg_exp > 0} ->
  Lemma (let r = build_jwt_introspection iss None now cfg_exp "jti" true in
         r.wrapper.ji_exp <= now + max_exp_secs)
let lemma_exp_bounded iss now cfg_exp = ()

(** JI-4: The typ is always the distinct introspection type. *)
val lemma_distinct_typ :
  iss:string{String.length iss > 0} ->
  now:nat ->
  Lemma (let r = build_jwt_introspection iss None now 30 "jti" true in
         has_distinct_typ r.wrapper)
let lemma_distinct_typ iss now = ()

(** JI-5: The revocation staleness window is bounded. *)
val lemma_revocation_window :
  iss:string{String.length iss > 0} ->
  now:nat ->
  cfg_exp:nat{cfg_exp > 0} ->
  Lemma (let r = build_jwt_introspection iss None now cfg_exp "jti" true in
         r.wrapper.ji_exp - r.wrapper.ji_iat <= max_exp_secs)
let lemma_revocation_window iss now cfg_exp = ()

(** JI-6: The issuer is always present. *)
val lemma_issuer_present :
  iss:string{String.length iss > 0} ->
  now:nat ->
  Lemma (let r = build_jwt_introspection iss None now 30 "jti" true in
         has_issuer r.wrapper)
let lemma_issuer_present iss now = ()

(** Inactive tokens produce well-formed JWT responses. *)
val lemma_inactive_well_formed :
  iss:string{String.length iss > 0} ->
  now:nat ->
  Lemma (let r = build_jwt_introspection iss None now 30 "jti" false in
         is_well_formed r /\ r.claims.ic_active = false)
let lemma_inactive_well_formed iss now = ()
