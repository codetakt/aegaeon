module OpEntityConfiguration

(** OpenID Federation: OP Entity Configuration — Formal Specification.

    Models the security properties of self-signed entity configurations
    published by Aegaeon when acting as an OpenID Provider in a federation.

    Security properties:
      EC-1  self_signed    — iss == sub (entity configuration is self-signed)
      EC-2  jwks_embedded  — JWKS present in payload (verifiers can check signature)
      EC-3  exp_bounded    — exp ≤ iat + MAX_EXP (limits stale configuration)
      EC-4  iat_present    — iat > 0 (temporal ordering)
      EC-5  metadata_valid — openid_provider and federation_entity present

    Production code reference:
      `crates/server/src/web/mod.rs` — build_entity_configuration, well_known_openid_federation
      `crates/server/src/config.rs`  — federation_op_enabled, federation_entity_exp_secs

    Tamarin companion: proofs/tamarin/federation/op_entity_configuration.spthy *)

open FStar.String

(* =========================================================================
   Constants
   ========================================================================= *)

(** Maximum entity configuration JWT lifetime in seconds (EC-3). *)
let max_exp_secs : nat = 86400

(** Required JOSE `typ` header value for entity statements. *)
let required_typ : string = "entity-statement+jwt"

(** Content-Type for entity configuration responses. *)
let content_type : string = "application/entity-statement+jwt"

(* =========================================================================
   Types
   ========================================================================= *)

(** Entity configuration claims (self-signed JWT payload). *)
noeq type entity_config = {
  ec_iss           : string;             (** entity_id — issuer *)
  ec_sub           : string;             (** entity_id — subject (must == iss) *)
  ec_iat           : nat;                (** issued-at epoch seconds *)
  ec_exp           : nat;                (** expiration epoch seconds *)
  ec_has_jwks      : bool;               (** whether jwks field is present *)
  ec_has_op_meta   : bool;               (** whether openid_provider metadata present *)
  ec_has_fed_meta  : bool;               (** whether federation_entity metadata present *)
  ec_typ           : string;             (** JOSE typ header value *)
  ec_authority_cnt : nat;                (** number of authority_hints *)
}

(* =========================================================================
   Well-formedness predicates
   ========================================================================= *)

(** EC-1: iss must equal sub (self-signed). *)
val is_self_signed : ec:entity_config -> bool
let is_self_signed ec =
  ec.ec_iss = ec.ec_sub

(** EC-2: JWKS must be embedded. *)
val has_jwks : ec:entity_config -> bool
let has_jwks ec =
  ec.ec_has_jwks

(** EC-3: exp within MAX_EXP_SECS of iat. *)
val exp_within_bound : ec:entity_config -> bool
let exp_within_bound ec =
  ec.ec_exp > ec.ec_iat &&
  ec.ec_exp <= ec.ec_iat + max_exp_secs

(** EC-4: iat present (non-zero). *)
val iat_present : ec:entity_config -> bool
let iat_present ec =
  ec.ec_iat > 0

(** EC-5: required metadata sections present. *)
val has_required_metadata : ec:entity_config -> bool
let has_required_metadata ec =
  ec.ec_has_op_meta && ec.ec_has_fed_meta

(** Correct typ header. *)
val has_correct_typ : ec:entity_config -> bool
let has_correct_typ ec =
  ec.ec_typ = required_typ

(** Complete well-formedness: all security properties hold. *)
val is_well_formed : ec:entity_config -> bool
let is_well_formed ec =
  is_self_signed ec &&
  has_jwks ec &&
  exp_within_bound ec &&
  iat_present ec &&
  has_required_metadata ec &&
  has_correct_typ ec

(* =========================================================================
   Construction
   ========================================================================= *)

(** Build an entity configuration with enforced security properties.

    Pre-conditions:
      - entity_id is non-empty
      - now > 0
      - configured_exp_secs > 0

    Post-conditions (verified):
      - EC-1: iss == sub
      - EC-2: jwks present
      - EC-3: exp ≤ iat + max_exp_secs
      - EC-4: iat > 0
      - EC-5: metadata sections present
      - typ = entity-statement+jwt *)
val build_entity_config :
  entity_id:string{String.length entity_id > 0} ->
  now:nat{now > 0} ->
  configured_exp_secs:nat{configured_exp_secs > 0} ->
  authority_count:nat ->
  Pure entity_config
    (requires True)
    (ensures fun ec ->
      ec.ec_iss = entity_id /\
      ec.ec_sub = entity_id /\
      ec.ec_iat = now /\
      ec.ec_exp <= now + max_exp_secs /\
      ec.ec_exp > now /\
      ec.ec_has_jwks = true /\
      ec.ec_has_op_meta = true /\
      ec.ec_has_fed_meta = true /\
      ec.ec_typ = required_typ /\
      is_well_formed ec)
let build_entity_config entity_id now configured_exp_secs authority_count =
  let clamped_exp = if configured_exp_secs <= max_exp_secs
                    then configured_exp_secs
                    else max_exp_secs in
  {
    ec_iss          = entity_id;
    ec_sub          = entity_id;
    ec_iat          = now;
    ec_exp          = now + clamped_exp;
    ec_has_jwks     = true;
    ec_has_op_meta  = true;
    ec_has_fed_meta = true;
    ec_typ          = required_typ;
    ec_authority_cnt = authority_count;
  }

(* =========================================================================
   Security Lemmas
   ========================================================================= *)

(** EC-1: Entity configuration is always self-signed. *)
val lemma_self_signed :
  entity_id:string{String.length entity_id > 0} ->
  now:nat{now > 0} ->
  Lemma (let ec = build_entity_config entity_id now 3600 0 in
         is_self_signed ec)
let lemma_self_signed entity_id now = ()

(** EC-3: The expiration is always bounded by max_exp_secs. *)
val lemma_exp_bounded :
  entity_id:string{String.length entity_id > 0} ->
  now:nat{now > 0} ->
  cfg_exp:nat{cfg_exp > 0} ->
  Lemma (let ec = build_entity_config entity_id now cfg_exp 0 in
         ec.ec_exp <= now + max_exp_secs)
let lemma_exp_bounded entity_id now cfg_exp = ()

(** EC-2: JWKS is always embedded. *)
val lemma_jwks_embedded :
  entity_id:string{String.length entity_id > 0} ->
  now:nat{now > 0} ->
  Lemma (let ec = build_entity_config entity_id now 3600 0 in
         has_jwks ec)
let lemma_jwks_embedded entity_id now = ()

(** EC-4: iat is always present. *)
val lemma_iat_present :
  entity_id:string{String.length entity_id > 0} ->
  now:nat{now > 0} ->
  Lemma (let ec = build_entity_config entity_id now 3600 0 in
         iat_present ec)
let lemma_iat_present entity_id now = ()

(** EC-5: Required metadata is always present. *)
val lemma_metadata_present :
  entity_id:string{String.length entity_id > 0} ->
  now:nat{now > 0} ->
  Lemma (let ec = build_entity_config entity_id now 3600 0 in
         has_required_metadata ec)
let lemma_metadata_present entity_id now = ()

(** Combined: all well-formedness properties hold. *)
val lemma_well_formed :
  entity_id:string{String.length entity_id > 0} ->
  now:nat{now > 0} ->
  cfg_exp:nat{cfg_exp > 0} ->
  Lemma (let ec = build_entity_config entity_id now cfg_exp 0 in
         is_well_formed ec)
let lemma_well_formed entity_id now cfg_exp = ()
