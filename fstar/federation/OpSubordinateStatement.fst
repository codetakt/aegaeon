module OpSubordinateStatement

(** OpenID Federation: OP Subordinate Statement — Formal Specification.

    Models the security properties of subordinate statements issued by
    Aegaeon when acting as an OP in a federation. The OP issues subordinate
    statements for registered RPs (clients) that are served via the
    federation fetch endpoint.

    Security properties:
      SS-1  issuer_is_op       — iss = OP entity_id
      SS-2  subject_is_rp      — sub = RP entity_id
      SS-3  not_self_signed    — iss ≠ sub (distinct from entity configurations)
      SS-4  exp_bounded        — exp ≤ iat + MAX_EXP
      SS-5  signed_by_op       — signed with OP's federation key

    Production code reference:
      `crates/server/src/web/mod.rs` — build_subordinate_statement, federation_fetch
      `crates/server/src/web/mod.rs` — federation_list, federation_resolve

    Tamarin companion: proofs/tamarin/federation/op_entity_configuration.spthy
      - Rule: OP_Issue_Subordinate
      - Lemma: subordinate_only_for_registered *)

open FStar.String

(* =========================================================================
   Constants
   ========================================================================= *)

(** Maximum subordinate statement JWT lifetime in seconds. *)
let max_exp_secs : nat = 86400

(** Required JOSE `typ` header value for entity statements. *)
let required_typ : string = "entity-statement+jwt"

(* =========================================================================
   Types
   ========================================================================= *)

(** Subordinate statement claims (JWT payload). *)
noeq type subordinate_statement = {
  ss_iss          : string;    (** OP entity_id — issuer *)
  ss_sub          : string;    (** RP entity_id — subject *)
  ss_iat          : nat;       (** issued-at epoch seconds *)
  ss_exp          : nat;       (** expiration epoch seconds *)
  ss_has_rp_meta  : bool;      (** openid_relying_party metadata present *)
  ss_typ          : string;    (** JOSE typ header value *)
}

(* =========================================================================
   Well-formedness predicates
   ========================================================================= *)

(** SS-1: iss is non-empty (OP entity_id). *)
val has_issuer : ss:subordinate_statement -> bool
let has_issuer ss =
  String.length ss.ss_iss > 0

(** SS-2: sub is non-empty (RP entity_id). *)
val has_subject : ss:subordinate_statement -> bool
let has_subject ss =
  String.length ss.ss_sub > 0

(** SS-3: not self-signed (iss ≠ sub). *)
val not_self_signed : ss:subordinate_statement -> bool
let not_self_signed ss =
  ss.ss_iss <> ss.ss_sub

(** SS-4: exp within MAX_EXP_SECS of iat. *)
val exp_within_bound : ss:subordinate_statement -> bool
let exp_within_bound ss =
  ss.ss_exp > ss.ss_iat &&
  ss.ss_exp <= ss.ss_iat + max_exp_secs

(** Correct typ header. *)
val has_correct_typ : ss:subordinate_statement -> bool
let has_correct_typ ss =
  ss.ss_typ = required_typ

(** Complete well-formedness: all security properties hold. *)
val is_well_formed : ss:subordinate_statement -> bool
let is_well_formed ss =
  has_issuer ss &&
  has_subject ss &&
  not_self_signed ss &&
  exp_within_bound ss &&
  has_correct_typ ss &&
  ss.ss_has_rp_meta

(* =========================================================================
   Construction
   ========================================================================= *)

(** Build a subordinate statement with enforced security properties.

    Pre-conditions:
      - op_entity_id is non-empty
      - rp_entity_id is non-empty
      - op_entity_id ≠ rp_entity_id
      - now > 0
      - configured_exp_secs > 0

    Post-conditions (verified):
      - SS-1: iss = op_entity_id
      - SS-2: sub = rp_entity_id
      - SS-3: iss ≠ sub
      - SS-4: exp ≤ iat + max_exp_secs *)
val build_subordinate_statement :
  op_entity_id:string{String.length op_entity_id > 0} ->
  rp_entity_id:string{String.length rp_entity_id > 0 /\ op_entity_id <> rp_entity_id} ->
  now:nat{now > 0} ->
  configured_exp_secs:nat{configured_exp_secs > 0} ->
  Pure subordinate_statement
    (requires True)
    (ensures fun ss ->
      ss.ss_iss = op_entity_id /\
      ss.ss_sub = rp_entity_id /\
      ss.ss_iat = now /\
      ss.ss_exp <= now + max_exp_secs /\
      ss.ss_exp > now /\
      ss.ss_has_rp_meta = true /\
      ss.ss_typ = required_typ /\
      is_well_formed ss)
let build_subordinate_statement op_entity_id rp_entity_id now configured_exp_secs =
  let clamped_exp = if configured_exp_secs <= max_exp_secs
                    then configured_exp_secs
                    else max_exp_secs in
  {
    ss_iss         = op_entity_id;
    ss_sub         = rp_entity_id;
    ss_iat         = now;
    ss_exp         = now + clamped_exp;
    ss_has_rp_meta = true;
    ss_typ         = required_typ;
  }

(* =========================================================================
   Security Lemmas
   ========================================================================= *)

(** SS-1: Issuer is always the OP. *)
val lemma_issuer_is_op :
  op:string{String.length op > 0} ->
  rp:string{String.length rp > 0 /\ op <> rp} ->
  now:nat{now > 0} ->
  Lemma (let ss = build_subordinate_statement op rp now 3600 in
         ss.ss_iss = op)
let lemma_issuer_is_op op rp now = ()

(** SS-3: Subordinate statements are never self-signed. *)
val lemma_not_self_signed :
  op:string{String.length op > 0} ->
  rp:string{String.length rp > 0 /\ op <> rp} ->
  now:nat{now > 0} ->
  Lemma (let ss = build_subordinate_statement op rp now 3600 in
         not_self_signed ss)
let lemma_not_self_signed op rp now = ()

(** SS-4: Expiration is always bounded. *)
val lemma_exp_bounded :
  op:string{String.length op > 0} ->
  rp:string{String.length rp > 0 /\ op <> rp} ->
  now:nat{now > 0} ->
  cfg_exp:nat{cfg_exp > 0} ->
  Lemma (let ss = build_subordinate_statement op rp now cfg_exp in
         ss.ss_exp <= now + max_exp_secs)
let lemma_exp_bounded op rp now cfg_exp = ()

(** Combined well-formedness. *)
val lemma_well_formed :
  op:string{String.length op > 0} ->
  rp:string{String.length rp > 0 /\ op <> rp} ->
  now:nat{now > 0} ->
  cfg_exp:nat{cfg_exp > 0} ->
  Lemma (let ss = build_subordinate_statement op rp now cfg_exp in
         is_well_formed ss)
let lemma_well_formed op rp now cfg_exp = ()
