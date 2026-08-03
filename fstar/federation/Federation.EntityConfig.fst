module Federation.EntityConfig

(** OpenID Federation 1.0 — Entity Configuration (OP role) Formal Specification.

    Models the security properties of a self-signed Entity Configuration
    as published at `/.well-known/openid-federation`:

    EC-1  self_signed          — iss == sub (Entity Configuration invariant)
    EC-2  jwks_present         — self-signed configs must include JWKS
    EC-3  temporal_validity    — exp > iat; now < exp (not expired); now >= iat (issued)
    EC-4  iss_non_empty        — iss must be non-empty URI
    EC-5  metadata_consistency — openid_provider metadata iss matches entity iss
    EC-6  authority_hints      — authority_hints present for non-TA entities

    Production code reference:
      `crates/server/src/federation.rs` — EntityStatement, verify_entity_configuration,
        validate_entity_statement, validate_temporal

    Companion F* specs:
      `fstar/jose/Jose.Federation.fst`    — trust chain verification
      `fstar/federation/Federation.PgRepo.fst` — cache invariants *)

(* =========================================================================
   Types
   ========================================================================= *)

(** Simplified entity statement for verification purposes. *)
noeq type entity_statement = {
  es_iss             : string;
  es_sub             : string;
  es_iat             : nat;
  es_exp             : nat;
  es_jwks_present    : bool;           (** whether JWKS is included *)
  es_op_iss          : option string;  (** openid_provider.issuer from metadata *)
  es_authority_hints : option (list string);
  es_is_trust_anchor : bool;           (** whether this entity is a trust anchor *)
}

(** Default clock skew leeway in seconds. *)
let default_clock_skew_secs : nat = 300

(* =========================================================================
   Well-formedness predicates
   ========================================================================= *)

(** EC-1: Self-signed — iss must equal sub for Entity Configurations. *)
val is_self_signed : es:entity_statement -> bool
let is_self_signed es = es.es_iss = es.es_sub

(** EC-2: JWKS must be present in self-signed Entity Configurations. *)
val has_jwks : es:entity_statement -> bool
let has_jwks es = es.es_jwks_present

(** EC-3: Temporal validity — exp > iat. *)
val temporal_well_formed : es:entity_statement -> bool
let temporal_well_formed es = es.es_exp > es.es_iat

(** EC-3: Not expired at time `now` (with leeway). *)
val not_expired : es:entity_statement -> now:nat -> leeway:nat -> bool
let not_expired es now leeway =
  now < es.es_exp + leeway

(** EC-3: Already issued at time `now` (with leeway). *)
val already_issued : es:entity_statement -> now:nat -> leeway:nat -> bool
let already_issued es now leeway =
  now + leeway >= es.es_iat

(** EC-3: Full temporal validation. *)
val temporal_valid : es:entity_statement -> now:nat -> leeway:nat -> bool
let temporal_valid es now leeway =
  temporal_well_formed es &&
  not_expired es now leeway &&
  already_issued es now leeway

(** EC-4: Issuer must be non-empty. *)
val iss_non_empty : es:entity_statement -> bool
let iss_non_empty es = String.length es.es_iss > 0

(** EC-4: Subject must be non-empty. *)
val sub_non_empty : es:entity_statement -> bool
let sub_non_empty es = String.length es.es_sub > 0

(** EC-5: If openid_provider metadata is present, its issuer must match
    the entity's iss claim. *)
val op_iss_consistent : es:entity_statement -> bool
let op_iss_consistent es =
  match es.es_op_iss with
  | Some op_iss -> op_iss = es.es_iss
  | None -> true  (* no OP metadata → vacuously true *)

(** EC-6: Non-TA entities should have authority_hints. *)
val has_authority_hints_if_needed : es:entity_statement -> bool
let has_authority_hints_if_needed es =
  if es.es_is_trust_anchor then true
  else
    match es.es_authority_hints with
    | Some hints -> Cons? hints  (* at least one hint *)
    | None -> false

(** Complete Entity Configuration well-formedness. *)
val entity_config_well_formed : es:entity_statement -> now:nat -> bool
let entity_config_well_formed es now =
  is_self_signed es &&
  has_jwks es &&
  temporal_valid es now default_clock_skew_secs &&
  iss_non_empty es &&
  sub_non_empty es &&
  op_iss_consistent es

(* =========================================================================
   Construction
   ========================================================================= *)

(** Build a well-formed Entity Configuration for an OP.

    Pre-conditions:
    - iss is non-empty
    - iss starts with "https://" (modelled as length > 8)
    - now is within validity window

    Post-conditions:
    - All EC-1 through EC-5 properties hold *)
val build_entity_config :
  iss:string{String.length iss > 8} ->
  now:nat ->
  validity_secs:nat{validity_secs > 0} ->
  is_ta:bool ->
  authority_hints:option (list string) ->
  Pure entity_statement
    (requires True)
    (ensures fun es ->
      is_self_signed es /\
      has_jwks es /\
      temporal_well_formed es /\
      iss_non_empty es /\
      sub_non_empty es /\
      op_iss_consistent es /\
      es.es_iss = iss /\
      es.es_sub = iss /\
      es.es_iat = now /\
      es.es_exp = now + validity_secs /\
      entity_config_well_formed es now)
let build_entity_config iss now validity_secs is_ta authority_hints =
  {
    es_iss             = iss;
    es_sub             = iss;             (* EC-1: self-signed *)
    es_iat             = now;
    es_exp             = now + validity_secs;
    es_jwks_present    = true;            (* EC-2: JWKS always included *)
    es_op_iss          = Some iss;        (* EC-5: OP issuer = entity iss *)
    es_authority_hints = authority_hints;
    es_is_trust_anchor = is_ta;
  }

(* =========================================================================
   Security Lemmas
   ========================================================================= *)

(** EC-1: Built configurations are always self-signed. *)
val lemma_self_signed :
  iss:string{String.length iss > 8} -> now:nat -> vs:nat{vs > 0} ->
  Lemma (is_self_signed (build_entity_config iss now vs false None))
let lemma_self_signed iss now vs = ()

(** EC-2: Built configurations always include JWKS. *)
val lemma_jwks_present :
  iss:string{String.length iss > 8} -> now:nat -> vs:nat{vs > 0} ->
  Lemma (has_jwks (build_entity_config iss now vs false None))
let lemma_jwks_present iss now vs = ()

(** EC-3: Built configurations have valid temporal claims. *)
val lemma_temporal_valid :
  iss:string{String.length iss > 8} -> now:nat -> vs:nat{vs > 0} ->
  Lemma (temporal_valid (build_entity_config iss now vs false None)
                        now default_clock_skew_secs)
let lemma_temporal_valid iss now vs = ()

(** EC-5: OP issuer matches entity issuer. *)
val lemma_op_iss_consistent :
  iss:string{String.length iss > 8} -> now:nat -> vs:nat{vs > 0} ->
  Lemma (op_iss_consistent (build_entity_config iss now vs false None))
let lemma_op_iss_consistent iss now vs = ()

(** Self-signed Entity Configurations without JWKS are rejected. *)
val lemma_self_signed_requires_jwks :
  es:entity_statement ->
  Lemma
    (requires is_self_signed es /\ not (has_jwks es))
    (ensures not (entity_config_well_formed es 0))
let lemma_self_signed_requires_jwks es = ()

(** Expired configurations are rejected. *)
val lemma_expired_rejected :
  es:entity_statement -> now:nat ->
  Lemma
    (requires es.es_exp + default_clock_skew_secs <= now)
    (ensures not (entity_config_well_formed es now))
let lemma_expired_rejected es now = ()

(** Non-self-signed statements cannot be valid Entity Configurations. *)
val lemma_non_self_signed_rejected :
  es:entity_statement{es.es_iss <> es.es_sub} -> now:nat ->
  Lemma (not (entity_config_well_formed es now))
let lemma_non_self_signed_rejected es now = ()

(** OP metadata issuer mismatch is rejected. *)
val lemma_op_iss_mismatch_rejected :
  es:entity_statement -> now:nat ->
  Lemma
    (requires
      Some? es.es_op_iss /\
      Some?.v es.es_op_iss <> es.es_iss)
    (ensures not (entity_config_well_formed es now))
let lemma_op_iss_mismatch_rejected es now = ()
