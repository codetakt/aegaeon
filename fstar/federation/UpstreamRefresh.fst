module UpstreamRefresh

(** OIDC RP Upstream Token Refresh Rotation — Formal Specification.

    Models the security properties of the `/oauth/upstream/refresh`
    endpoint, which proxies `refresh_token` grants to upstream IdPs on
    behalf of authenticated users.

    Security properties:
      UR-1  single_use_rotation    — each upstream refresh token is consumed
                                     and atomically replaced; reuse of a
                                     previously-rotated token is rejected
      UR-2  environment_scoping    — all account_link queries are scoped by
                                     environment_id derived from the bearer
                                     token's client_id (M-9 fix)
      UR-3  account_link_integrity — (env_id, upstream_issuer, sub_hash) is
                                     a unique composite key; mutation preserves
                                     the key triple
      UR-4  issuer_binding         — the refresh token is sent only to the
                                     token_endpoint discovered from the issuer
                                     that originally issued it
      UR-5  bearer_auth_required   — caller must present a valid bearer token;
                                     user_id extracted from the token scopes
                                     the account_link lookup
      UR-6  rotation_persistence   — when the upstream IdP returns a new
                                     refresh_token, the UPDATE is scoped by
                                     (environment_id, upstream_issuer, sub_hash)
                                     and guarded by token generation
      UR-7  id_token_validation    — a refreshed id_token (if present) has a
                                     valid signature and matching issuer; alg
                                     must be in discovery's supported list
      UR-8  token_chain_freshness  — the stored token is always the most recent
                                     one returned by the upstream IdP; stale
                                     tokens are overwritten atomically
      UR-9  connection_identity     — connection.issuer_url is an immutable
                                     identity component after creation
      UR-10 callback_currentness    — callback exchange uses a managed
                                     connection snapshot only when the current
                                     active connection row still matches it

    Production code reference:
      `crates/server/src/web/upstream_refresh.rs` — refresh exchange persistence
      `crates/server/src/web/upstream_callback_users/refresh.rs` — callback refresh persistence
      `db/migrations/20260624100000_account_link_refresh_binding.sql` — DB generation/binding
      `db/migrations/20260624110000_connection_issuer_identity.sql` — DB issuer immutability
      `crates/server/src/web/upstream_callback_connection.rs` — callback current row validation

    Companion specifications:
      `fstar/federation/OidcRp.Types.fst`       — RP session types
      `fstar/federation/OidcRp.Properties.fst`  — RP session invariants
      `fstar/federation/Federation.EntityConfig.fst` — entity config props *)

open FStar.String

(* =========================================================================
   Types
   ========================================================================= *)

(** Tenant environment identifier. *)
type environment_id = nat

(** Managed upstream connection identifier. *)
type connection_id = string

(** Opaque token string. *)
type token = string

(** SHA-256(upstream_issuer ‖ '\0' ‖ upstream_sub) — unique per identity. *)
type sub_hash = string

(** Monotonic generation counter for token chain freshness (UR-8).
    Each successful rotation increments the generation; stale tokens
    carry an older generation and are rejected. *)
type token_generation = nat

(** Account link: binds a local end-user to an upstream IdP identity.
    Corresponds to `aegaeon.account_links` row. *)
noeq type account_link = {
  al_env_id            : environment_id;
  al_upstream_issuer   : string;
  al_upstream_sub_hash : sub_hash;
  al_refresh_token     : option token;
  al_token_generation  : token_generation;     (** UR-8: monotonic freshness *)
  al_connection_issuer : string;               (** issuer_url from connection *)
  al_end_user_subject  : string;
}

(** Bearer token metadata extracted from the caller's access token.
    Fields mirror `TokenMeta` / `AccessToken` in production. *)
noeq type bearer_meta = {
  bm_user_id   : string;
  bm_client_id : string;
  bm_env_id    : option environment_id;
  bm_valid     : bool;
}

(** Current managed connection row used to admit callback / refresh state.
    `cs_active_current` abstracts the production SQL requirement:
    connection.status = ACTIVE, environment.status = ACTIVE, and
    connection.configuration_version_id = environment.active_configuration_version_id. *)
noeq type connection_snapshot = {
  cs_id                 : connection_id;
  cs_env_id             : environment_id;
  cs_identifier         : string;
  cs_issuer_url         : string;
  cs_client_id          : string;
  cs_client_auth_method : string;
  cs_active_current     : bool;
}

(** Managed callback state captured before redirecting to the upstream IdP. *)
noeq type callback_snapshot = {
  cb_connection_id       : connection_id;
  cb_env_id              : environment_id;
  cb_identifier          : string;
  cb_issuer_url          : string;
  cb_client_id           : string;
  cb_client_auth_method  : string;
}

(** Upstream IdP token response (subset relevant for verification). *)
noeq type upstream_response = {
  ur_access_token   : option token;
  ur_id_token       : option token;
  ur_refresh_token  : option token;       (** new token if rotation occurred *)
  ur_issuer_match   : bool;               (** id_token.iss == expected *)
  ur_sig_valid      : bool;               (** id_token signature verified *)
  ur_alg_supported  : bool;               (** alg in discovery's supported list *)
}

(** Result of an upstream refresh attempt. *)
noeq type refresh_result =
  | RrOk           : upstream_response -> refresh_result
  | RrNoBearer     : refresh_result
  | RrNoEnvScope   : refresh_result
  | RrCrossTenant  : refresh_result
  | RrNoLink       : refresh_result
  | RrStaleToken   : refresh_result           (** UR-8: generation mismatch *)
  | RrIdTokenBad   : refresh_result           (** UR-7: validation failed *)
  | RrUpstreamErr  : string -> refresh_result

(* =========================================================================
   Well-formedness predicates
   ========================================================================= *)

(** UR-5: Bearer token is valid. *)
val bearer_valid : bm:bearer_meta -> bool
let bearer_valid bm =
  bm.bm_valid &&
  String.length bm.bm_user_id > 0

(** UR-2: Bearer token resolves to an environment. *)
val bearer_has_env : bm:bearer_meta -> bool
let bearer_has_env bm = Some? bm.bm_env_id

(** UR-3: Account link composite key is well-formed. *)
val link_key_valid : al:account_link -> bool
let link_key_valid al =
  al.al_env_id > 0 &&
  String.length al.al_upstream_issuer > 0 &&
  String.length al.al_upstream_sub_hash > 0

(** UR-4: The connection's issuer_url matches the stored upstream_issuer. *)
val issuer_bound : al:account_link -> bool
let issuer_bound al =
  al.al_connection_issuer = al.al_upstream_issuer

(** Account link carries a refresh token. *)
val has_token : al:account_link -> bool
let has_token al = Some? al.al_refresh_token

(** UR-7: If an id_token is present, all validation checks pass. *)
val id_token_ok : ur:upstream_response -> bool
let id_token_ok ur =
  match ur.ur_id_token with
  | Some _ -> ur.ur_issuer_match && ur.ur_sig_valid && ur.ur_alg_supported
  | None   -> true

(** UR-6 / UR-8: Upstream rotated the refresh token. *)
val rotated : ur:upstream_response -> bool
let rotated ur = Some? ur.ur_refresh_token

(* =========================================================================
   Scoping predicates (M-9 fix)
   ========================================================================= *)

(** UR-2: Lookup is scoped — bearer env_id matches link env_id. *)
val lookup_scoped : bm:bearer_meta -> al:account_link -> bool
let lookup_scoped bm al =
  match bm.bm_env_id with
  | Some eid -> eid = al.al_env_id
  | None     -> false

(** UR-2: Persist (UPDATE) is scoped — target env_id matches link. *)
val persist_scoped : target:environment_id -> al:account_link -> bool
let persist_scoped target al = target = al.al_env_id

(* =========================================================================
   Connection identity and callback currentness (UR-9 / UR-10)
   ========================================================================= *)

(** UR-9: An issuer update is admitted only when it preserves the exact
    issuer identity. In production this is enforced by management API
    validation plus the `connections_issuer_url_immutable` database trigger. *)
val connection_issuer_update_admitted : old_issuer:string -> new_issuer:string -> bool
let connection_issuer_update_admitted old_issuer new_issuer =
  old_issuer = new_issuer

(** UR-10: A stored callback snapshot is admissible only if the managed
    connection still resolves to the active/current row and all identity /
    token-client parameters match the snapshot. *)
val callback_connection_current :
  cb:callback_snapshot -> cs:connection_snapshot -> bool
let callback_connection_current cb cs =
  cs.cs_active_current &&
  cb.cb_connection_id = cs.cs_id &&
  cb.cb_env_id = cs.cs_env_id &&
  cb.cb_identifier = cs.cs_identifier &&
  cb.cb_issuer_url = cs.cs_issuer_url &&
  cb.cb_client_id = cs.cs_client_id &&
  cb.cb_client_auth_method = cs.cs_client_auth_method

(* =========================================================================
   Token chain freshness (UR-8)
   ========================================================================= *)

(** UR-8: The token presented for refresh must match the current generation.
    In production, this is enforced by account_links.upstream_refresh_token_generation:
    the row stores exactly one refresh token and persistence uses optimistic CAS on
    the loaded generation. *)
val generation_current : presented_gen:token_generation -> al:account_link -> bool
let generation_current presented_gen al =
  presented_gen = al.al_token_generation

(** UR-8: After rotation, the generation strictly increases. *)
val next_generation : al:account_link -> token_generation
let next_generation al = al.al_token_generation + 1

(* =========================================================================
   Composite precondition
   ========================================================================= *)

(** Full precondition for executing an upstream refresh. *)
val refresh_precondition :
  bm:bearer_meta -> al:account_link -> presented_gen:token_generation -> bool
let refresh_precondition bm al presented_gen =
  bearer_valid bm &&
  bearer_has_env bm &&
  lookup_scoped bm al &&
  link_key_valid al &&
  issuer_bound al &&
  has_token al &&
  generation_current presented_gen al

(* =========================================================================
   State transition
   ========================================================================= *)

(** Apply rotation to an account link, producing the post-state.
    - If upstream rotated: store new token, bump generation.
    - Otherwise: keep current token and generation unchanged. *)
val apply_rotation :
  al:account_link{has_token al} ->
  ur:upstream_response ->
  Pure account_link
    (requires True)
    (ensures fun al' ->
      al'.al_env_id = al.al_env_id /\
      al'.al_upstream_issuer = al.al_upstream_issuer /\
      al'.al_upstream_sub_hash = al.al_upstream_sub_hash /\
      al'.al_end_user_subject = al.al_end_user_subject /\
      al'.al_connection_issuer = al.al_connection_issuer /\
      (rotated ur ==>
        (Some? al'.al_refresh_token /\
         al'.al_token_generation = al.al_token_generation + 1)) /\
      (not (rotated ur) ==>
        (al'.al_refresh_token = al.al_refresh_token /\
         al'.al_token_generation = al.al_token_generation)))
let apply_rotation al ur =
  match ur.ur_refresh_token with
  | Some new_tok ->
    { al with al_refresh_token = Some new_tok;
              al_token_generation = al.al_token_generation + 1 }
  | None -> al

(** Execute upstream refresh: validates preconditions, applies rotation.

    Pre-conditions (all UR-* checked):
      - UR-5: bearer is valid
      - UR-2: bearer resolves to environment matching account link
      - UR-3: link composite key is well-formed
      - UR-4: issuer binding holds
      - UR-7: id_token validation passes (if present)
      - UR-8: presented generation matches current

    Post-conditions:
      - composite key invariant
      - issuer binding preserved
      - generation monotonicity (on rotation)
      - user subject preserved *)
val execute_refresh :
  bm:bearer_meta{bearer_valid bm /\ bearer_has_env bm} ->
  al:account_link ->
  presented_gen:token_generation ->
  ur:upstream_response ->
  refresh_result
let execute_refresh bm al presented_gen ur =
  if not (lookup_scoped bm al) then RrCrossTenant
  else if not (link_key_valid al) then RrNoLink
  else if not (issuer_bound al) then RrNoLink
  else if not (has_token al) then RrNoLink
  else if not (generation_current presented_gen al) then RrStaleToken
  else if not (id_token_ok ur) then RrIdTokenBad
  else RrOk ur

(** Apply the full transition: execute + persist rotation.
    Only called when execute_refresh returns RrOk. *)
val refresh_and_persist :
  bm:bearer_meta{bearer_valid bm /\ bearer_has_env bm} ->
  al:account_link{refresh_precondition bm al al.al_token_generation} ->
  ur:upstream_response{id_token_ok ur} ->
  Pure account_link
    (requires True)
    (ensures fun al' ->
      al'.al_env_id = al.al_env_id /\
      al'.al_upstream_issuer = al.al_upstream_issuer /\
      al'.al_upstream_sub_hash = al.al_upstream_sub_hash /\
      al'.al_end_user_subject = al.al_end_user_subject /\
      al'.al_connection_issuer = al.al_connection_issuer /\
      link_key_valid al' /\
      issuer_bound al' /\
      (rotated ur ==> al'.al_token_generation > al.al_token_generation) /\
      (not (rotated ur) ==> al'.al_token_generation = al.al_token_generation))
let refresh_and_persist bm al ur =
  apply_rotation al ur

(* =========================================================================
   Security Lemmas — Positive
   ========================================================================= *)

(** UR-2: Environment scoping is preserved across refresh. *)
val lemma_env_scoping_preserved :
  bm:bearer_meta{bearer_valid bm /\ bearer_has_env bm} ->
  al:account_link{refresh_precondition bm al al.al_token_generation} ->
  ur:upstream_response{id_token_ok ur} ->
  Lemma (let al' = refresh_and_persist bm al ur in
         al'.al_env_id = al.al_env_id /\
         persist_scoped al.al_env_id al')
let lemma_env_scoping_preserved bm al ur = ()

(** UR-3: Composite key (env_id, issuer, sub_hash) is invariant. *)
val lemma_link_key_invariant :
  bm:bearer_meta{bearer_valid bm /\ bearer_has_env bm} ->
  al:account_link{refresh_precondition bm al al.al_token_generation} ->
  ur:upstream_response{id_token_ok ur} ->
  Lemma (let al' = refresh_and_persist bm al ur in
         al'.al_env_id = al.al_env_id /\
         al'.al_upstream_issuer = al.al_upstream_issuer /\
         al'.al_upstream_sub_hash = al.al_upstream_sub_hash /\
         link_key_valid al')
let lemma_link_key_invariant bm al ur = ()

(** UR-4: Issuer binding is preserved. *)
val lemma_issuer_binding_preserved :
  bm:bearer_meta{bearer_valid bm /\ bearer_has_env bm} ->
  al:account_link{refresh_precondition bm al al.al_token_generation} ->
  ur:upstream_response{id_token_ok ur} ->
  Lemma (issuer_bound (refresh_and_persist bm al ur))
let lemma_issuer_binding_preserved bm al ur = ()

(** UR-6: When upstream rotates, the new token is persisted. *)
val lemma_rotation_persisted :
  bm:bearer_meta{bearer_valid bm /\ bearer_has_env bm} ->
  al:account_link{refresh_precondition bm al al.al_token_generation} ->
  ur:upstream_response{id_token_ok ur /\ rotated ur} ->
  Lemma (let al' = refresh_and_persist bm al ur in
         Some? al'.al_refresh_token /\
         al'.al_refresh_token = ur.ur_refresh_token)
let lemma_rotation_persisted bm al ur = ()

(** UR-8: Rotation strictly increases the generation counter. *)
val lemma_generation_increases_on_rotation :
  bm:bearer_meta{bearer_valid bm /\ bearer_has_env bm} ->
  al:account_link{refresh_precondition bm al al.al_token_generation} ->
  ur:upstream_response{id_token_ok ur /\ rotated ur} ->
  Lemma (let al' = refresh_and_persist bm al ur in
         al'.al_token_generation > al.al_token_generation /\
         al'.al_token_generation = next_generation al)
let lemma_generation_increases_on_rotation bm al ur = ()

(** UR-8: Without rotation, generation is unchanged. *)
val lemma_generation_stable_without_rotation :
  bm:bearer_meta{bearer_valid bm /\ bearer_has_env bm} ->
  al:account_link{refresh_precondition bm al al.al_token_generation} ->
  ur:upstream_response{id_token_ok ur /\ not (rotated ur)} ->
  Lemma (let al' = refresh_and_persist bm al ur in
         al'.al_token_generation = al.al_token_generation /\
         al'.al_refresh_token = al.al_refresh_token)
let lemma_generation_stable_without_rotation bm al ur = ()

(** UR-8: A stale generation is always rejected by execute_refresh. *)
val lemma_stale_generation_rejected :
  bm:bearer_meta{bearer_valid bm /\ bearer_has_env bm} ->
  al:account_link{link_key_valid al /\ issuer_bound al /\ has_token al /\
                   lookup_scoped bm al} ->
  stale_gen:token_generation{stale_gen <> al.al_token_generation} ->
  ur:upstream_response ->
  Lemma (RrStaleToken? (execute_refresh bm al stale_gen ur))
let lemma_stale_generation_rejected bm al stale_gen ur = ()

(** UR-8: After two consecutive rotations, the first token's generation
    cannot satisfy the precondition of the second link state. *)
val lemma_double_rotation_stale :
  bm:bearer_meta{bearer_valid bm /\ bearer_has_env bm} ->
  al:account_link{refresh_precondition bm al al.al_token_generation} ->
  ur:upstream_response{id_token_ok ur /\ rotated ur} ->
  Lemma (let al' = refresh_and_persist bm al ur in
         not (generation_current al.al_token_generation al'))
let lemma_double_rotation_stale bm al ur = ()

(** UR-9: Changing connection.issuer_url is never an admitted update. *)
val lemma_connection_issuer_change_rejected :
  old_issuer:string ->
  new_issuer:string{new_issuer <> old_issuer} ->
  Lemma (not (connection_issuer_update_admitted old_issuer new_issuer))
let lemma_connection_issuer_change_rejected old_issuer new_issuer = ()

(** UR-10: Inactive or non-current connection rows cannot admit callback
    exchange, even if other fields happen to match. *)
val lemma_callback_inactive_connection_rejected :
  cb:callback_snapshot ->
  cs:connection_snapshot{not cs.cs_active_current} ->
  Lemma (not (callback_connection_current cb cs))
let lemma_callback_inactive_connection_rejected cb cs = ()

(** UR-10: A callback snapshot with issuer drift cannot be admitted. *)
val lemma_callback_issuer_drift_rejected :
  cb:callback_snapshot ->
  cs:connection_snapshot{cb.cb_issuer_url <> cs.cs_issuer_url} ->
  Lemma (not (callback_connection_current cb cs))
let lemma_callback_issuer_drift_rejected cb cs = ()

(** UR-10: A callback snapshot with client authentication drift cannot be
    admitted before token exchange. *)
val lemma_callback_client_auth_drift_rejected :
  cb:callback_snapshot ->
  cs:connection_snapshot{cb.cb_client_auth_method <> cs.cs_client_auth_method} ->
  Lemma (not (callback_connection_current cb cs))
let lemma_callback_client_auth_drift_rejected cb cs = ()

(** User subject is preserved across refresh. *)
val lemma_user_subject_preserved :
  bm:bearer_meta{bearer_valid bm /\ bearer_has_env bm} ->
  al:account_link{refresh_precondition bm al al.al_token_generation} ->
  ur:upstream_response{id_token_ok ur} ->
  Lemma ((refresh_and_persist bm al ur).al_end_user_subject
          = al.al_end_user_subject)
let lemma_user_subject_preserved bm al ur = ()

(* =========================================================================
   Security Lemmas — Negative (rejection)
   ========================================================================= *)

(** UR-5: Invalid bearer cannot satisfy precondition. *)
val lemma_invalid_bearer_rejected :
  bm:bearer_meta{not (bearer_valid bm)} -> al:account_link ->
  gen:token_generation ->
  Lemma (not (refresh_precondition bm al gen))
let lemma_invalid_bearer_rejected bm al gen = ()

(** UR-2: Unscoped bearer (no env_id) cannot satisfy precondition. *)
val lemma_unscoped_bearer_rejected :
  bm:bearer_meta{bearer_valid bm /\ not (bearer_has_env bm)} ->
  al:account_link -> gen:token_generation ->
  Lemma (not (refresh_precondition bm al gen))
let lemma_unscoped_bearer_rejected bm al gen = ()

(** UR-2: Cross-tenant access is rejected by execute_refresh. *)
val lemma_cross_tenant_rejected :
  bm:bearer_meta{bearer_valid bm /\ bearer_has_env bm} ->
  al:account_link{link_key_valid al /\ Some?.v bm.bm_env_id <> al.al_env_id} ->
  gen:token_generation -> ur:upstream_response ->
  Lemma (RrCrossTenant? (execute_refresh bm al gen ur))
let lemma_cross_tenant_rejected bm al gen ur = ()

(** UR-7: Invalid id_token signature causes rejection. *)
val lemma_invalid_sig_rejected :
  ur:upstream_response{Some? ur.ur_id_token /\ not ur.ur_sig_valid} ->
  Lemma (not (id_token_ok ur))
let lemma_invalid_sig_rejected ur = ()

(** UR-7: Issuer mismatch in id_token causes rejection. *)
val lemma_issuer_mismatch_rejected :
  ur:upstream_response{Some? ur.ur_id_token /\ not ur.ur_issuer_match} ->
  Lemma (not (id_token_ok ur))
let lemma_issuer_mismatch_rejected ur = ()

(** UR-7: Unsupported alg in id_token causes rejection. *)
val lemma_alg_unsupported_rejected :
  ur:upstream_response{Some? ur.ur_id_token /\ not ur.ur_alg_supported} ->
  Lemma (not (id_token_ok ur))
let lemma_alg_unsupported_rejected ur = ()

(** UR-7: Failed id_token in execute_refresh yields RrIdTokenBad. *)
val lemma_bad_id_token_execute_rejected :
  bm:bearer_meta{bearer_valid bm /\ bearer_has_env bm} ->
  al:account_link{link_key_valid al /\ issuer_bound al /\ has_token al /\
                   lookup_scoped bm al /\ generation_current al.al_token_generation al} ->
  ur:upstream_response{not (id_token_ok ur)} ->
  Lemma (RrIdTokenBad? (execute_refresh bm al al.al_token_generation ur))
let lemma_bad_id_token_execute_rejected bm al ur = ()

(* =========================================================================
   Combined invariant
   ========================================================================= *)

(** All link invariants are preserved across a successful refresh. *)
val lemma_all_invariants_preserved :
  bm:bearer_meta{bearer_valid bm /\ bearer_has_env bm} ->
  al:account_link{refresh_precondition bm al al.al_token_generation} ->
  ur:upstream_response{id_token_ok ur} ->
  Lemma (let al' = refresh_and_persist bm al ur in
         link_key_valid al' /\
         issuer_bound al' /\
         al'.al_end_user_subject = al.al_end_user_subject /\
         al'.al_env_id = al.al_env_id /\
         persist_scoped al.al_env_id al' /\
         (rotated ur ==> al'.al_token_generation > al.al_token_generation) /\
         (not (rotated ur) ==> al'.al_token_generation = al.al_token_generation))
let lemma_all_invariants_preserved bm al ur = ()
