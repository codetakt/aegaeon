module Federation.PgRepo

(** Federation PostgreSQL repository invariants formal specification.

    Models the three federation tables from
    `db/migrations/20260213090000_federation_tables.sql`:

      federation_trust_anchors   — configured trust anchors per environment
      federation_entity_cache    — cached entity configuration JWS
      federation_trust_chains    — cached resolved trust chains

    DB constraints formalised:
      - `federation_trust_anchors_env_entity_unique ON (environment_id, entity_id)`
      - `federation_entity_cache_env_entity_unique ON (environment_id, entity_id)`
      - `federation_entity_cache_expires_after_fetch CHECK (expires_at > fetched_at)`
      - `federation_trust_chains_env_leaf_anchor_unique ON (env_id, leaf, anchor)`
      - `federation_trust_chains_expires_after_resolve CHECK (expires_at > resolved_at)`

    This module proves six key invariants:
      R1  cache_get_expired        — expired entries invisible to get
      R2  cleanup_removes_expired  — cleanup leaves no expired entries
      R3  upsert_uniqueness        — at most one entry per natural key
      R4  chain_staleness_bound    — cached chain expires ≤ min(stmt.exp)
      R5  tenant_isolation         — cross-environment operations do not interfere
      R6  cache_roundtrip          — upsert then get returns stored entry

    Expiration boundary: `now >= expires_at` ⟹ expired (matches F* is_expired
    convention: strict `<` for valid). *)

open FStar.List.Tot

(* =========================================================================
   Types
   ========================================================================= *)

(** Opaque identifiers — modelled as nat for decidable equality. *)
type environment_id = nat
type entity_id_t    = string
type cache_uuid     = nat

(** A cached entity configuration entry.
    Models one row of `federation_entity_cache`. *)
type entity_cache_entry = {
  ec_id             : cache_uuid;
  ec_env_id         : environment_id;
  ec_entity_id      : entity_id_t;
  ec_jws            : string;            (** entity_configuration_jws *)
  ec_fetched_at     : nat;               (** epoch seconds *)
  ec_expires_at     : nat;               (** epoch seconds *)
}

(** A cached trust chain entry.
    Models one row of `federation_trust_chains`. *)
type chain_cache_entry = {
  cc_id             : cache_uuid;
  cc_env_id         : environment_id;
  cc_leaf_entity_id : entity_id_t;
  cc_anchor_entity_id : entity_id_t;
  cc_chain_jwts     : string;            (** JSON array of JWTs *)
  cc_resolved_at    : nat;               (** epoch seconds *)
  cc_expires_at     : nat;               (** epoch seconds *)
}

(** A trust anchor entry.
    Models one row of `federation_trust_anchors`. *)
type trust_anchor_entry = {
  ta_id             : cache_uuid;
  ta_env_id         : environment_id;
  ta_entity_id      : entity_id_t;
  ta_jwks           : string;            (** JWKS JSON *)
  ta_created_at     : nat;
  ta_updated_at     : nat;
}

(** The entity cache is a list of cache entries. *)
type entity_cache = list entity_cache_entry

(** The chain cache is a list of chain entries. *)
type chain_cache  = list chain_cache_entry

(** The trust anchor store is a list of anchor entries. *)
type anchor_store = list trust_anchor_entry

(* =========================================================================
   Entry validity predicates
   ========================================================================= *)

(** An entity cache entry satisfies the DB constraint
    `expires_at > fetched_at`. *)
val ec_well_formed : entity_cache_entry -> Tot bool
let ec_well_formed e = e.ec_expires_at > e.ec_fetched_at

(** A chain cache entry satisfies `expires_at > resolved_at`. *)
val cc_well_formed : chain_cache_entry -> Tot bool
let cc_well_formed e = e.cc_expires_at > e.cc_resolved_at

(** An entity cache entry is not expired at time `now`.
    Expiration boundary: `now >= expires_at` ⟹ expired. *)
val ec_is_valid : now:nat -> e:entity_cache_entry -> Tot bool
let ec_is_valid now e = now < e.ec_expires_at

(** A chain cache entry is not expired at time `now`. *)
val cc_is_valid : now:nat -> e:chain_cache_entry -> Tot bool
let cc_is_valid now e = now < e.cc_expires_at

(* =========================================================================
   Store well-formedness
   ========================================================================= *)

(** Count entries matching (env_id, entity_id) in an entity cache. *)
val count_ec_key :
  cache:entity_cache -> eid:environment_id -> entity:entity_id_t -> Tot nat
  (decreases cache)
let rec count_ec_key cache eid entity =
  match cache with
  | [] -> 0
  | e :: rest ->
    let tail = count_ec_key rest eid entity in
    if e.ec_env_id = eid && e.ec_entity_id = entity then 1 + tail
    else tail

(** Count entries matching (env_id, leaf, anchor) in a chain cache. *)
val count_cc_key :
  cache:chain_cache -> eid:environment_id ->
  leaf:entity_id_t -> anchor:entity_id_t -> Tot nat
  (decreases cache)
let rec count_cc_key cache eid leaf anchor =
  match cache with
  | [] -> 0
  | e :: rest ->
    let tail = count_cc_key rest eid leaf anchor in
    if e.cc_env_id = eid && e.cc_leaf_entity_id = leaf &&
       e.cc_anchor_entity_id = anchor then 1 + tail
    else tail

(** Count trust anchors matching (env_id, entity_id). *)
val count_ta_key :
  store:anchor_store -> eid:environment_id -> entity:entity_id_t -> Tot nat
  (decreases store)
let rec count_ta_key store eid entity =
  match store with
  | [] -> 0
  | a :: rest ->
    let tail = count_ta_key rest eid entity in
    if a.ta_env_id = eid && a.ta_entity_id = entity then 1 + tail
    else tail

(** Entity cache well-formedness: all entries satisfy the DB constraint,
    and no duplicate natural keys. *)
val ec_store_well_formed : entity_cache -> Tot bool
let ec_store_well_formed cache =
  for_all (fun e ->
    ec_well_formed e &&
    count_ec_key cache e.ec_env_id e.ec_entity_id <= 1
  ) cache

(** Chain cache well-formedness. *)
val cc_store_well_formed : chain_cache -> Tot bool
let cc_store_well_formed cache =
  for_all (fun e ->
    cc_well_formed e &&
    count_cc_key cache e.cc_env_id e.cc_leaf_entity_id e.cc_anchor_entity_id <= 1
  ) cache

(* =========================================================================
   Operations: Entity Cache
   ========================================================================= *)

(** Get a non-expired entity cache entry by (env_id, entity_id). *)
val ec_get :
  cache:entity_cache -> eid:environment_id ->
  entity:entity_id_t -> now:nat -> Tot (option entity_cache_entry)
  (decreases cache)
let rec ec_get cache eid entity now =
  match cache with
  | [] -> None
  | e :: rest ->
    if e.ec_env_id = eid && e.ec_entity_id = entity && ec_is_valid now e then
      Some e
    else
      ec_get rest eid entity now

(** Upsert an entity cache entry.
    If an entry with the same (env_id, entity_id) exists, replace it.
    Otherwise, insert at the front. *)
val ec_upsert :
  cache:entity_cache -> entry:entity_cache_entry ->
  Tot entity_cache
  (decreases cache)
let rec ec_upsert cache entry =
  match cache with
  | [] -> [entry]
  | e :: rest ->
    if e.ec_env_id = entry.ec_env_id && e.ec_entity_id = entry.ec_entity_id then
      entry :: rest  (* replace existing *)
    else
      e :: ec_upsert rest entry

(** Remove expired entries from an entity cache. *)
val ec_cleanup : cache:entity_cache -> now:nat -> Tot entity_cache
  (decreases cache)
let rec ec_cleanup cache now =
  match cache with
  | [] -> []
  | e :: rest ->
    let cleaned_rest = ec_cleanup rest now in
    if ec_is_valid now e then e :: cleaned_rest
    else cleaned_rest

(* =========================================================================
   Operations: Chain Cache
   ========================================================================= *)

(** Get a non-expired chain cache entry. *)
val cc_get :
  cache:chain_cache -> eid:environment_id ->
  leaf:entity_id_t -> anchor:entity_id_t -> now:nat ->
  Tot (option chain_cache_entry)
  (decreases cache)
let rec cc_get cache eid leaf anchor now =
  match cache with
  | [] -> None
  | e :: rest ->
    if e.cc_env_id = eid && e.cc_leaf_entity_id = leaf &&
       e.cc_anchor_entity_id = anchor && cc_is_valid now e then
      Some e
    else
      cc_get rest eid leaf anchor now

(** Upsert a chain cache entry. *)
val cc_upsert :
  cache:chain_cache -> entry:chain_cache_entry ->
  Tot chain_cache
  (decreases cache)
let rec cc_upsert cache entry =
  match cache with
  | [] -> [entry]
  | e :: rest ->
    if e.cc_env_id = entry.cc_env_id &&
       e.cc_leaf_entity_id = entry.cc_leaf_entity_id &&
       e.cc_anchor_entity_id = entry.cc_anchor_entity_id then
      entry :: rest
    else
      e :: cc_upsert rest entry

(** Remove expired entries from a chain cache. *)
val cc_cleanup : cache:chain_cache -> now:nat -> Tot chain_cache
  (decreases cache)
let rec cc_cleanup cache now =
  match cache with
  | [] -> []
  | e :: rest ->
    let cleaned_rest = cc_cleanup rest now in
    if cc_is_valid now e then e :: cleaned_rest
    else cleaned_rest

(* =========================================================================
   R1: cache_get_expired — expired entries are invisible
   =========================================================================

   If `now >= expires_at`, `ec_get` returns None for that entry.
   Matches the production code:
     `entries.iter().find(|e| ... && e.expires_at > now_epoch_secs)` *)

(** Helper: if an entry is expired, ec_get skips it. *)
val lemma_ec_get_skips_expired :
  cache:entity_cache -> eid:environment_id -> entity:entity_id_t -> now:nat ->
  Lemma (ensures (
    match ec_get cache eid entity now with
    | Some e -> ec_is_valid now e
    | None   -> True))
  (decreases cache)
let rec lemma_ec_get_skips_expired cache eid entity now =
  match cache with
  | [] -> ()
  | e :: rest ->
    if e.ec_env_id = eid && e.ec_entity_id = entity && ec_is_valid now e then ()
    else lemma_ec_get_skips_expired rest eid entity now

(** Corollary: if all matching entries are expired, get returns None. *)
val lemma_ec_get_expired_returns_none :
  cache:entity_cache -> eid:environment_id -> entity:entity_id_t -> now:nat ->
  Lemma
    (requires (for_all (fun e ->
      not (e.ec_env_id = eid && e.ec_entity_id = entity) ||
      not (ec_is_valid now e)) cache))
    (ensures ec_get cache eid entity now == None)
  (decreases cache)
let rec lemma_ec_get_expired_returns_none cache eid entity now =
  match cache with
  | [] -> ()
  | e :: rest ->
    lemma_ec_get_expired_returns_none rest eid entity now

(** Same property for chain cache. *)
val lemma_cc_get_skips_expired :
  cache:chain_cache -> eid:environment_id ->
  leaf:entity_id_t -> anchor:entity_id_t -> now:nat ->
  Lemma (ensures (
    match cc_get cache eid leaf anchor now with
    | Some e -> cc_is_valid now e
    | None   -> True))
  (decreases cache)
let rec lemma_cc_get_skips_expired cache eid leaf anchor now =
  match cache with
  | [] -> ()
  | e :: rest ->
    if e.cc_env_id = eid && e.cc_leaf_entity_id = leaf &&
       e.cc_anchor_entity_id = anchor && cc_is_valid now e then ()
    else lemma_cc_get_skips_expired rest eid leaf anchor now

(* =========================================================================
   R2: cleanup_removes_expired — no expired entries after cleanup
   ========================================================================= *)

(** After cleanup, every remaining entry is still valid. *)
val lemma_ec_cleanup_no_expired :
  cache:entity_cache -> now:nat ->
  Lemma (ensures for_all (fun e -> ec_is_valid now e) (ec_cleanup cache now))
  (decreases cache)
let rec lemma_ec_cleanup_no_expired cache now =
  match cache with
  | [] -> ()
  | _ :: rest -> lemma_ec_cleanup_no_expired rest now

(** After cleanup, no entry has `expires_at <= now`. *)
val lemma_ec_cleanup_all_valid :
  cache:entity_cache -> now:nat ->
  Lemma (ensures (
    let cleaned = ec_cleanup cache now in
    forall (e:entity_cache_entry). mem e cleaned ==> now < e.ec_expires_at))
  (decreases cache)
let rec lemma_ec_cleanup_all_valid cache now =
  match cache with
  | [] -> ()
  | _ :: rest -> lemma_ec_cleanup_all_valid rest now

(** Same for chain cache. *)
val lemma_cc_cleanup_no_expired :
  cache:chain_cache -> now:nat ->
  Lemma (ensures for_all (fun e -> cc_is_valid now e) (cc_cleanup cache now))
  (decreases cache)
let rec lemma_cc_cleanup_no_expired cache now =
  match cache with
  | [] -> ()
  | _ :: rest -> lemma_cc_cleanup_no_expired rest now

(** Cleanup preserves all non-expired entries. *)
val lemma_ec_cleanup_preserves_valid :
  cache:entity_cache -> now:nat ->
  Lemma (ensures (
    forall (e:entity_cache_entry).
      (mem e cache /\ ec_is_valid now e) ==>
      mem e (ec_cleanup cache now)))
  (decreases cache)
let rec lemma_ec_cleanup_preserves_valid cache now =
  match cache with
  | [] -> ()
  | _ :: rest -> lemma_ec_cleanup_preserves_valid rest now

(* =========================================================================
   R3: upsert_uniqueness — at most one entry per natural key
   =========================================================================

   After ec_upsert, the count for the entry's natural key is exactly 1
   (if the store was well-formed before). *)

(** Helper: ec_upsert does not increase count for other keys. *)
val lemma_ec_upsert_other_key_unchanged :
  cache:entity_cache -> entry:entity_cache_entry ->
  eid:environment_id -> entity:entity_id_t ->
  Lemma
    (requires not (eid = entry.ec_env_id && entity = entry.ec_entity_id))
    (ensures count_ec_key (ec_upsert cache entry) eid entity
             = count_ec_key cache eid entity)
  (decreases cache)
let rec lemma_ec_upsert_other_key_unchanged cache entry eid entity =
  match cache with
  | [] -> ()
  | e :: rest ->
    if e.ec_env_id = entry.ec_env_id && e.ec_entity_id = entry.ec_entity_id then ()
    else lemma_ec_upsert_other_key_unchanged rest entry eid entity

(** After upsert on a well-formed store, the entry's key has count exactly 1. *)
val lemma_ec_upsert_preserves_uniqueness :
  cache:entity_cache -> entry:entity_cache_entry ->
  Lemma
    (requires count_ec_key cache entry.ec_env_id entry.ec_entity_id <= 1)
    (ensures count_ec_key (ec_upsert cache entry) entry.ec_env_id
                          entry.ec_entity_id = 1)
  (decreases cache)
let rec lemma_ec_upsert_preserves_uniqueness cache entry =
  match cache with
  | [] -> ()
  | e :: rest ->
    if e.ec_env_id = entry.ec_env_id && e.ec_entity_id = entry.ec_entity_id then
      (* Replace: count stays at 1 because we replaced exactly one match *)
      ()
    else
      lemma_ec_upsert_preserves_uniqueness rest entry

(* =========================================================================
   R4: chain_staleness_bound — cached chain expires ≤ min(stmt.exp)
   =========================================================================

   A cached trust chain's expires_at must not exceed the minimum
   expiry of its constituent entity statements.  This ensures the
   cache does not serve a chain whose underlying statements have
   expired.

   Production code: `resolve_trust_chain_cached` computes
     `expires_at = min(config_ttl + now, min(stmt.exp for stmt in chain))`
   So: `cc_expires_at <= min_stmt_expiry`.                               *)

(** A chain cache entry has a staleness-bounded expiry. *)
val chain_staleness_bounded :
  entry:chain_cache_entry -> min_stmt_expiry:nat -> Tot bool
let chain_staleness_bounded entry min_stmt_expiry =
  entry.cc_expires_at <= min_stmt_expiry

(** Compute the cache TTL from config and statement expiries.
    cache_ttl = min(config_ttl + now, min_stmt_expiry) *)
val compute_chain_ttl :
  now:nat -> config_ttl:nat -> min_stmt_expiry:nat -> Tot nat
let compute_chain_ttl now config_ttl min_stmt_expiry =
  let config_expiry = now + config_ttl in
  if config_expiry <= min_stmt_expiry then config_expiry
  else min_stmt_expiry

(** The computed TTL never exceeds the minimum statement expiry. *)
val lemma_chain_ttl_bounded :
  now:nat -> config_ttl:nat -> min_stmt_expiry:nat ->
  Lemma (ensures
    compute_chain_ttl now config_ttl min_stmt_expiry <= min_stmt_expiry)
let lemma_chain_ttl_bounded now config_ttl min_stmt_expiry = ()

(** If a chain is stored with the computed TTL and a statement expires,
    the chain is no longer valid (conservative freshness). *)
val lemma_chain_stale_after_stmt_expires :
  entry:chain_cache_entry -> min_stmt_expiry:nat -> now:nat ->
  Lemma
    (requires
      chain_staleness_bounded entry min_stmt_expiry /\
      now >= min_stmt_expiry)
    (ensures not (cc_is_valid now entry))
let lemma_chain_stale_after_stmt_expires entry min_stmt_expiry now = ()

(** Upsert with computed TTL preserves the staleness bound. *)
val lemma_chain_upsert_staleness :
  now:nat -> config_ttl:nat -> min_stmt_expiry:nat ->
  Lemma (ensures (
    let ttl = compute_chain_ttl now config_ttl min_stmt_expiry in
    ttl <= min_stmt_expiry))
let lemma_chain_upsert_staleness now config_ttl min_stmt_expiry =
  lemma_chain_ttl_bounded now config_ttl min_stmt_expiry

(* =========================================================================
   R5: tenant_isolation — cross-environment non-interference
   =========================================================================

   Operations on env_id₁ do not affect lookups for env_id₂. *)

(** ec_upsert for env₁ does not affect get for env₂. *)
val lemma_ec_tenant_isolation :
  cache:entity_cache -> entry:entity_cache_entry ->
  other_env:environment_id -> entity:entity_id_t -> now:nat ->
  Lemma
    (requires other_env <> entry.ec_env_id)
    (ensures ec_get (ec_upsert cache entry) other_env entity now
             == ec_get cache other_env entity now)
  (decreases cache)
let rec lemma_ec_tenant_isolation cache entry other_env entity now =
  match cache with
  | [] -> ()
  | e :: rest ->
    if e.ec_env_id = entry.ec_env_id && e.ec_entity_id = entry.ec_entity_id then
      (* Replaced entry has different env_id, so get for other_env skips it *)
      ()
    else
      lemma_ec_tenant_isolation rest entry other_env entity now

(** Cleanup does not break tenant isolation: it only removes entries based
    on temporal validity, not environment_id. *)
val lemma_ec_cleanup_tenant_neutral :
  cache:entity_cache -> now:nat ->
  eid:environment_id -> entity:entity_id_t ->
  Lemma (ensures (
    match ec_get cache eid entity now with
    | Some e -> ec_is_valid now e ==> mem e (ec_cleanup cache now)
    | None -> True))
  (decreases cache)
let rec lemma_ec_cleanup_tenant_neutral cache now eid entity =
  match cache with
  | [] -> ()
  | _ :: rest -> lemma_ec_cleanup_tenant_neutral rest now eid entity

(* =========================================================================
   R6: cache_roundtrip — upsert then get returns stored entry
   =========================================================================

   Immediately after upsert, get returns the new entry (if not expired). *)

(** After ec_upsert, get returns the upserted entry when it is valid. *)
val lemma_ec_upsert_then_get :
  cache:entity_cache -> entry:entity_cache_entry -> now:nat ->
  Lemma
    (requires
      ec_is_valid now entry /\
      count_ec_key cache entry.ec_env_id entry.ec_entity_id <= 1)
    (ensures
      ec_get (ec_upsert cache entry) entry.ec_env_id entry.ec_entity_id now
        == Some entry)
  (decreases cache)
let rec lemma_ec_upsert_then_get cache entry now =
  match cache with
  | [] -> ()
  | e :: rest ->
    if e.ec_env_id = entry.ec_env_id && e.ec_entity_id = entry.ec_entity_id then
      (* Replaced: entry is at head, and it's valid *)
      ()
    else
      (* e doesn't match the key, so ec_get recurses *)
      if e.ec_env_id = entry.ec_env_id && e.ec_entity_id = entry.ec_entity_id &&
         ec_is_valid now e then
        (* This branch is unreachable given the guard above, but F* needs it *)
        ()
      else
        lemma_ec_upsert_then_get rest entry now
