module Management.KeyRotation

(** Management plane signing key lifecycle formal specification.

    Models the lifecycle state machine for environment signing keys:

      NEXT ─activate─> ACTIVE ─rotate─> RETIRING ─revoke─> REVOKED

    DB schema constraints formalised:
      - `signing_keys_one_active_per_environment ON (environment_id)
         WHERE status = 'ACTIVE'`  — at most one ACTIVE key per env
      - `signing_keys_one_next_per_environment ON (environment_id)
         WHERE status = 'NEXT'`    — at most one NEXT key per env
      - `signing_keys_environment_kid_unique ON (environment_id, kid)`
         — kid unique within environment

    This module proves three key invariants:
      I1  one_active_per_environment
      I2  rotation_preserves_active_until_activate
      I3  revoked_key_excluded_from_jwks                                 *)

open FStar.List.Tot

(* =========================================================================
   Types
   ========================================================================= *)

type environment_id = nat
type key_uuid       = nat
type kid_t          = string
type algorithm_t    = string

(** Signing key status mirrors `aegaeon.signing_key_status`. *)
type key_status =
  | KeyActive
  | KeyNext
  | KeyRetiring
  | KeyRevoked

(** A signing key record. *)
type signing_key = {
  uuid         : key_uuid;
  env_id       : environment_id;
  kid          : kid_t;
  algorithm    : algorithm_t;
  status       : key_status;
  activated_at : option nat;
  revoked_at   : option nat;
}

(** The key store is a list of signing key records. *)
type key_store = list signing_key

(* =========================================================================
   Counting predicates
   ========================================================================= *)

(** Count keys with a given status in an environment. *)
val count_with_status :
  store:key_store -> eid:environment_id -> s:key_status -> Tot nat
  (decreases store)
let rec count_with_status store eid s =
  match store with
  | [] -> 0
  | k :: rest ->
    let tail = count_with_status rest eid s in
    if k.env_id = eid && k.status = s then 1 + tail
    else tail

(** Count keys with a given kid in an environment (any status). *)
val count_kid :
  store:key_store -> eid:environment_id -> kid:kid_t -> Tot nat
  (decreases store)
let rec count_kid store eid kid =
  match store with
  | [] -> 0
  | k :: rest ->
    let tail = count_kid rest eid kid in
    if k.env_id = eid && k.kid = kid then 1 + tail
    else tail

(** An environment has at most one ACTIVE key. *)
val has_at_most_one_active : store:key_store -> eid:environment_id -> Tot bool
let has_at_most_one_active store eid =
  count_with_status store eid KeyActive <= 1

(** An environment has at most one NEXT key. *)
val has_at_most_one_next : store:key_store -> eid:environment_id -> Tot bool
let has_at_most_one_next store eid =
  count_with_status store eid KeyNext <= 1

(** Kid is unique within an environment. *)
val kid_unique : store:key_store -> eid:environment_id -> kid:kid_t -> Tot bool
let kid_unique store eid kid =
  count_kid store eid kid <= 1

(** Store well-formedness: for every environment present in the store,
    - at most one ACTIVE key
    - at most one NEXT key
    - all kids unique within that environment *)
val well_formed : store:key_store -> Tot bool
let well_formed store =
  for_all
    (fun k ->
      has_at_most_one_active store k.env_id &&
      has_at_most_one_next store k.env_id &&
      kid_unique store k.env_id k.kid)
    store

(* =========================================================================
   JWKS construction
   ========================================================================= *)

(** Build the public JWKS for an environment.
    Only ACTIVE and NEXT keys are included; RETIRING keys MAY be included
    for grace periods; REVOKED keys are NEVER included.

    Models the `GET /.well-known/jwks.json` endpoint behaviour. *)
val jwks_keys : store:key_store -> eid:environment_id -> Tot (list signing_key)
  (decreases store)
let rec jwks_keys store eid =
  match store with
  | [] -> []
  | k :: rest ->
    let tail = jwks_keys rest eid in
    if k.env_id = eid && (KeyActive? k.status || KeyNext? k.status) then
      k :: tail
    else
      tail

(** I3 predicate: no REVOKED key appears in the JWKS. *)
val no_revoked_in_jwks : store:key_store -> eid:environment_id -> Tot bool
let no_revoked_in_jwks store eid =
  for_all (fun k -> not (KeyRevoked? k.status)) (jwks_keys store eid)

(* =========================================================================
   Operations
   ========================================================================= *)

(** Generate a new NEXT key for an environment.

    Preconditions:
    - No existing NEXT key (at most one NEXT per env)
    - Kid must be unique within the environment *)
val generate_next_key :
  store:key_store -> new_key:signing_key ->
  Pure (option key_store)
    (requires True)
    (ensures fun result ->
      match result with
      | Some store' ->
        has_at_most_one_next store new_key.env_id = true /\
        count_with_status store new_key.env_id KeyNext = 0 /\
        kid_unique store new_key.env_id new_key.kid = true /\
        count_kid store new_key.env_id new_key.kid = 0 /\
        KeyNext? new_key.status /\
        mem new_key store'
      | None ->
        count_with_status store new_key.env_id KeyNext > 0 \/
        count_kid store new_key.env_id new_key.kid > 0 \/
        not (KeyNext? new_key.status))
let generate_next_key store new_key =
  if count_with_status store new_key.env_id KeyNext > 0 then None
  else if count_kid store new_key.env_id new_key.kid > 0 then None
  else if not (KeyNext? new_key.status) then None
  else Some (new_key :: store)

(** Update the status of a key identified by (env_id, kid). *)
val update_key_status :
  store:key_store -> eid:environment_id -> kid:kid_t ->
  old_status:key_status -> new_status:key_status -> now:nat ->
  Tot (option key_store)
  (decreases store)
let rec update_key_status store eid kid old_status new_status now =
  match store with
  | [] -> None
  | k :: rest ->
    if k.env_id = eid && k.kid = kid && k.status = old_status then
      let updated = { k with
        status = new_status;
        activated_at = (if KeyActive? new_status then Some now else k.activated_at);
        revoked_at   = (if KeyRevoked? new_status then Some now else k.revoked_at);
      } in
      Some (updated :: rest)
    else
      match update_key_status rest eid kid old_status new_status now with
      | None -> None
      | Some rest' -> Some (k :: rest')

(** Demote the first ACTIVE key for an environment to RETIRING.
    Extracted from activate_next_key for separate proof reasoning. *)
val demote_active : store:key_store -> eid:environment_id -> Tot key_store
  (decreases store)
let rec demote_active store eid =
  match store with
  | [] -> []
  | k :: rest ->
    if k.env_id = eid && KeyActive? k.status then
      { k with status = KeyRetiring } :: rest
    else
      k :: demote_active rest eid

(** Activate the NEXT key: NEXT → ACTIVE.
    Simultaneously demotes the current ACTIVE key to RETIRING.

    This is the core rotation operation:
      1. Find the NEXT key → set to ACTIVE
      2. Find the current ACTIVE key → set to RETIRING

    Precondition: exactly one NEXT key and at most one ACTIVE key exist. *)
val activate_next_key :
  store:key_store -> eid:environment_id -> now:nat ->
  Tot (option key_store)
let activate_next_key store eid now =
  (* Step 1: Demote ACTIVE → RETIRING *)
  let store_after_demote = demote_active store eid in
  (* Step 2: Promote NEXT → ACTIVE *)
  update_key_status store_after_demote eid
    (* find the NEXT key's kid *)
    (match filter (fun k -> k.env_id = eid && KeyNext? k.status) store with
     | [k] -> k.kid
     | _ -> "")  (* empty string kid will not match anything *)
    KeyNext KeyActive now

(** Revoke a key: ACTIVE or RETIRING → REVOKED. *)
val revoke_key :
  store:key_store -> eid:environment_id -> kid:kid_t -> now:nat ->
  Tot (option key_store)
let revoke_key store eid kid now =
  (* Try ACTIVE → REVOKED first, then RETIRING → REVOKED *)
  match update_key_status store eid kid KeyActive KeyRevoked now with
  | Some s -> Some s
  | None -> update_key_status store eid kid KeyRetiring KeyRevoked now

(* =========================================================================
   I1: one_active_per_environment
   =========================================================================

   After any valid operation, at most one ACTIVE key exists per
   environment. *)

(** Generating a NEXT key does not affect ACTIVE count. *)
val lemma_generate_preserves_active_count :
  store:key_store -> new_key:signing_key ->
  Lemma
    (requires
      well_formed store /\
      KeyNext? new_key.status /\
      count_with_status store new_key.env_id KeyNext = 0 /\
      count_kid store new_key.env_id new_key.kid = 0)
    (ensures (
      let result = generate_next_key store new_key in
      Some? result /\
      count_with_status (Some?.v result) new_key.env_id KeyActive
        = count_with_status store new_key.env_id KeyActive))
let lemma_generate_preserves_active_count store new_key =
  (* Adding a NEXT key does not change the ACTIVE count because
     KeyNext? new_key.status, so the new key is not counted as ACTIVE. *)
  ()

(** After demoting, no ACTIVE keys remain for the environment
    (given at most one existed before).

    Proof: by structural induction on the store.
    - If k matches (ACTIVE for eid): k becomes RETIRING, rest unchanged.
      Since count(k::rest) = 1 + count(rest) ≤ 1, count(rest) = 0.
      Result count = 0 + 0 = 0.
    - If k does not match: recurse. k contributes 0 to ACTIVE count.
      By IH, demote_active rest has 0 ACTIVE. Total: 0. *)
val lemma_demote_zeroes_active :
  store:key_store -> eid:environment_id ->
  Lemma (requires count_with_status store eid KeyActive <= 1)
        (ensures count_with_status (demote_active store eid) eid KeyActive = 0)
  (decreases store)
let rec lemma_demote_zeroes_active store eid =
  match store with
  | [] -> ()
  | k :: rest ->
    if k.env_id = eid && KeyActive? k.status then ()
    else lemma_demote_zeroes_active rest eid

(** Promoting a NEXT key to ACTIVE increases the ACTIVE count by exactly 1.

    Proof: by structural induction on the store, mirroring update_key_status.
    - If k matches (NEXT key with given kid): k becomes ACTIVE, rest unchanged.
      k was NEXT (contributed 0 to ACTIVE), now ACTIVE (contributes 1).
      Result count = old count + 1.
    - If k does not match: recurse on rest. k unchanged, IH gives rest' count.
    - If update_key_status returns None: postcondition is True. *)
val lemma_update_next_to_active_count :
  store:key_store -> eid:environment_id -> kid:kid_t -> now:nat ->
  Lemma (ensures (
    match update_key_status store eid kid KeyNext KeyActive now with
    | Some store' ->
      count_with_status store' eid KeyActive =
        count_with_status store eid KeyActive + 1
    | None -> True))
  (decreases store)
let rec lemma_update_next_to_active_count store eid kid now =
  match store with
  | [] -> ()
  | k :: rest ->
    if k.env_id = eid && k.kid = kid && k.status = KeyNext then ()
    else lemma_update_next_to_active_count rest eid kid now

(** After activation, the ACTIVE count remains at most 1.
    Activation demotes the old ACTIVE → RETIRING and promotes NEXT → ACTIVE.

    Proof: compose the two helper lemmas.
    1. lemma_demote_zeroes_active: after demote, ACTIVE count = 0.
    2. lemma_update_next_to_active_count: if promotion succeeds,
       ACTIVE count = 0 + 1 = 1 ≤ 1.  If it fails, None → True. *)
val lemma_activate_preserves_one_active :
  store:key_store -> eid:environment_id -> now:nat ->
  Lemma
    (requires
      well_formed store /\
      count_with_status store eid KeyNext = 1 /\
      count_with_status store eid KeyActive <= 1)
    (ensures (
      match activate_next_key store eid now with
      | Some store' -> count_with_status store' eid KeyActive <= 1
      | None -> True))
let lemma_activate_preserves_one_active store eid now =
  lemma_demote_zeroes_active store eid;
  let store_d = demote_active store eid in
  let kid = match filter (fun k -> k.env_id = eid && KeyNext? k.status) store with
    | [k] -> k.kid
    | _ -> "" in
  lemma_update_next_to_active_count store_d eid kid now

(** Helper: update_key_status from old_status to REVOKED can only
    decrease the count of old_status keys and does not increase
    ACTIVE count if old_status is ACTIVE or RETIRING. *)
val lemma_update_key_status_count :
  store:key_store -> eid:environment_id -> kid:kid_t ->
  old_status:key_status -> now:nat ->
  Lemma (ensures (
    match update_key_status store eid kid old_status KeyRevoked now with
    | Some store' ->
      (* If we revoked an ACTIVE key, ACTIVE count decreases by 1 *)
      (KeyActive? old_status ==>
        count_with_status store' eid KeyActive =
          count_with_status store eid KeyActive - 1) /\
      (* If we revoked a non-ACTIVE key, ACTIVE count is unchanged *)
      (not (KeyActive? old_status) ==>
        count_with_status store' eid KeyActive =
          count_with_status store eid KeyActive)
    | None -> True))
  (decreases store)
let rec lemma_update_key_status_count store eid kid old_status now =
  match store with
  | [] -> ()
  | k :: rest ->
    if k.env_id = eid && k.kid = kid && k.status = old_status then
      (* Found the key: it becomes REVOKED. If it was ACTIVE,
         count decreases by 1. If RETIRING, ACTIVE count is unchanged
         because the updated key has status=REVOKED ≠ ACTIVE. *)
      ()
    else
      lemma_update_key_status_count rest eid kid old_status now

(** Revoking a key can only decrease the ACTIVE count. *)
val lemma_revoke_decreases_active :
  store:key_store -> eid:environment_id -> kid:kid_t -> now:nat ->
  Lemma
    (requires well_formed store)
    (ensures (
      match revoke_key store eid kid now with
      | Some store' ->
        count_with_status store' eid KeyActive <=
          count_with_status store eid KeyActive
      | None -> True))
let lemma_revoke_decreases_active store eid kid now =
  (* revoke_key tries ACTIVE → REVOKED first, then RETIRING → REVOKED.
     Case 1: ACTIVE key found — ACTIVE count decreases by 1.
     Case 2: RETIRING key found — ACTIVE count unchanged.
     Both cases: result <= original. *)
  lemma_update_key_status_count store eid kid KeyActive now;
  match update_key_status store eid kid KeyActive KeyRevoked now with
  | Some _ -> () (* Case 1: ACTIVE → REVOKED, count decreases *)
  | None ->
    (* Case 2: no ACTIVE key with that kid, try RETIRING *)
    lemma_update_key_status_count store eid kid KeyRetiring now

(* =========================================================================
   I2: rotation_preserves_active_until_activate
   =========================================================================

   Generating a NEXT key does not change the ACTIVE key.  The environment
   continues to sign with the existing ACTIVE key until `activate_next_key`
   is called explicitly. *)

(** The ACTIVE key for an environment. *)
val active_key_for : store:key_store -> eid:environment_id -> Tot (option signing_key)
  (decreases store)
let rec active_key_for store eid =
  match store with
  | [] -> None
  | k :: rest ->
    if k.env_id = eid && KeyActive? k.status then Some k
    else active_key_for rest eid

(** Generating a NEXT key preserves the active key identity. *)
val lemma_generate_preserves_active_key :
  store:key_store -> new_key:signing_key ->
  Lemma
    (requires
      KeyNext? new_key.status /\
      count_with_status store new_key.env_id KeyNext = 0 /\
      count_kid store new_key.env_id new_key.kid = 0)
    (ensures (
      match generate_next_key store new_key with
      | Some store' ->
        active_key_for store' new_key.env_id = active_key_for store new_key.env_id
      | None -> True))
let lemma_generate_preserves_active_key store new_key =
  (* The new key has status NEXT, so active_key_for skips it
     and finds the same ACTIVE key (or None) as before. *)
  ()

(* =========================================================================
   I3: revoked_key_excluded_from_jwks
   =========================================================================

   REVOKED keys never appear in the JWKS endpoint output. *)

(** REVOKED keys are never in the JWKS. *)
val lemma_revoked_excluded_from_jwks :
  store:key_store -> eid:environment_id ->
  Lemma (ensures no_revoked_in_jwks store eid = true)
  (decreases store)
let rec lemma_revoked_excluded_from_jwks store eid =
  match store with
  | [] -> ()
  | k :: rest ->
    lemma_revoked_excluded_from_jwks rest eid;
    (* If k.env_id = eid, then k is included in jwks_keys only if
       KeyActive? k.status || KeyNext? k.status.  Since KeyRevoked
       is neither, a REVOKED key is never included. *)
    ()

(** After revoking a key, the JWKS still contains no REVOKED keys.
    (Trivially follows from lemma_revoked_excluded_from_jwks.) *)
val lemma_revoke_then_jwks_clean :
  store:key_store -> eid:environment_id -> kid:kid_t -> now:nat ->
  Lemma (ensures (
    match revoke_key store eid kid now with
    | Some store' -> no_revoked_in_jwks store' eid = true
    | None -> True))
let lemma_revoke_then_jwks_clean store eid kid now =
  match revoke_key store eid kid now with
  | Some store' -> lemma_revoked_excluded_from_jwks store' eid
  | None -> ()
