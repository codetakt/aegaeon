module Management.ClientLifecycle

(** Management plane client CRUD formal specification.

    Models the lifecycle of OAuth 2.0 clients in the management plane.
    Each client belongs to exactly one environment; identifiers must be
    unique within that environment (among non-deleted clients).  Deletion
    is soft: the client record remains with status='DELETED' and a
    `deleted_at` timestamp.

    Formalised from the DB schema constraints:
      - `clients_env_client_identifier_unique ON (environment_id, client_identifier)
         WHERE status <> 'DELETED'`
      - `environment_id` FK to `aegaeon.environments`
      - `redirect_uris text[] NOT NULL`

    This module proves three key invariants:
      I1  client_create_requires_environment
      I2  client_identifier_unique_within_environment
      I3  client_delete_is_soft                                          *)

open FStar.List.Tot

(* =========================================================================
   Types
   ========================================================================= *)

(** Opaque identifiers — modelled as nat for decidable equality. *)
type environment_id = nat
type client_uuid    = nat

(** Client status mirrors `aegaeon.client_status`. *)
type client_status =
  | Active
  | Deleted

(** A redirect URI is a non-empty string. *)
type redirect_uri = string

(** Minimal client record capturing the management-relevant fields. *)
type client = {
  uuid           : client_uuid;
  env_id         : environment_id;
  identifier     : string;         (** `client_identifier` in DB *)
  redirect_uris  : list redirect_uri;
  status         : client_status;
  deleted_at     : option nat;     (** epoch seconds, set on soft-delete *)
}

(** An environment record (existence witness). *)
type environment = {
  env_uuid : environment_id;
  active   : bool;
}

(** The client store is a list of client records plus known environments. *)
type client_store = {
  clients      : list client;
  environments : list environment;
}

(** Tail-recursive list reversal with append.
    Local definition to avoid FStar.List.Tot.Properties.rev_append shadowing
    (which is a lemma returning unit, not a function returning list). *)
let rec client_rev_append (l1:list client) (l2:list client) : Tot (list client) (decreases l1) =
  match l1 with
  | [] -> l2
  | hd :: tl -> client_rev_append tl (hd :: l2)

(* =========================================================================
   Predicates
   ========================================================================= *)

(** Check that an environment exists and is active. *)
val environment_exists : store:client_store -> eid:environment_id -> Tot bool
let environment_exists store eid =
  existsb (fun env -> env.env_uuid = eid && env.active) store.environments

(** Check whether a client_identifier is already used by a non-deleted
    client in the given environment.

    Models the partial unique index:
      `WHERE status <> 'DELETED'` *)
val identifier_taken : store:client_store -> eid:environment_id -> ident:string -> Tot bool
let identifier_taken store eid ident =
  existsb
    (fun c -> c.env_id = eid && c.identifier = ident && Active? c.status)
    store.clients

(** A client has at least one redirect URI. *)
val has_redirect_uris : c:client -> Tot bool
let has_redirect_uris c =
  length c.redirect_uris > 0

(** A client is non-deleted (live). *)
val is_live : c:client -> Tot bool
let is_live c = Active? c.status

(** Count live clients with a given identifier in an environment. *)
val count_live_with_id :
  clients:list client -> eid:environment_id -> ident:string -> Tot nat
  (decreases clients)
let rec count_live_with_id clients eid ident =
  match clients with
  | [] -> 0
  | c :: rest ->
    let tail_count = count_live_with_id rest eid ident in
    if c.env_id = eid && c.identifier = ident && Active? c.status then
      1 + tail_count
    else
      tail_count

(** Store well-formedness: no duplicate live identifiers per environment.
    For all (eid, ident) pairs, at most one live client exists. *)
val well_formed : store:client_store -> Tot bool
let well_formed store =
  for_all
    (fun c ->
      (not (is_live c)) ||
      count_live_with_id store.clients c.env_id c.identifier <= 1)
    store.clients

(* =========================================================================
   I1: client_create_requires_environment
   =========================================================================

   Creating a client requires that the target environment exists and is
   active.  The client must have at least one redirect URI and its
   identifier must not collide with an existing live client. *)

(** Create a client, returning the updated store. *)
val create_client :
  store:client_store ->
  new_client:client ->
  Pure (option client_store)
    (requires True)
    (ensures fun result ->
      match result with
      | Some store' ->
        (* Preconditions were met *)
        environment_exists store new_client.env_id = true /\
        not (identifier_taken store new_client.env_id new_client.identifier) /\
        has_redirect_uris new_client = true /\
        Active? new_client.status /\
        None? new_client.deleted_at /\
        (* The new client is in the store *)
        mem new_client store'.clients /\
        (* All old clients are preserved *)
        (forall (c:client). mem c store.clients ==> mem c store'.clients)
      | None ->
        (* At least one precondition failed *)
        not (environment_exists store new_client.env_id) \/
        identifier_taken store new_client.env_id new_client.identifier \/
        not (has_redirect_uris new_client) \/
        Deleted? new_client.status \/
        Some? new_client.deleted_at)
let create_client store new_client =
  if not (environment_exists store new_client.env_id) then None
  else if identifier_taken store new_client.env_id new_client.identifier then None
  else if not (has_redirect_uris new_client) then None
  else if Deleted? new_client.status then None
  else if Some? new_client.deleted_at then None
  else
    Some { store with clients = new_client :: store.clients }

(* =========================================================================
   I2: client_identifier_unique_within_environment
   =========================================================================

   After a successful create, the live identifier count for (env, ident)
   is exactly 1 (assuming the store was well-formed before). *)

(** Helper: if ident is not taken, count is 0. *)
val lemma_not_taken_count_zero :
  store:client_store -> eid:environment_id -> ident:string ->
  Lemma (requires not (identifier_taken store eid ident))
        (ensures count_live_with_id store.clients eid ident = 0)
  (decreases store.clients)
let rec lemma_not_taken_count_zero store eid ident =
  match store.clients with
  | [] -> ()
  | c :: rest ->
    lemma_not_taken_count_zero { store with clients = rest } eid ident

(** After a successful create_client, the identifier count for
    (new_client.env_id, new_client.identifier) in the new store is 1
    if the store was well-formed and the identifier was not taken. *)
val lemma_create_uniqueness :
  store:client_store -> new_client:client ->
  Lemma
    (requires
      well_formed store /\
      environment_exists store new_client.env_id = true /\
      not (identifier_taken store new_client.env_id new_client.identifier) /\
      has_redirect_uris new_client = true /\
      Active? new_client.status /\
      None? new_client.deleted_at)
    (ensures (
      let result = create_client store new_client in
      Some? result /\
      (let store' = Some?.v result in
       count_live_with_id store'.clients new_client.env_id new_client.identifier = 1)))
let lemma_create_uniqueness store new_client =
  lemma_not_taken_count_zero store new_client.env_id new_client.identifier

(* =========================================================================
   I3: client_delete_is_soft
   =========================================================================

   Deleting a client sets status='DELETED' and records a `deleted_at`
   timestamp.  The client record remains in the store. *)

(** Top-level helper for soft-delete: search for a live client and
    mark it deleted, preserving all other clients via rev_append.
    Extracted from the local `go` to enable top-level inductive proofs. *)
val soft_delete_go :
  prefix:list client -> remaining:list client ->
  eid:environment_id -> ident:string -> now:nat ->
  Tot (option (list client))
  (decreases remaining)
let rec soft_delete_go prefix remaining eid ident now =
  match remaining with
  | [] -> None
  | c :: rest ->
    if c.env_id = eid && c.identifier = ident && Active? c.status then
      let deleted_c = { c with status = Deleted; deleted_at = Some now } in
      let result : list client = client_rev_append prefix (deleted_c :: rest) in
      Some result
    else
      soft_delete_go (c :: prefix) rest eid ident now

(** Soft-delete: find a live client by (env_id, identifier) and mark it
    as deleted with a timestamp. *)
val soft_delete_client :
  store:client_store -> eid:environment_id -> ident:string -> now:nat ->
  Tot (option client_store)
let soft_delete_client store eid ident now =
  match soft_delete_go [] store.clients eid ident now with
  | None -> None
  | Some new_clients -> Some { store with clients = new_clients }

(** Helper: mem in client_rev_append. If x is in prefix or suffix,
    x is in client_rev_append prefix suffix. *)
val lemma_mem_rev_append :
  x:client -> prefix:list client -> suffix:list client ->
  Lemma (ensures mem x (client_rev_append prefix suffix) =
                 (mem x prefix || mem x suffix))
  (decreases prefix)
let rec lemma_mem_rev_append x prefix suffix =
  match prefix with
  | [] -> ()
  | hd :: tl -> lemma_mem_rev_append x tl (hd :: suffix)

(** existsb distributes over rev_append for any boolean predicate. *)
val lemma_existsb_rev_append_client :
  f:(client -> Tot bool) -> prefix:list client -> suffix:list client ->
  Lemma (ensures existsb f (client_rev_append prefix suffix) =
                 (existsb f prefix || existsb f suffix))
  (decreases prefix)
let rec lemma_existsb_rev_append_client f prefix suffix =
  match prefix with
  | [] -> ()
  | hd :: tl -> lemma_existsb_rev_append_client f tl (hd :: suffix)

(** Helper: when soft_delete_go finds a match, the result contains
    the deleted client with status=Deleted and deleted_at=Some.

    Proved by induction on remaining: when the Active match is found,
    the constructed deleted_c satisfies the deletion predicate, and
    lemma_existsb_rev_append_client distributes existsb over client_rev_append.
    Explicit assertions guide Z3 through the 6-field record field accesses. *)
#push-options "--z3rlimit 40"
val lemma_soft_delete_go_found :
  prefix:list client -> remaining:list client ->
  eid:environment_id -> ident:string -> now:nat ->
  Lemma
    (requires
      existsb
        (fun c -> c.env_id = eid && c.identifier = ident && Active? c.status)
        remaining /\
      not (existsb
        (fun c -> c.env_id = eid && c.identifier = ident && Active? c.status)
        prefix))
    (ensures (
      let result = soft_delete_go prefix remaining eid ident now in
      Some? result /\
      (let clients = Some?.v result in
       existsb
         (fun c -> c.env_id = eid && c.identifier = ident &&
                Deleted? c.status && Some? c.deleted_at)
         clients)))
  (decreases remaining)
let rec lemma_soft_delete_go_found prefix remaining eid ident now =
  let del_pred (c:client) : Tot bool =
    c.env_id = eid && c.identifier = ident &&
    Deleted? c.status && Some? c.deleted_at in
  match remaining with
  | [] -> ()  (* unreachable: existsb on [] is false *)
  | c :: rest ->
    if c.env_id = eid && c.identifier = ident && Active? c.status then begin
      (* Found the Active match — construct the deleted record *)
      let deleted_c = { c with status = Deleted; deleted_at = Some now } in
      (* Guide Z3 through the record field accesses *)
      assert (deleted_c.env_id = eid);
      assert (deleted_c.identifier = ident);
      assert (Deleted? deleted_c.status);
      assert (Some? deleted_c.deleted_at);
      assert (del_pred deleted_c = true);
      assert (existsb del_pred (deleted_c :: rest) = true);
      (* Distribute existsb over client_rev_append *)
      lemma_existsb_rev_append_client del_pred prefix (deleted_c :: rest)
    end
    else
      (* c doesn't match — recurse with c moved to prefix *)
      lemma_soft_delete_go_found (c :: prefix) rest eid ident now
#pop-options

(** If count_live_with_id is 0, no Active match with (eid, ident) exists. *)
val count_zero_no_existsb_active :
  l:list client -> eid:environment_id -> ident:string ->
  Lemma (requires count_live_with_id l eid ident = 0)
        (ensures not (existsb
          (fun c -> c.env_id = eid && c.identifier = ident && Active? c.status) l))
  (decreases l)
let rec count_zero_no_existsb_active l eid ident =
  match l with
  | [] -> ()
  | _ :: rest -> count_zero_no_existsb_active rest eid ident

(** After soft_delete_go succeeds on a list with at most one Active
    (eid, ident) match, the result contains no Active match.

    Key insight: when the match c is found, count(c :: rest) <= 1
    means count(rest) = 0, so no Active match remains in rest.
    The prefix has no match (scan invariant).
    deleted_c has Deleted status.
    Therefore client_rev_append prefix (deleted_c :: rest) has no Active match. *)
val lemma_soft_delete_go_removes_active :
  prefix:list client -> remaining:list client ->
  eid:environment_id -> ident:string -> now:nat ->
  Lemma
    (requires
      existsb
        (fun c -> c.env_id = eid && c.identifier = ident && Active? c.status)
        remaining /\
      not (existsb
        (fun c -> c.env_id = eid && c.identifier = ident && Active? c.status)
        prefix) /\
      count_live_with_id remaining eid ident <= 1)
    (ensures (
      let result = soft_delete_go prefix remaining eid ident now in
      Some? result /\
      not (existsb
        (fun c -> c.env_id = eid && c.identifier = ident && Active? c.status)
        (Some?.v result))))
  (decreases remaining)
let rec lemma_soft_delete_go_removes_active prefix remaining eid ident now =
  let match_pred = fun (c:client) ->
    c.env_id = eid && c.identifier = ident && Active? c.status in
  match remaining with
  | [] -> ()  (* unreachable given existsb precondition *)
  | c :: rest ->
    if c.env_id = eid && c.identifier = ident && Active? c.status then begin
      (* Found the match. c contributes 1 to count, so count(rest) = 0. *)
      count_zero_no_existsb_active rest eid ident;
      let deleted_c = { c with status = Deleted; deleted_at = Some now } in
      (* Decompose existsb over rev_append *)
      lemma_existsb_rev_append_client match_pred prefix (deleted_c :: rest)
      (* Now: existsb match_pred (client_rev_append prefix (deleted_c :: rest))
              = existsb match_pred prefix || existsb match_pred (deleted_c :: rest)
              = false || (match_pred deleted_c || existsb match_pred rest)
              = false || (false || false) = false *)
    end
    else begin
      (* c doesn't match the predicate, so count(c :: rest) = count(rest) *)
      (* Recurse with (c :: prefix) and rest *)
      lemma_soft_delete_go_removes_active (c :: prefix) rest eid ident now
    end

(** Extract the count bound from well_formed + identifier_taken.

    If the store is well-formed and an identifier is taken, then
    count_live_with_id for that (eid, ident) is at most 1.
    Proved by finding the witness in the list and applying for_all. *)
val lemma_well_formed_count_bound :
  clients:list client -> all_clients:list client ->
  eid:environment_id -> ident:string ->
  Lemma
    (requires
      for_all
        (fun c ->
          (not (is_live c)) ||
          count_live_with_id all_clients c.env_id c.identifier <= 1)
        clients /\
      existsb
        (fun c -> c.env_id = eid && c.identifier = ident && Active? c.status)
        clients)
    (ensures count_live_with_id all_clients eid ident <= 1)
  (decreases clients)
let rec lemma_well_formed_count_bound clients all_clients eid ident =
  match clients with
  | [] -> ()
  | c :: rest ->
    if c.env_id = eid && c.identifier = ident && Active? c.status then
      (* c is the witness: for_all gives us the predicate for c.
         is_live c = true (Active), so count <= 1. *)
      ()
    else
      lemma_well_formed_count_bound rest all_clients eid ident

(** After soft-delete, the deleted client record is still in the store
    with status=Deleted and a non-None deleted_at. *)
val lemma_soft_delete_preserves_record :
  store:client_store -> eid:environment_id -> ident:string -> now:nat ->
  Lemma (requires
          well_formed store /\
          identifier_taken store eid ident = true)
        (ensures (
          let result = soft_delete_client store eid ident now in
          Some? result ==>
          (let store' = Some?.v result in
           (* A Deleted client with matching id exists *)
           existsb
             (fun c -> c.env_id = eid && c.identifier = ident &&
                    Deleted? c.status && Some? c.deleted_at)
             store'.clients /\
           (* The identifier is no longer taken by a live client *)
           not (identifier_taken store' eid ident))))
let lemma_soft_delete_preserves_record store eid ident now =
  (* Part 1: Show the deleted record exists in the result *)
  lemma_soft_delete_go_found [] store.clients eid ident now;
  (* Part 2: Extract count bound from well_formed *)
  lemma_well_formed_count_bound store.clients store.clients eid ident;
  (* Part 3: Show no Active match remains in the result *)
  lemma_soft_delete_go_removes_active [] store.clients eid ident now

(** Helper: if no Active client with (eid, ident) exists in `remaining`,
    soft_delete_go returns None regardless of prefix. *)
val lemma_soft_delete_go_none :
  prefix:list client -> remaining:list client ->
  eid:environment_id -> ident:string -> now:nat ->
  Lemma
    (requires not (existsb
      (fun c -> c.env_id = eid && c.identifier = ident && Active? c.status)
      remaining))
    (ensures soft_delete_go prefix remaining eid ident now == None)
  (decreases remaining)
let rec lemma_soft_delete_go_none prefix remaining eid ident now =
  match remaining with
  | [] -> ()
  | c :: rest ->
    (* By precondition, c doesn't match, so we recurse *)
    lemma_soft_delete_go_none (c :: prefix) rest eid ident now

(** Soft-delete is idempotent on already-deleted clients:
    attempting to delete a non-existent live client returns None. *)
val lemma_soft_delete_idempotent :
  store:client_store -> eid:environment_id -> ident:string -> now:nat ->
  Lemma (requires not (identifier_taken store eid ident))
        (ensures soft_delete_client store eid ident now == None)
let lemma_soft_delete_idempotent store eid ident now =
  lemma_soft_delete_go_none [] store.clients eid ident now
