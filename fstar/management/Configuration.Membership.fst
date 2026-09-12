module Configuration.Membership

(* Effective membership, not immutable configuration snapshots. A row's payload
   includes identity, authentication material, expiry and lifecycle timestamps.
   SQL transaction/locking and serialization correspondence remain obligations. *)
type kind = | Client | Profile | Connection | Key | Secret
type lifecycle = | Active | Disabled | Retired | Deleted | Revoked
type row = {
  environment: nat;
  version: nat;
  category: kind;
  status: lifecycle;
  payload: nat
}
type store = nat -> Tot (option row)

let eligible (r:row) : Tot bool =
  match r.category with
  | Client | Profile -> r.status = Active
  | Connection -> r.status = Active || r.status = Disabled
  | Key | Secret -> false

let selected (environment:nat) (version:nat) (r:row) : Tot bool =
  r.environment = environment && r.version = version && eligible r

let carry_row (environment:nat) (previous:nat) (next:nat) (r:row) : Tot row =
  if selected environment previous r then { r with version = next } else r

let carry (s:store) (environment:nat) (previous:nat) (next:nat) : Tot store =
  fun id -> match s id with
  | None -> None
  | Some r -> Some (carry_row environment previous next r)

let lemma_member_survives (environment:nat) (previous:nat) (next:nat) (r:row)
  : Lemma (requires (selected environment previous r))
    (ensures (selected environment next (carry_row environment previous next r))) = ()

let lemma_exact_membership (environment:nat) (previous:nat) (next:nat) (r:row)
  : Lemma (requires (previous <> next && not (selected environment next r)))
    (ensures (selected environment next (carry_row environment previous next r) =
      selected environment previous r)) = ()

let lemma_preserve_payload (environment:nat) (previous:nat) (next:nat) (r:row)
  : Lemma (let after = carry_row environment previous next r in
    after.payload = r.payload && after.category = r.category &&
    after.status = r.status && after.environment = r.environment) = ()

let lemma_no_history_import (environment:nat) (previous:nat) (next:nat) (r:row)
  : Lemma (requires (r.version <> previous))
    (ensures (carry_row environment previous next r = r)) = ()

let lemma_environment_isolation (environment:nat) (previous:nat) (next:nat) (r:row)
  : Lemma (requires (r.environment <> environment))
    (ensures (carry_row environment previous next r = r)) = ()

let lemma_no_resurrection (environment:nat) (previous:nat) (next:nat) (r:row)
  : Lemma (requires (r.status = Deleted || r.status = Retired || r.status = Revoked))
    (ensures (carry_row environment previous next r = r)) = ()

let lemma_disabled_connection_preserved (environment:nat) (previous:nat) (next:nat) (r:row)
  : Lemma (requires (r.environment = environment && r.version = previous &&
    r.category = Connection && r.status = Disabled))
    (ensures ((carry_row environment previous next r).version = next &&
      (carry_row environment previous next r).status = Disabled)) = ()

let lemma_credential_provenance_unchanged (environment:nat) (previous:nat) (next:nat) (r:row)
  : Lemma (requires (r.category = Key || r.category = Secret))
    (ensures (carry_row environment previous next r = r)) = ()

let lemma_id_presence_unchanged (s:store) (environment:nat) (previous:nat) (next:nat) (id:nat)
  : Lemma ((carry s environment previous next id = None) <==> (s id = None)) =
  match s id with | None -> () | Some _ -> ()

let lemma_idempotent (environment:nat) (previous:nat) (next:nat) (r:row)
  : Lemma (carry_row environment previous next (carry_row environment previous next r) =
    carry_row environment previous next r) = ()

(* Only committed transitions publish the paired pointer and membership store.
   Freshness/absence of live target members is checked by the implementation;
   the exact-membership theorem above explains why that check is required. *)
noeq type state = { active: nat; rows: store }
let transition (s:state) (environment:nat) (base:nat) (next:nat)
  (target_clean:bool) (committed:bool) : Tot state =
  if s.active <> base || not target_clean || not committed then s
  else { active = next; rows = carry s.rows environment base next }

let lemma_stale_base_rejected (s:state) (environment:nat) (base:nat) (next:nat)
  (clean:bool) (committed:bool)
  : Lemma (requires (s.active <> base))
    (ensures (transition s environment base next clean committed == s)) = ()

let lemma_abort_unchanged (s:state) (environment:nat) (base:nat) (next:nat) (clean:bool)
  : Lemma (transition s environment base next clean false == s) = ()

let lemma_dirty_target_rejected (s:state) (environment:nat) (base:nat) (next:nat) (commit:bool)
  : Lemma (transition s environment base next false commit == s) = ()

let lemma_commit_pair (s:state) (environment:nat) (next:nat) (id:nat)
  : Lemma (let after = transition s environment s.active next true true in
    after.active = next && after.rows id = carry s.rows environment s.active next id) = ()

let member_at (s:store) (environment:nat) (version:nat) (id:nat) : Tot bool =
  match s id with | None -> false | Some r -> selected environment version r

let target_clean (s:store) (environment:nat) (next:nat) : Type0 =
  forall (id:nat). not (member_at s environment next id)

let lemma_store_exact_membership (s:store) (environment:nat) (previous:nat) (next:nat) (id:nat)
  : Lemma (requires (previous <> next /\ target_clean s environment next))
    (ensures (member_at (carry s environment previous next) environment next id =
      member_at s environment previous id)) =
  match s id with
  | None -> ()
  | Some r -> lemma_exact_membership environment previous next r

let lemma_commit_exact_membership (s:state) (environment:nat) (next:nat) (id:nat)
  : Lemma (requires (s.active <> next /\ target_clean s.rows environment next))
    (ensures (let after = transition s environment s.active next true true in
      member_at after.rows environment after.active id =
      member_at s.rows environment s.active id)) =
  lemma_store_exact_membership s.rows environment s.active next id

let lemma_same_version_no_change (environment:nat) (version:nat) (r:row)
  : Lemma (carry_row environment version version r = r) = ()

let lemma_live_witness ()
  : Lemma (let r = {environment=1; version=2; category=Client; status=Active; payload=7} in
    (carry_row 1 2 3 r).version = 3 /\ (carry_row 1 2 3 r).payload = 7) = ()
