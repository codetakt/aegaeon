module AuthCode.Snapshot

(* Design slice: immutable decoded snapshots and a single-key CAS.
   This is not a refinement proof of serde, Redis, or the complete grant Lua.
   decode/approve are explicit total parameters, never assumed raw/fields pairs.
   The core CAS abstracts successful primitive execution. The final section
   describes a failure-aware publication boundary; it does not refine the Lua.
   Redis script errors do NOT roll back prior writes.
   Code-key reuse, restored consumed keys, time, and token/session writes are
   outside this slice. No permanent exchange-lock ownership is assumed. *)

type bindings = {
  subject: string;
  client: string;
  redirect: string;
  scope: string;
  pkce: string;
  nonce_session: string;
  profile_attributes: string;
  authority_context: string;
  expires_at: nat
}

type candidate = {
  code_key: string;
  raw: string;
  fields: bindings
}

type snapshot (decode: string -> Tot (option bindings)) =
  s:candidate{decode s.raw = Some s.fields}

let read_snapshot
  (decode: string -> Tot (option bindings)) (key:string) (raw:string)
  : Tot (option (snapshot decode)) =
  match decode raw with
  | None -> None
  | Some fields -> Some { code_key = key; raw = raw; fields = fields }

type validated_snapshot
  (decode: string -> Tot (option bindings)) (approve: bindings -> Tot bool) =
  s:snapshot decode{approve s.fields}

let validate_snapshot
  (decode: string -> Tot (option bindings)) (approve: bindings -> Tot bool)
  (s:snapshot decode) : Tot (option (validated_snapshot decode approve)) =
  if approve s.fields then Some s else None

type store = {
  key: string;
  current_raw: option string;
  commits: nat
}

(* This guard does not depend on a lease, a re-encoder, or decoder ordering. *)
let commit (st:store) (s:candidate) : Tot (store * option bindings) =
  if st.key = s.code_key && st.current_raw = Some s.raw then
    ({ st with current_raw = None; commits = st.commits + 1 }, Some s.fields)
  else (st, None)

(* The public model transition passes the same snapshot through validation.
   commit is a storage primitive; it is not an authorization decision. *)
let redeem
  (decode: string -> Tot (option bindings)) (approve: bindings -> Tot bool)
  (st:store) (key:string) (raw:string) : Tot (store * option bindings) =
  match read_snapshot decode key raw with
  | None -> (st, None)
  | Some s ->
    match validate_snapshot decode approve s with
    | None -> (st, None)
    | Some accepted -> commit st accepted

let lemma_read_preserves_raw
  (decode: string -> Tot (option bindings)) (key:string) (raw:string)
  : Lemma
    (match read_snapshot decode key raw with
     | None -> decode raw = None
     | Some s -> s.raw = raw /\ s.code_key = key /\ decode raw = Some s.fields)
  = ()

let lemma_validation_preserves_snapshot
  (decode: string -> Tot (option bindings)) (approve: bindings -> Tot bool)
  (s:snapshot decode)
  : Lemma
    (match validate_snapshot decode approve s with
     | None -> not (approve s.fields)
     | Some accepted -> accepted = s /\ approve accepted.fields)
  = ()

let lemma_commit_uses_validated_fields
  (decode: string -> Tot (option bindings)) (approve: bindings -> Tot bool)
  (st:store) (s:validated_snapshot decode approve)
  : Lemma
    (match snd (commit st s) with
     | None -> True
     | Some issued -> issued = s.fields /\ decode s.raw = Some issued /\ approve issued)
  = ()

let lemma_mismatch_preserves_store (st:store) (s:candidate)
  : Lemma
    (requires (st.key <> s.code_key \/ st.current_raw <> Some s.raw))
    (ensures (commit st s = (st, None)))
  = ()

let lemma_commit_consumes (st:store) (s:candidate)
  : Lemma
    (requires (st.key = s.code_key /\ st.current_raw = Some s.raw))
    (ensures
      ((fst (commit st s)).current_raw = None /\
       (fst (commit st s)).commits = st.commits + 1 /\
       snd (commit st s) = Some s.fields))
  = ()

(* The second candidate is arbitrary: expiry of the old worker's lease does
   not create a second success in this successful-CAS transition slice. *)
let lemma_no_second_commit (st:store) (first:candidate) (second:candidate)
  : Lemma
    (requires (snd (commit st first) <> None))
    (ensures (commit (fst (commit st first)) second = (fst (commit st first), None)))
  = ()

let lemma_redeem_only_approved_fields
  (decode: string -> Tot (option bindings)) (approve: bindings -> Tot bool)
  (st:store) (key:string) (raw:string)
  : Lemma
    (match snd (redeem decode approve st key raw) with
     | None -> True
     | Some fields -> decode raw = Some fields /\ approve fields)
  = ()

let lemma_denied_fields_preserve_store
  (decode: string -> Tot (option bindings)) (approve: bindings -> Tot bool)
  (st:store) (key:string) (raw:string) (fields:bindings)
  : Lemma
    (requires (decode raw = Some fields /\ not (approve fields)))
    (ensures (redeem decode approve st key raw = (st, None)))
  = ()

let lemma_undecodable_bytes_preserve_store
  (decode: string -> Tot (option bindings)) (approve: bindings -> Tot bool)
  (st:store) (key:string) (raw:string)
  : Lemma
    (requires (decode raw = None))
    (ensures (redeem decode approve st key raw = (st, None)))
  = ()

let lemma_validated_legacy_bytes_redeem
  (decode: string -> Tot (option bindings)) (approve: bindings -> Tot bool)
  (key:string) (raw:string) (fields:bindings)
  : Lemma
    (requires (decode raw = Some fields /\ approve fields))
    (ensures
      (redeem decode approve {key=key; current_raw=Some raw; commits=0} key raw =
       ({key=key; current_raw=None; commits=1}, Some fields)))
  = ()

(* Concrete witnesses prevent an always-failing decoder/validation from
   explaining the results. They are model inputs, not serde/JSON tests. *)
let witness_fields : bindings = {
  subject="subject"; client="client"; redirect="callback"; scope="openid";
  pkce="checked-pkce-context"; nonce_session="session";
  profile_attributes="two-attributes"; authority_context="profile-v1"; expires_at=30
}

let witness_decode (raw:string) : Tot (option bindings) =
  if raw = "order-a" || raw = "order-b" then Some witness_fields else None

let witness_approve (fields:bindings) : Tot bool =
  fields.client = "client" && fields.pkce = "checked-pkce-context"

let lemma_two_encodings_reachable ()
  : Lemma
    (read_snapshot witness_decode "key" "order-a" <>
       read_snapshot witness_decode "key" "order-b" /\
     snd (redeem witness_decode witness_approve
       {key="key"; current_raw=Some "order-a"; commits=0} "key" "order-a") =
       Some witness_fields /\
     snd (redeem witness_decode witness_approve
       {key="key"; current_raw=Some "order-b"; commits=0} "key" "order-b") =
       Some witness_fields)
  = ()

let lemma_reencoding_is_not_a_valid_cas_substitute ()
  : Lemma
    (witness_decode "order-a" = witness_decode "order-b" /\
     snd (commit {key="key"; current_raw=Some "order-b"; commits=0}
                 {code_key="key"; raw="order-a"; fields=witness_fields}) = None)
  = ()

(* Failure-aware design for the grant publication boundary. The grant Lua must
   retire the code BEFORE token writes; its full correspondence is not proved.
   Rejectable preflight work precedes retirement; once a publication starts,
   every error (including response loss) leaves the code retired. A failed grant
   can have partial token/session effects; all-or-nothing publication is NOT
   claimed. The caller must restart authorization instead of restoring the code.
   Serial Redis execution and no resurrection/reuse of retired code generations
   are explicit storage/deployment assumptions, not theorems about Redis. *)

type publication_fault =
  | NoFault
  | BeforeTokenWrites
  | DuringTokenWrites
  | LostReply

type reply = | Rejected | Failed | Unknown | Succeeded

type publication_store = {
  snapshot_store: store;
  publish_attempts: nat;
  token_effects: bool
}

let publish_after_retirement (st:publication_store) (fault:publication_fault)
  : Tot (publication_store * reply) =
  let started = {st with publish_attempts=st.publish_attempts + 1} in
  match fault with
  | BeforeTokenWrites -> (started, Failed)
  | DuringTokenWrites -> ({started with token_effects=true}, Failed)
  | LostReply -> ({started with token_effects=true}, Unknown)
  | NoFault -> ({started with token_effects=true}, Succeeded)

let redeem_and_publish
  (decode: string -> Tot (option bindings)) (approve: bindings -> Tot bool)
  (st:publication_store) (key:string) (raw:string) (preflight_ok:bool)
  (fault:publication_fault) : Tot (publication_store * reply) =
  if not preflight_ok then (st, Rejected)
  else
    let (retired, fields) = redeem decode approve st.snapshot_store key raw in
    match fields with
    | None -> (st, Rejected)
    | Some _ -> publish_after_retirement {st with snapshot_store=retired} fault

let lemma_preflight_rejection_preserves_code
  (decode: string -> Tot (option bindings)) (approve: bindings -> Tot bool)
  (st:publication_store) (key:string) (raw:string) (fault:publication_fault)
  : Lemma (redeem_and_publish decode approve st key raw false fault = (st, Rejected))
  = ()

let lemma_publication_retires_code_even_on_error
  (decode: string -> Tot (option bindings)) (approve: bindings -> Tot bool)
  (st:publication_store) (key:string) (raw:string) (ok:bool) (fault:publication_fault)
  : Lemma
    (let (next, response) = redeem_and_publish decode approve st key raw ok fault in
     response <> Rejected ==> next.snapshot_store.current_raw = None /\
                             next.publish_attempts = st.publish_attempts + 1)
  = ()

let lemma_retry_cannot_publish_again
  (decode: string -> Tot (option bindings)) (approve: bindings -> Tot bool)
  (st:publication_store) (key:string) (raw:string) (ok:bool) (fault:publication_fault)
  (key2:string) (raw2:string) (fault2:publication_fault)
  : Lemma
    (let (next, response) = redeem_and_publish decode approve st key raw ok fault in
     response <> Rejected ==>
       redeem_and_publish decode approve next key2 raw2 true fault2 = (next, Rejected))
  = ()

let expire_code (st:publication_store) : Tot publication_store =
  {st with snapshot_store={st.snapshot_store with current_raw=None}}

let lemma_cleanup_never_reenables_code
  (decode: string -> Tot (option bindings)) (approve: bindings -> Tot bool)
  (st:publication_store) (key:string) (raw:string) (fault:publication_fault)
  : Lemma
    (redeem_and_publish decode approve (expire_code st) key raw true fault =
     (expire_code st, Rejected))
  = ()

let witness_publication_store : publication_store = {
  snapshot_store={key="code"; current_raw=Some "order-a"; commits=0};
  publish_attempts=0; token_effects=false
}

let lemma_partial_error_is_not_rollback ()
  : Lemma
    (let (next, response) =
       redeem_and_publish witness_decode witness_approve witness_publication_store
         "code" "order-a" true DuringTokenWrites in
     response = Failed /\ next.token_effects /\ next.publish_attempts = 1 /\
     next.snapshot_store.current_raw = None)
  = ()

let lemma_lost_reply_requires_new_authorization ()
  : Lemma
    (let (next, response) =
       redeem_and_publish witness_decode witness_approve witness_publication_store
         "code" "order-a" true LostReply in
     response = Unknown /\
     redeem_and_publish witness_decode witness_approve next "code" "order-a" true NoFault =
       (next, Rejected))
  = ()

(* Lease ownership is advisory. Its expiry does not replace code CAS; releasing
   an old lease must not delete a successor's ownership. Redis clock progress
   and successful single-key primitives are the execution boundary. *)
type lease = { owner: string; deadline: nat }
let live_lease (held:option lease) (now:nat) : Tot (option lease) =
  match held with | Some l -> if now < l.deadline then held else None | None -> None
let acquire_lease (held:option lease) (now:nat) (new_owner:string) (ttl:nat)
  : Tot (option lease * bool) =
  let current = live_lease held now in
  if current = None && ttl > 0
  then (Some {owner=new_owner;deadline=now+ttl},true) else (current,false)
let release_lease (held:option lease) (owner:string) : Tot (option lease) =
  match held with | Some l -> if l.owner = owner then None else held | None -> None
let lemma_live_lease_rejects_contender (l:lease) (now:nat) (other:string) (ttl:nat)
  : Lemma (requires (now < l.deadline))
          (ensures (acquire_lease (Some l) now other ttl = (Some l,false))) = ()
let lemma_expired_lease_allows_successor (l:lease) (now:nat) (other:string) (ttl:nat)
  : Lemma (requires (now >= l.deadline /\ ttl > 0))
          (ensures (acquire_lease (Some l) now other ttl =
                    (Some {owner=other;deadline=now+ttl},true))) = ()
let lemma_old_owner_preserves_successor (l:lease) (old:string)
  : Lemma (requires (old <> l.owner)) (ensures (release_lease (Some l) old = Some l)) = ()
let lemma_owner_release_reachable (l:lease)
  : Lemma (release_lease (Some l) l.owner = None) = ()
let lemma_lease_does_not_resurrect_retired_code (st:store) (s:candidate) (l:lease) (now:nat) (owner:string) (ttl:nat)
  : Lemma (requires (st.current_raw = None))
          (ensures (let _ = acquire_lease (Some l) now owner ttl in commit st s = (st,None))) = ()
