module OIDC.AuthorizationTransactions

(* Admission/retention design slice. Counts are supplied from one serialized,
   fresh database snapshot. SQL locking, clock progress, byte measurement,
   cleanup scheduling and correspondence to Rust are separate obligations.
   Completed records continue to count until expiry; this is not authorization.
   No matrix or release claim is activated by this module. *)

type counters = { retained:nat; recent:nat }
type limits = { capacity:pos; rate:pos; max_uri:pos; max_snapshot:pos }

let reserve (s:counters) (l:limits) (uri_bytes:nat) (snapshot_bytes:nat)
  : Tot (option counters) =
  if s.retained >= l.capacity || s.recent >= l.rate ||
     uri_bytes > l.max_uri || snapshot_bytes > l.max_snapshot then None
  else Some {retained=s.retained+1; recent=s.recent+1}

let lemma_reservation_bounded (s:counters) (l:limits) (u:nat) (j:nat)
  : Lemma (match reserve s l u j with
           | None -> True
           | Some next -> next.retained <= l.capacity /\ next.recent <= l.rate)
  = ()

let lemma_full_rejected (s:counters) (l:limits) (u:nat) (j:nat)
  : Lemma (requires (s.retained >= l.capacity \/ s.recent >= l.rate))
          (ensures (reserve s l u j = None))
  = ()

let lemma_oversize_rejected (s:counters) (l:limits) (u:nat) (j:nat)
  : Lemma (requires (u > l.max_uri \/ j > l.max_snapshot))
          (ensures (reserve s l u j = None))
  = ()

(* Serial callers must reserve on the state returned by their predecessor. *)
let lemma_last_slot_has_one_winner (l:limits) =
  let s = {retained=l.capacity-1; recent=0} in
  assert (reserve s l 0 0 = Some {retained=l.capacity; recent=1});
  assert (reserve {retained=l.capacity; recent=1} l 0 0 = None)

let complete (s:counters) : Tot counters = s

let lemma_completion_never_refunds_budget (s:counters) (l:limits) (u:nat) (j:nat)
  : Lemma (reserve (complete s) l u j = reserve s l u j)
  = ()

type row = { environment:string; expires_at:nat; consumed:bool }

let keep (selected:string) (now:nat) (r:row) : Tot bool =
  r.environment <> selected || r.expires_at > now

let lemma_live_row_preserved (selected:string) (now:nat) (r:row)
  : Lemma (requires (r.expires_at > now)) (ensures (keep selected now r))
  = ()

let lemma_foreign_row_preserved (selected:string) (now:nat) (r:row)
  : Lemma (requires (r.environment <> selected)) (ensures (keep selected now r))
  = ()

let lemma_expired_local_row_removed (selected:string) (now:nat) (r:row)
  : Lemma (requires (r.environment = selected /\ r.expires_at <= now))
          (ensures (not (keep selected now r)))
  = ()

let lemma_consumption_does_not_extend_retention (selected:string) (now:nat) (r:row)
  : Lemma (keep selected now {r with consumed=true} = keep selected now r)
  = ()

let witness_limits : limits = {capacity=4096; rate=300; max_uri=32768; max_snapshot=65536}

let lemma_admission_reachable ()
  : Lemma (reserve {retained=0; recent=0} witness_limits 16384 32768 =
           Some {retained=1; recent=1})
  = ()
