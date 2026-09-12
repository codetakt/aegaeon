module TokenExchange.Lifetime

open FStar.Mul

(* Exact signed integer-nanosecond specification of the exchange expiry calculation.
   This has no clock, SystemTime representation, machine-overflow or Lua-number
   correspondence claim. Positive configured TTL is an explicit precondition. *)
let billion : nat = 1000000000

let expires_in (deadline:int) (now:int) (ttl:nat) : Tot (option nat) =
  if deadline < now then None
  else
    let seconds = (deadline - now) / billion in
    if seconds = 0 then None
    else Some (if seconds < ttl then seconds else ttl)

let lemma_past_deadline_rejected (deadline:int) (now:int) (ttl:nat)
  : Lemma (requires (deadline <= now)) (ensures (expires_in deadline now ttl = None)) = ()

let lemma_subsecond_rejected (deadline:int) (now:int) (ttl:nat)
  : Lemma (requires (deadline < now + billion)) (ensures (expires_in deadline now ttl = None)) = ()

let lemma_configured_bound (deadline:int) (now:int) (ttl:nat) (result:nat)
  : Lemma (requires (expires_in deadline now ttl = Some result)) (ensures (result <= ttl)) = ()

let lemma_positive_lifetime (deadline:int) (now:int) (ttl:nat) (result:nat)
  : Lemma (requires (ttl > 0 && expires_in deadline now ttl = Some result))
    (ensures (result > 0)) = ()

let lemma_output_deadline_bounded (deadline:int) (now:int) (ttl:nat) (result:nat)
  : Lemma (requires (expires_in deadline now ttl = Some result))
    (ensures (now + result * billion <= deadline)) = ()

let lemma_no_rounding_extension (deadline:int) (now:int) (ttl:nat) (result:nat)
  : Lemma (requires (expires_in deadline now ttl = Some result))
    (ensures (result <= (deadline - now) / billion)) = ()

let lemma_time_translation (deadline:int) (now:int) (ttl:nat) (shift:nat)
  : Lemma (expires_in (deadline + shift) (now + shift) ttl = expires_in deadline now ttl) = ()

let lemma_acceptance_threshold (deadline:int) (now:int) (ttl:nat)
  : Lemma ((expires_in deadline now ttl = None) <==> (deadline < now + billion)) = ()

let lemma_fractional_witnesses ()
  : Lemma (expires_in 2499999999 1500000000 3600 = None &&
    expires_in 2500000000 1500000000 3600 = Some 1 &&
    expires_in 100000000000 0 7 = Some 7) = ()

(* Division-free equivalent oracle for direct machine-level checks. This does
   not narrow the timestamp domain and does not replace SystemTime in production. *)
let borrowed_seconds (ds:int) (dn:nat{dn < billion}) (ns:int) (nn:nat{nn < billion}) : Tot int =
  ds - ns - (if dn < nn then 1 else 0)

let lemma_borrowed_seconds_exact (ds:int) (dn:nat{dn < billion}) (ns:int) (nn:nat{nn < billion})
  : Lemma (borrowed_seconds ds dn ns nn =
    (ds * billion + dn - (ns * billion + nn)) / billion) = ()

let expires_in_parts (ds:int) (dn:nat{dn < billion}) (ns:int) (nn:nat{nn < billion}) (ttl:nat)
  : Tot (option nat) =
  let seconds = borrowed_seconds ds dn ns nn in
  if seconds <= 0 then None else Some (if seconds < ttl then seconds else ttl)

let lemma_parts_match_nanoseconds (ds:int) (dn:nat{dn < billion})
  (ns:int) (nn:nat{nn < billion}) (ttl:nat)
  : Lemma (expires_in_parts ds dn ns nn ttl = expires_in (ds * billion + dn) (ns * billion + nn) ttl) =
  lemma_borrowed_seconds_exact ds dn ns nn
