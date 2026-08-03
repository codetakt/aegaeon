module Lifetime

(** Expiration times are represented as natural numbers. *)
type expiry = nat

val is_expired: now:nat -> expiry -> Tot bool
let is_expired now exp = exp <= now

(** Lemma: if a value is expired with respect to `now`, then its expiration time
    is less than or equal to `now`. *)
let lemma_is_expired (now:nat) (exp:expiry) :
  Lemma (requires is_expired now exp)
        (ensures exp <= now) =
  ()
