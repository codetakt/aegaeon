module Dpop.Nonce

(** DPoP Nonce lifecycle per RFC 9449 Section 5.

    Models the security properties of server-issued nonces in DPoP proofs:

    DN-1  nonce_freshness            — a nonce is valid iff now is within its TTL window
    DN-2  nonce_binding              — if server requires nonce, proof must carry matching value
    DN-3  nonce_rotation_safety      — after rotation, old nonce outside grace period is rejected
    DN-3b nonce_grace_period         — after rotation, previous nonce accepted within grace window
    DN-4  nonce_required_enforcement — when policy requires nonce, missing nonce is rejected
    DN-5  grace_window_bounded       — previous nonce rejected after grace window expires

    Production code reference:
      `crates/server/src/middleware/dpop.rs` — DpopNonceStore, verify_components *)

(* =========================================================================
   Types
   ========================================================================= *)

(** A server-issued nonce with bounded lifetime. *)
type nonce_entry = {
  value: string;
  issued_at: nat;  (** timestamp in seconds *)
  ttl: nat;        (** validity window in seconds *)
}

(** Nonce store state: current nonce with optional previous for grace period.
    `rotated_at` records the timestamp when the previous nonce was installed,
    bounding the grace period to [rotated_at, rotated_at + ttl). *)
type nonce_store = {
  current: nonce_entry;
  previous: option nonce_entry;
  rotated_at: option nat;
}

(* =========================================================================
   Predicates
   ========================================================================= *)

(** DN-1: A nonce is fresh iff `now` is within [issued_at, issued_at + ttl). *)
val nonce_is_fresh : entry:nonce_entry -> now:nat -> Tot bool
let nonce_is_fresh entry now =
  now >= entry.issued_at && now < entry.issued_at + entry.ttl

(** Check whether the previous nonce is within its bounded grace window.
    Grace window = [rotated_at, rotated_at + grace_ttl). *)
val previous_in_grace : store:nonce_store -> now:nat -> Tot bool
let previous_in_grace store now =
  match store.previous, store.rotated_at with
  | Some _, Some ra -> now < ra + store.current.ttl
  | _, _ -> false

(** Check if a nonce value matches the current or previous (grace) nonce.
    The previous nonce is only accepted within the bounded grace window. *)
val nonce_accepted : store:nonce_store -> candidate:string -> now:nat -> Tot bool
let nonce_accepted store candidate now =
  (candidate = store.current.value && nonce_is_fresh store.current now) ||
  (match store.previous with
   | Some prev -> candidate = prev.value && previous_in_grace store now
   | None -> false)

(** Rotate the nonce store: current becomes previous, a fresh nonce is installed.
    Records `rotated_at = now` to start the grace window clock. *)
val rotate_nonce : store:nonce_store -> fresh_value:string -> now:nat -> Tot nonce_store
let rotate_nonce store fresh_value now =
  let new_entry = { value = fresh_value; issued_at = now; ttl = store.current.ttl } in
  { current = new_entry; previous = Some store.current; rotated_at = Some now }

(* =========================================================================
   Lemmas
   ========================================================================= *)

(** DN-1: nonce_freshness — fresh nonce accepted, expired nonce rejected. *)
val lemma_nonce_freshness :
  entry:nonce_entry -> now:nat ->
  Lemma (ensures
    nonce_is_fresh entry now = (now >= entry.issued_at && now < entry.issued_at + entry.ttl))
let lemma_nonce_freshness entry now = ()

(** DN-2: nonce_binding — if server requires a nonce and the proof carries the
    correct current value within the TTL window, it is accepted. *)
val lemma_nonce_binding :
  store:nonce_store -> now:nat ->
  Lemma
    (requires nonce_is_fresh store.current now)
    (ensures nonce_accepted store store.current.value now = true)
let lemma_nonce_binding store now = ()

(** DN-3: nonce_rotation_safety — after rotation, a nonce not matching
    current or previous is rejected regardless of timing. *)
val lemma_nonce_rotation_safety :
  store:nonce_store ->
  fresh_value:string ->
  now:nat ->
  stale_value:string ->
  Lemma
    (requires
      fresh_value <> store.current.value /\
      stale_value <> fresh_value /\
      stale_value <> store.current.value /\
      (match store.previous with | Some p -> stale_value <> p.value | None -> true))
    (ensures
      (let rotated = rotate_nonce store fresh_value now in
       nonce_accepted rotated stale_value now = false))
let lemma_nonce_rotation_safety store fresh_value now stale_value = ()

(** DN-3b: grace period — after rotation, the previous current is still valid
    within the grace window (now < rotated_at + ttl). *)
val lemma_nonce_grace_period :
  store:nonce_store ->
  fresh_value:string ->
  now:nat ->
  Lemma
    (requires
      fresh_value <> store.current.value /\
      store.current.ttl > 0)
    (ensures
      (let rotated = rotate_nonce store fresh_value now in
       nonce_accepted rotated store.current.value now = true))
let lemma_nonce_grace_period store fresh_value now = ()

(** DN-4: nonce_required_enforcement — when a nonce is required (store is Some),
    a proof with no nonce (None) or a wrong nonce is rejected.
    Modeled as: a candidate that does not match current or previous is rejected. *)
val lemma_nonce_required_enforcement :
  store:nonce_store ->
  candidate:string ->
  now:nat ->
  Lemma
    (requires
      candidate <> store.current.value /\
      (match store.previous with | Some p -> candidate <> p.value | None -> true))
    (ensures nonce_accepted store candidate now = false)
let lemma_nonce_required_enforcement store candidate now = ()

(** DN-5: grace_window_bounded — the previous nonce is rejected once the
    grace window has expired (now >= rotated_at + ttl). *)
val lemma_grace_window_bounded :
  store:nonce_store ->
  fresh_value:string ->
  rotation_time:nat ->
  check_time:nat ->
  Lemma
    (requires
      fresh_value <> store.current.value /\
      check_time >= rotation_time + store.current.ttl)
    (ensures
      (let rotated = rotate_nonce store fresh_value rotation_time in
       nonce_accepted rotated store.current.value check_time = false))
let lemma_grace_window_bounded store fresh_value rotation_time check_time = ()
