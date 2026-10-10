module OidcRp.BrowserBinding

(** Pure admission/consumption contract for upstream authorization callbacks.
    Source: upstream/auth_store.rs::consume_bound and upstream_callback_state.rs.
    This is a simplified model, not extracted Rust or a Redis/Lua refinement.
    See docs/verification/oidc/upstream-browser-binding-fstar.md.

    Raw payloads, state, routes and digests have decidable equality. A supplied
    deterministic decoder relates raw payloads to records; its correctness is
    not assumed/proved here. The supplied hash need not be injective. Invalid
    cookie syntax/digest format must be rejected by the caller supplier.
    The three clock readings are independent; no clock ordering is assumed. *)

type seconds = n:nat{n <= 18446744073709551615}
type nanos = n:nat{n < 1000000000}
type micros = n:nat{n < 1000000}
type instant = { seconds: seconds; nanos: nanos }
type redis_instant = { redis_seconds: seconds; redis_micros: micros }
let redis_time (t:redis_instant) : instant =
  { seconds = t.redis_seconds; nanos = op_Multiply t.redis_micros 1000 }
let live (now:instant) (deadline:instant) : Tot bool =
  now.seconds < deadline.seconds ||
  (now.seconds = deadline.seconds && now.nanos < deadline.nanos)

type request = {
  state: string;
  digest: option nat;
  route: string;
  deadline: instant;
  context: string
}
type callback = {
  callback_state: string;
  cookie_secret: option string;
  callback_route: string;
  (* false means malformed state/code/cookie or digest supplier rejection *)
  input_valid: bool;
  upstream_error: bool;
  issuer_valid: bool
}
type slot = option string
(* AcceptedCode is permission to continue; it is not an authenticated session. *)
type outcome =
  | Rejected
  | ConsumedLate
  | ConsumedIssuerFailure
  | BoundError of request
  | AcceptedCode of request
type consume_result = { remaining: slot; result: outcome }
let admitted (o:outcome) : Tot bool = BoundError? o || AcceptedCode? o
let consumed (o:outcome) : Tot bool = not (Rejected? o)

let bound (hash:string -> Tot nat) (r:request) (cb:callback) : Tot bool =
  cb.input_valid && r.state = cb.callback_state && r.route = cb.callback_route &&
  (match cb.cookie_secret, r.digest with
   | Some secret, Some digest -> hash secret = digest
   | _ -> false)

let finish (r:request) (cb:callback) (after:instant) : Tot outcome =
  if not (live after r.deadline) then ConsumedLate
  else if not cb.issuer_valid then ConsumedIssuerFailure
  else if cb.upstream_error then BoundError r
  else AcceptedCode r

(** read_snapshot is GET's observed value; current is the slot at atomic CAS.
    Concurrent replacement is arbitrary, including different or identical bytes.
    Decoder errors and pre-admission failures leave the current slot untouched.
    Transport errors after an unknown completion are outside this total model. *)
let consume
  (decode:string -> Tot (option request)) (hash:string -> Tot nat)
  (read_snapshot:slot) (current:slot) (cb:callback)
  (before:instant) (at_redis:redis_instant) (after:instant) : Tot consume_result =
  match read_snapshot with
  | None -> { remaining = current; result = Rejected }
  | Some payload ->
    match decode payload with
    | None -> { remaining = current; result = Rejected }
    | Some r ->
      if not (bound hash r cb) || not (live before r.deadline) then
        { remaining = current; result = Rejected }
      else if current <> Some payload || not (live (redis_time at_redis) r.deadline) then
        { remaining = current; result = Rejected }
      else { remaining = None; result = finish r cb after }

let lemma_live_strict (t:instant) : Lemma (not (live t t)) = ()
let lemma_redis_fraction (s:seconds) (u:micros) (n:nanos) :
  Lemma (live (redis_time { redis_seconds=s; redis_micros=u })
             { seconds=s; nanos=n } == (op_Multiply u 1000 < n)) = ()

let lemma_rejected_preserves
  (decode:string -> Tot (option request)) (hash:string -> Tot nat)
  (read:slot) (current:slot) (cb:callback)
  (before:instant) (at_redis:redis_instant) (after:instant) :
  Lemma (let res = consume decode hash read current cb before at_redis after in
         Rejected? res.result ==> res.remaining == current) = ()

let lemma_consumed_absent
  (decode:string -> Tot (option request)) (hash:string -> Tot nat)
  (read:slot) (current:slot) (cb:callback)
  (before:instant) (at_redis:redis_instant) (after:instant) :
  Lemma (let res = consume decode hash read current cb before at_redis after in
         consumed res.result ==> res.remaining == None) = ()

let lemma_absent_rejects
  (decode:string -> Tot (option request)) (hash:string -> Tot nat)
  (read:slot) (cb:callback)
  (before:instant) (at_redis:redis_instant) (after:instant) :
  Lemma (Rejected? (consume decode hash read None cb before at_redis after).result) = ()

(** At most one consumption with no intervening insertion; both requests,
    decoders, hashes, snapshots and clock readings may differ. *)
let lemma_two_consumptions
  (decode1:string -> Tot (option request)) (decode2:string -> Tot (option request))
  (hash1:string -> Tot nat) (hash2:string -> Tot nat)
  (read1:slot) (read2:slot) (current:slot) (cb1:callback) (cb2:callback)
  (before1:instant) (redis1:redis_instant) (after1:instant)
  (before2:instant) (redis2:redis_instant) (after2:instant) :
  Lemma (let first = consume decode1 hash1 read1 current cb1 before1 redis1 after1 in
         let second = consume decode2 hash2 read2 first.remaining cb2 before2 redis2 after2 in
         consumed first.result ==> Rejected? second.result) =
  lemma_consumed_absent decode1 hash1 read1 current cb1 before1 redis1 after1;
  lemma_absent_rejects decode2 hash2 read2 cb2 before2 redis2 after2

let lemma_changed_snapshot_rejected
  (decode:string -> Tot (option request)) (hash:string -> Tot nat)
  (payload:string) (current:slot{current <> Some payload}) (cb:callback)
  (before:instant) (at_redis:redis_instant) (after:instant) :
  Lemma (let res = consume decode hash (Some payload) current cb before at_redis after in
         Rejected? res.result /\ res.remaining == current) = ()

let lemma_binding_mismatch_preserves
  (decode:string -> Tot (option request)) (hash:string -> Tot nat)
  (payload:string) (r:request{decode payload == Some r}) (current:slot)
  (cb:callback{not (bound hash r cb)})
  (before:instant) (at_redis:redis_instant) (after:instant) :
  Lemma (let res = consume decode hash (Some payload) current cb before at_redis after in
         Rejected? res.result /\ res.remaining == current) = ()

let lemma_decode_failure_preserves
  (decode:string -> Tot (option request)) (hash:string -> Tot nat)
  (payload:string{decode payload == None}) (current:slot) (cb:callback)
  (before:instant) (at_redis:redis_instant) (after:instant) :
  Lemma (let res = consume decode hash (Some payload) current cb before at_redis after in
         Rejected? res.result /\ res.remaining == current) = ()

let lemma_admitted_snapshot
  (decode:string -> Tot (option request)) (hash:string -> Tot nat)
  (read:slot) (current:slot) (cb:callback)
  (before:instant) (at_redis:redis_instant) (after:instant) :
  Lemma (let res = consume decode hash read current cb before at_redis after in
    match res.result with
    | BoundError r | AcceptedCode r ->
      (exists payload. read == Some payload /\ current == Some payload /\
        decode payload == Some r) /\
      bound hash r cb /\ live before r.deadline /\
      live (redis_time at_redis) r.deadline /\ live after r.deadline /\
      cb.issuer_valid /\ res.remaining == None
    | _ -> True) = ()

let lemma_bound_fields (hash:string -> Tot nat) (r:request) (cb:callback) :
  Lemma (bound hash r cb ==>
    r.state == cb.callback_state /\ r.route == cb.callback_route /\
    (exists secret digest. cb.cookie_secret == Some secret /\
      r.digest == Some digest /\ hash secret == digest)) = ()

let lemma_no_digest_unbound (hash:string -> Tot nat) (r:request{r.digest == None}) (cb:callback) :
  Lemma (not (bound hash r cb)) = ()

let lemma_error_not_code
  (decode:string -> Tot (option request)) (hash:string -> Tot nat)
  (read:slot) (current:slot) (cb:callback{cb.upstream_error})
  (before:instant) (at_redis:redis_instant) (after:instant) :
  Lemma (not (AcceptedCode? (consume decode hash read current cb before at_redis after).result)) = ()

let lemma_late_return
  (decode:string -> Tot (option request)) (hash:string -> Tot nat)
  (payload:string) (r:request{decode payload == Some r})
  (cb:callback{bound hash r cb}) (before:instant{live before r.deadline})
  (at_redis:redis_instant{live (redis_time at_redis) r.deadline})
  (after:instant{not (live after r.deadline)}) :
  Lemma (let res = consume decode hash (Some payload) (Some payload) cb before at_redis after in
         ConsumedLate? res.result /\ res.remaining == None /\ not (admitted res.result)) = ()

(** Separate specifications name actual fields, not just the bound predicate,
    so removing a binding check cannot weaken these statements with it. *)
let lemma_wrong_state_preserves
  (decode:string -> Tot (option request)) (hash:string -> Tot nat)
  (payload:string) (r:request{decode payload == Some r}) (current:slot)
  (cb:callback{r.state <> cb.callback_state})
  (before:instant) (at_redis:redis_instant) (after:instant) :
  Lemma (let res = consume decode hash (Some payload) current cb before at_redis after in
         Rejected? res.result /\ res.remaining == current) = ()

let lemma_wrong_route_preserves
  (decode:string -> Tot (option request)) (hash:string -> Tot nat)
  (payload:string) (r:request{decode payload == Some r}) (current:slot)
  (cb:callback{r.route <> cb.callback_route})
  (before:instant) (at_redis:redis_instant) (after:instant) :
  Lemma (let res = consume decode hash (Some payload) current cb before at_redis after in
         Rejected? res.result /\ res.remaining == current) = ()

let lemma_wrong_digest_preserves
  (decode:string -> Tot (option request)) (hash:string -> Tot nat)
  (payload:string) (r:request{decode payload == Some r}) (current:slot)
  (cb:callback) (secret:string{cb.cookie_secret == Some secret})
  (digest:nat{r.digest == Some digest /\ hash secret <> digest})
  (before:instant) (at_redis:redis_instant) (after:instant) :
  Lemma (let res = consume decode hash (Some payload) current cb before at_redis after in
         Rejected? res.result /\ res.remaining == current) = ()
