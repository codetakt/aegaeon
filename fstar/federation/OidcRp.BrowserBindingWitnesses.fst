module OidcRp.BrowserBindingWitnesses

open OidcRp.BrowserBinding

(** Nonempty successful executions of the functional model, not wire parser or
    RNG witnesses. No cryptographic injectivity assumption: this hash collides. *)
let witness_hash (secret:string) : Tot nat = if secret = "wrong" then 8 else 7
let request0 : request = {
  state="state"; digest=Some 7; route="https://example.org/oauth/upstream/c/callback";
  deadline={seconds=100; nanos=999999999}; context="preserved context"
}
let decode0 (raw:string) : Tot (option request) =
  if raw = "snapshot" then Some request0 else None
let callback0 : callback = {
  callback_state="state"; cookie_secret=Some "secret";
  callback_route="https://example.org/oauth/upstream/c/callback";
  input_valid=true; upstream_error=false; issuer_valid=true
}
let local0 : instant = {seconds=100; nanos=999999000}
let redis0 : redis_instant = {redis_seconds=100; redis_micros=999999}
let normal = consume decode0 witness_hash (Some "snapshot") (Some "snapshot") callback0 local0 redis0 local0
let lemma_normal_code_witness () :
  Lemma (normal.result == AcceptedCode request0 /\ normal.remaining == None) = ()
let lemma_error_witness () :
  Lemma (let res = consume decode0 witness_hash (Some "snapshot") (Some "snapshot")
           {callback0 with upstream_error=true} local0 redis0 local0 in
         res.result == BoundError request0 /\ res.remaining == None) = ()
let lemma_late_witness () :
  Lemma (let res = consume decode0 witness_hash (Some "snapshot") (Some "snapshot")
           callback0 local0 redis0 request0.deadline in
         res.result == ConsumedLate /\ res.remaining == None) = ()
let lemma_issuer_failure_witness () :
  Lemma (let res = consume decode0 witness_hash (Some "snapshot") (Some "snapshot")
           {callback0 with issuer_valid=false} local0 redis0 local0 in
         res.result == ConsumedIssuerFailure /\ res.remaining == None) = ()
let lemma_wrong_route_then_normal () :
  Lemma (let wrong = consume decode0 witness_hash (Some "snapshot") (Some "snapshot")
           {callback0 with callback_route="https://example.org/other"} local0 redis0 local0 in
         let right = consume decode0 witness_hash (Some "snapshot") wrong.remaining
           callback0 local0 redis0 local0 in
         wrong.result == Rejected /\ right.result == AcceptedCode request0) = ()
let lemma_missing_cookie_then_normal () :
  Lemma (let wrong = consume decode0 witness_hash (Some "snapshot") (Some "snapshot")
           {callback0 with cookie_secret=None} local0 redis0 local0 in
         let right = consume decode0 witness_hash (Some "snapshot") wrong.remaining
           callback0 local0 redis0 local0 in
         wrong.result == Rejected /\ right.result == AcceptedCode request0) = ()

(** Same-byte ABA is intentionally NOT rejected: no generation exists in CAS. *)
let lemma_reinsertion_limit () :
  Lemma (let again_after_reinsertion = consume decode0 witness_hash
           (Some "snapshot") (Some "snapshot") callback0 local0 redis0 local0 in
         normal.result == AcceptedCode request0 /\
         again_after_reinsertion.result == AcceptedCode request0) = ()

let legacy : request = {request0 with deadline={seconds=101; nanos=0}}
let decode_legacy (raw:string) : Tot (option request) =
  if raw = "legacy-timestamp-with-digest" then Some legacy else None
let lemma_legacy_whole_second_live () :
  Lemma (let res = consume decode_legacy witness_hash
           (Some "legacy-timestamp-with-digest") (Some "legacy-timestamp-with-digest")
           callback0 local0 redis0 local0 in res.result == AcceptedCode legacy) = ()

let lemma_wrong_browser_then_normal () :
  Lemma (let wrong = consume decode0 witness_hash (Some "snapshot") (Some "snapshot")
           {callback0 with cookie_secret=Some "wrong"} local0 redis0 local0 in
         let right = consume decode0 witness_hash (Some "snapshot") wrong.remaining
           callback0 local0 redis0 local0 in
         wrong.result == Rejected /\ right.result == AcceptedCode request0) = ()
