module Request_uri

open FStar.HyperStack
open FStar.HyperStack.ST
open FStar.Math.Lemmas

(** A request URI is modeled as a natural number. *)
type request_uri = nat

let uri_eqb (a:request_uri) (b:request_uri) : Tot bool =
  if a = b then true else false

let lemma_uri_eqb_true (a:request_uri) (b:request_uri)
  : Lemma (requires uri_eqb a b = true)
          (ensures a == b)
  = ()

let lemma_uri_eqb_false (a:request_uri) (b:request_uri)
  : Lemma (requires uri_eqb a b = false)
          (ensures a <> b)
  = ()

let lemma_uri_eqb_true_false_contra
  (a:request_uri)
  (b:request_uri)
  (pf_false:unit { uri_eqb a b = false })
  : Lemma (requires uri_eqb a b = true)
          (ensures False)
  =
  let _ = pf_false in
  ()

let lemma_request_uri_eq_sym
  (a:request_uri)
  (b:request_uri)
  (pf:a == b)
  : Lemma (ensures b == a)
  = ()

let lemma_uri_eqb_true_of_eq
  (a:request_uri)
  (b:request_uri)
  (pf:a == b)
  : Lemma (ensures uri_eqb a b = true)
  = ()

let lemma_uri_eqb_false_sym
  (a:request_uri)
  (b:request_uri)
  (pf_false:unit { uri_eqb a b = false })
  : Lemma (ensures uri_eqb b a = false)
  =
  match uri_eqb b a with
  | true ->
      let eq_ba = lemma_uri_eqb_true b a in
      let eq_ab = lemma_request_uri_eq_sym b a eq_ba in
      let _ = lemma_uri_eqb_true_of_eq a b eq_ab in
      lemma_uri_eqb_true_false_contra a b pf_false
  | false ->
      ()

(** Generate a fresh request URI from the given counter.  The function returns
    the new URI and the incremented counter.  This pure function makes it easy
    to reason about issuance and uniqueness. *)
val generate_request_uri: next:request_uri -> Tot (request_uri * request_uri)
let generate_request_uri next = (next, next + 1)

(** Lemma: generating a request URI always increases the counter and the value
    returned is the previous counter. *)
let lemma_generate_request_uri n :
  Lemma (let (uri, n') = generate_request_uri n in uri = n /\ n' = n + 1) =
  ()
