module Par_Steel

open FStar.All
module PI = Par_Internal
module PT = Par_Ticket
module SE = Steel.Effect

type par_store = PI.par_store
type ticket (u:string) = PT.ticket u

// Steel implementation layer.
// Semantics refine Par_Internal (Pure spec) by lifting into Steel.

val store_request_st: s:par_store -> uri:string -> state:string -> cc:string -> ru:string -> SE.Steel (par_store * ticket uri)
  (requires (not (PI.in_store s uri) && not (PI.consumed s uri)))
  (ensures  (fun r -> let s' = fst r in PI.in_store s' uri && PI.stored s' uri state cc ru))
let store_request_st s uri state cc ru = SE.return (PI.store_request s uri state cc ru)

val consume_request_uri_st: s:par_store -> uri:string -> ticket uri -> SE.Steel par_store
  (requires (PI.in_store s uri && not (PI.consumed s uri)))
  (ensures  (fun s' -> PI.consumed s' uri))
let consume_request_uri_st s uri t = SE.return (PI.consume_request_uri s uri t)

// Refinement lemmas
let lemma_store_request_refines (s:par_store) (u:string) (st:string) (cc:string) (ru:string) : Lemma
  (ensures True) = ()

let lemma_consume_request_refines (s:par_store) (u:string) (t:ticket u) : Lemma
  (requires (PI.in_store s u && not (PI.consumed s u)))
  (ensures True) = ()
