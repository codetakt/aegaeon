module Par

open FStar.All

// Keep types public as aliases for now (abstraction deferred)
type par_store = Par_Internal.par_store
type ticket: string -> Type0 = Par_Ticket.ticket

val in_store  : par_store -> string -> Tot bool
val consumed  : par_store -> string -> Tot bool
val stored    : par_store -> string -> string -> string -> string -> Tot bool

val empty_store : par_store

val store_request_uri: s:par_store -> uri:string -> Pure par_store
  (requires (not (in_store s uri) && not (consumed s uri)))
  (ensures  (fun s' -> in_store s' uri))

val store_request: s:par_store -> uri:string -> state:string -> cc:string -> ru:string -> Pure (par_store * ticket uri)
  (requires (not (in_store s uri) && not (consumed s uri)))
  (ensures  (fun r -> let s' = fst r in in_store s' uri && stored s' uri state cc ru))

val consume_request_uri: s:par_store -> uri:string -> ticket uri -> Pure par_store
  (requires (in_store s uri && not (consumed s uri)))
  (ensures  (fun s' -> consumed s' uri))

// Public lemmas
val lemma_consume_removes:
  s:par_store -> uri:string -> t:ticket uri -> Lemma
  (requires (in_store s uri && not (consumed s uri)))
  (ensures  (let s' = consume_request_uri s uri t in (not (in_store s' uri)) && (consumed s' uri)))

val lemma_par_binding:
  s:par_store -> uri:string -> state:string -> cc:string -> ru:string -> Lemma
  (requires (stored s uri state cc ru))
  (ensures  (in_store s uri))
