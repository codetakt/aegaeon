module Par_Internal

open FStar.All
module PT = Par_Ticket

// Concrete ghost-state model for PAR request_uri lifecycle
type par_store = {
  uris: list string;      // request_uris currently stored (not yet consumed)
  consumed: list string;  // request_uris already consumed
  binds: list (string * string * string * string); // (uri, state, code_challenge, redirect_uri)
}

let empty_store : par_store = { uris = []; consumed = []; binds = [] }

// Linear capability (abstracted at the Par.fsti layer)
type ticket (u:string) = PT.ticket u

let rec contains (x:string) (l:list string) : Tot bool =
  match l with
  | [] -> false
  | y::ys -> if x = y then true else contains x ys

let rec remove_all (x:string) (l:list string) : Tot (list string) =
  match l with
  | [] -> []
  | y::ys -> if x = y then remove_all x ys else y :: remove_all x ys

// Ghost predicates
let in_store = fun (s:par_store) (u:string) -> contains u s.uris
let consumed = fun (s:par_store) (u:string) -> contains u s.consumed

let rec contains_bind (x:(string*string*string*string)) (l:list (string*string*string*string)) : Tot bool =
  match l with
  | [] -> false
  | y::ys -> if x = y then true else contains_bind x ys

// Remove all bindings for a given uri
let rec remove_bind_uri (u:string) (bs:list (string*string*string*string)) : Tot (list (string*string*string*string)) =
  match bs with
  | [] -> []
  | (u0,st,cc,ru)::ys -> if u = u0 then remove_bind_uri u ys else (u0,st,cc,ru) :: remove_bind_uri u ys

// Store a new request_uri (abstracting server-side issuance after validation)
val store_request_uri: s:par_store -> uri:string -> Pure par_store
  (requires (not (in_store s uri) && not (consumed s uri)))
  (ensures  (fun s' -> in_store s' uri))
let store_request_uri s uri = { uris = uri :: s.uris; consumed = s.consumed; binds = s.binds }

// Binding relation (ghost): the request stored under uri binds (state, code_challenge, redirect_uri)
let stored s uri state cc ru =
  in_store s uri && contains_bind (uri,state,cc,ru) s.binds

// Store a request with its binding tuple (state, code_challenge, redirect_uri)
val store_request: s:par_store -> uri:string -> state:string -> cc:string -> ru:string -> Pure (par_store * ticket uri)
  (requires (not (in_store s uri) && not (consumed s uri)))
  (ensures  (fun r -> let s' = fst r in in_store s' uri && stored s' uri state cc ru))
let store_request s uri state cc ru =
  ({ uris = uri :: s.uris; consumed = s.consumed; binds = (uri,state,cc,ru) :: s.binds }, PT.issue uri)

// Consume a request_uri exactly once: remove from active set and mark consumed
val consume_request_uri: s:par_store -> uri:string -> ticket uri -> Pure par_store
  (requires (in_store s uri && not (consumed s uri)))
  (ensures  (fun s' -> consumed s' uri))
let consume_request_uri s uri t =
  let _ = PT.consume uri t in
  { uris = remove_all uri s.uris; consumed = uri :: s.consumed; binds = remove_bind_uri uri s.binds }

// Helper lemma: removing all occurrences eliminates membership
let rec lemma_remove_all_not_contains (x:string) (l:list string) : Lemma
  (ensures not (contains x (remove_all x l))) =
  match l with
  | [] -> ()
  | y::ys -> if x = y then lemma_remove_all_not_contains x ys else lemma_remove_all_not_contains x ys

// Removing x preserves membership for y != x
let rec lemma_remove_all_preserves_others (x:string) (y:string) (l:list string) : Lemma
  (requires (x <> y))
  (ensures  (contains y (remove_all x l) <==> contains y l)) =
  match l with
  | [] -> ()
  | z::zs -> if x = z then lemma_remove_all_preserves_others x y zs
             else if y = z then () else lemma_remove_all_preserves_others x y zs

// Proven single-use effect: after consume, the URI is not in-store and is marked consumed
let lemma_consume_removes (s:par_store) (uri:string) (t:ticket uri) : Lemma
  (requires (in_store s uri && not (consumed s uri)))
  (ensures  (let s' = consume_request_uri s uri t in (not (in_store s' uri)) && (consumed s' uri))) =
  let _ = lemma_remove_all_not_contains uri s.uris in
  ()

// If a PAR request is recorded as Stored, the uri is present in-store (ghost linkage)
let lemma_par_binding (s:par_store) (uri:string) (state:string) (cc:string) (ru:string) : Lemma
  (requires (stored s uri state cc ru))
  (ensures  (in_store s uri)) = ()

// Well-formedness: each binding's uri appears in the active uri set
let rec wf_binds (uris:list string) (bs:list (string*string*string*string)) : Tot bool =
  match bs with
  | [] -> true
  | (u,_,_,_)::ys -> contains u uris && wf_binds uris ys

let well_formed s = wf_binds s.uris s.binds

let lemma_wf_empty () : Lemma (ensures (well_formed empty_store)) = ()

// Removing bindings for a uri eliminates membership of that (uri,st,cc,ru) tuple
let rec lemma_remove_bind_uri_removes_entry (u:string) (st:string) (cc:string) (ru:string)
  (bs:list (string*string*string*string)) : Lemma
  (ensures not (contains_bind (u,st,cc,ru) (remove_bind_uri u bs))) =
  match bs with
  | [] -> ()
  | (u0,st0,cc0,ru0)::ys -> if u = u0 then lemma_remove_bind_uri_removes_entry u st cc ru ys else lemma_remove_bind_uri_removes_entry u st cc ru ys

// After consume, the binding for the consumed uri is no longer present
let lemma_consume_clears_binding (s:par_store) (u:string) (st:string) (cc:string) (ru:string) (t:ticket u) : Lemma
  (requires (stored s u st cc ru && not (consumed s u)))
  (ensures  (let s' = consume_request_uri s u t in not (stored s' u st cc ru))) =
  let _ = lemma_remove_bind_uri_removes_entry u st cc ru s.binds in
  ()
