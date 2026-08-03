module ParBinding

open FStar.Classical
open FStar.List.Tot
open Authorization
open Request_uri
open Response
open Lifetime
open FStar.Pervasives

(** Individual PAR request entries carried in the store. *)
type request_entry = request_uri * par_request * expiry

(** Storage for PAR requests.  The `next` field tracks the next unused request
    URI. *)
type par_store = {
  requests: list request_entry;
  current_time: nat;
  next: request_uri;
}

(** Fresh URIs live for 90 seconds.  Expose the value once to avoid magic
    numbers throughout proofs. *)
let par_expiration_window : nat = 90

(** --------------------------------------------------------------------------
    Structural predicates over the request list.
    -------------------------------------------------------------------------- *)
type uri_not_in_w (uri:request_uri) : list request_entry -> Type =
| UriNotInNil :
    uri_not_in_w uri []
| UriNotInCons :
    u:request_uri ->
    req:par_request ->
    exp:expiry ->
    rest:list request_entry ->
    (_:unit { uri_eqb u uri = false }) ->
    uri_not_in_w uri rest ->
    uri_not_in_w uri ((u, req, exp) :: rest)

type unique_uris_w : list request_entry -> Type =
| UniqueNil :
    unique_uris_w []
| UniqueCons :
    u:request_uri ->
    req:par_request ->
    exp:expiry ->
    rest:list request_entry ->
    uri_not_in_w u rest ->
    unique_uris_w rest ->
    unique_uris_w ((u, req, exp) :: rest)

type all_uris_lt_w (limit:nat) : list request_entry -> Type =
| AllLtNil :
    all_uris_lt_w limit []
| AllLtCons :
    u:request_uri ->
    req:par_request ->
    exp:expiry ->
    rest:list request_entry ->
    (_:unit { u < limit }) ->
    all_uris_lt_w limit rest ->
    all_uris_lt_w limit ((u, req, exp) :: rest)

type store_ok_w : par_store -> Type =
| StoreOk :
    store:par_store ->
    unique_uris_w store.requests ->
    all_uris_lt_w store.next store.requests ->
    store_ok_w store

let uri_not_in (uri:request_uri) (reqs:list request_entry) : Type0 =
  squash (uri_not_in_w uri reqs)

let unique_uris (reqs:list request_entry) : Type0 =
  squash (unique_uris_w reqs)

let all_uris_lt (limit:nat) (reqs:list request_entry) : Type0 =
  squash (all_uris_lt_w limit reqs)

let store_ok (store:par_store) : Type0 =
  squash (store_ok_w store)

(** --------------------------------------------------------------------------
    Helper list transformers used by the store API.
    -------------------------------------------------------------------------- *)
let rec lookup_entries (now:nat)
                       (uri:request_uri)
                       (reqs:list request_entry)
                       : Tot (option par_request) =
  match reqs with
  | [] -> None
  | (u,r,exp)::rest ->
    if uri_eqb u uri then
      if not (is_expired now exp) then Some r
      else lookup_entries now uri rest
    else lookup_entries now uri rest

let rec remove_uri (uri:request_uri) (reqs:list request_entry)
  : Tot (list request_entry) =
  match reqs with
  | [] -> []
  | (u,r,exp)::rest ->
    if uri_eqb u uri then rest
    else (u,r,exp) :: remove_uri uri rest

let lemma_remove_uri_head
  (uri:request_uri)
  (head:request_uri)
  (req:par_request)
  (exp:expiry)
  (rest:list request_entry)
  : Lemma
      (requires uri_eqb head uri == true)
      (ensures remove_uri uri ((head, req, exp) :: rest) == rest)
  = ()

let lemma_remove_uri_tail
  (uri:request_uri)
  (head:request_uri)
  (req:par_request)
  (exp:expiry)
  (rest:list request_entry)
  : Lemma
      (requires uri_eqb head uri == false)
      (ensures remove_uri uri ((head, req, exp) :: rest)
               == (head, req, exp) :: remove_uri uri rest)
  = ()

let rec filter_expired (now:nat) (reqs:list request_entry)
  : Tot (list request_entry) =
  match reqs with
  | [] -> []
  | (u,r,exp)::rest ->
    if is_expired now exp then filter_expired now rest
    else (u,r,exp) :: filter_expired now rest

let entry_uri (entry:request_entry) : request_uri =
  let (u,_,_) = entry in u

(** --------------------------------------------------------------------------
    Store API
    -------------------------------------------------------------------------- *)
val init_store: unit -> par_store
let init_store () = { requests = []; current_time = 0; next = 0 }

val lookup_request: par_store -> request_uri -> Tot (option par_request)
let lookup_request store uri =
  lookup_entries store.current_time uri store.requests

val store_request: par_store -> par_request -> Tot (par_store * par_response)
let store_request store req =
  let (uri, next') = generate_request_uri store.next in
  let expiry = store.current_time + par_expiration_window in
  let entry = (uri, req, expiry) in
  let store' = {
    requests = store.requests @ [entry];
    current_time = store.current_time;
    next = next';
  } in
  (store', Response.Success uri par_expiration_window)

let store_request_expected_store
  (store:par_store)
  (req:par_request)
  : par_store =
  let (uri, next') = generate_request_uri store.next in
  let expiry = store.current_time + par_expiration_window in
  let entry = (uri, req, expiry) in
  {
    requests = store.requests @ [entry];
    current_time = store.current_time;
    next = next';
  }

let store_request_expected_resp
  (store:par_store)
  (req:par_request)
  : par_response =
  let (uri, _) = generate_request_uri store.next in
  Response.Success uri par_expiration_window

val use_request_uri: par_store -> request_uri -> Tot (par_store * option par_request)
let use_request_uri store uri =
  match lookup_request store uri with
  | None -> (store, None)
  | Some req ->
    let requests' = remove_uri uri store.requests in
    ({ store with requests = requests' }, Some req)

val cleanup_expired: par_store -> Tot par_store
let cleanup_expired store =
  let filtered = filter_expired store.current_time store.requests in
  { store with requests = filtered }

(** --------------------------------------------------------------------------
    Helper lemmas over the structural predicates.
    -------------------------------------------------------------------------- *)
let lemma_neq_eq_contra (u v:request_uri)
  : Lemma (requires (u <> v) /\ (u == v))
          (ensures False)
  = ()

let lemma_pair_eq_proj
  #a #b (p q:a * b)
  : Lemma (requires p == q)
          (ensures fst p == fst q /\ snd p == snd q)
  = ()

let lemma_option_some_eq
  #a (x y:a)
  : Lemma (requires Some x == Some y)
          (ensures x == y)
  = ()

let lemma_option_none_some
  #a (x:a)
  : Lemma (requires None == Some x)
          (ensures False)
  = ()

let eq_sym
  #a (x y:a)
  (pf:x == y)
  : Tot (y == x)
  = match pf with
    | () -> ()

let rewrite_with_eq
  #a #p (x y:a)
  (eq:x == y)
  : Lemma (requires p x)
          (ensures  p y)
  = match eq with
    | () -> ()

let rewrite_uri_not_in
  (u:request_uri)
  (xs ys:list request_entry)
  (eq:xs == ys)
  : Lemma (requires uri_not_in_w u xs)
          (ensures  uri_not_in_w u ys)
  = rewrite_with_eq #(list request_entry)
                     #(uri_not_in_w u)
                     xs ys eq

let rewrite_unique
  (xs ys:list request_entry)
  (eq:xs == ys)
  : Lemma (requires unique_uris_w xs)
          (ensures  unique_uris_w ys)
  = rewrite_with_eq #(list request_entry)
                     #unique_uris_w
                     xs ys eq

let rewrite_all_lt
  (limit:nat)
  (xs ys:list request_entry)
  (eq:xs == ys)
  : Lemma (requires all_uris_lt_w limit xs)
          (ensures  all_uris_lt_w limit ys)
  = rewrite_with_eq #(list request_entry)
                     #(all_uris_lt_w limit)
                     xs ys eq

let rewrite_store_ok
  (s s':par_store)
  (eq:s == s')
  : Lemma (requires store_ok_w s)
          (ensures  store_ok_w s')
  = rewrite_with_eq #par_store #store_ok_w s s' eq

let rewrite_lookup_request_none
  (s s':par_store)
  (uri:request_uri)
  (eq:s == s')
  : Lemma (requires lookup_request s uri = None)
          (ensures  lookup_request s' uri = None)
  = rewrite_with_eq #par_store
                    #(fun st -> lookup_request st uri = None)
                    s s' eq

let rewrite_lookup_request_some_store
  (s s':par_store)
  (uri:request_uri)
  (req:par_request)
  (eq:s == s')
  : Lemma (requires lookup_request s uri = Some req)
          (ensures  lookup_request s' uri = Some req)
  = rewrite_with_eq #par_store
                    #(fun st -> lookup_request st uri = Some req)
                    s s' eq

let rewrite_lookup_request_some_uri
  (s:par_store)
  (uri uri':request_uri)
  (req:par_request)
  (eq:uri == uri')
  : Lemma (requires lookup_request s uri = Some req)
          (ensures  lookup_request s uri' = Some req)
  = rewrite_with_eq #request_uri
                    #(fun u -> lookup_request s u = Some req)
                    uri uri' eq

let rec lemma_uri_not_in_append_one
  (u:request_uri)
  (reqs:list request_entry)
  (entry:request_entry)
  (pf:uri_not_in_w u reqs)
  (neq:unit { uri_eqb u (entry_uri entry) = false })
: Tot (uri_not_in_w u (reqs @ [entry]))
        (decreases pf)
  = match pf with
    | UriNotInNil ->
        let (u_e, req_e, exp_e) = entry in
        let _ = lemma_uri_eqb_false_sym u u_e neq in
        let (neq_sym:unit { uri_eqb u_e u = false }) = () in
        UriNotInCons u_e req_e exp_e [] neq_sym UriNotInNil
    | UriNotInCons u_hd req_hd exp_hd rest hd_neq rest_pf ->
        let tail_pf =
          lemma_uri_not_in_append_one u rest entry rest_pf neq in
        UriNotInCons u_hd req_hd exp_hd (rest @ [entry]) hd_neq tail_pf

val lemma_lookup_not_in :
  now:nat -> uri:request_uri -> reqs:list request_entry ->
  uri_not_in_w uri reqs ->
  Lemma (lookup_entries now uri reqs = None)

let lemma_use_request_uri_result
  (store:par_store)
  (uri:request_uri)
  (store':par_store)
  (res:option par_request)
  : Lemma
      (requires use_request_uri store uri == (store', res))
      (ensures (
        match res with
        | None ->
            store' == store /\ lookup_request store uri = None
        | Some req0 ->
            store' == { store with requests = remove_uri uri store.requests } /\
            lookup_request store uri = Some req0))
  = match lookup_request store uri with
    | None ->
        lemma_pair_eq_proj (store, None) (store', res)
    | Some req0 ->
        let requests' = remove_uri uri store.requests in
        let store_expected = { store with requests = requests' } in
        lemma_pair_eq_proj (store_expected, Some req0) (store', res)

let lemma_store_request_result
  (store:par_store)
  (req:par_request)
  (store':par_store)
  (resp:par_response)
  : Lemma
      (requires store_request store req == (store', resp))
      (ensures
        store' == store_request_expected_store store req /\
        resp == store_request_expected_resp store req)
  = let expected_store = store_request_expected_store store req in
    let expected_resp = store_request_expected_resp store req in
    lemma_pair_eq_proj (expected_store, expected_resp) (store', resp)

let lemma_nat_lt_implies_neq (x y:nat)
  : Lemma (requires x < y)
          (ensures x <> y)
  = ()

let lemma_nat_lt_le_trans (x y z:nat)
  : Lemma (requires x < y /\ y <= z)
          (ensures x < z)
  = ()

let lemma_nat_le_succ (n:nat)
  : Lemma (ensures n <= n + 1)
  = ()

let lemma_nat_lt_succ (n:nat)
  : Lemma (ensures n < n + 1)
  = ()

let lemma_success_eq
  (uri1 uri2:request_uri)
  (exp1 exp2:nat)
  (pf:Response.Success uri1 exp1 == Response.Success uri2 exp2)
  : Lemma (ensures (uri1 == uri2 /\ exp1 == exp2))
  = match pf with
    | () -> ()

let lemma_not_expired_fresh (now:nat)
  : Lemma (ensures (not (is_expired now (now + par_expiration_window))))
  = ()

let rec lemma_lookup_not_in
  (now:nat)
  (uri:request_uri)
  (reqs:list request_entry)
  (pf:uri_not_in_w uri reqs)
: Lemma (ensures lookup_entries now uri reqs = None)
        (decreases reqs)
= match reqs with
  | [] ->
      (match pf with
       | UriNotInNil -> ()
       | UriNotInCons head _ _ _ hneq _ ->
           lemma_uri_eqb_true_false_contra head uri hneq)
  | (u,r,exp)::rest ->
      (match pf with
       | UriNotInNil -> ()
       | UriNotInCons head _ _ _ hneq pf_rest ->
           if uri_eqb u uri then
             lemma_uri_eqb_true_false_contra head uri hneq
           else
             lemma_lookup_not_in now uri rest pf_rest)

val lemma_lookup_append_new :
  now:nat -> uri:request_uri -> req:par_request -> exp:expiry ->
  reqs:list request_entry ->
  (not_exp:unit { not (is_expired now exp) }) ->
  uri_not_in_w uri reqs ->
  Lemma (lookup_entries now uri (reqs @ [(uri, req, exp)]) = Some req)

let rec lemma_lookup_append_new
  (now:nat)
  (uri:request_uri)
  (req:par_request)
  (exp:expiry)
  (reqs:list request_entry)
  (not_exp:unit { not (is_expired now exp) })
  (pf:uri_not_in_w uri reqs)
: Lemma (ensures lookup_entries now uri (reqs @ [(uri, req, exp)]) = Some req)
        (decreases reqs)
= match reqs with
  | [] ->
      (match pf with
       | UriNotInNil -> ()
       | UriNotInCons _ _ _ _ _ _ -> ())
  | (u',r',exp')::rest ->
      (match pf with
       | UriNotInNil -> ()
       | UriNotInCons _ _ _ _ hneq pf_rest ->
           match uri_eqb u' uri with
           | true ->
               lemma_uri_eqb_true_false_contra u' uri hneq
           | false ->
               lemma_lookup_append_new now uri req exp rest not_exp pf_rest)

let rec lemma_uri_not_in_retarget
  (src:request_uri)
  (dst:request_uri{ uri_eqb src dst = true })
  (reqs:list request_entry)
  (pf:uri_not_in_w src reqs)
: Tot (uri_not_in_w dst reqs)
        (decreases reqs)
= match pf with
  | UriNotInNil ->
      UriNotInNil
  | UriNotInCons head req exp rest head_neq rest_pf ->
      let _ = lemma_uri_eqb_true src dst in
      let head_neq_dst =
        let _ = head_neq in
        ()
      in
      let rest_pf_dst = lemma_uri_not_in_retarget src dst rest rest_pf in
      UriNotInCons head req exp rest head_neq_dst rest_pf_dst

val lemma_remove_not_in :
  u:request_uri -> target:request_uri -> reqs:list request_entry ->
  uri_not_in_w u reqs ->
  Tot (uri_not_in_w u (remove_uri target reqs))

let rec lemma_remove_not_in
  (u:request_uri)
  (target:request_uri)
  (reqs:list request_entry)
  (pf:uri_not_in_w u reqs)
: Tot (uri_not_in_w u (remove_uri target reqs))
       (decreases reqs)
= match reqs with
  | [] ->
      (match pf with
       | UriNotInNil -> UriNotInNil
       | UriNotInCons _ _ _ _ _ _ -> UriNotInNil)
  | (u_hd,r_hd,exp_hd)::rest_hd ->
      (match pf with
       | UriNotInNil -> UriNotInNil
       | UriNotInCons _ _ _ _ pf_hd pf_rest ->
           if uri_eqb u_hd target then
             let _ = lemma_remove_uri_head target u_hd r_hd exp_hd rest_hd in
             pf_rest
            else
             let tail_pf = lemma_remove_not_in u target rest_hd pf_rest in
             UriNotInCons
               u_hd
               r_hd
               exp_hd
               (remove_uri target rest_hd)
               pf_hd
               tail_pf)

val lemma_remove_preserves_unique :
  uri:request_uri -> reqs:list request_entry ->
  unique_uris_w reqs ->
  Tot (unique_uris_w (remove_uri uri reqs))

let rec lemma_remove_preserves_unique
  (uri:request_uri)
  (reqs:list request_entry)
  (pf:unique_uris_w reqs)
: Tot (unique_uris_w (remove_uri uri reqs))
        (decreases reqs)
= match reqs with
  | [] ->
      (match pf with
       | UniqueNil -> UniqueNil
       | UniqueCons _ _ _ _ _ _ -> UniqueNil)
  | (u_hd,r_hd,exp_hd)::rest_hd ->
      (match pf with
       | UniqueNil -> UniqueNil
       | UniqueCons _ _ _ _ pf_uri pf_rest ->
           if uri_eqb u_hd uri then
             let _ = lemma_remove_uri_head uri u_hd r_hd exp_hd rest_hd in
             pf_rest
           else
             let _ = lemma_remove_uri_tail uri u_hd r_hd exp_hd rest_hd in
             let rest_unique = lemma_remove_preserves_unique uri rest_hd pf_rest in
             let rest_absent = lemma_remove_not_in u_hd uri rest_hd pf_uri in
             UniqueCons u_hd r_hd exp_hd (remove_uri uri rest_hd) rest_absent rest_unique)

val lemma_remove_preserves_all_lt :
  limit:nat -> uri:request_uri -> reqs:list request_entry ->
  all_uris_lt_w limit reqs ->
  Tot (all_uris_lt_w limit (remove_uri uri reqs))

let rec lemma_remove_preserves_all_lt
  (limit:nat)
  (uri:request_uri)
  (reqs:list request_entry)
  (pf:all_uris_lt_w limit reqs)
: Tot (all_uris_lt_w limit (remove_uri uri reqs))
        (decreases reqs)
= match reqs with
  | [] ->
      (match pf with
       | AllLtNil -> AllLtNil
       | AllLtCons _ _ _ _ _ _ -> AllLtNil)
  | (u,r,exp)::rest ->
      (match pf with
       | AllLtNil -> AllLtNil
       | AllLtCons _ _ _ _ pf_lt pf_rest ->
           if uri_eqb u uri then
             let _ = lemma_remove_uri_head uri u r exp rest in
             pf_rest
           else
             let rest_lt = lemma_remove_preserves_all_lt limit uri rest pf_rest in
             AllLtCons u r exp (remove_uri uri rest) pf_lt rest_lt)

val lemma_uri_not_in_filter :
  now:nat -> uri:request_uri -> reqs:list request_entry ->
  uri_not_in_w uri reqs ->
  Tot (uri_not_in_w uri (filter_expired now reqs))

let rec lemma_uri_not_in_filter
  (now:nat)
  (uri:request_uri)
  (reqs:list request_entry)
  (pf:uri_not_in_w uri reqs)
: Tot (uri_not_in_w uri (filter_expired now reqs))
        (decreases reqs)
= match reqs with
  | [] ->
      (match pf with
       | UriNotInNil -> UriNotInNil
       | UriNotInCons _ _ _ _ _ _ -> UriNotInNil)
  | (u,r,exp)::rest ->
      (match pf with
       | UriNotInNil -> UriNotInNil
       | UriNotInCons _ _ _ _ hneq pf_rest ->
           if is_expired now exp then
             lemma_uri_not_in_filter now uri rest pf_rest
           else
             let tail_pf = lemma_uri_not_in_filter now uri rest pf_rest in
             UriNotInCons u r exp (filter_expired now rest) hneq tail_pf)

val lemma_filter_preserves_unique :
  now:nat -> reqs:list request_entry ->
  unique_uris_w reqs ->
  Tot (unique_uris_w (filter_expired now reqs))

let rec lemma_filter_preserves_unique
  (now:nat)
  (reqs:list request_entry)
  (pf:unique_uris_w reqs)
: Tot (unique_uris_w (filter_expired now reqs))
        (decreases reqs)
= match reqs with
  | [] ->
      (match pf with
       | UniqueNil -> UniqueNil
       | UniqueCons _ _ _ _ _ _ -> UniqueNil)
  | (u,r,exp)::rest ->
      (match pf with
       | UniqueNil -> UniqueNil
       | UniqueCons _ _ _ _ pf_uri pf_rest ->
           if is_expired now exp then
             lemma_filter_preserves_unique now rest pf_rest
           else
             let tail_unique = lemma_filter_preserves_unique now rest pf_rest in
             let tail_absent = lemma_uri_not_in_filter now u rest pf_uri in
             UniqueCons u r exp (filter_expired now rest) tail_absent tail_unique)

val lemma_filter_preserves_all_lt :
  now:nat -> limit:nat -> reqs:list request_entry ->
  all_uris_lt_w limit reqs ->
  Tot (all_uris_lt_w limit (filter_expired now reqs))

let rec lemma_filter_preserves_all_lt
  (now:nat)
  (limit:nat)
  (reqs:list request_entry)
  (pf:all_uris_lt_w limit reqs)
: Tot (all_uris_lt_w limit (filter_expired now reqs))
        (decreases reqs)
= match reqs with
  | [] ->
      (match pf with
       | AllLtNil -> AllLtNil
       | AllLtCons _ _ _ _ _ _ -> AllLtNil)
  | (u,r,exp)::rest ->
      (match pf with
       | AllLtNil -> AllLtNil
       | AllLtCons _ _ _ _ pf_lt pf_rest ->
           if is_expired now exp then
             lemma_filter_preserves_all_lt now limit rest pf_rest
           else
             let tail_pf = lemma_filter_preserves_all_lt now limit rest pf_rest in
             AllLtCons u r exp (filter_expired now rest) pf_lt tail_pf)

val lemma_all_lt_not_contains :
  limit:nat -> reqs:list request_entry ->
  all_uris_lt_w limit reqs ->
  Tot (uri_not_in_w limit reqs)

let rec lemma_all_lt_not_contains
  (limit:nat)
  (reqs:list request_entry)
  (pf:all_uris_lt_w limit reqs)
: Tot (uri_not_in_w limit reqs)
        (decreases reqs)
= match reqs with
  | [] ->
      (match pf with
       | AllLtNil -> UriNotInNil
       | AllLtCons _ _ _ _ _ _ -> UriNotInNil)
  | (u,r,exp)::rest ->
      (match pf with
       | AllLtNil -> UriNotInNil
       | AllLtCons _ _ _ _ pf_lt pf_rest ->
           let tail_pf = lemma_all_lt_not_contains limit rest pf_rest in
           let _ = pf_lt in
           UriNotInCons u r exp rest (lemma_nat_lt_implies_neq u limit) tail_pf)

val lemma_all_lt_weaken :
  limit:nat -> limit2:nat -> reqs:list request_entry ->
  pf_le:unit { limit <= limit2 } ->
  all_uris_lt_w limit reqs ->
  Tot (all_uris_lt_w limit2 reqs)

let rec lemma_all_lt_weaken
  (limit:nat)
  (limit2:nat)
  (reqs:list request_entry)
  (pf_le:unit { limit <= limit2 })
  (pf:all_uris_lt_w limit reqs)
: Tot (all_uris_lt_w limit2 reqs)
        (decreases reqs)
= match reqs with
  | [] ->
      (match pf with
       | AllLtNil -> AllLtNil
       | AllLtCons _ _ _ _ _ _ -> AllLtNil)
  | (u,r,exp)::rest ->
      (match pf with
       | AllLtNil -> AllLtNil
       | AllLtCons _ _ _ _ _ pf_rest ->
           lemma_nat_lt_le_trans u limit limit2;
           let rest_pf = lemma_all_lt_weaken limit limit2 rest pf_le pf_rest in
           AllLtCons u r exp rest () rest_pf)

val lemma_unique_append_new :
  reqs:list request_entry -> entry:request_entry ->
  unique_uris_w reqs ->
  uri_not_in_w (entry_uri entry) reqs ->
  Tot (unique_uris_w (reqs @ [entry]))

let rec lemma_unique_append_new
  (reqs:list request_entry)
  (entry:request_entry)
  (pf_unique:unique_uris_w reqs)
  (pf_absent:uri_not_in_w (entry_uri entry) reqs)
: Tot (unique_uris_w (reqs @ [entry]))
        (decreases pf_unique)
= match pf_unique with
  | UniqueNil ->
      (match pf_absent with
       | UriNotInNil ->
           let (u,req,exp) = entry in
           UniqueCons u req exp [] UriNotInNil UniqueNil)
  | UniqueCons u_hd r_hd exp_hd rest head_not_in tail_unique ->
      (match pf_absent with
       | UriNotInCons _ _ _ _ head_absent tail_absent ->
           let tail_unique' =
             lemma_unique_append_new rest entry tail_unique tail_absent in
           let head_not_in' =
             lemma_uri_not_in_append_one
               u_hd
               rest
               entry
               head_not_in
               head_absent in
           UniqueCons u_hd r_hd exp_hd (rest @ [entry]) head_not_in' tail_unique')

val lemma_remove_target_not_in :
  uri:request_uri -> reqs:list request_entry ->
  unique_uris_w reqs ->
  Tot (uri_not_in_w uri (remove_uri uri reqs))

let rec lemma_remove_target_not_in
  (uri:request_uri)
  (reqs:list request_entry)
  (uniq:unique_uris_w reqs)
: Tot (uri_not_in_w uri (remove_uri uri reqs))
        (decreases uniq)
= match uniq with
  | UniqueNil -> UriNotInNil
  | UniqueCons u_hd r_hd exp_hd rest head_not_in tail_unique ->
      (match uri_eqb u_hd uri with
       | true ->
           let rest_pf =
             lemma_uri_not_in_retarget u_hd uri rest head_not_in in
           let _ = lemma_remove_uri_head uri u_hd r_hd exp_hd rest in
           rest_pf
       | false ->
           let tail_pf =
             lemma_remove_target_not_in uri rest tail_unique in
           let _ = lemma_remove_uri_tail uri u_hd r_hd exp_hd rest in
           let (head_neq:unit { uri_eqb u_hd uri = false }) = () in
           UriNotInCons
             u_hd
             r_hd
             exp_hd
             (remove_uri uri rest)
             head_neq
             tail_pf)

val lemma_all_lt_append_one :
  limit:nat -> reqs:list request_entry -> entry:request_entry ->
  all_uris_lt_w limit reqs ->
  pf_entry:unit { entry_uri entry < limit } ->
  Tot (all_uris_lt_w limit (reqs @ [entry]))

let rec lemma_all_lt_append_one
  (limit:nat)
  (reqs:list request_entry)
  (entry:request_entry)
  (pf:all_uris_lt_w limit reqs)
  (pf_entry:unit { entry_uri entry < limit })
: Tot (all_uris_lt_w limit (reqs @ [entry]))
        (decreases reqs)
= match reqs with
  | [] ->
      (match pf with
       | AllLtNil ->
           let (u,req,exp) = entry in
           AllLtCons u req exp [] pf_entry AllLtNil
       | AllLtCons _ _ _ _ _ _ ->
           let (u,req,exp) = entry in
           AllLtCons u req exp [] pf_entry AllLtNil)
  | (u,r,exp)::rest ->
      (match pf with
       | AllLtNil ->
           let (u_e,req_e,exp_e) = entry in
           AllLtCons u_e req_e exp_e [] pf_entry AllLtNil
       | AllLtCons _ _ _ _ pf_lt pf_rest ->
           let tail_pf = lemma_all_lt_append_one limit rest entry pf_rest pf_entry in
           AllLtCons u r exp (rest @ [entry]) pf_lt tail_pf)

(** --------------------------------------------------------------------------
    Store invariant lemmas.
    -------------------------------------------------------------------------- *)
val lemma_init_store_ok : unit -> Tot (store_ok_w (init_store ()))

let lemma_init_store_ok () =
  StoreOk (init_store ()) UniqueNil AllLtNil

val lemma_store_request_preserves_ok :
  store:par_store -> req:par_request ->
  store_ok_w store ->
  Tot (store_ok_w (fst (store_request store req)))

let lemma_store_request_preserves_ok
  (store:par_store)
  (req:par_request)
  (pf:store_ok_w store)
: Tot (store_ok_w (fst (store_request store req)))
= match pf with
  | StoreOk _ uniq all_lt ->
      let (uri, next') = generate_request_uri store.next in
      let expiry = store.current_time + par_expiration_window in
      let entry = (uri, req, expiry) in
      let pf_absent = lemma_all_lt_not_contains store.next store.requests all_lt in
      let uniq' = lemma_unique_append_new store.requests entry uniq pf_absent in
      let pf_le = lemma_nat_le_succ store.next in
      let all_lt_weakened = lemma_all_lt_weaken store.next next' store.requests pf_le all_lt in
      let pf_entry = lemma_nat_lt_succ store.next in
      let all_lt' = lemma_all_lt_append_one next' store.requests entry all_lt_weakened pf_entry in
      StoreOk
        {
          requests = store.requests @ [entry];
          current_time = store.current_time;
          next = next';
        }
        uniq'
        all_lt'

val lemma_use_request_uri_preserves_ok :
  store:par_store -> uri:request_uri ->
  store_ok_w store ->
  Tot (store_ok_w (fst (use_request_uri store uri)))

let lemma_use_request_uri_preserves_ok
  (store:par_store)
  (uri:request_uri)
  (pf:store_ok_w store)
: Tot (store_ok_w (fst (use_request_uri store uri)))
= match pf with
  | StoreOk _ uniq all_lt ->
      match lookup_request store uri with
      | None ->
          StoreOk store uniq all_lt
      | Some _ ->
          let requests' = remove_uri uri store.requests in
          let uniq' = lemma_remove_preserves_unique uri store.requests uniq in
          let all_lt' = lemma_remove_preserves_all_lt store.next uri store.requests all_lt in
          StoreOk { store with requests = requests' } uniq' all_lt'

val lemma_cleanup_expired_preserves_ok :
  store:par_store ->
  store_ok_w store ->
  Tot (store_ok_w (cleanup_expired store))

let lemma_cleanup_expired_preserves_ok
  (store:par_store)
  (pf:store_ok_w store)
: Tot (store_ok_w (cleanup_expired store))
= match pf with
  | StoreOk _ uniq all_lt ->
      let now = store.current_time in
      let uniq' = lemma_filter_preserves_unique now store.requests uniq in
      let all_lt' = lemma_filter_preserves_all_lt now store.next store.requests all_lt in
      StoreOk (cleanup_expired store) uniq' all_lt'

(** --------------------------------------------------------------------------
    Application-facing lemmas used by higher-level proofs.
    -------------------------------------------------------------------------- *)
val lemma_single_use :
  store:par_store -> uri:request_uri -> req:par_request -> store':par_store ->
  store_ok_w store ->
  lookup_request store uri == Some req ->
  use_request_uri store uri == (store', Some req) ->
  Lemma (ensures store_ok_w store' /\ lookup_request store' uri = None)

let lemma_single_use
  (store:par_store)
  (uri:request_uri)
  (req:par_request)
  (store':par_store)
  (pf:store_ok_w store)
  (lookup_pf:lookup_request store uri == Some req)
  (use_pf:use_request_uri store uri == (store', Some req))
: Lemma (store_ok_w store' /\ lookup_request store' uri = None)
  = match pf with
    | StoreOk _ uniq all_lt ->
        let _ = lookup_pf in
        let _ = use_pf in
        let requests' = remove_uri uri store.requests in
        let store_expected = { store with requests = requests' } in
        lemma_use_request_uri_result store uri store' (Some req);
        let uniq' = lemma_remove_preserves_unique uri store.requests uniq in
        let all_lt' = lemma_remove_preserves_all_lt store.next uri store.requests all_lt in
        let store_ok_expected =
          StoreOk
            store_expected
            uniq'
            all_lt' in
        let eq_store =
          FStar.Classical.get_equality store' store_expected in
        let eq_expected = eq_sym store' store_expected eq_store in
        let _ : store_ok_w store_expected = store_ok_expected in
        let _ = rewrite_store_ok store_expected store' eq_expected in
        let absent = lemma_remove_target_not_in uri store.requests uniq in
        let _ = lemma_lookup_not_in store.current_time uri requests' absent in
        rewrite_lookup_request_none
          store_expected
          store'
          uri
          eq_expected

val lemma_client_binding :
  store:par_store -> req:par_request -> store':par_store ->
  uri:request_uri -> exp:nat ->
  store_ok_w store ->
  store_request store req == (store', Response.Success uri exp) ->
  Lemma (ensures store_ok_w store' /\ lookup_request store' uri = Some req)

let lemma_client_binding
  (store:par_store)
  (req:par_request)
  (store':par_store)
  (uri:request_uri)
  (exp:nat)
  (pf:store_ok_w store)
  (eq_request: store_request store req == (store', Response.Success uri exp))
: Lemma (store_ok_w store' /\ lookup_request store' uri = Some req)
= match pf with
  | StoreOk _ uniq all_lt ->
      let (fresh_uri, next') = generate_request_uri store.next in
      let expiry = store.current_time + par_expiration_window in
      let entry = (fresh_uri, req, expiry) in
      let store_expected = {
        requests = store.requests @ [entry];
        current_time = store.current_time;
        next = next';
      } in
      let resp_expected = Response.Success fresh_uri par_expiration_window in
      lemma_store_request_result
        store
        req
        store'
        (Response.Success uri exp);
      let eq_store = FStar.Classical.get_equality store' store_expected in
      let eq_resp =
        FStar.Classical.get_equality (Response.Success uri exp) resp_expected in
      lemma_success_eq uri fresh_uri exp par_expiration_window eq_resp;
      let eq_uri = FStar.Classical.get_equality uri fresh_uri in
      let eq_uri_rev = eq_sym uri fresh_uri eq_uri in
      let store_ok_expected =
        lemma_store_request_preserves_ok store req pf in
      let _ : store_ok_w store_expected = store_ok_expected in
      let eq_expected = eq_sym store' store_expected eq_store in
      let _ = rewrite_store_ok store_expected store' eq_expected in
      let abs_pf = lemma_all_lt_not_contains store.next store.requests all_lt in
      let not_exp = lemma_not_expired_fresh store.current_time in
      let _ =
        lemma_lookup_append_new
          store.current_time
          fresh_uri
          req
          expiry
          store.requests
          not_exp
          abs_pf in
      let _ =
        rewrite_lookup_request_some_store
          store_expected
          store'
          fresh_uri
          req
          eq_expected in
      rewrite_lookup_request_some_uri
        store'
        fresh_uri
        uri
        req
        eq_uri_rev

let lemma_expired_unusable
  (store:par_store) (req:par_request) (uri:request_uri) (exp:expiry)
  : Lemma (requires store.requests = [ (uri, req, exp) ] /\
                   is_expired store.current_time exp)
          (ensures lookup_request (cleanup_expired store) uri = None)
  = ()
