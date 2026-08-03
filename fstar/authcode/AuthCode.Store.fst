module AuthCode.Store

open FStar.Seq
open FStar.Seq.Properties
open FStar.HyperStack.ST
open FStar.List.Tot
open AuthCode.Types

(* Auxiliary lemmas for Seq operations — proved via FStar.Seq.Properties *)
let lemma_mem_cons
  (#a:eqtype) (x:a) (t:seq a) : Lemma (Seq.mem x (Seq.cons x t))
  = lemma_append_count (Seq.create 1 x) t

let lemma_mem_append_right
  (#a:eqtype) (s1:seq a) (s2:seq a) (x:a)
  : Lemma (requires Seq.mem x s2)
          (ensures Seq.mem x (Seq.append s1 s2))
  = lemma_append_count s1 s2

let lemma_mem_append_cons
  (#a:eqtype) (acc:seq a) (x:a) (tail:seq a)
  : Lemma (Seq.mem x (Seq.append acc (Seq.cons x tail)))
  = lemma_mem_cons x tail;
    lemma_mem_append_right acc (Seq.cons x tail) x

(* Lemma for snoc: adding an element at end preserves membership *)
let lemma_mem_snoc
  (#a:eqtype) (s:seq a) (x:a) : Lemma (Seq.mem x (Seq.snoc s x))
  = FStar.Seq.Properties.lemma_mem_snoc s x

(* Secure storage for authorization codes and tokens *)

noeq type auth_store = {
  codes: seq authorization_code;
  access_tokens: seq access_token;
  refresh_tokens: seq refresh_token;
  states: seq state;  (* Used states for uniqueness *)
  nonces: seq nonce;  (* Used nonces for uniqueness *)
  current_time: nat;
}

(* Initialize empty store *)
val init_store: unit -> ST auth_store
  (requires fun h -> True)
  (ensures fun h0 r h1 ->
    modifies_none h0 h1 /\
    Seq.length r.codes = 0 /\
    Seq.length r.access_tokens = 0 /\
    Seq.length r.refresh_tokens = 0 /\
    Seq.length r.states = 0 /\
    Seq.length r.nonces = 0)
let init_store () = {
  codes = Seq.empty;
  access_tokens = Seq.empty;
  refresh_tokens = Seq.empty;
  states = Seq.empty;
  nonces = Seq.empty;
  current_time = 0;
}

(* Check if state is unique *)
val is_state_unique: store:auth_store -> s:state -> Tot bool
let is_state_unique store s =
  not (Seq.mem s store.states)

(* Check if nonce is unique *)
val is_nonce_unique: store:auth_store -> n:nonce -> Tot bool
let is_nonce_unique store n =
  not (Seq.mem n store.nonces)

(* Linear resource lemma: nonces added only once and preserved *)
let lemma_nonce_linear (store:auth_store) (n:nonce)
  : Lemma (requires is_nonce_unique store n)
          (ensures Seq.mem n (Seq.snoc store.nonces n)) =
  lemma_mem_snoc store.nonces n

(* ---------- Helper functions for store operations ---------- *)

(* Find authorization code index by code string (unused codes only) *)
let rec find_code_index (codes:seq authorization_code) (code_str:string) (i:nat)
  : Tot (option (idx:nat{idx < Seq.length codes}))
  (decreases (Seq.length codes - i))
  = if i >= Seq.length codes then None
    else if (Seq.index codes i).code = code_str && not (Seq.index codes i).used
    then Some i
    else find_code_index codes code_str (i + 1)

(* Find access token by token string *)
let rec find_access_token (tokens:seq access_token) (token_str:string) (i:nat)
  : Tot (option access_token)
  (decreases (Seq.length tokens - i))
  = if i >= Seq.length tokens then None
    else if (Seq.index tokens i).token = token_str
    then Some (Seq.index tokens i)
    else find_access_token tokens token_str (i + 1)

(* Named predicates for cleanup filtering (Z3 4.13 compatibility) *)
let code_not_expired (current_time:nat) (c:authorization_code) : Tot bool =
  not (is_expired c.expires_at current_time)

let access_token_not_expired (current_time:nat) (t:access_token) : Tot bool =
  not (is_expired (t.created_at + t.expires_in) current_time)

let refresh_token_not_expired (current_time:nat) (r:refresh_token) : Tot bool =
  not (is_expired r.expires_at current_time)

(* ---------- Store operations ---------- *)

(* Store authorization code with invariants *)
val store_auth_code: store:auth_store -> code:authorization_code -> ST auth_store
  (requires fun h ->
    (* State must be unique if present *)
    (match code.state with
     | Some s -> is_state_unique store s
     | None -> true) /\
    (* Nonce must be unique if present *)
    (match code.nonce with
     | Some n -> is_nonce_unique store n
     | None -> true) /\
    (* Code must not be expired *)
    not (is_expired code.expires_at store.current_time) /\
    (* Code must be unused *)
    not code.used)
  (ensures fun _ _ _ -> True)
let store_auth_code store code =
  let new_codes = Seq.snoc store.codes code in
  let new_states = (match code.state with
    | Some s -> Seq.snoc store.states s
    | None -> store.states) in
  let new_nonces = (match code.nonce with
    | Some n -> Seq.snoc store.nonces n
    | None -> store.nonces) in
  { store with codes = new_codes; states = new_states; nonces = new_nonces }

(* Use authorization code (single-use enforcement) *)
val use_auth_code: store:auth_store -> code_str:string -> ST (auth_store * option authorization_code)
  (requires fun h -> True)
  (ensures fun _ _ _ -> True)
let use_auth_code store code_str =
  match find_code_index store.codes code_str 0 with
  | None -> (store, None)
  | Some idx ->
    let found_code = Seq.index store.codes idx in
    let marked = { found_code with used = true } in
    let new_codes = Seq.upd store.codes idx marked in
    ({ store with codes = new_codes }, Some found_code)

(* Store access token *)
val store_access_token: store:auth_store -> token:access_token -> ST auth_store
  (requires fun h -> True)
  (ensures fun _ _ _ -> True)
let store_access_token store token =
  { store with access_tokens = Seq.snoc store.access_tokens token }

(* Verify access token *)
val verify_access_token: store:auth_store -> token_str:string -> Tot (option access_token)
let verify_access_token store token_str =
  find_access_token store.access_tokens token_str 0

(* Clean expired codes and tokens *)
val cleanup_expired: store:auth_store -> Tot auth_store
let cleanup_expired store =
  let code_list = seq_to_list store.codes in
  let token_list = seq_to_list store.access_tokens in
  let refresh_list = seq_to_list store.refresh_tokens in
  { store with
    codes = seq_of_list (filter (code_not_expired store.current_time) code_list);
    access_tokens = seq_of_list (filter (access_token_not_expired store.current_time) token_list);
    refresh_tokens = seq_of_list (filter (refresh_token_not_expired store.current_time) refresh_list) }
