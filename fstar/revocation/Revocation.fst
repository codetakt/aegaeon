module Revocation

open FStar.UInt32
module List = FStar.List.Tot

(* RFC 7009: OAuth 2.0 Token Revocation *)

(* Token types that can be revoked *)
type token_type_hint =
  | AccessToken
  | RefreshToken

(* Token state for revocation tracking *)
noeq type token_state = {
  token_id: UInt32.t;
  is_revoked: bool;
  revoked_at: UInt32.t;  (* 0 if not revoked *)
  token_type: token_type_hint;
}

(* Maximum number of tokens we can track *)
let max_tokens : UInt32.t = 10000ul

(* Store entry tying a child token to its parent for cascade revocation. *)
noeq type child_token_entry = {
  child_id: UInt32.t;
  child_state: token_state;
  parent_id: UInt32.t
}

(* Revocation request *)
noeq type revocation_request = {
  token: UInt32.t;  (* token identifier *)
  token_hint: token_type_hint;
}

(* Revocation response *)
type revocation_response =
  | Success
  | InvalidToken
  | UnsupportedTokenType

(* Check if a token is already revoked *)
val is_token_revoked : state:token_state -> bool
let is_token_revoked state =
  state.is_revoked

(* Revoke a token - idempotent operation per RFC 7009 *)
val revoke_token : state:token_state -> now:UInt32.t -> Pure token_state
  (requires UInt32.v now > 0)
  (ensures fun r ->
    r.token_id = state.token_id /\
    r.token_type = state.token_type /\
    r.is_revoked = true /\
    (if state.is_revoked then
      (* Idempotency: already revoked tokens keep original revoked_at *)
      r.revoked_at = state.revoked_at
    else
      (* First revocation: set revoked_at to current time *)
      UInt32.v r.revoked_at = UInt32.v now))
let revoke_token state now =
  if state.is_revoked then
    (* Already revoked - return unchanged for idempotency *)
    state
  else
    (* First revocation *)
    { state with is_revoked = true; revoked_at = now }

(* Process a revocation request *)
val process_revocation : req:revocation_request -> state:token_state -> now:UInt32.t
  -> Pure (token_state * revocation_response)
  (requires
    UInt32.v now > 0 /\
    UInt32.v req.token < pow2 32)
  (ensures fun (new_state, resp) ->
    new_state.token_id = state.token_id /\
    new_state.token_type = state.token_type /\
    (match resp with
     | Success ->
         new_state.is_revoked = true /\
         (state.is_revoked ==> new_state.revoked_at = state.revoked_at) /\
         (not state.is_revoked ==> new_state.revoked_at = now)
     | InvalidToken ->
         new_state.is_revoked = state.is_revoked /\
         new_state.revoked_at = state.revoked_at
     | UnsupportedTokenType ->
         (* Currently unused path: conservatively leave state unchanged *)
         new_state.is_revoked = state.is_revoked /\
         new_state.revoked_at = state.revoked_at))
let process_revocation req state now =
  if UInt32.eq req.token state.token_id then
    (* Token found - revoke it (idempotent) *)
    let new_state = revoke_token state now in
    (new_state, Success)
  else
    (* Token not found or mismatch *)
    (state, InvalidToken)

(* Cascade revocation for refresh tokens *)
val cascade_revoke : parent_token:UInt32.t -> child_tokens:list UInt32.t -> now:UInt32.t
  -> Pure (list bool)
  (requires UInt32.v now > 0)
  (ensures fun results ->
    (* All child tokens in the list are marked for revocation *)
    List.length results = List.length child_tokens /\
    List.for_all (fun b -> b) results = true)
let rec lemma_for_all_true_map
  (xs:list UInt32.t)
  : Lemma
      (ensures List.for_all (fun b -> b) (List.map (fun _ -> true) xs) = true)
  (decreases xs)
  =
    match xs with
    | [] -> ()
    | _ :: tl ->
        lemma_for_all_true_map tl;
        ()

let cascade_revoke parent child_tokens now =
  let results = List.map (fun _ -> true) child_tokens in
  let _ = lemma_for_all_true_map child_tokens in
  results

let rec lemma_length_map_const (#a:Type) (xs:list a)
  : Lemma
      (ensures List.length (List.map (fun _ -> true) xs) = List.length xs)
  (decreases xs)
  =
    match xs with
    | [] -> ()
    | _ :: tl ->
        lemma_length_map_const tl;
        ()

let rec lemma_length_map_child_ids (xs:list child_token_entry)
  : Lemma
      (ensures List.length (List.map (fun entry -> entry.child_id) xs) = List.length xs)
  (decreases xs)
  =
    match xs with
    | [] -> ()
    | _ :: tl ->
        lemma_length_map_child_ids tl;
        ()

(* Prove idempotency property *)
val lemma_revoke_token_idempotent :
  state:token_state -> now:UInt32.t{UInt32.v now > 0} ->
  Lemma
    (ensures (let first = revoke_token state now in
              let second = revoke_token first now in
              first.token_id = second.token_id /\
              first.token_type = second.token_type /\
              first.is_revoked = true /\
              second.is_revoked = true /\
              first.revoked_at = second.revoked_at))
let lemma_revoke_token_idempotent state now =
  let first = revoke_token state now in
  let second = revoke_token first now in
  if state.is_revoked then
    ()
  else
    ()

(* Lemma: cascade result propagates to updated child token states *)
val lemma_cascade_revoke_child_states :
  parent_id:UInt32.t ->
  children:list child_token_entry ->
  now:UInt32.t{UInt32.v now > 0} ->
  Lemma
    (requires List.for_all (fun entry -> UInt32.eq entry.parent_id parent_id) children = true)
    (ensures (
      let ids = List.map (fun entry -> entry.child_id) children in
      let flags = cascade_revoke parent_id ids now in
      List.length flags = List.length children /\
      List.for_all (fun b -> b) flags = true /\
      List.for_all
        (fun entry ->
           let revoked = revoke_token entry.child_state now in
           revoked.is_revoked &&
           (if entry.child_state.is_revoked then
              revoked.revoked_at = entry.child_state.revoked_at
            else
              true) &&
           (if not entry.child_state.is_revoked then
              revoked.revoked_at = now
            else
              true))
        children = true))
  (decreases children)
let rec lemma_cascade_revoke_child_states parent_id children now =
  match children with
  | [] -> ()
  | entry :: rest ->
      lemma_cascade_revoke_child_states parent_id rest now;
      let ids = List.map (fun e -> e.child_id) children in
      let _ = lemma_length_map_child_ids children in
      let _ = lemma_length_map_const ids in

      let flags = cascade_revoke parent_id ids now in
      let _ = lemma_for_all_true_map ids in

      let prop (child:child_token_entry) : Tot bool =
        let revoked_child = revoke_token child.child_state now in
        revoked_child.is_revoked &&
        (if child.child_state.is_revoked then
           revoked_child.revoked_at = child.child_state.revoked_at
         else
           true) &&
        (if not child.child_state.is_revoked then
           revoked_child.revoked_at = now
         else
           true)
      in

      let revoked_entry = revoke_token entry.child_state now in
      let _ = assert (revoked_entry.is_revoked = true) in
      if entry.child_state.is_revoked then
        let _ = assert (revoked_entry.revoked_at = entry.child_state.revoked_at) in
        ()
      else
        let _ = assert (revoked_entry.revoked_at = now) in
        ();

      let _ = assert_norm (prop entry) in
      let _ = assert_norm (List.for_all prop rest) in
      let _ = assert_norm (List.for_all prop children) in
      let _ = assert_norm (List.length flags = List.length children) in
      let _ = assert_norm (List.for_all (fun b -> b) flags) in
      ()
