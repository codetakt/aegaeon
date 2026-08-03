module OidcRp.Properties

(** OIDC Relying Party session state machine — security properties.

    Proves six security invariants:
      SM1  state_parameter_binds      — callback state must match authorize
      SM2  nonce_binds_id_token       — ID token nonce must match session
      SM3  issuer_matches_chain       — ID token iss must match session
      SM4  pkce_verifier_binds        — code_verifier generated at authorize
      SM5  single_use_state           — state consumed after callback
      SM6  state_ttl_enforced         — PendingCallback expires at TTL

    All properties proved without admit(). *)

open OidcRp.Types
open OidcRp.Transitions
open FStar.List.Tot

(* =========================================================================
   SM1: state_parameter_binds
   =========================================================================

   The callback only succeeds when the state parameter matches a
   PendingCallback session.  A wrong state results in CbNotPending. *)

(** If no PendingCallback session has the given state, callback fails. *)
val lemma_state_mismatch_fails :
  store:session_store ->
  wrong_state:state_param_t ->
  nonce:nonce_param_t -> iss:issuer_t -> now:timestamp_t ->
  Lemma
    (requires not (state_in_use store wrong_state))
    (ensures CbNotPending? (process_callback store wrong_state nonce iss now))
  (decreases store)
let rec lemma_state_mismatch_fails store wrong_state nonce iss now =
  match store with
  | [] -> ()
  | s :: rest ->
    if s.state_param = wrong_state && PendingCallback? s.state then ()
    else lemma_state_mismatch_fails rest wrong_state nonce iss now

(** Helper: find_pending_by_state returns sessions whose state_param matches. *)
val find_pending_returns_matching :
  store:session_store -> st:state_param_t ->
  Lemma (ensures (
    match find_pending_by_state store st with
    | Some s -> s.state_param = st
    | None -> True))
  (decreases store)
let rec find_pending_returns_matching store st =
  match store with
  | [] -> ()
  | s :: rest ->
    if s.state_param = st && PendingCallback? s.state then ()
    else find_pending_returns_matching rest st

(** A successful callback implies the state matched. *)
#push-options "--z3rlimit 40"
val lemma_success_implies_state_match :
  store:session_store ->
  st:state_param_t -> nonce:nonce_param_t ->
  iss:issuer_t -> now:timestamp_t ->
  Lemma (ensures (
    match process_callback store st nonce iss now with
    | CbSuccess s -> s.state_param = st
    | _ -> True))
let lemma_success_implies_state_match store st nonce iss now =
  find_pending_returns_matching store st;
  match find_pending_by_state store st with
  | None -> ()
  | Some s ->
    if not (session_valid_at now s) then ()
    else if s.nonce_param <> nonce then ()
    else if s.issuer <> iss then ()
    else ()
#pop-options

(* =========================================================================
   SM2: nonce_binds_id_token
   =========================================================================

   A wrong nonce results in CbNonceMismatch (not CbSuccess). *)

(** Nonce mismatch causes failure. *)
val lemma_nonce_mismatch_fails :
  store:session_store ->
  st:state_param_t -> wrong_nonce:nonce_param_t ->
  iss:issuer_t -> now:timestamp_t ->
  s:rp_session ->
  Lemma
    (requires
      find_pending_by_state store st == Some s /\
      session_valid_at now s /\
      s.nonce_param <> wrong_nonce)
    (ensures CbNonceMismatch? (process_callback store st wrong_nonce iss now))
let lemma_nonce_mismatch_fails store st wrong_nonce iss now s = ()

(** A successful callback implies the nonce matched. *)
val lemma_success_implies_nonce_match :
  store:session_store ->
  st:state_param_t -> nonce:nonce_param_t ->
  iss:issuer_t -> now:timestamp_t ->
  Lemma (ensures (
    match process_callback store st nonce iss now with
    | CbSuccess s -> s.nonce_param = nonce
    | _ -> True))
let lemma_success_implies_nonce_match store st nonce iss now =
  match find_pending_by_state store st with
  | None -> ()
  | Some s ->
    if not (session_valid_at now s) then ()
    else if s.nonce_param <> nonce then ()
    else if s.issuer <> iss then ()
    else ()

(* =========================================================================
   SM3: issuer_matches_chain
   =========================================================================

   A wrong issuer results in CbIssuerMismatch. *)

(** Issuer mismatch causes failure. *)
val lemma_issuer_mismatch_fails :
  store:session_store ->
  st:state_param_t -> nonce:nonce_param_t ->
  wrong_iss:issuer_t -> now:timestamp_t ->
  s:rp_session ->
  Lemma
    (requires
      find_pending_by_state store st == Some s /\
      session_valid_at now s /\
      s.nonce_param = nonce /\
      s.issuer <> wrong_iss)
    (ensures CbIssuerMismatch? (process_callback store st nonce wrong_iss now))
let lemma_issuer_mismatch_fails store st nonce wrong_iss now s = ()

(** A successful callback implies the issuer matched. *)
val lemma_success_implies_issuer_match :
  store:session_store ->
  st:state_param_t -> nonce:nonce_param_t ->
  iss:issuer_t -> now:timestamp_t ->
  Lemma (ensures (
    match process_callback store st nonce iss now with
    | CbSuccess s -> s.issuer = iss
    | _ -> True))
let lemma_success_implies_issuer_match store st nonce iss now =
  match find_pending_by_state store st with
  | None -> ()
  | Some s ->
    if not (session_valid_at now s) then ()
    else if s.nonce_param <> nonce then ()
    else if s.issuer <> iss then ()
    else ()

(* =========================================================================
   SM4: pkce_verifier_binds
   =========================================================================

   If PKCE was required (code_verifier is Some), the verifier is
   generated at authorize time and carried through to the token
   exchange.  The authorize function stores it; callback preserves it. *)

(** If session has PKCE, the successful callback result preserves it. *)
val lemma_pkce_preserved_on_success :
  store:session_store ->
  st:state_param_t -> nonce:nonce_param_t ->
  iss:issuer_t -> now:timestamp_t ->
  Lemma (ensures (
    match process_callback store st nonce iss now with
    | CbSuccess s ->
      s.code_verifier ==
        (match find_pending_by_state store st with
         | Some pending -> pending.code_verifier
         | None -> None)  (* unreachable *)
    | _ -> True))
let lemma_pkce_preserved_on_success store st nonce iss now =
  match find_pending_by_state store st with
  | None -> ()
  | Some s ->
    if not (session_valid_at now s) then ()
    else if s.nonce_param <> nonce then ()
    else if s.issuer <> iss then ()
    else ()

(** Authorize with PKCE stores the verifier in the session. *)
val lemma_authorize_stores_pkce :
  store:session_store -> s:rp_session ->
  Lemma
    (requires
      Idle? s.state /\
      session_has_bindings s /\
      session_well_formed s /\
      not (state_in_use store s.state_param) /\
      session_has_pkce s)
    (ensures (
      let result = authorize store s in
      Some? result /\
      (let store' = Some?.v result in
       match find_pending_by_state store' s.state_param with
       | Some pending -> Some? pending.code_verifier
       | None -> False)))
let lemma_authorize_stores_pkce store s = ()

(* =========================================================================
   SM5: single_use_state
   =========================================================================

   After a successful callback, the session transitions to Authenticated.
   The state parameter is consumed — it cannot be used again because
   find_pending_by_state only matches PendingCallback sessions. *)

(** Count PendingCallback sessions with a given state_param.
    Used to prove uniqueness: authorize's state_in_use check
    ensures count <= 1 for any state_param. *)
val count_pending_by_state :
  store:session_store -> st:state_param_t -> Tot nat
  (decreases store)
let rec count_pending_by_state store st =
  match store with
  | [] -> 0
  | s :: rest ->
    (if s.state_param = st && PendingCallback? s.state then 1 else 0)
    + count_pending_by_state rest st

(** Check that no session before the first PendingCallback-with-st has
    the given sid.  Ensures update_session_state (which updates by sid)
    targets the same session that find_pending_by_state (which searches
    by state_param) found.  Always true when sids are unique. *)
val sid_not_before_pending :
  store:session_store -> sid:session_id -> st:state_param_t -> Tot bool
  (decreases store)
let rec sid_not_before_pending store sid st =
  match store with
  | [] -> true
  | s :: rest ->
    if s.state_param = st && PendingCallback? s.state then true
    else s.sid <> sid && sid_not_before_pending rest sid st

(** Helper: when count_pending_by_state is 0, find_pending_by_state
    returns None — there are no PendingCallback sessions with st. *)
val lemma_count_zero_find_none :
  store:session_store -> st:state_param_t ->
  Lemma
    (requires count_pending_by_state store st = 0)
    (ensures find_pending_by_state store st == None)
  (decreases store)
let rec lemma_count_zero_find_none store st =
  match store with
  | [] -> ()
  | _ :: rest -> lemma_count_zero_find_none rest st

(** After marking a session as Authenticated, the state is no longer
    matched by find_pending_by_state.

    Preconditions (maintained by authorize invariants):
    - sid_not_before_pending: update_session_state targets the session
      that find_pending_by_state found (always true when sids are unique)
    - count_pending_by_state <= 1: no duplicate PendingCallback sessions
      with the same state_param (maintained by authorize's state_in_use)

    Previously assume val (Z3 blew up on 12-field record equality).
    Proved by field-projection decomposition: explicit asserts on
    state_param and state projections guide Z3 past the record encoding. *)
#push-options "--z3rlimit 40 --fuel 2 --ifuel 1"
val lemma_authenticated_not_pending :
  store:session_store -> sid:session_id -> st:state_param_t ->
  Lemma
    (requires
      sid_not_before_pending store sid st /\
      count_pending_by_state store st <= 1)
    (ensures (
      let store' = update_session_state store sid Authenticated in
      match find_pending_by_state store st with
      | Some s ->
        s.sid = sid ==>
        find_pending_by_state store' st == None
      | None -> True))
  (decreases store)
let rec lemma_authenticated_not_pending store sid st =
  match store with
  | [] -> ()
  | s :: rest ->
    if s.state_param = st && PendingCallback? s.state then begin
      (* s is the first PendingCallback session with state_param = st.
         find_pending_by_state returns Some s. *)
      if s.sid = sid then begin
        (* update_session_state targets s (first with sid).
           Key: project through the 12-field record update to avoid
           Z3 blowup on full record equality encoding. *)
        let s_auth = { s with state = Authenticated } in
        assert (s_auth.state_param = s.state_param);
        assert (not (PendingCallback? s_auth.state));
        (* count(s::rest, st) = 1 + count(rest, st) <= 1
           so count(rest, st) = 0.  Explicit asserts stabilize SMT
           against Z3 instability with 12-field record encoding. *)
        assert (count_pending_by_state (s :: rest) st =
                1 + count_pending_by_state rest st);
        assert (count_pending_by_state rest st = 0);
        lemma_count_zero_find_none rest st
      end
      else
        (* s.sid <> sid: implication s.sid = sid ==> ... is vacuously true *)
        ()
    end
    else if s.sid = sid then
      (* s.sid = sid but s is not PendingCallback-with-st.
         sid_not_before_pending requires s.sid <> sid for non-pending
         sessions before the target — contradiction, branch unreachable. *)
      assert (not (sid_not_before_pending store sid st))
    else
      (* s doesn't match and s.sid <> sid: both functions skip s.
         Preconditions transfer to rest by definition. *)
      lemma_authenticated_not_pending rest sid st
#pop-options

(** A successful callback result is in Authenticated state. *)
val lemma_success_is_authenticated :
  store:session_store ->
  st:state_param_t -> nonce:nonce_param_t ->
  iss:issuer_t -> now:timestamp_t ->
  Lemma (ensures (
    match process_callback store st nonce iss now with
    | CbSuccess s -> Authenticated? s.state
    | _ -> True))
let lemma_success_is_authenticated store st nonce iss now = ()

(* =========================================================================
   SM6: state_ttl_enforced
   =========================================================================

   PendingCallback sessions expire after expires_at.
   If now >= expires_at, callback returns CbExpired.
   expire_sessions marks all timed-out sessions as Expired. *)

(** Callback fails with CbExpired when session has timed out. *)
val lemma_expired_callback_rejected :
  store:session_store ->
  st:state_param_t -> nonce:nonce_param_t ->
  iss:issuer_t -> now:timestamp_t ->
  s:rp_session ->
  Lemma
    (requires
      find_pending_by_state store st == Some s /\
      now >= s.expires_at)
    (ensures CbExpired? (process_callback store st nonce iss now))
let lemma_expired_callback_rejected store st nonce iss now s = ()

(** After expire_sessions, no PendingCallback session has expires_at <= now. *)
val lemma_expire_sessions_complete :
  store:session_store -> now:timestamp_t ->
  Lemma (ensures
    not (existsb
      (fun s -> PendingCallback? s.state && not (session_valid_at now s))
      (expire_sessions store now)))
  (decreases store)
let rec lemma_expire_sessions_complete store now =
  match store with
  | [] -> ()
  | _ :: rest -> lemma_expire_sessions_complete rest now

(** Expire preserves valid PendingCallback sessions. *)
val lemma_expire_preserves_valid :
  store:session_store -> now:timestamp_t ->
  Lemma (ensures (
    forall (s:rp_session).
      (mem s store /\ PendingCallback? s.state /\ session_valid_at now s) ==>
      mem s (expire_sessions store now)))
  (decreases store)
let rec lemma_expire_preserves_valid store now =
  match store with
  | [] -> ()
  | _ :: rest -> lemma_expire_preserves_valid rest now

(** Expire changes Expired sessions, not Authenticated ones. *)
val lemma_expire_preserves_authenticated :
  store:session_store -> now:timestamp_t ->
  Lemma (ensures (
    forall (s:rp_session).
      (mem s store /\ Authenticated? s.state) ==>
      mem s (expire_sessions store now)))
  (decreases store)
let rec lemma_expire_preserves_authenticated store now =
  match store with
  | [] -> ()
  | _ :: rest -> lemma_expire_preserves_authenticated rest now
