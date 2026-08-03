module OidcRp.Transitions

(** OIDC Relying Party session state machine — transition functions.

    Defines the three state transitions:
      1. authorize  : Idle → PendingCallback
      2. callback   : PendingCallback → Authenticated | Failed
      3. timeout    : PendingCallback → Expired (when now >= expires_at)

    Production code reference:
      `crates/server/src/web/mod.rs` lines ~997-1012  (authorize)
      `crates/server/src/web/mod.rs` lines ~1260-1300 (callback)
      `crates/server/src/upstream.rs` lines ~60-90     (cleanup) *)

open OidcRp.Types
open FStar.List.Tot

(* =========================================================================
   Authorize transition: Idle → PendingCallback
   ========================================================================= *)

(** Create a new PendingCallback session.

    Preconditions:
    - state_param not already in use (prevents state reuse)
    - Non-empty binding parameters
    - expires_at > issued_at (well-formed TTL)

    Models the authorize handler which generates random state/nonce,
    optional PKCE code_verifier, and stores them keyed by state. *)
val authorize :
  store:session_store ->
  s:rp_session ->
  Pure (option session_store)
    (requires True)
    (ensures fun result ->
      match result with
      | Some store' ->
        (* Preconditions were met *)
        Idle? s.state /\
        session_has_bindings s /\
        session_well_formed s /\
        not (state_in_use store s.state_param) /\
        (* Session is in the store with PendingCallback status *)
        mem ({ s with state = PendingCallback }) store'
      | None ->
        (* At least one precondition failed *)
        not (Idle? s.state) \/
        not (session_has_bindings s) \/
        not (session_well_formed s) \/
        state_in_use store s.state_param)
let authorize store s =
  if not (Idle? s.state) then None
  else if not (session_has_bindings s) then None
  else if not (session_well_formed s) then None
  else if state_in_use store s.state_param then None
  else
    let pending = { s with state = PendingCallback } in
    Some (pending :: store)

(* =========================================================================
   Callback transition: PendingCallback → Authenticated | Failed
   ========================================================================= *)

(** Callback result: success or specific failure reason. *)
type callback_result =
  | CbSuccess of rp_session    (** Authenticated session *)
  | CbStateMismatch            (** SM1 violation *)
  | CbNonceMismatch            (** SM2 violation *)
  | CbIssuerMismatch           (** SM3 violation *)
  | CbExpired                  (** SM6 violation *)
  | CbNotPending               (** Session not in PendingCallback *)

(** Find a PendingCallback session by state parameter.
    Returns the first match (state is unique by authorize precondition). *)
val find_pending_by_state :
  store:session_store -> st:state_param_t -> Tot (option rp_session)
  (decreases store)
let rec find_pending_by_state store st =
  match store with
  | [] -> None
  | s :: rest ->
    if s.state_param = st && PendingCallback? s.state then Some s
    else find_pending_by_state rest st

(** Process the OIDC callback.

    Verifies:
    - SM1: state parameter matches
    - SM2: nonce matches ID token nonce
    - SM3: issuer matches ID token iss
    - SM4: code_verifier was generated (PKCE binding, if required)
    - SM6: session not expired (now < expires_at) *)
val process_callback :
  store:session_store ->
  callback_state:state_param_t ->
  id_token_nonce:nonce_param_t ->
  id_token_iss:issuer_t ->
  now:timestamp_t ->
  Tot callback_result
let process_callback store callback_state id_token_nonce id_token_iss now =
  match find_pending_by_state store callback_state with
  | None -> CbNotPending
  | Some s ->
    (* SM6: check expiration first *)
    if not (session_valid_at now s) then CbExpired
    (* SM1: state already matched by find_pending_by_state *)
    (* SM2: nonce binding *)
    else if s.nonce_param <> id_token_nonce then CbNonceMismatch
    (* SM3: issuer binding *)
    else if s.issuer <> id_token_iss then CbIssuerMismatch
    else
      CbSuccess { s with state = Authenticated }

(** Update a session's state in the store by session_id.
    Used to mark sessions as Authenticated, Failed, or Expired. *)
val update_session_state :
  store:session_store -> sid:session_id ->
  new_state:rp_session_state -> Tot session_store
  (decreases store)
let rec update_session_state store sid new_state =
  match store with
  | [] -> []
  | s :: rest ->
    if s.sid = sid then
      { s with state = new_state } :: rest
    else
      s :: update_session_state rest sid new_state

(** Expire all PendingCallback sessions whose expires_at <= now. *)
val expire_sessions : store:session_store -> now:timestamp_t -> Tot session_store
  (decreases store)
let rec expire_sessions store now =
  match store with
  | [] -> []
  | s :: rest ->
    let rest' = expire_sessions rest now in
    if PendingCallback? s.state && not (session_valid_at now s) then
      { s with state = Expired } :: rest'
    else
      s :: rest'
