module OIDC.Reauthentication

(* Request-bound local reauthentication. Parsed/validated request snapshots,
   successful credentials and fresh session creation are inputs. This model
   does not prove HTTP/cookie parsing, entropy, SQL atomicity or Rust refinement. *)
type binding = { environment: string; issuer: string; client: string;
                 snapshot: string; uri: string; browser: string }
(* The completed string represents the entire authenticated session observation:
   session ID, subject, authentication time and achieved ACR, not just the ID. *)
type phase = | Pending | Completed : string -> phase | Spent
type ticket = { bound: binding; deadline: nat; csrf: option string; state: phase }

let bind_form (t:ticket) (b:binding) (now:nat) (csrf:string) : Tot ticket =
  if t.state = Pending && t.bound = b && now < t.deadline && csrf <> ""
  then {t with csrf=Some csrf} else t

let complete (t:ticket) (b:binding) (now:nat) (csrf:string)
  (credentials:bool) (fresh_session:string) : Tot (ticket * bool) =
  if t.state = Pending && t.bound = b && now < t.deadline
     && t.csrf = Some csrf && csrf <> "" && credentials && fresh_session <> ""
  then ({t with state=Completed fresh_session}, true) else (t, false)

let resume (t:ticket) (b:binding) (now:nat) (session:string)
  : Tot (ticket * bool) =
  match t.state with
  | Completed sid ->
    if t.bound = b && now < t.deadline && sid = session && session <> ""
    then ({t with state=Spent}, true) else (t, false)
  | _ -> (t, false)

let needs_login (session_valid:bool) (login_prompt:bool) (receipt:bool)
  (stepup:bool) : Tot bool =
  not session_valid || (login_prompt && not receipt) || stepup

(* max_age=0 requests active authentication for this request; it is not an
   impossible wall-clock age test on a later HTTP request. Positive bounds and
   achieved ACR are still checked independently of the receipt. *)
let age_exceeded (bound:nat) (elapsed:nat) (receipt:bool) : Tot bool =
  if bound = 0 then not receipt else elapsed > bound
let lemma_zero_requires_active_auth (elapsed:nat)
  : Lemma (age_exceeded 0 elapsed false) = ()
let lemma_zero_satisfied_for_request (elapsed:nat)
  : Lemma (not (age_exceeded 0 elapsed true)) = ()
let lemma_positive_age_not_bypassed (bound:nat) (elapsed:nat) (receipt:bool)
  : Lemma (requires (bound > 0))
          (ensures (age_exceeded bound elapsed receipt = (elapsed > bound))) = ()

let lemma_form_bound (t:ticket) (b:binding) (now:nat) (csrf:string)
  : Lemma (requires (t.bound <> b)) (ensures (bind_form t b now csrf = t)) = ()
let lemma_no_credentials (t:ticket) (b:binding) (now:nat) (csrf:string) (sid:string)
  : Lemma (complete t b now csrf false sid = (t,false)) = ()
let lemma_wrong_csrf (t:ticket) (b:binding) (now:nat) (csrf:string) (sid:string)
  : Lemma (requires (t.csrf <> Some csrf))
          (ensures (complete t b now csrf true sid = (t,false))) = ()
let lemma_wrong_browser_or_request (t:ticket) (b:binding) (now:nat) (csrf:string) (sid:string)
  : Lemma (requires (t.bound <> b))
          (ensures (complete t b now csrf true sid = (t,false))) = ()
let lemma_expired_completion (t:ticket) (b:binding) (now:nat) (csrf:string) (sid:string)
  : Lemma (requires (now >= t.deadline))
          (ensures (complete t b now csrf true sid = (t,false))) = ()
let lemma_completion_reachable (t:ticket) (now:nat) (csrf:string) (sid:string)
  : Lemma (requires (t.state = Pending /\ now < t.deadline /\ t.csrf = Some csrf /\ csrf <> "" /\ sid <> ""))
          (ensures (complete t t.bound now csrf true sid = ({t with state=Completed sid},true))) = ()
let lemma_completion_cannot_rebind (t:ticket) (b:binding) (now:nat) (csrf:string) (sid:string)
  : Lemma (requires (t.state <> Pending))
          (ensures (complete t b now csrf true sid = (t,false))) = ()
let lemma_pending_cannot_resume (t:ticket) (b:binding) (now:nat) (sid:string)
  : Lemma (requires (t.state = Pending)) (ensures (resume t b now sid = (t,false))) = ()
let lemma_expired_resume (t:ticket) (b:binding) (now:nat) (sid:string)
  : Lemma (requires (now >= t.deadline)) (ensures (resume t b now sid = (t,false))) =
  match t.state with | Completed _ -> () | _ -> ()
let lemma_wrong_resume_binding (t:ticket) (b:binding) (now:nat) (sid:string)
  : Lemma (requires (t.bound <> b)) (ensures (resume t b now sid = (t,false))) =
  match t.state with | Completed _ -> () | _ -> ()
let lemma_wrong_session (t:ticket) (b:binding) (now:nat) (sid:string) (other:string)
  : Lemma (requires (t.state = Completed sid /\ sid <> other))
          (ensures (resume t b now other = (t,false))) = ()
let lemma_resume_reachable (t:ticket) (now:nat) (sid:string)
  : Lemma (requires (t.state = Completed sid /\ now < t.deadline /\ sid <> ""))
          (ensures (resume t t.bound now sid = ({t with state=Spent},true))) = ()
let lemma_replay_rejected (t:ticket) (b:binding) (now:nat) (sid:string)
  : Lemma (requires (t.state = Spent)) (ensures (resume t b now sid = (t,false))) = ()
let lemma_at_most_once (t:ticket) (b:binding) (now:nat) (later:nat) (sid:string)
  : Lemma (match resume t b now sid with
           | (spent,true) -> resume spent b later sid = (spent,false)
           | _ -> True) = match t.state with | Completed _ -> () | _ -> ()
let lemma_signed_request_unchanged (t:ticket) (b:binding) (now:nat) (sid:string)
  : Lemma (let (next,_) = resume t b now sid in next.bound = t.bound) =
  match t.state with | Completed _ -> () | _ -> ()
let lemma_receipt_needs_session (login:bool) (receipt:bool) (stepup:bool)
  : Lemma (needs_login false login receipt stepup) = ()
let lemma_prompt_requires_receipt ()
  : Lemma (needs_login true true false false) = ()
let lemma_receipt_satisfies_prompt ()
  : Lemma (not (needs_login true true true false)) = ()
let lemma_receipt_does_not_bypass_stepup (login:bool) (receipt:bool)
  : Lemma (needs_login true login receipt true) = ()

let resume_needs_login (t:ticket) (b:binding) (now:nat) (sid:string)
  (session_valid:bool) (login:bool) (stepup:bool) : Tot bool =
  let (_,receipt) = resume t b now sid in
  needs_login session_valid login receipt stepup

let lemma_pending_never_discharges_prompt (t:ticket) (b:binding) (now:nat) (sid:string)
  : Lemma (requires (t.state = Pending))
          (ensures (resume_needs_login t b now sid true true false)) = ()
let lemma_wrong_request_never_discharges_prompt (t:ticket) (b:binding) (now:nat) (sid:string)
  : Lemma (requires (t.bound <> b))
          (ensures (resume_needs_login t b now sid true true false)) =
  match t.state with | Completed _ -> () | _ -> ()
let lemma_wrong_session_never_discharges_prompt (t:ticket) (b:binding) (now:nat) (sid:string) (other:string)
  : Lemma (requires (t.state = Completed sid /\ sid <> other))
          (ensures (resume_needs_login t b now other true true false)) = ()
let lemma_expired_never_discharges_prompt (t:ticket) (b:binding) (now:nat) (sid:string)
  : Lemma (requires (now >= t.deadline))
          (ensures (resume_needs_login t b now sid true true false)) =
  match t.state with | Completed _ -> () | _ -> ()
let lemma_completed_request_discharges_prompt (t:ticket) (now:nat) (sid:string)
  : Lemma (requires (t.state = Completed sid /\ now < t.deadline /\ sid <> ""))
          (ensures (not (resume_needs_login t t.bound now sid true true false))) = ()

(* Only the request/session-bound consent record inherits the consumed receipt.
   The HTTP adapter cannot supply a standalone Boolean. Consent expiry and the
   explicit approve/deny decision remain governed by OIDC.OfflineConsent. *)
type consent_receipt = { consent_bound: binding; consent_session: string;
                        active_auth: bool }
let prepare_consent (t:ticket) (b:binding) (now:nat) (sid:string)
  : Tot consent_receipt =
  let (_,receipt) = resume t b now sid in
  {consent_bound=b; consent_session=sid; active_auth=receipt}
let inherit_receipt (c:consent_receipt) (b:binding) (sid:string) : Tot bool =
  c.consent_bound = b && c.consent_session = sid && c.active_auth
let lemma_consent_no_substitution (c:consent_receipt) (b:binding) (sid:string)
  : Lemma (requires (c.consent_bound <> b \/ c.consent_session <> sid))
          (ensures (not (inherit_receipt c b sid))) = ()
let lemma_consent_cannot_invent_authentication (t:ticket) (b:binding) (now:nat) (sid:string)
  : Lemma (requires (t.state = Pending))
          (ensures (not (inherit_receipt (prepare_consent t b now sid) b sid))) = ()
let lemma_consent_keeps_completed_authentication (t:ticket) (now:nat) (sid:string)
  : Lemma (requires (t.state = Completed sid /\ now < t.deadline /\ sid <> ""))
          (ensures (inherit_receipt (prepare_consent t t.bound now sid) t.bound sid)) = ()
