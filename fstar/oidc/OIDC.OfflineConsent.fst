module OIDC.OfflineConsent

(* Parsed request / authenticated-session boundary model. This does not prove
   HTTP parsing, entropy, PostgreSQL atomicity or Rust/SQL refinement. No prior
   consent contract is assumed; explicit consent is obtained per request. *)

type request = { code: bool; offline: bool; consent: bool; none: bool; other_prompt: bool }
type policy = | Invalid | Continue | IgnoreOffline | Ask

let select (r:request) : Tot policy =
  if r.none && (r.consent || r.other_prompt) then Invalid
  else if r.offline && (not r.code || not r.consent) then IgnoreOffline
  else if r.consent then Ask else Continue

let lemma_no_implicit_offline (r:request)
  : Lemma (requires (r.offline /\ not r.consent /\ not (r.none && r.other_prompt)))
          (ensures (select r = IgnoreOffline)) = ()
let lemma_no_noncode_offline (r:request)
  : Lemma (requires (r.offline /\ not r.code /\ not r.none))
          (ensures (select r = IgnoreOffline)) = ()
let lemma_silent_consent_invalid (r:request)
  : Lemma (requires (r.none /\ r.consent)) (ensures (select r = Invalid)) = ()
let lemma_explicit_offline_asks (r:request)
  : Lemma (requires (r.code /\ r.offline /\ r.consent /\ not r.none))
          (ensures (select r = Ask)) = ()

(* A present wrapper may contain no prompt. Its absence must not permit an
   unsigned outer prompt to supply authority to the wrapped request. *)
let selected_prompt (outer:option string) (pushed:option (option string))
  (signed:option (option string)) : Tot (option string) =
  match signed, pushed with
  | Some value, _ -> value
  | None, Some value -> value
  | None, None -> outer

let lemma_signed_prompt_source (outer:option string) (pushed:option (option string)) (value:option string)
  : Lemma (selected_prompt outer pushed (Some value) = value) = ()
let lemma_pushed_prompt_source (outer:option string) (value:option string)
  : Lemma (selected_prompt outer (Some value) None = value) = ()
let lemma_direct_prompt_source (outer:option string)
  : Lemma (selected_prompt outer None None = outer) = ()
let lemma_missing_pushed_prompt_is_not_outer_consent (outer:option string)
  : Lemma (selected_prompt outer (Some None) None = None) = ()

type binding = { environment: string; issuer: string; subject: string;
                 session: string; request_snapshot: string }
type ticket = { bound: binding; deadline: nat; pending: bool }
type outcome = | Rejected | Denied | Approved : binding -> outcome

let decide (t:ticket) (b:binding) (now:nat) (approve:bool)
  : Tot (ticket * outcome) =
  if not t.pending || now >= t.deadline || t.bound <> b then (t, Rejected)
  else let result = if approve then Approved t.bound else Denied in
       ({t with pending=false}, result)

let lemma_replay_rejected (t:ticket) (b:binding) (now:nat) (approve:bool)
  : Lemma (requires (not t.pending)) (ensures (decide t b now approve = (t, Rejected))) = ()
let lemma_expired_rejected (t:ticket) (b:binding) (now:nat) (approve:bool)
  : Lemma (requires (now >= t.deadline)) (ensures (decide t b now approve = (t, Rejected))) = ()
let lemma_wrong_binding_rejected (t:ticket) (b:binding) (now:nat) (approve:bool)
  : Lemma (requires (t.bound <> b)) (ensures (decide t b now approve = (t, Rejected))) = ()
let lemma_denial_is_consumed (t:ticket) (now:nat)
  : Lemma (requires (t.pending /\ now < t.deadline))
          (ensures (decide t t.bound now false = ({t with pending=false}, Denied))) = ()
let lemma_approval_preserves_binding (t:ticket) (b:binding) (now:nat)
  : Lemma (match decide t b now true with
           | (_, Approved original) -> original = t.bound /\ original = b
           | _ -> True) = ()
let lemma_approval_requires_action (t:ticket) (b:binding) (now:nat)
  : Lemma (match decide t b now false with | (_, Approved _) -> False | _ -> True) = ()
let lemma_approval_reachable (t:ticket) (now:nat)
  : Lemma (requires (t.pending /\ now < t.deadline))
          (ensures (decide t t.bound now true = ({t with pending=false}, Approved t.bound))) = ()
let lemma_consumed_cannot_approve_again (t:ticket) (b:binding) (now:nat) (later:nat)
  : Lemma (match decide t b now true with
           | (spent, Approved _) -> decide spent b later true = (spent, Rejected)
           | _ -> True) = ()
