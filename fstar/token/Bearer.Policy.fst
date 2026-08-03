module Bearer.Policy

open FStar.List.Tot
open FStar.String

module List = FStar.List.Tot
module Str = FStar.String

// -----------------------------------------------------------------------------
// Bearer token hardening prerequisites
// -----------------------------------------------------------------------------

type audience = string
type scope = list string

type sender_binding =
  | SenderDPoP of string // JWK thumbprint / proof identifier
  | SenderMTLS of string // client certificate fingerprint

type bearer_token = {
  token_id: string;
  issuer: string;
  audience: audience;
  scopes: scope;
  binding: option sender_binding;
  revoked: bool;
}

let scope_contains (granted:scope) (requested:scope) : Tot bool =
  List.for_all (fun s -> List.mem s granted) requested

let audience_matches (token:bearer_token) (required:audience) : Tot bool =
  token.audience = required

// Refresh history model: captures previous token ids tied to refresh chains
type refresh_history = list string

// Holder-of-key state: tracks active sender bindings for token ids
type sender_state = list (string * sender_binding)

// -----------------------------------------------------------------------------
// Lemma declarations (proofs required)
// -----------------------------------------------------------------------------

let rec token_ids (tokens:list bearer_token) : Tot (list string) =
  match tokens with
  | [] -> []
  | t :: ts -> t.token_id :: token_ids ts

let rec binding_entries_for (state:sender_state) (token_id:string) : Tot (list sender_binding) =
  match state with
  | [] -> []
  | (id, binding) :: rest ->
      if id = token_id then binding :: binding_entries_for rest token_id
      else binding_entries_for rest token_id

let binding_unique (state:sender_state) (token_id:string) (binding:sender_binding) : Tot bool =
  binding_entries_for state token_id = [binding]

let history_excludes_active (active:list bearer_token) (history:refresh_history) : Tot bool =
  List.for_all (fun t -> not (List.mem t.token_id history)) active

let lemma_scope_containment
  (granted:scope)
  (requested:scope)
  : Lemma
      (requires scope_contains granted requested)
      (ensures List.for_all (fun s -> List.mem s granted) requested)
  = ()

let lemma_audience_binding
  (token:bearer_token)
  (required:audience)
  : Lemma
      (requires audience_matches token required)
      (ensures token.audience = required)
  = ()

let rec lemma_refresh_history_excludes_active
  (active_tokens:list bearer_token)
  (history:refresh_history)
  : Lemma
      (requires history_excludes_active active_tokens history)
      (ensures List.for_all (fun id -> not (List.mem id history)) (token_ids active_tokens))
  = match active_tokens with
    | [] -> ()
    | _ :: ts -> lemma_refresh_history_excludes_active ts history

let lemma_sender_binding_unique
  (state:sender_state)
  (token_id:string)
  (binding:sender_binding)
  : Lemma
      (requires binding_entries_for state token_id = [binding])
      (ensures binding_unique state token_id binding)
  = ()

// Placeholder for combined policy lemma tying everything together.
let lemma_bearer_policy_ok
  (token:bearer_token)
  (required_aud:audience)
  (required_scope:scope)
  (sender:option sender_binding)
  (history:refresh_history)
  (sender_state:sender_state)
  : Lemma
      (requires
        scope_contains token.scopes required_scope &&
        audience_matches token required_aud &&
        not token.revoked &&
        (match token.binding, sender with
         | None, None -> true
         | Some b, Some presented -> b = presented
         | _, _ -> false) &&
        List.for_all (fun id -> not (List.mem id history)) [token.token_id] &&
        (match token.binding with
         | None -> true
         | Some b -> binding_unique sender_state token.token_id b))
      (ensures True)
  = ()

// -----------------------------------------------------------------------------
// RFC 7800 confirmation (cnf) semantics
// -----------------------------------------------------------------------------

type confirmation = {
  dpop_jkt: option string;
  mtls_x5t: option string;
}

let cnf_single_key (cnf:confirmation) : Tot bool =
  match cnf.dpop_jkt, cnf.mtls_x5t with
  | Some _, None -> true
  | None, Some _ -> true
  | None, None -> true
  | Some _, Some _ -> false

let cnf_from_sender_binding (binding: option sender_binding) : Tot confirmation =
  match binding with
  | None -> { dpop_jkt = None; mtls_x5t = None }
  | Some (SenderDPoP jkt) -> { dpop_jkt = Some jkt; mtls_x5t = None }
  | Some (SenderMTLS fp) -> { dpop_jkt = None; mtls_x5t = Some fp }

let lemma_cnf_single_key
  (binding: option sender_binding)
  : Lemma (ensures (cnf_single_key (cnf_from_sender_binding binding) = true))
  = ()

// -----------------------------------------------------------------------------
// RFC 8693 Token Exchange (Aegaeon MVP profile)
// -----------------------------------------------------------------------------

type token_exchange_request = {
  requested_scopes: scope;
  target_audience: audience;
  presented_binding: option sender_binding;
}

let token_exchange_allowed (subject: bearer_token) (req: token_exchange_request) : Tot bool =
  not subject.revoked
  && scope_contains subject.scopes req.requested_scopes
  && audience_matches subject req.target_audience
  && (match subject.binding with
      | None -> true
      | Some b -> req.presented_binding = Some b)

let token_exchange_mint
  (new_token_id: string)
  (subject: bearer_token)
  (req: token_exchange_request)
  : Pure bearer_token
      (requires token_exchange_allowed subject req)
      (ensures (fun t ->
        t.token_id = new_token_id
        && t.issuer = subject.issuer
        && t.audience = req.target_audience
        && t.scopes = req.requested_scopes
        && t.binding = req.presented_binding
        && not t.revoked))
  =
  {
    token_id = new_token_id;
    issuer = subject.issuer;
    audience = req.target_audience;
    scopes = req.requested_scopes;
    binding = req.presented_binding;
    revoked = false;
  }

let lemma_token_exchange_scope_subset
  (subject: bearer_token)
  (req: token_exchange_request)
  : Lemma
      (requires token_exchange_allowed subject req)
      (ensures scope_contains subject.scopes req.requested_scopes)
  = ()

let lemma_token_exchange_audience_stable
  (subject: bearer_token)
  (req: token_exchange_request)
  : Lemma
      (requires token_exchange_allowed subject req)
      (ensures subject.audience = req.target_audience)
  = ()

let lemma_token_exchange_preserves_sender_binding_when_present
  (subject: bearer_token)
  (req: token_exchange_request)
  : Lemma
      (requires token_exchange_allowed subject req)
      (ensures (match subject.binding with
        | None -> True
        | Some b -> req.presented_binding = Some b))
  = ()
