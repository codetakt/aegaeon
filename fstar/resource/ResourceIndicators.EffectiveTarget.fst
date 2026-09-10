module ResourceIndicators.EffectiveTarget

(* Single-target context design, not production refinement or the general
   multi-resource OAuth profile. Inputs are parsed and grant authorization is
   supplied at an explicit boundary; a URI is not an authorization grant.
   Stored issuer/configuration and consent evidence are proposed requirements,
   not fields or checks claimed to exist in the current server. *)

type profile = {
  issuer: string;
  client_id: string;
  userinfo: string;
  oidc_enabled: bool;
  configuration_version: nat
}

type request = {
  openid_granted: bool;
  explicit_resource: option string
}

type grant_context = {
  grant_issuer: string;
  grant_client: string;
  grant_configuration: nat;
  effective_target: string
}

let resolve (p:profile) (r:request) : Tot string =
  match r.explicit_resource with
  | Some resource -> resource
  | None -> if p.oidc_enabled && r.openid_granted then p.userinfo else p.client_id

(* Same-grant access re-minting must share saved-target precedence with refresh.
   The legacy branch preserves the existing resource/client-only record policy;
   it does not supply missing issuer evidence to a modern refresh request. *)
let parent_target (saved:option string) (resource:option string) (client:string)
  : Tot string =
  match saved with
  | Some target -> target
  | None -> (match resource with | Some target -> target | None -> client)

let remint_permitted (saved:option string) (resource:option string)
  (client:string) (audience:string) : Tot bool =
  audience = parent_target saved resource client

let lemma_remint_preserves_saved_target (saved:string) (resource:option string)
  (client:string) (audience:string)
  : Lemma (remint_permitted (Some saved) resource client audience = (audience = saved))
  = ()

let lemma_remint_rejects_client_fallback (saved:string) (client:string)
  : Lemma (requires (saved <> client))
          (ensures (not (remint_permitted (Some saved) None client client)))
  = ()

let lemma_remint_oidc_target_reachable ()
  : Lemma (remint_permitted (Some "issuer/userinfo") None "client" "issuer/userinfo")
  = ()

let lemma_remint_legacy_resource (resource:string) (client:string)
  : Lemma (parent_target None (Some resource) client = resource)
  = ()

let initial (p:profile) (r:request) : Tot (string * grant_context) =
  let target = resolve p r in
  (target, {grant_issuer=p.issuer; grant_client=p.client_id;
            grant_configuration=p.configuration_version; effective_target=target})

(* RFC 8707 section 2.2 leaves acceptable resources to authorization-server
   policy. This single-resource policy permits only an explicit resource in the
   original grant. None preserves default selection; it is not authority to add
   an arbitrary target at redemption. The outer None means rejection, whereas
   Some None means acceptance with the original default. URI parsing and the
   authority that approved the original grant are separate obligations. *)
let redeem_code_resource (granted:option string) (requested:option string)
  : Tot (option (option string)) =
  match requested with
  | None -> Some granted
  | Some target -> if granted = Some target then Some granted else None

let lemma_code_resource_omission (granted:option string)
  : Lemma (redeem_code_resource granted None = Some granted)
  = ()

let lemma_code_resource_exact (target:string)
  : Lemma (redeem_code_resource (Some target) (Some target) = Some (Some target))
  = ()

let lemma_code_resource_no_late_addition (target:string)
  : Lemma (redeem_code_resource None (Some target) = None)
  = ()

let lemma_code_resource_no_retarget (granted:string) (requested:string)
  : Lemma
    (requires (granted <> requested))
    (ensures (redeem_code_resource (Some granted) (Some requested) = None))
  = ()

let lemma_code_resource_acceptance_preserves_grant
  (granted:option string) (requested:option string)
  : Lemma
    (match redeem_code_resource granted requested with
     | None -> True
     | Some selected -> selected = granted)
  = ()

let lemma_code_resource_default_remains_default ()
  : Lemma (redeem_code_resource None None = Some None)
  = ()

let refresh (p:profile) (saved:grant_context) (requested:option string)
  : Tot (option (string * grant_context)) =
  if p.issuer <> saved.grant_issuer || p.client_id <> saved.grant_client ||
     p.configuration_version <> saved.grant_configuration then None
  else if (match requested with
           | None -> false
           | Some target -> target <> saved.effective_target) then None
  else Some (saved.effective_target, saved)

let lemma_explicit_target (p:profile) (openid:bool) (target:string)
  : Lemma (resolve p {openid_granted=openid; explicit_resource=Some target} = target)
  = ()

let lemma_oidc_default (p:profile)
  : Lemma
    (requires p.oidc_enabled)
    (ensures (resolve p {openid_granted=true; explicit_resource=None} = p.userinfo))
  = ()

let lemma_client_fallback (p:profile) (openid:bool)
  : Lemma
    (requires (not p.oidc_enabled \/ not openid))
    (ensures (resolve p {openid_granted=openid; explicit_resource=None} = p.client_id))
  = ()

let lemma_initial_context_consistent (p:profile) (r:request)
  : Lemma (fst (initial p r) = (snd (initial p r)).effective_target)
  = ()

let lemma_initial_then_refresh_reachable (p:profile) (r:request)
  : Lemma (refresh p (snd (initial p r)) None = Some (initial p r))
  = ()

let lemma_refresh_preserves_context
  (p:profile) (saved:grant_context) (requested:option string)
  : Lemma
    (match refresh p saved requested with
     | None -> True
     | Some (target, context) -> target = saved.effective_target /\ context = saved)
  = ()

let lemma_retarget_rejected (p:profile) (saved:grant_context) (target:string)
  : Lemma
    (requires (target <> saved.effective_target))
    (ensures (refresh p saved (Some target) = None))
  = ()

let lemma_changed_context_rejected (p:profile) (saved:grant_context)
  (requested:option string)
  : Lemma
    (requires
      (p.issuer <> saved.grant_issuer \/ p.client_id <> saved.grant_client \/
       p.configuration_version <> saved.grant_configuration))
    (ensures (refresh p saved requested = None))
  = ()

(* Model counterexample to the legacy None -> client fallback, not HTTP E2E. *)
let witness_profile : profile = {
  issuer="issuer"; client_id="client"; userinfo="issuer/userinfo";
  oidc_enabled=true; configuration_version=1
}

let lemma_legacy_fallback_conflicts ()
  : Lemma
    (resolve witness_profile {openid_granted=true; explicit_resource=None} <>
     witness_profile.client_id)
  = ()

(* Scope strings have already passed protocol parsing. This list model does
   not assign application permissions to equal strings at different targets. *)
let rec scope_member (name:string) (scopes:list string) : Tot bool =
  match scopes with
  | [] -> false
  | head::tail -> name = head || scope_member name tail

let rec scope_subset (requested:list string) (granted:list string) : Tot bool =
  match requested with
  | [] -> true
  | head::tail -> scope_member head granted && scope_subset tail granted

type offline_conditions = {
  returns_code: bool;
  has_offline_consent: bool;
  prompt_requests_consent: bool;
  other_offline_conditions: bool
}

(* OIDC Core section 11: a prompt requests consent; it does not prove consent.
   Refresh tokens for other OAuth uses are outside this constructor. *)
let offline_permitted (c:offline_conditions) : Tot bool =
  c.returns_code && c.has_offline_consent &&
  (c.prompt_requests_consent || c.other_offline_conditions)

type scoped_context = {
  target_context: grant_context;
  subject: string;
  granted_scopes: list string;
  sender_binding: option string;
  expires_at: nat;
  active: bool
}

let issue_oidc_offline_context
  (p:profile) (authorized:bool) (subject:string) (scopes:list string)
  (resource:option string) (binding:option string) (conditions:offline_conditions)
  (now:nat) (expires_at:nat) : Tot (option scoped_context) =
  if not authorized || not p.oidc_enabled ||
     not (scope_member "openid" scopes) ||
     not (scope_member "offline_access" scopes) ||
     not (offline_permitted conditions) || now >= expires_at then None
  else Some {
    target_context = snd (initial p {openid_granted=true; explicit_resource=resource});
    subject=subject; granted_scopes=scopes; sender_binding=binding;
    expires_at=expires_at; active=true
  }

(* RFC 6749 section 6 separates the requested access-token scope from the
   refresh-token grant: a replacement refresh token retains the original scope.
   Scope syntax parsing is outside this model; lists represent parsed tokens. *)
type refreshed_context = {
  access_scopes: list string;
  refresh_grant: scoped_context
}

(* active is a fresh storage decision supplied to this pure slice, not a
   proof that revocation caches or Redis deliver fresh state. Expiry is not
   extended here; token lifetime policy and rotation atomicity are separate. *)
let refresh_scoped_context
  (p:profile) (saved:scoped_context) (target:option string)
  (requested_scopes:option (list string)) (binding:option string) (now:nat)
  : Tot (option refreshed_context) =
  if not saved.active || now >= saved.expires_at || binding <> saved.sender_binding
  then None
  else
    match refresh p saved.target_context target with
    | None -> None
    | Some (_, context) ->
      match requested_scopes with
      | None -> Some {access_scopes=saved.granted_scopes;
                      refresh_grant={saved with target_context=context}}
      | Some scopes ->
        if not (scope_subset scopes saved.granted_scopes) then None
        else Some {access_scopes=scopes;
                   refresh_grant={saved with target_context=context}}

let lemma_no_offline_context_without_authorization
  (p:profile) (subject:string) (scopes:list string) (resource:option string)
  (binding:option string) (conditions:offline_conditions) (now:nat) (expiry:nat)
  : Lemma
    (issue_oidc_offline_context p false subject scopes resource binding conditions now expiry = None)
  = ()

let lemma_no_offline_context_without_conditions
  (p:profile) (authorized:bool) (subject:string) (scopes:list string)
  (resource:option string) (binding:option string) (c:offline_conditions)
  (now:nat) (expiry:nat)
  : Lemma
    (requires
      (not c.returns_code \/ not c.has_offline_consent \/
       (not c.prompt_requests_consent /\ not c.other_offline_conditions)))
    (ensures
      (issue_oidc_offline_context p authorized subject scopes resource binding c now expiry = None))
  = ()

let lemma_scoped_refresh_preserves_identity
  (p:profile) (saved:scoped_context) (target:option string)
  (scopes:option (list string)) (binding:option string) (now:nat)
  : Lemma
    (match refresh_scoped_context p saved target scopes binding now with
     | None -> True
     | Some next ->
       next.refresh_grant = saved)
  = ()

let lemma_expired_or_inactive_refresh_rejected
  (p:profile) (saved:scoped_context) (target:option string)
  (scopes:option (list string)) (binding:option string) (now:nat)
  : Lemma
    (requires (not saved.active \/ now >= saved.expires_at))
    (ensures (refresh_scoped_context p saved target scopes binding now = None))
  = ()

let lemma_sender_binding_mismatch_rejected
  (p:profile) (saved:scoped_context) (target:option string)
  (scopes:option (list string)) (binding:option string) (now:nat)
  : Lemma
    (requires (binding <> saved.sender_binding))
    (ensures (refresh_scoped_context p saved target scopes binding now = None))
  = ()

let lemma_scope_expansion_rejected
  (p:profile) (saved:scoped_context) (target:option string)
  (scopes:list string) (binding:option string) (now:nat)
  : Lemma
    (requires (not (scope_subset scopes saved.granted_scopes)))
    (ensures (refresh_scoped_context p saved target (Some scopes) binding now = None))
  = ()

let lemma_requested_scopes_are_bounded
  (p:profile) (saved:scoped_context) (target:option string)
  (scopes:list string) (binding:option string) (now:nat)
  : Lemma
    (match refresh_scoped_context p saved target (Some scopes) binding now with
     | None -> True
     | Some next -> next.access_scopes = scopes /\ scope_subset scopes saved.granted_scopes)
  = ()

let lemma_omitted_scope_preserves_grant
  (p:profile) (saved:scoped_context) (target:option string)
  (binding:option string) (now:nat)
  : Lemma
    (match refresh_scoped_context p saved target None binding now with
     | None -> True
     | Some next -> next.access_scopes = saved.granted_scopes /\ next.refresh_grant = saved)
  = ()

let lemma_replacement_refresh_scope_unchanged
  (p:profile) (saved:scoped_context) (target:option string)
  (scopes:option (list string)) (binding:option string) (now:nat)
  : Lemma
    (match refresh_scoped_context p saved target scopes binding now with
     | None -> True
     | Some next -> next.refresh_grant.granted_scopes = saved.granted_scopes)
  = ()

let lemma_attenuation_then_omission_uses_original_scope
  (p:profile) (saved:scoped_context) (target:option string)
  (scopes:list string) (binding:option string) (now:nat)
  : Lemma
    (match refresh_scoped_context p saved target (Some scopes) binding now with
     | None -> True
     | Some next ->
       refresh_scoped_context p next.refresh_grant None None binding now =
         Some {access_scopes=saved.granted_scopes; refresh_grant=saved})
  = ()

(* Legacy reconstruction requires externally grounded original context.
   This function never constructs an issuer or target from today's defaults.
   Obtaining and authenticating that evidence is a persistence obligation. *)
let restore_legacy_context
  (p:profile) (legacy_client:string) (recorded_resource:option string)
  (original_context:option grant_context) : Tot (option grant_context) =
  match original_context with
  | None -> None
  | Some saved ->
    if legacy_client <> saved.grant_client then None
    else
      match refresh p saved recorded_resource with
      | None -> None
      | Some (_, context) -> Some context

let lemma_missing_legacy_evidence_rejected
  (p:profile) (client:string) (resource:option string)
  : Lemma (restore_legacy_context p client resource None = None)
  = ()

let lemma_legacy_restore_preserves_original
  (p:profile) (client:string) (resource:option string) (original:grant_context)
  : Lemma
    (match restore_legacy_context p client resource (Some original) with
     | None -> True
     | Some context -> context = original /\ context.grant_client = client)
  = ()

let witness_consent : offline_conditions = {
  returns_code=true; has_offline_consent=true;
  prompt_requests_consent=true; other_offline_conditions=false
}

let witness_offline (scopes:list string) : Tot (option scoped_context) =
  issue_oidc_offline_context witness_profile true "subject" scopes None
    (Some "sender-key") witness_consent 0 30

let lemma_two_and_four_scope_flows_reachable ()
  : Lemma
    (witness_offline ["openid"; "offline_access"] <> None /\
     witness_offline ["openid"; "profile"; "email"; "offline_access"] <> None /\
     (match witness_offline ["openid"; "profile"; "email"; "offline_access"] with
      | None -> False
      | Some saved ->
        saved.target_context.effective_target = witness_profile.userinfo /\
        refresh_scoped_context witness_profile saved None None (Some "sender-key") 1 =
          Some {access_scopes=saved.granted_scopes; refresh_grant=saved}))
  = ()

let lemma_attenuation_does_not_reselect_target ()
  : Lemma
    (match witness_offline ["openid"; "profile"; "email"; "offline_access"] with
     | None -> False
     | Some saved ->
       (match refresh_scoped_context witness_profile saved None (Some ["profile"])
                (Some "sender-key") 1 with
        | None -> False
        | Some next -> next.refresh_grant.target_context.effective_target = witness_profile.userinfo /\
                       next.access_scopes = ["profile"] /\
                       next.refresh_grant.granted_scopes =
                         ["openid"; "profile"; "email"; "offline_access"] /\
                       refresh_scoped_context witness_profile next.refresh_grant None None
                         (Some "sender-key") 2 =
                         Some {access_scopes=saved.granted_scopes; refresh_grant=saved}))
  = ()

let lemma_grounded_legacy_context_reachable ()
  : Lemma
    (let original = snd (initial witness_profile
       {openid_granted=true; explicit_resource=None}) in
     restore_legacy_context witness_profile "client" None (Some original) = Some original)
  = ()
