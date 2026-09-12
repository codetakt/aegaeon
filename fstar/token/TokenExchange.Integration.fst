module TokenExchange.Integration

(* Abstract composition only: configuration versions and exchange-policy identity
   are distinct. SQL locking, Rust representation and Lua execution remain open.
   This slice concerns captured cross-target authority, not legacy same-target exchange. *)
module M = Configuration.Membership
module T = TokenExchange.TargetPolicy

type parent = { context_target: option nat; resource_target: option nat; client: nat }

let parent_audience (p:parent) : Tot nat =
  match p.context_target with
  | Some target -> target
  | None -> (match p.resource_target with | Some resource -> resource | None -> p.client)

noeq type state = {
  configuration: M.state;
  refresh_parent: parent;
  captured: option T.subject;
  root_denied: bool
}

let activate (s:state) (environment:nat) (base:nat) (next:nat)
  (clean:bool) (committed:bool) : Tot state =
  {s with configuration = M.transition s.configuration environment base next clean committed}

let exchange (s:state) (rules:list T.rule) (request:T.request) : Tot (option T.subject) =
  match s.captured with
  | None -> None
  | Some subject -> if s.root_denied then None else T.exchange rules subject request

let lemma_context_target_precedes_resource (context:nat) (resource:nat) (client:nat)
  : Lemma (parent_audience {context_target=Some context; resource_target=Some resource;
    client=client} = context) = ()

let lemma_resource_precedes_client (resource:nat) (client:nat)
  : Lemma (parent_audience {context_target=None; resource_target=Some resource;
    client=client} = resource) = ()

let lemma_client_fallback_requires_no_target (client:nat)
  : Lemma (parent_audience {context_target=None; resource_target=None; client=client} = client) = ()

let lemma_activation_preserves_grant (s:state) (environment:nat) (base:nat) (next:nat)
  (clean:bool) (committed:bool)
  : Lemma ((activate s environment base next clean committed).captured = s.captured) = ()

let lemma_activation_preserves_parent_audience (s:state) (environment:nat) (base:nat) (next:nat)
  (clean:bool) (committed:bool)
  : Lemma (parent_audience (activate s environment base next clean committed).refresh_parent =
    parent_audience s.refresh_parent) = ()

let lemma_activation_cannot_create_missing_authority (s:state) (environment:nat)
  (base:nat) (next:nat) (clean:bool) (committed:bool) (rules:list T.rule) (request:T.request)
  : Lemma (requires (s.captured = None))
    (ensures (exchange (activate s environment base next clean committed) rules request = None)) = ()

let lemma_activation_cannot_clear_root_denial (s:state) (environment:nat)
  (base:nat) (next:nat) (clean:bool) (committed:bool) (rules:list T.rule) (request:T.request)
  : Lemma (requires s.root_denied)
    (ensures (exchange (activate s environment base next clean committed) rules request = None)) = ()

let lemma_changed_exchange_context_rejected (s:state) (environment:nat)
  (base:nat) (next:nat) (clean:bool) (committed:bool) (rules:list T.rule)
  (request:T.request) (subject:T.subject)
  : Lemma (requires (s.captured = Some subject /\ subject.origin <> request.caller))
    (ensures (exchange (activate s environment base next clean committed) rules request = None)) =
  T.lemma_context_cannot_change rules subject request

let lemma_exchange_after_activation_retains_bounds (s:state) (environment:nat)
  (base:nat) (next:nat) (clean:bool) (committed:bool) (rules:list T.rule)
  (request:T.request) (subject:T.subject) (output:T.subject)
  : Lemma (requires (s.captured = Some subject /\
      exchange (activate s environment base next clean committed) rules request = Some output))
    (ensures (output.origin = subject.origin /\ output.user = subject.user /\
      output.root_authority = subject.root_authority /\
      T.subset output.remaining_authority subject.remaining_authority /\
      output.expires <= subject.expires /\ T.sender_ok subject.sender output.sender)) =
  T.lemma_output_binds_authority rules subject request output

let lemma_commit_carries_members_and_preserves_grant (s:state) (environment:nat)
  (next:nat) (id:nat)
  : Lemma (requires (s.configuration.active <> next /\
      M.target_clean s.configuration.rows environment next))
    (ensures (let after = activate s environment s.configuration.active next true true in
      M.member_at after.configuration.rows environment after.configuration.active id =
        M.member_at s.configuration.rows environment s.configuration.active id /\
      after.captured = s.captured /\ after.refresh_parent = s.refresh_parent)) =
  M.lemma_commit_exact_membership s.configuration environment next id

let lemma_abort_keeps_active_members (s:state) (environment:nat) (base:nat)
  (next:nat) (clean:bool) (id:nat)
  : Lemma (let after = activate s environment base next clean false in
    after.configuration.active = s.configuration.active /\
    after.configuration.rows id = s.configuration.rows id /\ after.captured = s.captured) = ()

let lemma_version_change_with_same_policy_success_witness ()
  : Lemma (let s = {
      configuration={M.active=1; M.rows=(fun _ -> None)};
      refresh_parent={context_target=Some 1; resource_target=None; client=0};
      captured=Some T.witness_subject; root_denied=false} in
    let after = activate s 1 1 2 true true in
    after.configuration.active = 2 /\
    exchange after T.witness_rules T.witness_request =
      Some {T.witness_subject with T.audience=2; T.remaining_authority=[T.read_target]; T.expires=50}) =
  T.lemma_distinct_audience_success_witness ()
