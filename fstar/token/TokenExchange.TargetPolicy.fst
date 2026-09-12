module TokenExchange.TargetPolicy

(* Initial design slice only. No Rust/HTTP/Redis refinement claim.
   Identity, URI syntax and authenticated token/grant lookup are outer obligations.
   Targets/actions are canonical registered identities, not interchangeable scope strings.
   root_authority/remaining_authority model server-side captured exchange authority.
   Their relation to BearerTokenMeta and serialized records remains unproved;
   they are not raw JWT claims. *)
module L = FStar.List.Tot

type target = nat
type capability = { resource: target; operation: nat }
type context = { issuer: string; tenant: string; client: string; policy_version: nat }
type binding = | Unbound | DPoP of nat | Mtls of nat

type subject = {
  origin: context;
  user: string;
  audience: target;
  root_authority: list capability;
  remaining_authority: list capability;
  sender: binding;
  valid: bool;
  expires: nat
}

type request = {
  caller: context;
  authenticated: bool;
  destination: target;
  rights: list capability;
  presented: binding;
  now: nat;
  output_expires: nat
}

type rule = {
  authority: context;
  source: target;
  destination: target;
  ceiling: list capability
}

let subset (xs:list capability) (ys:list capability) : Tot bool =
  L.for_all (fun c -> L.mem c ys) xs

let sender_ok (old:binding) (presented:binding) : Tot bool =
  match old with | Unbound -> true | _ -> old = presented

let registered (rules:list rule) (s:subject) (r:request) : Tot bool =
  L.existsb (fun rule -> rule.authority = r.caller && rule.source = s.audience &&
    rule.destination = r.destination && subset r.rights rule.ceiling) rules

let at_target (cs:list capability) (t:target) : Tot bool =
  L.for_all (fun c -> c.resource = t) cs

let allowed (rules:list rule) (s:subject) (r:request) : Tot bool =
  r.authenticated && s.valid &&
  s.origin = r.caller &&
  registered rules s r &&
  r.rights <> [] && at_target r.rights r.destination &&
  subset s.remaining_authority s.root_authority &&
  subset r.rights s.remaining_authority && subset r.rights s.root_authority &&
  sender_ok s.sender r.presented &&
  r.now < r.output_expires && r.output_expires <= s.expires

let exchange (rules:list rule) (s:subject) (r:request) : Tot (option subject) =
  if allowed rules s r then
    Some {s with audience = r.destination; remaining_authority = r.rights;
                 sender = r.presented; expires = r.output_expires}
  else None

(* Canonicalization follows registry lookup. None is an unknown identifier.
   Both audience and resource lists contribute targets; neither takes precedence. *)
let rec all_targets (t:target) (xs:list (option target)) : Tot bool =
  match xs with
  | [] -> true
  | Some x :: rest -> x = t && all_targets t rest
  | None :: _ -> false

let resolve (default:option target) (xs:list (option target)) : Tot (option target) =
  match xs with
  | [] -> default
  | None :: _ -> None
  | Some t :: rest -> if all_targets t rest then Some t else None

let lemma_same_target_aliases (t:target)
  : Lemma (resolve None [Some t; Some t] = Some t) = ()

let lemma_conflicting_targets (a:target) (b:target)
  : Lemma (requires (a <> b)) (ensures (resolve None [Some a; Some b] = None)) = ()

let lemma_unknown_target (default:option target)
  : Lemma (resolve default [None] = None) = ()

let lemma_explicit_target_overrides_default (a:target) (b:target)
  : Lemma (resolve (Some a) [Some b] = Some b) = ()

let lemma_default_is_explicit_policy (d:option target)
  : Lemma (resolve d [] = d) = ()

let lemma_requires_authentication (ps:list rule) (s:subject) (r:request)
  : Lemma (requires (not r.authenticated)) (ensures (exchange ps s r = None)) = ()

let lemma_requires_valid_subject (ps:list rule) (s:subject) (r:request)
  : Lemma (requires (not s.valid)) (ensures (exchange ps s r = None)) = ()

let lemma_context_cannot_change (ps:list rule) (s:subject) (r:request)
  : Lemma (requires (s.origin <> r.caller)) (ensures (exchange ps s r = None)) = ()

let lemma_explicit_route_required (ps:list rule) (s:subject) (r:request)
  : Lemma (requires (not (registered ps s r))) (ensures (exchange ps s r = None)) = ()

let lemma_no_scope_regrowth (ps:list rule) (s:subject) (r:request)
  : Lemma (requires (not (subset r.rights s.remaining_authority)))
    (ensures (exchange ps s r = None)) = ()

let lemma_target_semantics_required (ps:list rule) (s:subject) (r:request)
  : Lemma (requires (not (at_target r.rights r.destination)))
    (ensures (exchange ps s r = None)) = ()

let lemma_sender_cannot_weaken (ps:list rule) (s:subject) (r:request)
  : Lemma (requires (not (sender_ok s.sender r.presented)))
    (ensures (exchange ps s r = None)) = ()

let lemma_expiry_cannot_extend (ps:list rule) (s:subject) (r:request)
  : Lemma (requires (s.expires < r.output_expires))
    (ensures (exchange ps s r = None)) = ()

let lemma_expired_subject_rejected (ps:list rule) (s:subject) (r:request)
  : Lemma (requires (s.expires <= r.now)) (ensures (exchange ps s r = None)) = ()

let lemma_output_binds_authority (ps:list rule) (s:subject) (r:request) (out:subject)
  : Lemma (requires (exchange ps s r = Some out))
    (ensures (out.origin = s.origin && out.user = s.user && out.audience = r.destination &&
              out.root_authority = s.root_authority && out.remaining_authority = r.rights &&
              subset out.remaining_authority s.remaining_authority &&
              subset out.remaining_authority s.root_authority &&
              out.expires <= s.expires && sender_ok s.sender out.sender)) = ()

let witness_context : context = {issuer="https://issuer.example"; tenant="one";
  client="application"; policy_version=1}
let read_target : capability = {resource=2; operation=1}
let write_target : capability = {resource=2; operation=2}
let witness_subject : subject = {origin=witness_context; user="user"; audience=1;
  root_authority=[read_target; write_target]; remaining_authority=[read_target; write_target];
  sender=Unbound; valid=true; expires=100}
let witness_request : request = {caller=witness_context; authenticated=true; destination=2;
  rights=[read_target]; presented=Unbound; now=10; output_expires=50}
let witness_rules : list rule = [{authority=witness_context; source=1; destination=2;
  ceiling=[read_target; write_target]}]

let lemma_distinct_audience_success_witness ()
  : Lemma (witness_subject.audience <> witness_request.destination &&
    exchange witness_rules witness_subject witness_request =
      Some {witness_subject with audience=2; remaining_authority=[read_target]; expires=50}) = ()

let lemma_sequential_regrowth_rejected ()
  : Lemma (let first = {witness_subject with audience=2; remaining_authority=[read_target]; expires=50} in
    let second = {witness_request with rights=[write_target]; now=20; output_expires=40} in
    let second_rule = {authority=witness_context; source=2; destination=2;
      ceiling=[read_target; write_target]} in
    exchange [second_rule] first second = None) = ()


(* A refresh keeps its original grant. Each new access token receives only
   capabilities whose original source requirements are still satisfied.
   These mappings are persisted at authorization, never rebuilt from JWT claims. *)
type source_scope = nat
type mapping = { right: capability; needs: list source_scope }
let scope_subset (xs:list source_scope) (ys:list source_scope) : Tot bool =
  L.for_all (fun x -> L.mem x ys) xs
let enabled (m:mapping) (actual:list source_scope) : Tot bool =
  m.needs <> [] && scope_subset m.needs actual
let attenuate (ms:list mapping) (actual:list source_scope) : Tot (list mapping) =
  L.filter (fun m -> enabled m actual) ms
let rec lemma_attenuation_membership (ms:list mapping) (actual:list source_scope) (m:mapping)
  : Lemma (requires (L.mem m (attenuate ms actual)))
    (ensures (L.mem m ms && enabled m actual)) =
  match ms with | [] -> () | x::xs ->
    if L.mem m (attenuate xs actual) then lemma_attenuation_membership xs actual m
let read_map : mapping = {right=read_target; needs=[1]}
let write_map : mapping = {right=write_target; needs=[2]}
let lemma_refresh_narrowing_witness ()
  : Lemma (attenuate [read_map;write_map] [1] = [read_map]) = ()
let lemma_missing_conditions_never_authorize (m:mapping) (actual:list source_scope)
  : Lemma (requires (m.needs=[])) (ensures (not (enabled m actual))) = ()


(* Root denial is monotone and independent of bounded child-index cleanup.
   Integer times denote the exact enforcement deadline; rounding/indexing
   and concrete Redis atomicity are separate correspondence obligations. *)
type root_state = { denied: bool; deadline: nat; children: list nat }
let root_live (s:root_state) (now:nat) : Tot bool = not s.denied && now < s.deadline
let deny_root (s:root_state) : Tot root_state = {s with denied=true}
let cleanup_children (s:root_state) (success:bool) : Tot root_state =
  if success then {s with children=[]} else s
let lemma_root_denial_independent_of_cleanup (s:root_state) (now:nat) (success:bool)
  : Lemma (not (root_live (cleanup_children (deny_root s) success) now)) = ()
let lemma_lost_children_do_not_restore_root (s:root_state) (now:nat) (old:list nat)
  : Lemma (requires s.denied) (ensures (not (root_live {s with children=old} now))) = ()
let lemma_expired_root_stays_unusable (s:root_state) (now:nat)
  : Lemma (requires (s.deadline <= now)) (ensures (not (root_live s now))) = ()
