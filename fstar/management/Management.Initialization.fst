module Management.Initialization

(* Design model, not a Rust/SQL refinement proof. The operator entry point
   supplies validated input. PostgreSQL commits the complete write set or none;
   all initializer paths serialize on one lock and read a fresh snapshot after
   acquiring it. DNS/JSON validation, password hashing and lock correspondence
   require separate implementation evidence. No credential is an output. *)
noeq type state = {
  administrators: nat;
  policy: option nat;
  owner: option nat;
  environments: nat -> option nat
}

type request = {
  administrator: nat;
  allowed_policy: nat;
  environment: nat;
  document: nat;
  valid: bool
}

let initialize (s:state) (r:request) (commit:bool) : state =
  if r.valid && s.administrators = 0 && s.policy = None && commit then
    { administrators = 1; policy = Some r.allowed_policy;
      owner = Some r.administrator;
      environments = (fun e -> if e = r.environment then Some r.document else s.environments e) }
  else s

let initialized_is_immutable (s:state{ s.administrators > 0 }) (r:request) (c:bool)
  : Lemma (initialize s r c == s) = ()

let existing_policy_is_not_replaced (s:state{ s.policy <> None }) (r:request) (c:bool)
  : Lemma (initialize s r c == s) = ()

let invalid_input_is_noop (s:state) (r:request{ not r.valid }) (c:bool)
  : Lemma (initialize s r c == s) = ()

let rollback_is_noop (s:state) (r:request)
  : Lemma (initialize s r false == s) = ()

let success_is_complete (s:state{ s.administrators = 0 /\ s.policy = None })
  (r:request{ r.valid })
  : Lemma (let n = initialize s r true in
      n.administrators = 1 /\ n.owner = Some r.administrator /\
      n.policy = Some r.allowed_policy /\ n.environments r.environment = Some r.document) = ()

let serial_initializers_have_one_winner
  (s:state{ s.administrators = 0 /\ s.policy = None })
  (first:request{ first.valid }) (second:request)
  : Lemma (initialize (initialize s first true) second true == initialize s first true) = ()

let insert_environment (s:state) (id:nat) (document:nat) (authorized:bool) : state =
  if authorized && s.environments id = None then
    { s with environments = (fun e -> if e = id then Some document else s.environments e) }
  else s

let environment_creation_preserves_authority (s:state) (id:nat) (d:nat) (a:bool)
  : Lemma (let n = insert_environment s id d a in
    n.administrators = s.administrators /\ n.policy = s.policy /\ n.owner = s.owner) = ()

let environment_creation_preserves_other_environment
  (s:state) (id:nat) (other:nat{ other <> id }) (d:nat) (a:bool)
  : Lemma ((insert_environment s id d a).environments other = s.environments other) = ()

let unauthorized_creation_is_noop (s:state) (id:nat) (d:nat)
  : Lemma (insert_environment s id d false == s) = ()

(* Runtime snapshot fingerprints must not depend on connection search_path.
   Both functions are abstract: this proves namespace independence, not SHA-256. *)
type digest_namespace =
  | ManagedSchema
  | CallerSearchPath

let call_digest (namespace:digest_namespace) (managed:nat -> nat)
  (caller:nat -> nat) (document:nat) : nat =
  match namespace with
  | ManagedSchema -> managed document
  | CallerSearchPath -> caller document

let managed_digest_is_independent_of_caller
  (managed:nat -> nat) (first:nat -> nat) (second:nat -> nat) (document:nat)
  : Lemma (call_digest ManagedSchema managed first document =
           call_digest ManagedSchema managed second document) = ()
