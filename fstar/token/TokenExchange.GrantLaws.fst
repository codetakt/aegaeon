module TokenExchange.GrantLaws

(* General laws for the accepted abstract model's attenuation function.
   This is not a Rust/serde/string-identity/Redis refinement theorem.
   Sequential attenuation here means descendants of the SAME access grant;
   refresh keeps the original authorization separately and may reissue its scope. *)
module L = FStar.List.Tot
open TokenExchange.TargetPolicy

let rec lemma_attenuation_complete (ms:list mapping) (actual:list source_scope) (m:mapping)
  : Lemma (requires (L.mem m ms && enabled m actual))
    (ensures (L.mem m (attenuate ms actual))) =
  match ms with
  | [] -> ()
  | x::xs -> if x <> m then lemma_attenuation_complete xs actual m

let lemma_attenuation_exact_membership (ms:list mapping) (actual:list source_scope) (m:mapping)
  : Lemma (L.mem m (attenuate ms actual) <==> (L.mem m ms && enabled m actual)) =
  if L.mem m (attenuate ms actual) then lemma_attenuation_membership ms actual m;
  if L.mem m ms && enabled m actual then lemma_attenuation_complete ms actual m

let rec lemma_attenuation_idempotent (ms:list mapping) (actual:list source_scope)
  : Lemma (attenuate (attenuate ms actual) actual = attenuate ms actual) =
  match ms with
  | [] -> ()
  | _::xs -> lemma_attenuation_idempotent xs actual

let rec lemma_attenuation_commutes (ms:list mapping) (a:list source_scope) (b:list source_scope)
  : Lemma (attenuate (attenuate ms a) b = attenuate (attenuate ms b) a) =
  match ms with
  | [] -> ()
  | _::xs -> lemma_attenuation_commutes xs a b

let rec lemma_scope_subset_member (xs:list source_scope) (ys:list source_scope) (x:source_scope)
  : Lemma (requires (scope_subset xs ys && L.mem x xs)) (ensures (L.mem x ys)) =
  match xs with
  | [] -> ()
  | h::tail -> if h <> x then lemma_scope_subset_member tail ys x

let rec lemma_scope_subset_transitive (xs:list source_scope) (ys:list source_scope) (zs:list source_scope)
  : Lemma (requires (scope_subset xs ys && scope_subset ys zs)) (ensures (scope_subset xs zs)) =
  match xs with
  | [] -> ()
  | x::tail -> lemma_scope_subset_member ys zs x; lemma_scope_subset_transitive tail ys zs

let lemma_enabled_monotone (m:mapping) (narrow:list source_scope) (wide:list source_scope)
  : Lemma (requires (scope_subset narrow wide && enabled m narrow)) (ensures (enabled m wide)) =
  lemma_scope_subset_transitive m.needs narrow wide

let lemma_narrowing_never_adds_mapping (ms:list mapping) (narrow:list source_scope)
  (wide:list source_scope) (m:mapping)
  : Lemma (requires (scope_subset narrow wide && L.mem m (attenuate ms narrow)))
    (ensures (L.mem m (attenuate ms wide))) =
  lemma_attenuation_membership ms narrow m;
  lemma_enabled_monotone m narrow wide;
  lemma_attenuation_complete ms wide m

let rec attenuate_many (ms:list mapping) (history:list (list source_scope))
  : Tot (list mapping) (decreases history) =
  match history with
  | [] -> ms
  | actual::rest -> attenuate_many (attenuate ms actual) rest

let rec lemma_descendants_never_regrow (ms:list mapping) (history:list (list source_scope)) (m:mapping)
  : Lemma (requires (L.mem m (attenuate_many ms history))) (ensures (L.mem m ms))
    (decreases history) =
  match history with
  | [] -> ()
  | actual::rest ->
    lemma_descendants_never_regrow (attenuate ms actual) rest m;
    lemma_attenuation_membership ms actual m

let lemma_missing_source_condition_refuses_mapping (ms:list mapping) (actual:list source_scope) (m:mapping)
  : Lemma (requires (m.needs = [])) (ensures (not (L.mem m (attenuate ms actual)))) =
  if L.mem m (attenuate ms actual) then lemma_attenuation_membership ms actual m

let lemma_empty_effective_scope_has_no_authority (m:mapping)
  : Lemma (not (enabled m [])) =
  match m.needs with | [] -> () | _::_ -> ()

let lemma_positive_narrowing_witness ()
  : Lemma (attenuate_many [read_map;write_map] [[1;2];[1];[1;2]] = [read_map]) = ()
