module Jose.Federation.Policy.Merge

(** OpenID Federation metadata policy merge algorithm.

    Implements the policy combination semantics from OIDF 1.0 §6.1.
    The merge of two policies (ancestor + descendant) resolves each
    operator according to its combination rule:

      value      — equal → keep; differ → conflict (bottom)
      default    — descendant wins
      add        — union (dedup)
      one_of     — intersection
      subset_of  — intersection
      superset_of — union
      essential  — OR

    All functions are Tot; no admit() or assume val. *)

open FStar.List.Tot
open Jose.Federation.Policy.Types

(* =========================================================================
   Per-operator merge helpers
   ========================================================================= *)

(** Merge the 'default' operator: descendant wins. *)
private val merge_default_op :
  ancestor:option metadata_value -> descendant:option metadata_value ->
  Tot (option metadata_value)
private let merge_default_op ancestor descendant =
  match descendant with
  | Some _ -> descendant
  | None   -> ancestor

(** Merge the 'add' operator: union (dedup) of both lists. *)
private val merge_add_op :
  a:option policy_array -> b:option policy_array ->
  Tot (option policy_array)
private let merge_add_op a b =
  match a, b with
  | None,    None    -> None
  | Some xs, None    -> Some xs
  | None,    Some ys -> Some ys
  | Some xs, Some ys -> Some (list_dedup (list_union xs ys))

(** Merge operators using intersection (one_of, subset_of):
    both present → intersect; one present → keep; neither → None. *)
private val merge_intersect_op :
  a:option policy_array -> b:option policy_array ->
  Tot (option policy_array)
private let merge_intersect_op a b =
  match a, b with
  | None,    None    -> None
  | Some xs, None    -> Some xs
  | None,    Some ys -> Some ys
  | Some xs, Some ys -> Some (list_intersect xs ys)

(** Merge operators using union (superset_of):
    both present → union (dedup); one present → keep; neither → None. *)
private val merge_union_op :
  a:option policy_array -> b:option policy_array ->
  Tot (option policy_array)
private let merge_union_op a b =
  match a, b with
  | None,    None    -> None
  | Some xs, None    -> Some xs
  | None,    Some ys -> Some ys
  | Some xs, Some ys -> Some (list_dedup (list_union xs ys))

(** Merge the 'essential' operator: OR (true if either is true). *)
private val merge_essential_op :
  a:option bool -> b:option bool ->
  Tot (option bool)
private let merge_essential_op a b =
  match a, b with
  | None,   None   -> None
  | Some x, None   -> Some x
  | None,   Some y -> Some y
  | Some x, Some y -> Some (x || y)

(* =========================================================================
   Field-level merge
   ========================================================================= *)

(** Merge two field policies (ancestor + descendant).
    Implements per-operator merge rules from OIDF 1.0 §6.1.

    Value conflict: if both policies specify 'value' with different values,
    the result sets fp_value = None and fp_essential = Some true, marking
    the field as unsatisfiable (bottom in the policy lattice). *)
val merge_field_policy : ancestor:field_policy -> descendant:field_policy ->
  Tot field_policy
let merge_field_policy ancestor descendant =
  (* Bottom is sticky: once a field is unsatisfiable (essential=true,
     value=None), merging with any descendant preserves the bottom.
     This ensures the restrictiveness ordering is preserved through
     successive merges (needed for resolve_policies monotonicity). *)
  if ancestor.fp_essential = Some true && ancestor.fp_value = None
  then ancestor
  else
  (* Detect value conflict: both present with different values *)
  let value_conflict =
    match ancestor.fp_value, descendant.fp_value with
    | Some v1, Some v2 -> v1 <> v2
    | _, _ -> false
  in
  (* Merge the value operator *)
  let merged_value =
    match ancestor.fp_value, descendant.fp_value with
    | None,    None    -> None
    | Some v,  None    -> Some v
    | None,    Some v  -> Some v
    | Some v1, Some v2 ->
      if v1 = v2 then Some v1 else None
  in
  {
    fp_value       = merged_value;
    fp_default     = merge_default_op ancestor.fp_default descendant.fp_default;
    fp_add         = merge_add_op ancestor.fp_add descendant.fp_add;
    fp_one_of      = merge_intersect_op ancestor.fp_one_of descendant.fp_one_of;
    fp_subset_of   = merge_intersect_op ancestor.fp_subset_of descendant.fp_subset_of;
    fp_superset_of = merge_union_op ancestor.fp_superset_of descendant.fp_superset_of;
    fp_essential   = if value_conflict then Some true
                     else merge_essential_op ancestor.fp_essential descendant.fp_essential;
  }

(* =========================================================================
   Policy-level merge
   ========================================================================= *)

(** Merge two metadata policies (ancestor + descendant).
    For each field in the ancestor, merge with the corresponding field
    in the descendant (or field_policy_top if absent).  Fields only in
    the descendant are included as-is (appended from the remainder). *)
val merge_policy :
  p1:metadata_policy_concrete -> p2:metadata_policy_concrete ->
  Tot metadata_policy_concrete
  (decreases p1)
let rec merge_policy p1 p2 =
  match p1 with
  | [] -> p2
  | (k, fp1) :: rest ->
    let fp2 =
      match lookup_field k p2 with
      | Some fp -> fp
      | None    -> field_policy_top
    in
    (k, merge_field_policy fp1 fp2) :: merge_policy rest (remove_key k p2)

(** Resolve a list of policies by left-folding merge.
    Policies are in ancestor-first order (trust anchor first, leaf last).
    This is the concrete implementation of the abstract resolve_policies
    in Jose.Federation. *)
val resolve_policies_concrete :
  policies:list metadata_policy_concrete -> Tot metadata_policy_concrete
let resolve_policies_concrete policies =
  fold_left merge_policy policy_top policies
