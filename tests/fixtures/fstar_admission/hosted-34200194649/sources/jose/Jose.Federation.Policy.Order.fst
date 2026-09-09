module Jose.Federation.Policy.Order

(** Restrictiveness ordering for OpenID Federation metadata policies.

    Defines a concrete partial order on field policies and metadata
    policies.  A policy p1 is "at least as restrictive" as p2 when
    every constraint in p2 is present in p1 in at least as tight a
    form:

      - value: present ≥ absent; if both present, must be equal
      - one_of / subset_of: smaller set = more restrictive (⊆)
      - superset_of: larger set = more restrictive (⊇, i.e. rhs ⊆ lhs)
      - essential: true ≥ false
      - default / add: not compared (always true)

    Special case: a "bottom" field (essential=Some true with value=None)
    represents an unsatisfiable constraint from a value conflict.
    Bottom is vacuously at least as restrictive as any field policy.

    All functions are Tot; no admit() or assume val. *)

open FStar.List.Tot
open Jose.Federation.Policy.Types

(* =========================================================================
   Bottom detection
   ========================================================================= *)

(** A field policy is "bottom" (unsatisfiable) when it has essential=true
    but no value specified.  This arises from value conflicts during merge
    and represents the most restrictive possible constraint. *)
val is_field_bottom : fp:field_policy -> Tot bool
let is_field_bottom fp =
  fp.fp_essential = Some true && fp.fp_value = None

(* =========================================================================
   Field-level restrictiveness
   ========================================================================= *)

(** fp1 is at least as restrictive as fp2.
    If fp1 is bottom (unsatisfiable), it is vacuously at least as
    restrictive as any fp2. *)
val field_at_least_as_restrictive : fp1:field_policy -> fp2:field_policy -> Tot bool
let field_at_least_as_restrictive fp1 fp2 =
  (* Bottom is maximally restrictive *)
  if is_field_bottom fp1 then true
  else
    (* value: if fp2 has Some v, fp1 must also have Some v *)
    (match fp2.fp_value with
     | None -> true
     | Some v2 -> fp1.fp_value = Some v2) &&
    (* one_of: fp2 has Some ys => fp1 has Some xs with xs ⊆ ys *)
    (match fp2.fp_one_of with
     | None -> true
     | Some ys ->
       (match fp1.fp_one_of with
        | None -> false
        | Some xs -> list_subset xs ys)) &&
    (* subset_of: same rule as one_of *)
    (match fp2.fp_subset_of with
     | None -> true
     | Some ys ->
       (match fp1.fp_subset_of with
        | None -> false
        | Some xs -> list_subset xs ys)) &&
    (* superset_of: fp2 has Some ys => fp1 has Some xs with ys ⊆ xs *)
    (match fp2.fp_superset_of with
     | None -> true
     | Some ys ->
       (match fp1.fp_superset_of with
        | None -> false
        | Some xs -> list_subset ys xs)) &&
    (* essential: if fp2 = Some true, fp1 must be Some true *)
    (match fp2.fp_essential with
     | None -> true
     | Some false -> true
     | Some true ->
       (match fp1.fp_essential with
        | None -> false
        | Some b -> b))

(* =========================================================================
   Policy-level restrictiveness
   ========================================================================= *)

(** p1 is at least as restrictive as p2.
    For every field in p2, the corresponding field in p1 must be
    at least as restrictive.  Fields in p1 not in p2 are ignored
    (extra constraints only narrow further). *)
val policy_at_least_as_restrictive_concrete :
  p1:metadata_policy_concrete -> p2:metadata_policy_concrete -> Tot bool
  (decreases p2)
let rec policy_at_least_as_restrictive_concrete p1 p2 =
  match p2 with
  | [] -> true
  | (k, fp2) :: rest ->
    let fp1 =
      match lookup_field k p1 with
      | Some fp -> fp
      | None -> field_policy_top
    in
    field_at_least_as_restrictive fp1 fp2 &&
    policy_at_least_as_restrictive_concrete p1 rest
