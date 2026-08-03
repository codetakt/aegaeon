module Jose.Federation.Policy.Types

(** Concrete types for OpenID Federation metadata policy algebra.

    Replaces the opaque [metadata_policy = json] in Jose.Federation with
    a structured representation supporting merge, ordering, and proofs.

    The policy algebra follows OIDF 1.0 §6: each metadata field can be
    constrained by operators (value, default, add, one_of, subset_of,
    superset_of, essential).  A metadata policy is an association list
    mapping field names to per-field operator bundles.

    All functions are Tot; no admit() or assume val. Named predicates
    are used throughout to avoid Z3 4.13 lambda closure issues. *)

open FStar.List.Tot

(* =========================================================================
   Core types
   ========================================================================= *)

(** Scalar values that can appear in metadata policy constraints. *)
type policy_scalar =
  | PString : v:string -> policy_scalar
  | PBool   : v:bool   -> policy_scalar
  | PInt    : v:int     -> policy_scalar

(** An array of string values (for set-like operators). *)
type policy_array = list string

(** A metadata value is either a scalar or an array. *)
type metadata_value =
  | ScalarVal : v:policy_scalar -> metadata_value
  | ArrayVal  : v:policy_array  -> metadata_value

(** A field-level policy constraining a single metadata claim.
    Each field corresponds to an OpenID Federation policy operator
    (OIDF 1.0 §6.1).  None = operator not present = no constraint. *)
type field_policy = {
  fp_value       : option metadata_value;    (* fixed value *)
  fp_default     : option metadata_value;    (* default if absent *)
  fp_add         : option policy_array;      (* values to add *)
  fp_one_of      : option policy_array;      (* allowed values *)
  fp_subset_of   : option policy_array;      (* must be subset *)
  fp_superset_of : option policy_array;      (* must be superset *)
  fp_essential   : option bool;              (* claim required? *)
}

(** The unconstrained field policy (all operators absent). *)
let field_policy_top : field_policy = {
  fp_value = None; fp_default = None; fp_add = None;
  fp_one_of = None; fp_subset_of = None; fp_superset_of = None;
  fp_essential = None;
}

(** A metadata policy is an association list mapping field names to
    field policies.  Invariant: no duplicate keys (checked by nodup_keys). *)
type metadata_policy_concrete = list (string * field_policy)

(** The unconstrained policy (empty = no fields constrained). *)
let policy_top : metadata_policy_concrete = []

(* =========================================================================
   String-list membership (named predicate for Z3 4.13 compatibility)
   ========================================================================= *)

(** Decidable membership for string lists.  Named predicate avoids
    Z3 4.13 lambda closure issues in the full 140-module context. *)
val list_mem_string : s:string -> xs:list string -> Tot bool
  (decreases xs)
let rec list_mem_string s xs =
  match xs with
  | [] -> false
  | x :: rest -> x = s || list_mem_string s rest

(* =========================================================================
   Set operations on policy_array (list string)
   ========================================================================= *)

(** Intersection: keep elements of xs that appear in ys. *)
val list_intersect : xs:list string -> ys:list string -> Tot (list string)
  (decreases xs)
let rec list_intersect xs ys =
  match xs with
  | [] -> []
  | x :: rest ->
    if list_mem_string x ys then x :: list_intersect rest ys
    else list_intersect rest ys

(** Filter elements of candidates not present in reference.
    Named helper for list_union (avoids lambda in filter). *)
val filter_not_in : reference:list string -> candidates:list string -> Tot (list string)
  (decreases candidates)
let rec filter_not_in reference candidates =
  match candidates with
  | [] -> []
  | y :: rest ->
    if list_mem_string y reference then filter_not_in reference rest
    else y :: filter_not_in reference rest

(** Union: xs followed by elements of ys not already in xs. *)
val list_union : list string -> list string -> Tot (list string)
let list_union xs ys = xs @ filter_not_in xs ys

(** Remove duplicates (preserves last occurrence of each element). *)
val list_dedup : xs:list string -> Tot (list string)
  (decreases xs)
let rec list_dedup xs =
  match xs with
  | [] -> []
  | x :: rest ->
    if list_mem_string x rest then list_dedup rest
    else x :: list_dedup rest

(** Subset check: all elements of xs appear in ys. *)
val list_subset : xs:list string -> ys:list string -> Tot bool
  (decreases xs)
let rec list_subset xs ys =
  match xs with
  | [] -> true
  | x :: rest -> list_mem_string x ys && list_subset rest ys

(* =========================================================================
   Association-list operations on metadata_policy_concrete
   ========================================================================= *)

(** Lookup a field policy by name. *)
val lookup_field : name:string -> pol:metadata_policy_concrete -> Tot (option field_policy)
  (decreases pol)
let rec lookup_field name pol =
  match pol with
  | [] -> None
  | (k, v) :: rest -> if k = name then Some v else lookup_field name rest

(** Update or insert a field policy by name.
    If the key exists, replace its value; otherwise append at end. *)
val update_field : name:string -> fp:field_policy -> pol:metadata_policy_concrete ->
  Tot metadata_policy_concrete
  (decreases pol)
let rec update_field name fp pol =
  match pol with
  | [] -> [(name, fp)]
  | (k, v) :: rest ->
    if k = name then (k, fp) :: rest
    else (k, v) :: update_field name fp rest

(** Remove all entries with the given key. *)
val remove_key : name:string -> pol:metadata_policy_concrete -> Tot metadata_policy_concrete
  (decreases pol)
let rec remove_key name pol =
  match pol with
  | [] -> []
  | (k, v) :: rest ->
    if k = name then remove_key name rest
    else (k, v) :: remove_key name rest

(** Check that a key does not appear in the association list. *)
val key_not_in : name:string -> pol:metadata_policy_concrete -> Tot bool
  (decreases pol)
let rec key_not_in name pol =
  match pol with
  | [] -> true
  | (k, _) :: rest -> k <> name && key_not_in name rest

(** Check no duplicate keys in the association list. *)
val nodup_keys : pol:metadata_policy_concrete -> Tot bool
  (decreases pol)
let rec nodup_keys pol =
  match pol with
  | [] -> true
  | (k, _) :: rest -> key_not_in k rest && nodup_keys rest
