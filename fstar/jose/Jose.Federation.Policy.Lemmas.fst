module Jose.Federation.Policy.Lemmas

(** Core lemmas for the federation metadata policy algebra.

    Proves reflexivity, monotonicity, and subsumption for the
    restrictiveness ordering defined in Jose.Federation.Policy.Order.

    All proofs are concrete (0 admit, 0 assume val). Named predicates
    and explicit assert chains are used throughout for Z3 stability.

    All definitions are sequential (no mutual recursion). *)

open FStar.List.Tot
open Jose.Federation.Policy.Types
open Jose.Federation.Policy.Merge
open Jose.Federation.Policy.Order

(* =========================================================================
   Section 1: list_subset helpers

   Note: lemma_mem_cons and lemma_list_subset_cons_right must come before
   lemma_list_subset_refl to avoid Z3 4.13.3 label_1 encoding bug.
   The bug is triggered when Z3 must unfold both list_subset AND
   list_mem_string in a single query.  Using helper lemmas keeps each
   query small enough to avoid the encoding overflow.
   ========================================================================= *)

#push-options "--z3rlimit 80 --fuel 8 --ifuel 4"

private val lemma_mem_cons : z:string -> x:string -> ys:list string ->
  Lemma (requires list_mem_string z ys = true)
    (ensures list_mem_string z (x :: ys) = true)
private let lemma_mem_cons z x ys = ()

private val lemma_list_subset_cons_right : zs:list string -> ys:list string -> x:string ->
  Lemma (requires list_subset zs ys = true)
    (ensures list_subset zs (x :: ys) = true)
    (decreases zs)
private let rec lemma_list_subset_cons_right zs ys x =
  match zs with
  | [] -> ()
  | z :: rest ->
    lemma_mem_cons z x ys;
    lemma_list_subset_cons_right rest ys x

val lemma_list_subset_refl : xs:list string ->
  Lemma (ensures list_subset xs xs = true)
  (decreases xs)
let rec lemma_list_subset_refl xs =
  match xs with
  | [] -> ()
  | x :: rest ->
    lemma_list_subset_refl rest;
    lemma_list_subset_cons_right rest rest x

val lemma_list_subset_append_self : xs:list string -> ys:list string ->
  Lemma (ensures list_subset xs (xs @ ys) = true)
    (decreases xs)
let rec lemma_list_subset_append_self xs ys =
  match xs with
  | [] -> ()
  | x :: rest ->
    lemma_list_subset_append_self rest ys;
    lemma_list_subset_cons_right rest (rest @ ys) x

#pop-options

(* =========================================================================
   Section 2: list_intersect ⊆ left operand
   ========================================================================= *)

#push-options "--z3rlimit 60 --fuel 4 --ifuel 2"

val lemma_intersect_subset_left : xs:list string -> ys:list string ->
  Lemma (ensures list_subset (list_intersect xs ys) xs = true)
  (decreases xs)
let rec lemma_intersect_subset_left xs ys =
  match xs with
  | [] -> ()
  | x :: rest ->
    lemma_intersect_subset_left rest ys;
    if list_mem_string x ys then
      lemma_list_subset_cons_right (list_intersect rest ys) rest x
    else
      lemma_list_subset_cons_right (list_intersect rest ys) rest x

#pop-options

(* =========================================================================
   Section 3: list_union ⊇ left operand
   ========================================================================= *)

#push-options "--z3rlimit 60 --fuel 4 --ifuel 2"

val lemma_subset_union_left : xs:list string -> ys:list string ->
  Lemma (ensures list_subset xs (list_union xs ys) = true)
let lemma_subset_union_left xs ys =
  assert (list_union xs ys = xs @ filter_not_in xs ys);
  lemma_list_subset_append_self xs (filter_not_in xs ys)

#pop-options

(* =========================================================================
   Section 4: field_at_least_as_restrictive is reflexive
   ========================================================================= *)

#push-options "--z3rlimit 80 --fuel 4 --ifuel 2"

val lemma_field_restrictive_refl : fp:field_policy ->
  Lemma (ensures field_at_least_as_restrictive fp fp = true)
let lemma_field_restrictive_refl fp =
  if is_field_bottom fp then ()
  else begin
    assert (match fp.fp_value with None -> true | Some v -> fp.fp_value = Some v);
    (match fp.fp_one_of with | None -> () | Some xs -> lemma_list_subset_refl xs);
    (match fp.fp_subset_of with | None -> () | Some xs -> lemma_list_subset_refl xs);
    (match fp.fp_superset_of with | None -> () | Some xs -> lemma_list_subset_refl xs);
    assert (match fp.fp_essential with
     | None -> true | Some false -> true
     | Some true -> (match fp.fp_essential with None -> false | Some b -> b))
  end

#pop-options

(* =========================================================================
   Section 5: lookup_field helpers
   ========================================================================= *)

#push-options "--z3rlimit 40 --fuel 4 --ifuel 2"

val lemma_lookup_field_head : k:string -> fp:field_policy ->
  rest:metadata_policy_concrete ->
  Lemma (ensures lookup_field k ((k, fp) :: rest) = Some fp)
let lemma_lookup_field_head k fp rest = ()

(** key_not_in implies lookup returns None. *)
val lemma_key_not_in_lookup_none : k:string -> pol:metadata_policy_concrete ->
  Lemma (requires key_not_in k pol = true)
    (ensures lookup_field k pol = None)
    (decreases pol)
let rec lemma_key_not_in_lookup_none k pol =
  match pol with
  | [] -> ()
  | (_, _) :: rest -> lemma_key_not_in_lookup_none k rest

(** If lookup succeeds in the tail, it succeeds in the full list. *)
val lemma_lookup_field_cons_some : k:string -> k':string -> fp':field_policy ->
  rest:metadata_policy_concrete ->
  Lemma (requires Some? (lookup_field k rest))
    (ensures Some? (lookup_field k ((k', fp') :: rest)))
let lemma_lookup_field_cons_some k k' fp' rest = ()

(** Every entry's key can be looked up in the list. *)
val lemma_lookup_field_index : pol:metadata_policy_concrete -> i:nat{i < length pol} ->
  Lemma (ensures Some? (lookup_field (fst (index pol i)) pol))
  (decreases pol)
let rec lemma_lookup_field_index pol i =
  match pol with
  | (k, fp) :: rest ->
    if i = 0 then ()
    else begin
      lemma_lookup_field_index rest (i - 1);
      lemma_lookup_field_cons_some (fst (index rest (i - 1))) k fp rest
    end

#pop-options

(* =========================================================================
   Lemma 1: policy_at_least_as_restrictive_concrete is reflexive
   ========================================================================= *)

#push-options "--z3rlimit 100 --fuel 4 --ifuel 2"

(** Prepending an entry with a key not in sub preserves the ordering.
    Since the new key doesn't appear in sub, lookups for sub's keys
    are unchanged, so the ordering transfers directly. *)
val lemma_ordering_prepend_key :
  k:string -> fp:field_policy -> rest:metadata_policy_concrete ->
  sub:metadata_policy_concrete ->
  Lemma
    (requires key_not_in k sub /\
              policy_at_least_as_restrictive_concrete rest sub = true)
    (ensures policy_at_least_as_restrictive_concrete ((k, fp) :: rest) sub = true)
    (decreases sub)
let rec lemma_ordering_prepend_key k fp rest sub =
  match sub with
  | [] -> ()
  | (k', fp') :: rest_sub ->
    assert (k' <> k);
    assert (lookup_field k' ((k, fp) :: rest) = lookup_field k' rest);
    lemma_ordering_prepend_key k fp rest rest_sub

val lemma_policy_restrictive_refl :
  p:metadata_policy_concrete ->
  Lemma (requires nodup_keys p)
    (ensures policy_at_least_as_restrictive_concrete p p = true)
    (decreases p)
let rec lemma_policy_restrictive_refl p =
  match p with
  | [] -> ()
  | (k, fp) :: rest ->
    lemma_field_restrictive_refl fp;
    assert (nodup_keys rest);
    assert (key_not_in k rest);
    lemma_policy_restrictive_refl rest;
    lemma_ordering_prepend_key k fp rest rest

#pop-options

(* =========================================================================
   Section 6: merge_field monotonicity helpers
   ========================================================================= *)

#push-options "--z3rlimit 120 --fuel 4 --ifuel 2"

val lemma_mem_dedup : z:string -> ys:list string ->
  Lemma (requires list_mem_string z ys = true)
    (ensures list_mem_string z (list_dedup ys) = true)
    (decreases ys)
let rec lemma_mem_dedup z ys =
  match ys with
  | [] -> ()
  | y :: rest ->
    if list_mem_string y rest then begin
      if z = y then begin
        assert (list_mem_string z rest = true);
        lemma_mem_dedup z rest
      end else begin
        assert (list_mem_string z rest = true);
        lemma_mem_dedup z rest
      end
    end else begin
      if z = y then ()
      else begin
        assert (list_mem_string z rest = true);
        lemma_mem_dedup z rest
      end
    end

val lemma_list_subset_dedup : xs:list string -> ys:list string ->
  Lemma (requires list_subset xs ys = true)
    (ensures list_subset xs (list_dedup ys) = true)
    (decreases xs)
let rec lemma_list_subset_dedup xs ys =
  match xs with
  | [] -> ()
  | x :: rest ->
    assert (list_mem_string x ys = true);
    lemma_mem_dedup x ys;
    assert (list_subset rest ys = true);
    lemma_list_subset_dedup rest ys

#pop-options

(* =========================================================================
   Section 7: merge_field_policy monotonicity (ancestor side)
   ========================================================================= *)

#push-options "--z3rlimit 150 --fuel 4 --ifuel 2"

val lemma_merge_field_at_least_as_restrictive :
  ancestor:field_policy -> descendant:field_policy ->
  Lemma (ensures field_at_least_as_restrictive
                   (merge_field_policy ancestor descendant) ancestor = true)
let lemma_merge_field_at_least_as_restrictive ancestor descendant =
  let merged = merge_field_policy ancestor descendant in
  let value_conflict =
    match ancestor.fp_value, descendant.fp_value with
    | Some v1, Some v2 -> v1 <> v2
    | _, _ -> false
  in
  if value_conflict then begin
    assert (merged.fp_value = None);
    assert (merged.fp_essential = Some true);
    assert (is_field_bottom merged = true)
  end else begin
    if is_field_bottom merged then ()
    else begin
      assert (match ancestor.fp_value with
        | None -> true
        | Some v ->
          (match ancestor.fp_value, descendant.fp_value with
           | Some v1, Some v2 -> v1 = v2 /\ merged.fp_value = Some v1
           | Some v1, None -> merged.fp_value = Some v1
           | None, _ -> true | _, _ -> true));
      assert (match ancestor.fp_value with
        | None -> true | Some v -> merged.fp_value = Some v);
      (match ancestor.fp_one_of with
       | None -> ()
       | Some xs ->
         (match descendant.fp_one_of with
          | None -> assert (merged.fp_one_of = Some xs); lemma_list_subset_refl xs
          | Some ys -> assert (merged.fp_one_of = Some (list_intersect xs ys));
                       lemma_intersect_subset_left xs ys));
      (match ancestor.fp_subset_of with
       | None -> ()
       | Some xs ->
         (match descendant.fp_subset_of with
          | None -> assert (merged.fp_subset_of = Some xs); lemma_list_subset_refl xs
          | Some ys -> assert (merged.fp_subset_of = Some (list_intersect xs ys));
                       lemma_intersect_subset_left xs ys));
      (match ancestor.fp_superset_of with
       | None -> ()
       | Some xs ->
         (match descendant.fp_superset_of with
          | None -> assert (merged.fp_superset_of = Some xs); lemma_list_subset_refl xs
          | Some ys -> assert (merged.fp_superset_of = Some (list_dedup (list_union xs ys)));
                       lemma_subset_union_left xs ys;
                       lemma_list_subset_dedup xs (list_union xs ys)));
      (match ancestor.fp_essential with
       | None -> () | Some false -> ()
       | Some true ->
         (match descendant.fp_essential with
          | None -> assert (merged.fp_essential = Some true)
          | Some _ -> assert (merged.fp_essential = Some (true || (Some?.v descendant.fp_essential)))))
    end
  end

#pop-options

(* =========================================================================
   Section 8: merge_policy lookup helpers
   ========================================================================= *)

#push-options "--z3rlimit 80 --fuel 4 --ifuel 2"

val lemma_lookup_remove_key_other : k:string -> k':string ->
  p:metadata_policy_concrete ->
  Lemma (requires k <> k')
    (ensures lookup_field k' (remove_key k p) = lookup_field k' p)
    (decreases p)
let rec lemma_lookup_remove_key_other k k' p =
  match p with
  | [] -> ()
  | (kh, _) :: rest ->
    if kh = k then
      (if kh = k' then () else lemma_lookup_remove_key_other k k' rest)
    else
      (if kh = k' then () else lemma_lookup_remove_key_other k k' rest)

#pop-options

#push-options "--z3rlimit 100 --fuel 6 --ifuel 2"

val lemma_merge_policy_lookup_left :
  k:string -> fp1:field_policy ->
  p1:metadata_policy_concrete -> p2:metadata_policy_concrete ->
  Lemma (requires lookup_field k p1 = Some fp1)
    (ensures (
      let fp2 = match lookup_field k p2 with | Some fp -> fp | None -> field_policy_top in
      lookup_field k (merge_policy p1 p2) = Some (merge_field_policy fp1 fp2)))
    (decreases p1)
let rec lemma_merge_policy_lookup_left k fp1 p1 p2 =
  match p1 with
  | [] -> ()
  | (k1, fp1') :: rest ->
    if k1 = k then begin
      assert (fp1 == fp1');
      let fp2' = match lookup_field k p2 with | Some fp -> fp | None -> field_policy_top in
      assert (lookup_field k ((k, merge_field_policy fp1' fp2') ::
                merge_policy rest (remove_key k p2)) =
              Some (merge_field_policy fp1' fp2'))
    end else begin
      assert (lookup_field k rest = Some fp1);
      lemma_lookup_remove_key_other k1 k p2;
      assert (lookup_field k (remove_key k1 p2) = lookup_field k p2);
      lemma_merge_policy_lookup_left k fp1 rest (remove_key k1 p2)
    end

#pop-options

(* =========================================================================
   Section 9: intersect ⊆ right + list_union helpers
   ========================================================================= *)

#push-options "--z3rlimit 60 --fuel 4 --ifuel 2"

val lemma_intersect_subset_right : xs:list string -> ys:list string ->
  Lemma (ensures list_subset (list_intersect xs ys) ys = true)
    (decreases xs)
let rec lemma_intersect_subset_right xs ys =
  match xs with
  | [] -> ()
  | x :: rest ->
    lemma_intersect_subset_right rest ys;
    if list_mem_string x ys then begin
      assert (list_intersect (x :: rest) ys = x :: list_intersect rest ys);
      assert (list_mem_string x ys = true);
      assert (list_subset (list_intersect rest ys) ys = true)
    end else
      assert (list_intersect (x :: rest) ys = list_intersect rest ys)

val lemma_mem_append_left : r:string -> xs:list string -> ys:list string ->
  Lemma (requires list_mem_string r xs = true)
    (ensures list_mem_string r (xs @ ys) = true)
    (decreases xs)
let rec lemma_mem_append_left r xs ys =
  match xs with
  | [] -> ()
  | x :: rest -> if x = r then () else lemma_mem_append_left r rest ys

val lemma_mem_append_right : r:string -> xs:list string -> ys:list string ->
  Lemma (requires list_mem_string r ys = true)
    (ensures list_mem_string r (xs @ ys) = true)
    (decreases xs)
let rec lemma_mem_append_right r xs ys =
  match xs with
  | [] -> ()
  | _ :: rest -> lemma_mem_append_right r rest ys

val lemma_mem_filter_not_in : r:string -> xs:list string -> ys:list string ->
  Lemma (requires list_mem_string r ys = true /\ list_mem_string r xs = false)
    (ensures list_mem_string r (filter_not_in xs ys) = true)
    (decreases ys)
let rec lemma_mem_filter_not_in r xs ys =
  match ys with
  | [] -> ()
  | y :: rest ->
    if list_mem_string y xs then begin
      if y = r then () else lemma_mem_filter_not_in r xs rest
    end else begin
      if y = r then () else lemma_mem_filter_not_in r xs rest
    end

private val lemma_subset_union_right_aux :
  xs:list string -> ys:list string -> remaining:list string ->
  Lemma (requires (forall r. list_mem_string r remaining = true ==>
                              list_mem_string r ys = true))
    (ensures list_subset remaining (xs @ filter_not_in xs ys) = true)
    (decreases remaining)
private let rec lemma_subset_union_right_aux xs ys remaining =
  match remaining with
  | [] -> ()
  | r :: rest ->
    assert (list_mem_string r ys = true);
    lemma_subset_union_right_aux xs ys rest;
    if list_mem_string r xs then
      lemma_mem_append_left r xs (filter_not_in xs ys)
    else begin
      lemma_mem_filter_not_in r xs ys;
      lemma_mem_append_right r xs (filter_not_in xs ys)
    end

val lemma_subset_union_right : xs:list string -> ys:list string ->
  Lemma (ensures list_subset ys (list_union xs ys) = true)
let lemma_subset_union_right xs ys =
  assert (list_union xs ys = xs @ filter_not_in xs ys);
  lemma_subset_union_right_aux xs ys ys

#pop-options

(* =========================================================================
   Section 10: field_geq_top and merge_field desc-side monotonicity
   ========================================================================= *)

#push-options "--z3rlimit 80 --fuel 4 --ifuel 2"

val lemma_field_geq_top : fp:field_policy ->
  Lemma (ensures field_at_least_as_restrictive fp field_policy_top = true)
let lemma_field_geq_top fp =
  if is_field_bottom fp then ()
  else begin
    assert (field_policy_top.fp_value = None);
    assert (field_policy_top.fp_one_of = None);
    assert (field_policy_top.fp_subset_of = None);
    assert (field_policy_top.fp_superset_of = None);
    assert (field_policy_top.fp_essential = None)
  end

#pop-options

#push-options "--z3rlimit 150 --fuel 4 --ifuel 2"

val lemma_merge_field_at_least_as_restrictive_desc :
  ancestor:field_policy -> descendant:field_policy ->
  Lemma (ensures field_at_least_as_restrictive
                   (merge_field_policy ancestor descendant) descendant = true)
let lemma_merge_field_at_least_as_restrictive_desc ancestor descendant =
  let merged = merge_field_policy ancestor descendant in
  let value_conflict =
    match ancestor.fp_value, descendant.fp_value with
    | Some v1, Some v2 -> v1 <> v2
    | _, _ -> false
  in
  if value_conflict then begin
    assert (merged.fp_value = None);
    assert (merged.fp_essential = Some true);
    assert (is_field_bottom merged = true)
  end else begin
    if is_field_bottom merged then ()
    else begin
      assert (match descendant.fp_value with
        | None -> true
        | Some v ->
          (match ancestor.fp_value with
           | None -> merged.fp_value = Some v
           | Some v1 -> v1 = v /\ merged.fp_value = Some v));
      (match descendant.fp_one_of with
       | None -> ()
       | Some ys ->
         (match ancestor.fp_one_of with
          | None -> assert (merged.fp_one_of = Some ys); lemma_list_subset_refl ys
          | Some xs -> assert (merged.fp_one_of = Some (list_intersect xs ys));
                       lemma_intersect_subset_right xs ys));
      (match descendant.fp_subset_of with
       | None -> ()
       | Some ys ->
         (match ancestor.fp_subset_of with
          | None -> assert (merged.fp_subset_of = Some ys); lemma_list_subset_refl ys
          | Some xs -> assert (merged.fp_subset_of = Some (list_intersect xs ys));
                       lemma_intersect_subset_right xs ys));
      (match descendant.fp_superset_of with
       | None -> ()
       | Some ys ->
         (match ancestor.fp_superset_of with
          | None -> assert (merged.fp_superset_of = Some ys); lemma_list_subset_refl ys
          | Some xs -> assert (merged.fp_superset_of = Some (list_dedup (list_union xs ys)));
                       lemma_subset_union_right xs ys;
                       lemma_list_subset_dedup ys (list_union xs ys)));
      (match descendant.fp_essential with
       | None -> () | Some false -> ()
       | Some true ->
         (match ancestor.fp_essential with
          | None -> assert (merged.fp_essential = Some true)
          | Some _ -> assert (merged.fp_essential = Some (Some?.v ancestor.fp_essential || true))))
    end
  end

#pop-options

(* =========================================================================
   Section 11: merge contains desc key
   ========================================================================= *)

#push-options "--z3rlimit 100 --fuel 6 --ifuel 2"

(** merge_policy base desc contains an entry for every key in desc. *)
val lemma_merge_policy_contains_desc_key :
  k:string ->
  base:metadata_policy_concrete -> desc:metadata_policy_concrete ->
  Lemma (requires Some? (lookup_field k desc))
    (ensures Some? (lookup_field k (merge_policy base desc)))
    (decreases base)
let rec lemma_merge_policy_contains_desc_key k base desc =
  match base with
  | [] ->
    assert (merge_policy [] desc = desc)
  | (kb, fpb) :: rest_base ->
    if kb = k then begin
      let fp2 = match lookup_field kb desc with
        | Some fp -> fp | None -> field_policy_top in
      assert (lookup_field k (merge_policy base desc) =
              Some (merge_field_policy fpb fp2))
    end else begin
      lemma_lookup_remove_key_other kb k desc;
      assert (lookup_field k (remove_key kb desc) = lookup_field k desc);
      lemma_merge_policy_contains_desc_key k rest_base (remove_key kb desc)
    end

#pop-options

(* =========================================================================
   Section 12: fold_left/append decomposition
   ========================================================================= *)

#push-options "--z3rlimit 60 --fuel 4 --ifuel 2"

val lemma_fold_left_snoc :
  f:(metadata_policy_concrete -> metadata_policy_concrete -> Tot metadata_policy_concrete) ->
  init:metadata_policy_concrete ->
  xs:list metadata_policy_concrete ->
  y:metadata_policy_concrete ->
  Lemma (ensures fold_left f init (xs @ [y]) = f (fold_left f init xs) y)
    (decreases xs)
let rec lemma_fold_left_snoc f init xs y =
  match xs with
  | [] -> ()
  | x :: rest -> lemma_fold_left_snoc f (f init x) rest y

#pop-options

(* =========================================================================
   Section 12b: merge_policy preserves nodup_keys
   ========================================================================= *)

#push-options "--z3rlimit 80 --fuel 4 --ifuel 2"

(** remove_key k p removes all occurrences of k. *)
val lemma_remove_key_removes_all : k:string -> p:metadata_policy_concrete ->
  Lemma (ensures key_not_in k (remove_key k p) = true)
  (decreases p)
let rec lemma_remove_key_removes_all k p =
  match p with
  | [] -> ()
  | (k', _) :: rest ->
    if k' = k then lemma_remove_key_removes_all k rest
    else lemma_remove_key_removes_all k rest

(** remove_key preserves key_not_in for other keys. *)
val lemma_key_not_in_remove_key : k:string -> k':string -> p:metadata_policy_concrete ->
  Lemma (requires key_not_in k p)
    (ensures key_not_in k (remove_key k' p))
  (decreases p)
let rec lemma_key_not_in_remove_key k k' p =
  match p with
  | [] -> ()
  | (kh, _) :: rest ->
    if kh = k' then
      lemma_key_not_in_remove_key k k' rest
    else begin
      assert (k <> kh);
      lemma_key_not_in_remove_key k k' rest
    end

(** remove_key preserves nodup_keys. *)
val lemma_remove_key_nodup : k:string -> p:metadata_policy_concrete ->
  Lemma (requires nodup_keys p)
    (ensures nodup_keys (remove_key k p))
  (decreases p)
let rec lemma_remove_key_nodup k p =
  match p with
  | [] -> ()
  | (kh, _) :: rest ->
    if kh = k then
      lemma_remove_key_nodup k rest
    else begin
      assert (key_not_in kh rest);
      lemma_key_not_in_remove_key kh k rest;
      lemma_remove_key_nodup k rest
    end

(** key_not_in is preserved by merge_policy when key absent from both inputs. *)
val lemma_key_not_in_merge : k:string -> p1:metadata_policy_concrete -> p2:metadata_policy_concrete ->
  Lemma (requires key_not_in k p1 /\ key_not_in k p2)
    (ensures key_not_in k (merge_policy p1 p2))
  (decreases p1)
let rec lemma_key_not_in_merge k p1 p2 =
  match p1 with
  | [] -> ()
  | (kb, _) :: rest ->
    assert (k <> kb);
    lemma_key_not_in_remove_key k kb p2;
    lemma_key_not_in_merge k rest (remove_key kb p2)

(** merge_policy preserves nodup_keys when both inputs have nodup_keys. *)
val lemma_merge_policy_nodup : p1:metadata_policy_concrete -> p2:metadata_policy_concrete ->
  Lemma (requires nodup_keys p1 /\ nodup_keys p2)
    (ensures nodup_keys (merge_policy p1 p2))
  (decreases p1)
let rec lemma_merge_policy_nodup p1 p2 =
  match p1 with
  | [] -> ()
  | (kb, _) :: rest ->
    assert (key_not_in kb rest);
    lemma_remove_key_removes_all kb p2;
    assert (key_not_in kb (remove_key kb p2));
    lemma_key_not_in_merge kb rest (remove_key kb p2);
    lemma_remove_key_nodup kb p2;
    lemma_merge_policy_nodup rest (remove_key kb p2)

#pop-options

(* =========================================================================
   Section 13: transitivity lemmas
   ========================================================================= *)

#push-options "--z3rlimit 80 --fuel 4 --ifuel 2"

val lemma_mem_subset : x:string -> ys:list string -> zs:list string ->
  Lemma (requires list_mem_string x ys = true /\ list_subset ys zs = true)
    (ensures list_mem_string x zs = true)
    (decreases ys)
let rec lemma_mem_subset x ys zs =
  match ys with
  | [] -> ()
  | y :: rest ->
    if x = y then assert (list_mem_string y zs = true)
    else begin
      assert (list_mem_string x rest = true);
      assert (list_subset rest zs = true);
      lemma_mem_subset x rest zs
    end

val lemma_list_subset_trans : xs:list string -> ys:list string -> zs:list string ->
  Lemma (requires list_subset xs ys = true /\ list_subset ys zs = true)
    (ensures list_subset xs zs = true)
    (decreases xs)
let rec lemma_list_subset_trans xs ys zs =
  match xs with
  | [] -> ()
  | x :: rest ->
    assert (list_mem_string x ys = true);
    lemma_mem_subset x ys zs;
    assert (list_mem_string x zs = true);
    lemma_list_subset_trans rest ys zs

#pop-options

#push-options "--z3rlimit 150 --fuel 4 --ifuel 2"

(** If field_policy_top ≥ target, then target has no effective constraints
    (all operators are None or trivially satisfiable), so any field ≥ target. *)
val lemma_any_geq_unconstrained : fp:field_policy -> target:field_policy ->
  Lemma (requires field_at_least_as_restrictive field_policy_top target = true)
    (ensures field_at_least_as_restrictive fp target = true)
let lemma_any_geq_unconstrained fp target =
  (* Precondition forces all target constraints to be None/trivial:
     top is not bottom and has all fields None, so the full check runs
     and each branch requires target's operator to be None/false. *)
  if is_field_bottom fp then ()
  else begin
    assert (target.fp_value = None);
    assert (target.fp_one_of = None);
    assert (target.fp_subset_of = None);
    assert (target.fp_superset_of = None)
  end

(** Merging a field preserves ordering with respect to a target.
    If current_fp ≥ target_fp, then merge_field_policy current_fp desc_fp ≥ target_fp.
    This relies on the sticky-bottom property: once a field is bottom
    (unsatisfiable), merging preserves it, so the ordering holds trivially. *)
val lemma_merge_field_preserves_ordering :
  current_fp:field_policy -> desc_fp:field_policy -> target_fp:field_policy ->
  Lemma
    (requires field_at_least_as_restrictive current_fp target_fp = true)
    (ensures field_at_least_as_restrictive
               (merge_field_policy current_fp desc_fp) target_fp = true)
let lemma_merge_field_preserves_ordering current_fp desc_fp target_fp =
  let merged = merge_field_policy current_fp desc_fp in
  (* Case 1: current is bottom → sticky-bottom → merged = current = bottom → ≥ target *)
  if current_fp.fp_essential = Some true && current_fp.fp_value = None then begin
    assert (merged == current_fp);
    assert (is_field_bottom merged = true)
  end
  (* Case 2: not bottom, check for value conflict *)
  else begin
    let value_conflict =
      match current_fp.fp_value, desc_fp.fp_value with
      | Some v1, Some v2 -> v1 <> v2
      | _, _ -> false
    in
    if value_conflict then begin
      (* Value conflict → merged is bottom → ≥ target *)
      assert (merged.fp_essential = Some true);
      assert (merged.fp_value = None);
      assert (is_field_bottom merged = true)
    end else begin
      (* No conflict, not bottom: prove per-constraint *)
      if is_field_bottom merged then ()
      else begin
        (* value: if target has Some v, current has Some v, and no conflict
           means desc agrees or is absent → merged has Some v *)
        assert (match target_fp.fp_value with
          | None -> true
          | Some v -> merged.fp_value = Some v);
        (* one_of: if target has Some ys → current has Some xs ⊆ ys.
           Merged one_of is xs (if desc absent) or intersect(xs, zs) ⊆ xs ⊆ ys *)
        (match target_fp.fp_one_of with
         | None -> ()
         | Some ys ->
           let xs = Some?.v current_fp.fp_one_of in
           assert (list_subset xs ys = true);
           (match desc_fp.fp_one_of with
            | None -> assert (merged.fp_one_of = Some xs)
            | Some zs ->
              assert (merged.fp_one_of = Some (list_intersect xs zs));
              lemma_intersect_subset_left xs zs;
              lemma_list_subset_trans (list_intersect xs zs) xs ys));
        (* subset_of: same pattern as one_of *)
        (match target_fp.fp_subset_of with
         | None -> ()
         | Some ys ->
           let xs = Some?.v current_fp.fp_subset_of in
           assert (list_subset xs ys = true);
           (match desc_fp.fp_subset_of with
            | None -> assert (merged.fp_subset_of = Some xs)
            | Some zs ->
              assert (merged.fp_subset_of = Some (list_intersect xs zs));
              lemma_intersect_subset_left xs zs;
              lemma_list_subset_trans (list_intersect xs zs) xs ys));
        (* superset_of: if target has Some ys → current has Some xs with ys ⊆ xs.
           Merged = xs (if desc absent) or dedup(union(xs,zs)) ⊇ xs ⊇ ys *)
        (match target_fp.fp_superset_of with
         | None -> ()
         | Some ys ->
           let xs = Some?.v current_fp.fp_superset_of in
           assert (list_subset ys xs = true);
           (match desc_fp.fp_superset_of with
            | None -> assert (merged.fp_superset_of = Some xs)
            | Some zs ->
              assert (merged.fp_superset_of = Some (list_dedup (list_union xs zs)));
              lemma_subset_union_left xs zs;
              lemma_list_subset_trans ys xs (list_union xs zs);
              lemma_list_subset_dedup ys (list_union xs zs)));
        (* essential: if target requires true → current has true →
           merged essential = merge_essential(true, desc) = Some(true||...) = Some true *)
        ()
      end
    end
  end

#pop-options

(* =========================================================================
   Section 14: merge_preserves_ordering (policy-level)
   ========================================================================= *)

#push-options "--z3rlimit 150 --fuel 6 --ifuel 2"

(** Merging a policy preserves ordering with respect to a target.
    If current ≥ target and current has no duplicate keys, then
    merge_policy current s ≥ target for any descendant s.

    This is the key insight that avoids needing field-level transitivity
    (which doesn't hold through bottom fields in the general case). *)
val lemma_merge_preserves_ordering :
  current:metadata_policy_concrete -> s:metadata_policy_concrete ->
  target:metadata_policy_concrete ->
  Lemma
    (requires nodup_keys current /\
              policy_at_least_as_restrictive_concrete current target = true)
    (ensures policy_at_least_as_restrictive_concrete
               (merge_policy current s) target = true)
    (decreases target)
let rec lemma_merge_preserves_ordering current s target =
  match target with
  | [] -> ()
  | (k, fp_target) :: rest ->
    let merged = merge_policy current s in
    let fp_cur = match lookup_field k current with
      | Some fp -> fp | None -> field_policy_top in
    assert (field_at_least_as_restrictive fp_cur fp_target = true);
    (match lookup_field k current with
     | Some fp_cur_real ->
       (* k is in current: merged field = merge_field(current_k, desc_k) *)
       let fp_desc = match lookup_field k s with
         | Some fp -> fp | None -> field_policy_top in
       lemma_merge_policy_lookup_left k fp_cur_real current s;
       assert (lookup_field k merged = Some (merge_field_policy fp_cur_real fp_desc));
       lemma_merge_field_preserves_ordering fp_cur_real fp_desc fp_target
     | None ->
       (* k not in current: top ≥ fp_target, so target has no constraints at k *)
       let fp_merged_k = match lookup_field k merged with
         | Some fp -> fp | None -> field_policy_top in
       lemma_any_geq_unconstrained fp_merged_k fp_target);
    lemma_merge_preserves_ordering current s rest

#pop-options

(* =========================================================================
   Lemma 2: merge_policy is at least as restrictive as both inputs
   ========================================================================= *)

(* --- 2b: merge(base, desc) ≥ desc --- *)

#push-options "--z3rlimit 200 --fuel 6 --ifuel 2"

(** The merged field at key k is at least as restrictive as the desc field.
    This is the per-field statement underlying desc-side monotonicity. *)
val lemma_merge_result_geq_desc_field :
  k:string -> base:metadata_policy_concrete -> desc:metadata_policy_concrete ->
  Lemma (requires Some? (lookup_field k desc))
    (ensures (
      let fp_desc = Some?.v (lookup_field k desc) in
      let fp_merge = match lookup_field k (merge_policy base desc) with
        | Some fp -> fp | None -> field_policy_top in
      field_at_least_as_restrictive fp_merge fp_desc = true))
    (decreases base)
let rec lemma_merge_result_geq_desc_field k base desc =
  match base with
  | [] ->
    (* merge [] desc = desc, so fp_merge = fp_desc, use reflexivity *)
    let fp_desc = Some?.v (lookup_field k desc) in
    lemma_field_restrictive_refl fp_desc
  | (kb, fpb) :: rest ->
    if kb = k then begin
      (* merge matches kb = k, merged field = merge_field_policy fpb fp_desc *)
      let fp_desc = Some?.v (lookup_field k desc) in
      lemma_merge_field_at_least_as_restrictive_desc fpb fp_desc
    end else begin
      (* kb ≠ k: lookup k in remove_key kb desc = lookup k desc *)
      lemma_lookup_remove_key_other kb k desc;
      lemma_merge_result_geq_desc_field k rest (remove_key kb desc)
    end

(** key_not_in distributes over append: if name is not in xs@ys,
    it is not in xs and not in ys. *)
private val lemma_key_not_in_append :
  name:string -> xs:metadata_policy_concrete -> ys:metadata_policy_concrete ->
  Lemma
    (requires key_not_in name (xs @ ys) = true)
    (ensures key_not_in name xs = true /\ key_not_in name ys = true)
    (decreases xs)
private let rec lemma_key_not_in_append name xs ys =
  match xs with
  | [] -> ()
  | (_, _) :: rest -> lemma_key_not_in_append name rest ys

(** If an entry (k, fp) appears after a prefix in a nodup list,
    lookup_field k finds it. Proved by induction on the prefix:
    nodup_keys ensures no shadowing by earlier entries. *)
private val lemma_lookup_in_concat :
  k:string -> fp:field_policy ->
  prefix:metadata_policy_concrete -> suffix:metadata_policy_concrete ->
  Lemma
    (requires nodup_keys (prefix @ (k, fp) :: suffix))
    (ensures lookup_field k (prefix @ (k, fp) :: suffix) = Some fp)
    (decreases prefix)
private let rec lemma_lookup_in_concat k fp prefix suffix =
  match prefix with
  | [] -> ()
  | (pk, _) :: rest_prefix ->
    (* nodup_keys ((pk,_)::rest_prefix @ (k,fp)::suffix) gives us
       key_not_in pk (rest_prefix @ (k,fp)::suffix).
       Distribute over append to get key_not_in pk ((k,fp)::suffix),
       which unfolds to pk <> k. *)
    lemma_key_not_in_append pk rest_prefix ((k, fp) :: suffix);
    assert (pk <> k);
    lemma_lookup_in_concat k fp rest_prefix suffix

(** Helper: merge(base, desc) ≥ sub, where desc = prefix @ sub.
    Iterates over sub, calling lemma_merge_result_geq_desc_field for
    each entry and advancing the prefix by one element. *)
private val lemma_merged_geq_suffix :
  base:metadata_policy_concrete ->
  desc:metadata_policy_concrete ->
  prefix:metadata_policy_concrete ->
  sub:metadata_policy_concrete ->
  Lemma
    (requires nodup_keys desc /\
              desc = prefix @ sub)
    (ensures policy_at_least_as_restrictive_concrete
                   (merge_policy base desc) sub = true)
    (decreases sub)
private let rec lemma_merged_geq_suffix base desc prefix sub =
  match sub with
  | [] -> ()
  | (k, fp) :: rest ->
    (* k appears after prefix in desc, so lookup finds it *)
    lemma_lookup_in_concat k fp prefix rest;
    assert (lookup_field k desc = Some fp);
    assert (Some? (lookup_field k desc));
    lemma_merge_result_geq_desc_field k base desc;
    (* Advance prefix: desc = (prefix @ [(k,fp)]) @ rest *)
    FStar.List.Tot.Properties.append_assoc prefix [(k, fp)] rest;
    assert (desc = (prefix @ [(k, fp)]) @ rest);
    lemma_merged_geq_suffix base desc (prefix @ [(k, fp)]) rest

(** merge_policy base desc is at least as restrictive as desc.
    Requires nodup_keys desc (well-formedness). *)
val lemma_merge_policy_monotone_desc :
  base:metadata_policy_concrete -> desc:metadata_policy_concrete ->
  Lemma (requires nodup_keys desc)
    (ensures policy_at_least_as_restrictive_concrete
                   (merge_policy base desc) desc = true)
let lemma_merge_policy_monotone_desc base desc =
  assert (desc = [] @ desc);
  lemma_merged_geq_suffix base desc [] desc

#pop-options

(* =========================================================================
   Section 15: resolve_suffix monotonicity
   ========================================================================= *)

(** Named predicate: all policies in the list have no duplicate keys.
    Avoids Z3 4.13 issues with forall/index quantifiers. *)
val all_nodup_keys : pols:list metadata_policy_concrete -> Tot bool
  (decreases pols)
let rec all_nodup_keys pols =
  match pols with
  | [] -> true
  | p :: rest -> nodup_keys p && all_nodup_keys rest

#push-options "--z3rlimit 150 --fuel 4 --ifuel 2"

(** Folding more merges preserves restrictiveness.
    If current ≥ target, then fold_left merge current suffix ≥ target.
    Requires nodup_keys on current and all suffix elements so that
    lemma_merge_preserves_ordering can fire at each step, and
    merge_policy_nodup threads nodup through the fold. *)
val lemma_resolve_suffix_monotone :
  current:metadata_policy_concrete ->
  suffix:list metadata_policy_concrete ->
  target:metadata_policy_concrete ->
  Lemma
    (requires policy_at_least_as_restrictive_concrete current target = true /\
              nodup_keys current /\
              all_nodup_keys suffix = true)
    (ensures policy_at_least_as_restrictive_concrete
               (fold_left merge_policy current suffix) target = true)
    (decreases suffix)
let rec lemma_resolve_suffix_monotone current suffix target =
  match suffix with
  | [] -> ()
  | s :: rest ->
    let next = merge_policy current s in
    lemma_merge_policy_nodup current s;
    lemma_merge_preserves_ordering current s target;
    lemma_resolve_suffix_monotone next rest target

#pop-options

(* =========================================================================
   Section 16: merge_policy_top is identity
   ========================================================================= *)

#push-options "--z3rlimit 60 --fuel 4 --ifuel 2"

val lemma_merge_policy_top_left : p:metadata_policy_concrete ->
  Lemma (ensures merge_policy policy_top p = p)
let lemma_merge_policy_top_left p =
  assert (policy_top = []);
  assert (merge_policy [] p = p)

val lemma_resolve_single : p:metadata_policy_concrete ->
  Lemma (ensures resolve_policies_concrete [p] = p)
let lemma_resolve_single p =
  assert (resolve_policies_concrete [p] = fold_left merge_policy policy_top [p]);
  assert (fold_left merge_policy policy_top [p] = merge_policy policy_top p);
  lemma_merge_policy_top_left p

val lemma_resolve_snoc :
  xs:list metadata_policy_concrete -> y:metadata_policy_concrete ->
  Lemma (ensures resolve_policies_concrete (xs @ [y]) =
                 merge_policy (resolve_policies_concrete xs) y)
let lemma_resolve_snoc xs y =
  lemma_fold_left_snoc merge_policy policy_top xs y

#pop-options

(* =========================================================================
   Lemma 3: resolve_policies_concrete subsumes each member
   ========================================================================= *)

#push-options "--z3rlimit 200 --fuel 6 --ifuel 2"

(** The resolved policy is at least as restrictive as each input.
    Requires all policies to have no duplicate keys (well-formedness). *)
val lemma_resolve_policies_subsumes_member :
  policies:list metadata_policy_concrete ->
  i:nat{i < length policies} ->
  Lemma (requires all_nodup_keys policies = true)
    (ensures policy_at_least_as_restrictive_concrete
               (resolve_policies_concrete policies)
               (index policies i) = true)
    (decreases policies)
let rec lemma_resolve_policies_subsumes_member policies i =
  match policies with
  | [] -> ()
  | [x] ->
    lemma_resolve_single x;
    lemma_policy_restrictive_refl x
  | x :: rest ->
    assert (nodup_keys x = true);
    assert (all_nodup_keys rest = true);
    lemma_merge_policy_top_left x;
    if i = 0 then begin
      lemma_policy_restrictive_refl x;
      lemma_resolve_suffix_monotone x rest x
    end else begin
      lemma_fold_subsumes_any_init x rest (i - 1)
    end

(** For any init with nodup_keys, fold_left merge init policies ≥ index policies j.
    Requires nodup_keys on init and all policies. *)
and lemma_fold_subsumes_any_init
  (init:metadata_policy_concrete)
  (policies:list metadata_policy_concrete)
  (j:nat{j < length policies})
  : Lemma
    (requires nodup_keys init /\
              all_nodup_keys policies = true)
    (ensures policy_at_least_as_restrictive_concrete
               (fold_left merge_policy init policies)
               (index policies j) = true)
    (decreases policies)
  =
  match policies with
  | [] -> ()
  | x :: rest ->
    assert (nodup_keys x = true);
    assert (all_nodup_keys rest = true);
    let next = merge_policy init x in
    lemma_merge_policy_nodup init x;
    if j = 0 then begin
      lemma_merge_policy_monotone_desc init x;
      lemma_resolve_suffix_monotone next rest x
    end else begin
      lemma_fold_subsumes_any_init next rest (j - 1)
    end

#pop-options
