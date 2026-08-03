module Jose.HeaderKeyLemmas

open FStar.List.Tot
open Jose.StringLemmas
open FStar.Classical
module Policy = Jose.HeaderPolicy

module List = FStar.List.Tot
module SL = Jose.StringLemmas
let keys_of_entries (entries:list (string * string)) : list string =
  List.map #(string * string) #string
    (fun pair -> match pair with | (k, _) -> k)
    entries

val keys_of_entries_prop_to_eq
  : entries:list (string * string) ->
    rest_keys:list string ->
    Lemma
      (requires keys_of_entries entries = rest_keys)
      (ensures keys_of_entries entries == rest_keys)
let keys_of_entries_prop_to_eq entries rest_keys =
  (* For eqtype (list string), decidable equality (=) implies
     propositional equality (==) by the hasEq correctness axiom *)
  ()


let keys_of_entries_nil_prop ()
  : Lemma (keys_of_entries [] = [])
  = ()

/// Trivial lemma: keys_of_entries on empty list returns empty list
#push-options "--z3rlimit 20"
let eq_keys_of_entries_nil ()
  : (keys_of_entries [] == [])
  =
    keys_of_entries_nil_prop ();
    keys_of_entries_prop_to_eq [] [];
    get_equality (keys_of_entries []) []
#pop-options

let lemma_keys_of_entries_nil ()
  : Lemma (keys_of_entries [] == [])
  =
    let _ = eq_keys_of_entries_nil () in
    ()

let keys_of_entries_cons_prop
  (entries:list (string * string))
  (k:string)
  (v:string)
  : Lemma (keys_of_entries ((k, v) :: entries) = k :: keys_of_entries entries)
  = ()

/// Trivial lemma: keys_of_entries on cons preserves structure
#push-options "--z3rlimit 20"
let eq_keys_of_entries_cons
  (entries:list (string * string))
  (k:string)
  (v:string)
  : (keys_of_entries ((k, v) :: entries) == k :: keys_of_entries entries)
  =
    keys_of_entries_cons_prop entries k v;
    keys_of_entries_prop_to_eq
      ((k, v) :: entries)
      (k :: keys_of_entries entries);
    get_equality
      (keys_of_entries ((k, v) :: entries))
      (k :: keys_of_entries entries)
#pop-options

let rewrite_keys_entries_cons
  (entries:list (string * string))
  (k:string)
  (v:string)
  : Tot (keys_of_entries ((k, v) :: entries) == k :: keys_of_entries entries)
  = eq_keys_of_entries_cons entries k v

val keys_of_entries_eq_to_prop
  : entries:list (string * string) ->
    rest_keys:list string ->
    keys_of_entries entries == rest_keys ->
    Lemma (ensures keys_of_entries entries = rest_keys)
let keys_of_entries_eq_to_prop entries rest_keys _eq =
  FStar.Classical.give_witness_from_squash _eq


let lemma_keys_of_entries_cons
  (entries:list (string * string))
  (k:string)
  (v:string)
  : Lemma (keys_of_entries ((k, v) :: entries) == k :: keys_of_entries entries)
  =
    let _ = eq_keys_of_entries_cons entries k v in
    ()

let lemma_keys_of_entries_singleton
  (k:string)
  (v:string)
  : Lemma (keys_of_entries [(k, v)] = [k])
  = ()

val lemma_keys_of_entries_append :
  entries1:list (string * string) ->
  entries2:list (string * string) ->
  Lemma (ensures
    keys_of_entries (List.append entries1 entries2) =
    List.append (keys_of_entries entries1) (keys_of_entries entries2))
  (decreases entries1)
let rec lemma_keys_of_entries_append entries1 entries2 =
  (* Standard map/append distributivity by induction on entries1 *)
  match entries1 with
  | [] -> ()
  | _ :: tl -> lemma_keys_of_entries_append tl entries2

val lemma_keys_of_entries_rev :
  entries:list (string * string) ->
  Lemma (ensures
    keys_of_entries (List.rev entries) =
    List.rev (keys_of_entries entries))
  (decreases entries)
let rec lemma_keys_of_entries_rev entries =
  match entries with
  | [] -> ()
  | (k, v) :: tl ->
    lemma_keys_of_entries_rev tl;
    (* rev ((k,v)::tl) = append (rev tl) [(k,v)]
       by rev_append from FStar.List.Tot.Properties *)
    FStar.List.Tot.Properties.rev_append [(k, v)] tl;
    (* keys_of_entries distributes over append *)
    lemma_keys_of_entries_append (List.rev tl) [(k, v)];
    (* rev (k :: keys_of_entries tl) = append (rev (keys_of_entries tl)) [k] *)
    SL.lemma_rev_cons_eq k (keys_of_entries tl)

let rec no_duplicate_keys (keys:list string) : Tot bool =
  match keys with
  | [] -> true
  | hd::tl ->
      not (string_in_list hd tl) && no_duplicate_keys tl

let lemma_no_duplicate_tail
  (hd:string)
  (tl:list string)
  : Lemma
      (requires no_duplicate_keys (hd::tl))
      (ensures no_duplicate_keys tl)
  = ()

let lemma_no_duplicate_head_fresh
  (hd:string)
  (tl:list string)
  : Lemma
      (requires no_duplicate_keys (hd::tl))
      (ensures not (string_in_list hd tl))
  = ()

let lemma_not_in_cons_tail
  (x:string)
  (hd:string)
  (tl:list string)
  : Lemma
      (requires not (string_in_list x (hd::tl)))
      (ensures not (string_in_list x tl))
  = ()

let lemma_not_in_cons_head
  (x:string)
  (hd:string)
  (tl:list string)
  : Lemma
      (requires not (string_in_list x (hd::tl)))
      (ensures (=) x hd = false)
  = ()

let lemma_no_duplicate_eq
  (x:list string)
  (y:list string)
  : Lemma
      (requires no_duplicate_keys y /\ x = y)
      (ensures no_duplicate_keys x)
  = ()

let lemma_policy_for_all_eq
  (x:list string)
  (y:list string)
  : Lemma
      (requires List.for_all Policy.key_allowed y = true /\ x = y)
      (ensures List.for_all Policy.key_allowed x = true)
  = ()

let lemma_policy_for_all_tail
  (hd:string)
  (tl:list string)
  : Lemma
      (requires List.for_all Policy.key_allowed (hd :: tl) = true)
      (ensures List.for_all Policy.key_allowed tl = true)
  = ()

let lemma_policy_for_all_head
  (hd:string)
  (tl:list string)
  : Lemma
      (requires List.for_all Policy.key_allowed (hd :: tl) = true)
      (ensures Policy.key_allowed hd = true)
  = ()

let lemma_policy_for_all_cons
  (hd:string)
  (tl:list string)
  : Lemma
      (requires Policy.key_allowed hd = true /\ List.for_all Policy.key_allowed tl = true)
      (ensures List.for_all Policy.key_allowed (hd :: tl) = true)
  = ()

val lemma_policy_for_all_append_single
  : entries:list string ->
    k:string ->
    Lemma
      (requires List.for_all Policy.key_allowed entries = true /\ Policy.key_allowed k = true)
      (ensures List.for_all Policy.key_allowed (List.append entries [k]) = true)
  (decreases entries)
let rec lemma_policy_for_all_append_single entries k =
  match entries with
  | [] -> ()
  | hd :: tl ->
    lemma_policy_for_all_head hd tl;
    lemma_policy_for_all_tail hd tl;
    lemma_policy_for_all_append_single tl k

let rec lemma_policy_for_all_rev
  (entries:list string)
  : Lemma
      (requires List.for_all Policy.key_allowed entries = true)
      (ensures List.for_all Policy.key_allowed (List.rev entries) = true)
  (decreases entries)
  =
    match entries with
    | [] -> ()
    | hd :: tl ->
        lemma_policy_for_all_tail hd tl;
        lemma_policy_for_all_head hd tl;
        lemma_policy_for_all_rev tl;
        Jose.StringLemmas.lemma_rev_cons_eq hd tl;
        lemma_policy_for_all_append_single (List.rev tl) hd;
        ()

let rec lemma_policy_for_all_mem
  (entries:list string)
  (target:string)
  : Lemma
      (requires List.for_all Policy.key_allowed entries = true)
      (ensures List.mem target entries ==> Policy.key_allowed target = true)
  (decreases entries)
  =
    match entries with
    | [] -> ()
    | hd :: tl ->
        lemma_policy_for_all_head hd tl;
        lemma_policy_for_all_tail hd tl;
        if List.mem target (hd :: tl) then
          if target = hd then ()
          else (
            lemma_policy_for_all_mem tl target;
            ()
          )
        else ()

val lemma_no_duplicate_append_single :
  entries:list string -> k:string ->
  Lemma (requires no_duplicate_keys entries /\ not (string_in_list k entries))
        (ensures no_duplicate_keys (List.append entries [k]))
  (decreases entries)
let rec lemma_no_duplicate_append_single entries k =
  match entries with
  | [] -> ()
  | hd :: tl ->
    (* hd is not in tl (from no_duplicate_keys (hd::tl)) *)
    lemma_no_duplicate_tail hd tl;
    (* k is not in tl (from not (string_in_list k (hd::tl))) *)
    SL.lemma_string_in_list_append hd tl [k];
    lemma_not_in_cons_tail k hd tl;
    lemma_no_duplicate_append_single tl k

val lemma_no_duplicate_cons :
  k:string -> seen:list string ->
  Lemma (requires no_duplicate_keys seen /\ not (string_in_list k seen))
        (ensures no_duplicate_keys (k :: seen))
let lemma_no_duplicate_cons k seen =
  (* Immediate from no_duplicate_keys definition:
     no_duplicate_keys (k :: seen) = not (string_in_list k seen) && no_duplicate_keys seen *)
  ()
