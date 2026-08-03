module Jose.TlvLemmas

open FStar.List.Tot
open Jose.StringLemmas
open Jose.HeaderKeyLemmas

let rec lemma_rev_preserves_no_duplicates
  (keys:list string)
  : Lemma
      (requires no_duplicate_keys keys)
      (ensures no_duplicate_keys (List.rev keys))
  (decreases keys)
  =
    match keys with
    | [] -> ()
    | hd::tl ->
        lemma_no_duplicate_tail hd tl;
        lemma_no_duplicate_head_fresh hd tl;
        lemma_rev_preserves_no_duplicates tl;
        let rev_tl = List.rev tl in
        Jose.StringLemmas.lemma_string_not_in_rev hd tl;
        lemma_no_duplicate_append_single rev_tl hd;
        Jose.StringLemmas.lemma_rev_cons_eq hd tl;
        lemma_no_duplicate_eq (List.rev (hd::tl)) (List.append rev_tl [hd]);
        ()

let lemma_seen_acc_consistency
  (entries:list (string * string))
  (seen:list string)
  (k:string)
  (v:string)
  : Lemma
      (requires seen = keys_of_entries entries)
      (ensures k :: seen = keys_of_entries ((k, v) :: entries))
  =
    lemma_keys_of_entries_cons entries k v;
    ()

let lemma_no_duplicate_seen
  (entries:list (string * string))
  (seen:list string)
  (k:string)
  (v:string)
  : Lemma
      (requires seen = keys_of_entries entries /\
                no_duplicate_keys seen /\
                not (string_in_list k seen))
      (ensures no_duplicate_keys (k :: seen) /\
               no_duplicate_keys (keys_of_entries ((k, v) :: entries)))
  =
    lemma_keys_of_entries_cons entries k v;
    lemma_no_duplicate_cons k seen;
    assert (keys_of_entries ((k, v) :: entries) = k :: keys_of_entries entries);
    assert (keys_of_entries ((k, v) :: entries) = k :: seen);
    ()
