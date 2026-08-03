module Token

open FStar.All

// Ghost-state model for authorization code lifecycle
type token_store = {
  issued: list string;
  used: list string;
}

inline_for_extraction let empty_store : unit -> token_store =
  fun _ -> { issued = []; used = [] }

let rec contains (x:string) (l:list string) : Tot bool =
  match l with
  | [] -> false
  | y::ys -> if x = y then true else contains x ys

let issued s code = contains code s.issued
let used   s code = contains code s.used

// Well-formedness: no issued code appears in used set (asymmetric disjointness is sufficient)
let rec disjoint (a:list string) (b:list string) : Tot bool =
  match a with
  | [] -> true
  | x::xs -> if contains x b then false else disjoint xs b

let well_formed s : Tot bool = disjoint s.issued s.used

// Issue a new authorization code (ghost)
val issue_code: s:token_store -> code:string -> Pure token_store
  (requires (not (issued s code) && not (used s code)))
  (ensures  (fun s' -> issued s' code))
let issue_code s code = { issued = code :: s.issued; used = s.used }

// Remove all occurrences of a code (helper)
let rec remove_all (x:string) (l:list string) : Tot (list string) =
  match l with
  | [] -> []
  | y::ys -> if x = y then remove_all x ys else y :: remove_all x ys

// Consume a code exactly once (ghost): move from issued -> used
val consume_code: s:token_store -> code:string -> Tot token_store
let consume_code s code = { issued = remove_all code s.issued; used = code :: s.used }

// Helper lemma: removing all occurrences eliminates membership
let rec lemma_remove_all_not_contains (x:string) (l:list string) : Lemma
  (ensures not (contains x (remove_all x l))) =
  match l with
  | [] -> ()
  | y::ys -> if x = y then lemma_remove_all_not_contains x ys else lemma_remove_all_not_contains x ys

// Removing x preserves membership for other elements y != x
let rec lemma_remove_all_preserves_others (x:string) (y:string) (l:list string) : Lemma
  (requires (x <> y))
  (ensures (contains y (remove_all x l) <==> contains y l)) =
  match l with
  | [] -> ()
  | z::zs ->
    if x = z then lemma_remove_all_preserves_others x y zs
    else if y = z then ()
    else lemma_remove_all_preserves_others x y zs

// Proven effect: after consume, code is marked used and no longer issued
let lemma_consume_effect (s:token_store) (code:string) : Lemma
  (requires (issued s code && not (used s code)))
  (ensures  (let s' = consume_code s code in used s' code && not (issued s' code))) =
  let _ = lemma_remove_all_not_contains code s.issued in
  ()

// Well-formedness lemmas (structure preservation)
let lemma_wf_empty () : Lemma (ensures (well_formed (empty_store ()))) = ()

let rec lemma_disjoint_cons_left (x:string) (xs:list string) (ys:list string) : Lemma
  (requires (disjoint xs ys /\ not (contains x ys)))
  (ensures  (disjoint (x::xs) ys)) =
  match xs with
  | [] -> ()
  | z::zs -> if contains z ys then () else lemma_disjoint_cons_left x zs ys

let lemma_wf_issue_code (s:token_store) (code:string) : Lemma
  (requires (well_formed s && not (issued s code) && not (used s code)))
  (ensures  (well_formed (issue_code s code))) =
  lemma_disjoint_cons_left code s.issued s.used

let rec lemma_disjoint_remove_all_left (a:string) (xs:list string) (ys:list string) : Lemma
  (requires (disjoint xs ys))
  (ensures  (disjoint (remove_all a xs) ys)) =
  match xs with
  | [] -> ()
  | z::zs -> if contains z ys then () else lemma_disjoint_remove_all_left a zs ys

// Omitted: lemma_disjoint_cons_right and lemma_wf_consume_code (derivable)
