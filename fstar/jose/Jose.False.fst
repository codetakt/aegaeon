module Jose.False

let false_elim (#a:Type0) (pf:False) : Tot a =
  match pf with

let lemma_bool_conflict (p:bool) (pf_true:p = true) (pf_false:p = false) : Lemma False =
  match pf_true with
  | () ->
    match pf_false with
    | () -> ()

let bool_conflict_elim (#a:Type0) (p:bool) (pf_true:p = true) (pf_false:p = false) : Tot a =
  false_elim (lemma_bool_conflict p pf_true pf_false)
