module EqHelpers

/// Generic equality combinators for proof engineering.
///
/// Extracted from Jose.JsonHeaderSpec.fst.  These are general-purpose
/// transitivity, symmetry, and congruence lemmas on eqtype values
/// and lists/pairs thereof.

open FStar.List.Tot

let eq_trans
  (#a:eqtype)
  (x:a)
  (y:a)
  (z:a)
  : Lemma (requires x == y /\ y == z)
          (ensures x == z)
  = ()

let eq_to_prop
  (#a:eqtype)
  (x:a)
  (y:a)
  : Lemma (requires x == y)
          (ensures x = y)
  = ()

let eq_trans_prop
  (#a:eqtype)
  (x:a)
  (y:a)
  (z:a)
  : Lemma (requires x = y /\ y = z)
          (ensures x = z)
  = ()

let eq_sym_prop
  (#a:eqtype)
  (x:a)
  (y:a)
  (pf:x = y)
  : Lemma (y = x)
  =
    match pf with
    | () -> ()

let eq_sym
  (#a:eqtype)
  (x:a)
  (y:a)
  : Lemma (requires x == y)
          (ensures y == x)
  = ()

let eq_cons_preserve
  (#a:eqtype)
  (hd:a)
  (tl1:list a)
  (tl2:list a)
  : Lemma (requires tl1 == tl2)
          (ensures (hd :: tl1) == (hd :: tl2))
  = ()

let eq_cons_head_change
  (#a:eqtype)
  (hd1:a)
  (hd2:a)
  (tl:list a)
  : Lemma (requires hd1 == hd2)
          (ensures hd1 :: tl == hd2 :: tl)
  = ()

let eq_pair_second
  (#a:eqtype)
  (#b:eqtype)
  (x:a)
  (y1:b)
  (y2:b)
  : Lemma (requires y1 == y2)
          (ensures (x, y1) == (x, y2))
  = ()
