module Jose.UInt32Bounds

open FStar.UInt32
open FStar.Math.Lemmas
open JoseU32Lemmas

/// Bool-to-proposition bridge for UInt32 equality.
let lemma_eq_true_implies_eq
  (a:UInt32.t)
  (b:UInt32.t)
  : Lemma
      (requires UInt32.eq a b = true)
      (ensures a == b)
  =
    if UInt32.eq a b
    then ()
    else
      let _ = assert_norm (UInt32.eq a b = false) in
      ()

/// Bool-to-proposition bridge for UInt32 inequality.
let lemma_eq_false_implies_neq
  (a:UInt32.t)
  (b:UInt32.t)
  : Lemma
      (requires UInt32.eq a b = false)
      (ensures a <> b)
  =
    if UInt32.eq a b then
      let _ = assert_norm (UInt32.eq a b = true) in
      ()
    else
      assert (a <> b);
      ()

/// Equality transitivity for UInt32 eq booleans.
let lemma_eq_true_trans
  (a:UInt32.t)
  (b:UInt32.t)
  (c:UInt32.t)
  : Lemma
      (requires UInt32.eq a b = true /\ UInt32.eq b c = true)
      (ensures UInt32.eq a c = true)
  =
    let _ = lemma_eq_true_implies_eq a b in
    let _ = lemma_eq_true_implies_eq b c in
    assert_norm (UInt32.eq a c);
    ()

/// Equality on UInt32 implies equality on their underlying nat values.
let lemma_eq_true_implies_v_eq
  (a:UInt32.t)
  (b:UInt32.t)
  : Lemma
      (requires UInt32.eq a b = true)
      (ensures v a = v b)
  =
    lemma_eq_true_implies_eq a b;
    ()

/// Equality transitivity for boolean values.
let lemma_bool_eq_trans
  (p:bool)
  (q:bool)
  (r:bool)
  (pf1:p = q)
  (pf2:q = r)
  : Lemma (p = r)
  =
    match pf1, pf2 with
    | (), () -> ()

/// Bool-to-proposition bridge for UInt32 greater-than.
let lemma_gt_true_implies_strict
  (a:UInt32.t)
  (b:UInt32.t)
  : Lemma
      (requires UInt32.gt a b = true)
      (ensures v a > v b)
  =
    if UInt32.gt a b then begin
      assert_norm (UInt32.gt a b);
      assert (v a > v b);
      ()
    end else begin
      let _ = assert_norm (UInt32.gt a b = false) in
      ()
    end

/// Bool-to-proposition bridge for UInt32 greater-or-equal.
let lemma_gte_true_implies_nonstrict
  (a:UInt32.t)
  (b:UInt32.t)
  : Lemma
      (requires UInt32.gte a b = true)
      (ensures v a >= v b)
  =
    if UInt32.gte a b then begin
      assert_norm (UInt32.gte a b);
      assert (v a >= v b);
      ()
    end else begin
      let _ = assert_norm (UInt32.gte a b = false) in
      ()
    end

/// Subtraction/addition cancellation under non-wrap conditions.
let lemma_sub_add_cancel
  (x:UInt32.t)
  (y:UInt32.t{v y <= v x})
  : Lemma
      (ensures UInt32.eq (UInt32.add (UInt32.sub x y) y) x = true)
  =
    let _ = lemma_u32_sub_nonwrap x y in
    assert_norm (UInt32.eq (UInt32.add (UInt32.sub x y) y) x);
    ()

/// Same as lemma_sub_add_cancel but returning propositional equality.
let lemma_sub_add_cancel_eq
  (x:UInt32.t)
  (y:UInt32.t{v y <= v x})
  : Lemma
      (ensures UInt32.add (UInt32.sub x y) y == x)
  =
    lemma_sub_add_cancel x y;
    lemma_eq_true_implies_eq (UInt32.add (UInt32.sub x y) y) x

/// If x > y then the difference x - y is strictly positive.
let lemma_sub_positive_if_gt
  (x:UInt32.t)
  (y:UInt32.t)
  : Lemma
      (requires UInt32.gt x y = true)
      (ensures UInt32.gt (UInt32.sub x y) 0ul = true)
  =
    lemma_gt_true_implies_strict x y;
    let _ = lemma_u32_sub_nonwrap x y in
    assert (v (UInt32.sub x y) = v x - v y);
    assert (v x - v y > 0);
    assert (UInt32.gt (UInt32.sub x y) 0ul);
    ()

/// Strict inequality implies boolean equality is false.
let lemma_lt_implies_eq_false
  (a:UInt32.t)
  (b:UInt32.t)
  : Lemma
      (requires v a < v b)
      (ensures UInt32.eq a b = false)
  =
    assert (UInt32.eq a b = false);
    ()

/// Strict inequality gives both boolean and nat inequality.
let lemma_lt_implies_eq_false_strict
  (a:UInt32.t)
  (b:UInt32.t)
  : Lemma
      (requires v a < v b)
      (ensures UInt32.eq a b = false /\ v a <> v b)
  =
    lemma_lt_implies_eq_false a b;
    assert (v a <> v b);
    ()

/// Nat equality implies boolean equality for UInt32.
let lemma_v_eq_implies_eq_true
  (a:UInt32.t)
  (b:UInt32.t)
  : Lemma
      (requires v a = v b)
      (ensures UInt32.eq a b = true)
  =
    assert (UInt32.eq a b = true);
    ()

/// Boolean inequality implies nat inequality.
let lemma_eq_false_implies_v_neq
  (a:UInt32.t)
  (b:UInt32.t)
  : Lemma
      (requires UInt32.eq a b = false)
      (ensures v a <> v b)
  =
    assert (v a <> v b);
    ()

/// Combine <= and <> into < (requires nat-level check).
let lemma_le_and_neq_implies_lt
  (a:UInt32.t)
  (b:UInt32.t)
  : Lemma
      (requires v a <= v b /\ v a <> v b)
      (ensures v a < v b)
  =
    assert (v a < v b);
    ()

/// Boolean equality conflict yields False.
let lemma_eq_bool_conflict
  (p:bool)
  : Lemma
      (requires p = true /\ p = false)
      (ensures False)
  =
    ()

/// Convert boolean equality on UInt32 into False given a strict inequality.
let lemma_eq_true_implies_false
  (idx:UInt32.t)
  (count:UInt32.t)
  : Lemma
      (requires v idx < v count)
      (ensures not (UInt32.eq idx count = true))
  =
    ()
