module JoseNatLemmas

open FStar.Math.Lemmas
open FStar.List.Tot
open FStar.Calc

let lemma_nat_lt_succ (n:nat)
  : Lemma (ensures n < n + 1)
  = ()

let lemma_lt_trans (a b c:nat)
  : Lemma (requires a < b /\ b < c)
          (ensures a < c)
  = ()

let lemma_tail_length_one #a (x:a) (xs:list a)
  : Lemma (ensures List.length xs < List.length (x :: xs))
  = lemma_nat_lt_succ (List.length xs)

let lemma_tail_length_two #a (x y:a) (xs:list a)
  : Lemma (ensures List.length xs < List.length (x :: y :: xs))
  =
  lemma_tail_length_one y xs;
  lemma_tail_length_one x (y :: xs);
  lemma_lt_trans
    (List.length xs)
    (List.length (y :: xs))
    (List.length (x :: y :: xs))

let lemma_tail_length_three #a (x y z:a) (xs:list a)
  : Lemma (ensures List.length xs < List.length (x :: y :: z :: xs))
  =
  lemma_tail_length_two y z xs;
  lemma_tail_length_one x (y :: z :: xs);
  lemma_lt_trans
    (List.length xs)
    (List.length (y :: z :: xs))
    (List.length (x :: y :: z :: xs))

let lemma_tail_length_four #a (w x y z:a) (xs:list a)
  : Lemma (ensures List.length xs < List.length (w :: x :: y :: z :: xs))
  =
  lemma_tail_length_three x y z xs;
  lemma_tail_length_one w (x :: y :: z :: xs);
  lemma_lt_trans
    (List.length xs)
    (List.length (x :: y :: z :: xs))
    (List.length (w :: x :: y :: z :: xs))

let lemma_nat_sub_bounds (x:nat) (y:nat)
  : Lemma (requires y <= x)
          (ensures (x - y) + y = x)
  = ()

let nat_sub (x:nat) (y:nat{y <= x}) : Tot nat = x - y

let lemma_nat_sub_add (x:nat) (y:nat)
  : Lemma (ensures nat_sub (y + x) y = x)
  = ()

let lemma_append_singleton (#a:eqtype) (x:a) (xs:list a)
  : Lemma (ensures List.append [x] xs = x :: xs)
  = ()

let lemma_append_pair (#a:eqtype) (x y:a) (xs:list a)
  : Lemma (ensures List.append [x; y] xs = x :: y :: xs)
  =
  calc (==) {
    List.append [x; y] xs;
    == { }
    x :: List.append [y] xs;
    == { }
    x :: y :: xs;
  }

let lemma_append_triple (#a:eqtype) (x y z:a) (xs:list a)
  : Lemma (ensures List.append [x; y; z] xs = x :: y :: z :: xs)
  =
  calc (==) {
    List.append [x; y; z] xs;
    == { }
    x :: List.append [y; z] xs;
    == { }
    x :: y :: List.append [z] xs;
    == { }
    x :: y :: z :: xs;
  }

let lemma_append_quad (#a:eqtype) (w x y z:a) (xs:list a)
  : Lemma (ensures List.append [w; x; y; z] xs = w :: x :: y :: z :: xs)
  =
  calc (==) {
    List.append [w; x; y; z] xs;
    == { }
    w :: List.append [x; y; z] xs;
    == { }
    w :: x :: List.append [y; z] xs;
    == { }
    w :: x :: y :: List.append [z] xs;
    == { }
    w :: x :: y :: z :: xs;
  }

let lemma_base64_decompose_3 (cp:nat)
  : Lemma
      (ensures Prims.op_Multiply (cp / 4096) 4096
               + Prims.op_Multiply ((cp / 64) % 64) 64
               + cp % 64 = cp)
  =
    let _ = lemma_div_mod cp 64 in
    let _ = lemma_div_mod (cp / 64) 64 in
    calc (==) {
      cp;
      == {}
      Prims.op_Multiply (cp / 64) 64 + cp % 64;
      == {}
      Prims.op_Multiply
        (Prims.op_Multiply (cp / 4096) 64 + (cp / 64) % 64)
        64
      + cp % 64;
      == {}
      Prims.op_Multiply (cp / 4096) 4096
      + Prims.op_Multiply ((cp / 64) % 64) 64
      + cp % 64;
    }

let lemma_base64_decompose_4 (cp:nat)
  : Lemma
      (ensures Prims.op_Multiply (cp / 262144) 262144
               + Prims.op_Multiply ((cp / 4096) % 64) 4096
               + Prims.op_Multiply ((cp / 64) % 64) 64
               + cp % 64 = cp)
  =
    let _ = lemma_div_mod cp 64 in
    let _ = lemma_div_mod (cp / 64) 64 in
    let _ = lemma_div_mod (cp / 4096) 64 in
    calc (==) {
      cp;
      == {}
      Prims.op_Multiply (cp / 64) 64 + cp % 64;
      == {}
      Prims.op_Multiply
        (Prims.op_Multiply (cp / 4096) 64 + (cp / 64) % 64)
        64
      + cp % 64;
      == {}
      Prims.op_Multiply
        (Prims.op_Multiply (cp / 262144) 64 + (cp / 4096) % 64)
        4096
      + Prims.op_Multiply ((cp / 64) % 64) 64
      + cp % 64;
      == {}
      Prims.op_Multiply (cp / 262144) 262144
      + Prims.op_Multiply ((cp / 4096) % 64) 4096
      + Prims.op_Multiply ((cp / 64) % 64) 64
      + cp % 64;
    }

let lemma_utf8_four_byte_components
  (high mid1 mid2 low:nat)
  : Lemma
      (requires high < 5 /\ mid1 < 64 /\ mid2 < 64 /\ low < 64)
      (ensures (
        let cp =
          Prims.op_Multiply high 262144
          + Prims.op_Multiply mid1 4096
          + Prims.op_Multiply mid2 64
          + low in
        cp / 262144 = high /\
        cp / 4096 = Prims.op_Multiply high 64 + mid1 /\
        cp / 64 = Prims.op_Multiply high 4096
                  + Prims.op_Multiply mid1 64
                  + mid2 /\
        (cp / 4096) % 64 = mid1 /\
        (cp / 64) % 64 = mid2 /\
        cp % 64 = low))
  =
    let cp =
      Prims.op_Multiply high 262144
      + Prims.op_Multiply mid1 4096
      + Prims.op_Multiply mid2 64
      + low in
    assert_norm (cp / 262144 = high);
    assert_norm (cp / 4096
                 = Prims.op_Multiply high 64 + mid1);
    assert_norm (cp / 64
                 = Prims.op_Multiply high 4096
                   + Prims.op_Multiply mid1 64
                   + mid2);
    assert_norm ((cp / 4096) % 64 = mid1);
    assert_norm ((cp / 64) % 64 = mid2);
    assert_norm (cp % 64 = low)
