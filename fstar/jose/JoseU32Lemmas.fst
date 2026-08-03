module JoseU32Lemmas

open FStar.UInt32
open FStar.Math.Lemmas

let lemma_u32_sub_nonwrap
  (x:UInt32.t)
  (y:UInt32.t)
  : Lemma (requires v y <= v x)
          (ensures v (sub x y) = v x - v y)
  =
    assert (v (sub x y) + v y = v x);
    assert (v x - v y + v y = v x);
    ()
