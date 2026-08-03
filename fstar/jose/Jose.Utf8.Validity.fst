module Jose.Utf8.Validity

/// UTF-8 validation predicates, canonical scalar checks, and all
/// canonical/range/scalar bounds lemmas.  Also includes the pure
/// `decode_utf8_scalar_nat` function (no side-effects, depends only
/// on validation predicates).

open FStar.UInt8
open FStar.UInt32
open FStar.Math.Lemmas
open FStar.Pervasives
open FStar.List.Tot
open FStar.List.Tot.Properties
open FStar.String
open FStar.Char
open JoseNatLemmas
open Jose.Utf8

module U32 = FStar.UInt32
module Str = FStar.String

///////////////////////////////////////////////////////////////////////////////
// UTF-8 Validation
///////////////////////////////////////////////////////////////////////////////

let rec valid_utf8_bytes (bs:list UInt8.t) : Tot bool (decreases bs) =
  match bs with
  | [] -> true
  | b0::bs1 ->
      let v0 = byte_val b0 in
      if v0 <= 0x7F then
        valid_utf8_bytes bs1
      else if between v0 0xC2 0xDF then
        (match bs1 with
         | b1::bs2 -> is_cont b1 && valid_utf8_bytes bs2
         | _ -> false)
      else if between v0 0xE0 0xEF then
        (match bs1 with
         | b1::bs2 ->
             let v1 = byte_val b1 in
             if v0 = 0xE0 && not (between v1 0xA0 0xBF) then false
             else if v0 = 0xED && not (between v1 0x80 0x9F) then false
             else if not (between v1 0x80 0xBF) then false
             else (match bs2 with
                   | b2::bs3 -> is_cont b2 && valid_utf8_bytes bs3
                   | _ -> false)
         | _ -> false)
      else if between v0 0xF0 0xF4 then
        (match bs1 with
         | b1::bs2 ->
             let v1 = byte_val b1 in
             if v0 = 0xF0 && not (between v1 0x90 0xBF) then false
             else if v0 = 0xF4 && not (between v1 0x80 0x8F) then false
             else if not (between v1 0x80 0xBF) then false
             else (match bs2 with
                   | b2::bs3 ->
                       if not (is_cont b2) then false
                       else (match bs3 with
                             | b3::bs4 -> is_cont b3 && valid_utf8_bytes bs4
                             | _ -> false)
                   | _ -> false)
         | _ -> false)
      else false

let canonical_utf8_scalar (bs:list UInt8.t) : Tot bool =
  match bs with
  | [b0] -> byte_val b0 <= 0x7F
  | [b0; b1] ->
      let v0 = byte_val b0 in
      between v0 0xC2 0xDF && is_cont b1
  | [b0; b1; b2] ->
      let v0 = byte_val b0 in
      let v1 = byte_val b1 in
      between v0 0xE0 0xEF
      && (if v0 = 0xE0 then between v1 0xA0 0xBF
          else if v0 = 0xED then between v1 0x80 0x9F
          else between v1 0x80 0xBF)
      && is_cont b2
      && (if v0 = 0xED && v1 = 0x9F then byte_val b2 <= 0xBE else true)
      && not (v0 = 0xED && v1 = 0x9F && byte_val b2 = 0xBF)
  | [b0; b1; b2; b3] ->
      let v0 = byte_val b0 in
      let v1 = byte_val b1 in
      between v0 0xF0 0xF4
      && (if v0 = 0xF0 then between v1 0x90 0xBF
          else if v0 = 0xF4 then between v1 0x80 0x8F
          else between v1 0x80 0xBF)
      && is_cont b2 && is_cont b3
  | _ -> false

///////////////////////////////////////////////////////////////////////////////
// Canonical Bounds Lemmas
///////////////////////////////////////////////////////////////////////////////

let lemma_canonical_two_byte_bounds (b0 b1:UInt8.t)
  : Lemma
      (requires canonical_utf8_scalar [b0; b1])
      (ensures utf8_head_2 <= byte_val b0 /\
               byte_val b0 < utf8_head_3 /\
               utf8_cont_base <= byte_val b1 /\
               byte_val b1 < utf8_cont_base + 64)
  =
    let v0 = byte_val b0 in
    let v1 = byte_val b1 in
    assert (between v0 0xC2 0xDF);
    assert (utf8_head_2 <= v0);
    assert (v0 < utf8_head_3);
    assert (between v1 0x80 0xBF);
    assert (utf8_cont_base <= v1);
    assert (v1 < utf8_cont_base + 64)

let lemma_canonical_three_byte_bounds (b0 b1 b2:UInt8.t)
  : Lemma
      (requires canonical_utf8_scalar [b0; b1; b2])
      (ensures utf8_head_3 <= byte_val b0 /\
               byte_val b0 < utf8_head_4 /\
               utf8_cont_base <= byte_val b1 /\
               byte_val b1 < utf8_cont_base + 64 /\
               utf8_cont_base <= byte_val b2 /\
               byte_val b2 < utf8_cont_base + 64)
  =
    let v0 = byte_val b0 in
    let v1 = byte_val b1 in
    let v2 = byte_val b2 in
    assert (between v0 0xE0 0xEF);
    assert (utf8_head_3 <= v0);
    assert (v0 < utf8_head_4);
    assert (between v2 0x80 0xBF);
    assert (utf8_cont_base <= v2);
    assert (v2 < utf8_cont_base + 64);
    if v0 = 0xE0 then
      (assert (between v1 0xA0 0xBF);
       assert (utf8_cont_base <= v1);
       assert (v1 < utf8_cont_base + 64))
    else if v0 = 0xED then
      (assert (between v1 0x80 0x9F);
       assert (utf8_cont_base <= v1);
       assert (v1 < utf8_cont_base + 64);
       if v1 = 0x9F then (
         assert (byte_val b2 <= 0xBE);
         assert (v2 <= utf8_cont_base + 62)
       ) else ())
    else
      (assert (between v1 0x80 0xBF);
       assert (utf8_cont_base <= v1);
       assert (v1 < utf8_cont_base + 64))

let lemma_canonical_four_byte_bounds (b0 b1 b2 b3:UInt8.t)
  : Lemma
      (requires canonical_utf8_scalar [b0; b1; b2; b3])
      (ensures utf8_head_4 <= byte_val b0 /\
               byte_val b0 < utf8_head_4 + 5 /\
               utf8_cont_base <= byte_val b1 /\
               byte_val b1 < utf8_cont_base + 64 /\
               utf8_cont_base <= byte_val b2 /\
               byte_val b2 < utf8_cont_base + 64 /\
               utf8_cont_base <= byte_val b3 /\
               byte_val b3 < utf8_cont_base + 64)
  =
    let v0 = byte_val b0 in
    let v1 = byte_val b1 in
    let v2 = byte_val b2 in
    let v3 = byte_val b3 in
    assert (between v0 0xF0 0xF4);
    assert (utf8_head_4 <= v0);
    assert (v0 < utf8_head_4 + 5);
    assert (between v2 0x80 0xBF);
    assert (between v3 0x80 0xBF);
    assert (utf8_cont_base <= v2);
    assert (utf8_cont_base <= v3);
    assert (v2 < utf8_cont_base + 64);
    assert (v3 < utf8_cont_base + 64);
    if v0 = 0xF0 then
      (assert (between v1 0x90 0xBF);
       assert (utf8_cont_base <= v1);
       assert (v1 < utf8_cont_base + 64))
    else if v0 = 0xF4 then
      (assert (between v1 0x80 0x8F);
       assert (utf8_cont_base <= v1);
       assert (v1 < utf8_cont_base + 64))
    else
      (assert (between v1 0x80 0xBF);
       assert (utf8_cont_base <= v1);
       assert (v1 < utf8_cont_base + 64))

///////////////////////////////////////////////////////////////////////////////
// UTF-8 Prefix Length
///////////////////////////////////////////////////////////////////////////////

let utf8_prefix_len (b:UInt8.t) : option nat =
  let v0 = byte_val b in
  if v0 <= 0x7F then Some 1
  else if between v0 0xC2 0xDF then Some 2
  else if between v0 0xE0 0xEF then Some 3
  else if between v0 0xF0 0xF4 then Some 4
  else None

///////////////////////////////////////////////////////////////////////////////
// UTF-8 Scalar Decoding (pure, depends only on validation)
///////////////////////////////////////////////////////////////////////////////

let decode_utf8_scalar_nat (bs:list UInt8.t) : option nat =
  match bs with
  | [b0] ->
      let v0 = byte_val b0 in
      if v0 <= utf8_head_1_max then Some v0 else None
  | [b0; b1] ->
      if canonical_utf8_scalar bs then
        (lemma_canonical_two_byte_bounds b0 b1;
         let v0 = byte_val b0 in
         let v1 = byte_val b1 in
         let high = nat_sub v0 utf8_head_2 in
         let low = nat_sub v1 utf8_cont_base in
         lemma_nat_sub_bounds v0 utf8_head_2;
         lemma_nat_sub_bounds v1 utf8_cont_base;
         let cp = Prims.op_Multiply high 64 + low in
         Some #nat cp)
      else None
  | [b0; b1; b2] ->
      if canonical_utf8_scalar bs then
        (lemma_canonical_three_byte_bounds b0 b1 b2;
         let v0 = byte_val b0 in
         let v1 = byte_val b1 in
         let v2 = byte_val b2 in
         let high = nat_sub v0 utf8_head_3 in
         let mid = nat_sub v1 utf8_cont_base in
         let low = nat_sub v2 utf8_cont_base in
         lemma_nat_sub_bounds v0 utf8_head_3;
         lemma_nat_sub_bounds v1 utf8_cont_base;
         lemma_nat_sub_bounds v2 utf8_cont_base;
         let cp = Prims.op_Multiply high 4096
                  + Prims.op_Multiply mid 64
                  + low in
         Some #nat cp)
      else None
  | [b0; b1; b2; b3] ->
      if canonical_utf8_scalar bs then
        (lemma_canonical_four_byte_bounds b0 b1 b2 b3;
         let v0 = byte_val b0 in
         let v1 = byte_val b1 in
         let v2 = byte_val b2 in
         let v3 = byte_val b3 in
         let high = nat_sub v0 utf8_head_4 in
         let mid1 = nat_sub v1 utf8_cont_base in
         let mid2 = nat_sub v2 utf8_cont_base in
         let low = nat_sub v3 utf8_cont_base in
         lemma_nat_sub_bounds v0 utf8_head_4;
         lemma_nat_sub_bounds v1 utf8_cont_base;
         lemma_nat_sub_bounds v2 utf8_cont_base;
         lemma_nat_sub_bounds v3 utf8_cont_base;
         let cp = Prims.op_Multiply high 262144
                  + Prims.op_Multiply mid1 4096
                  + Prims.op_Multiply mid2 64
                  + low in
         Some #nat cp)
      else None
  | _ -> None

///////////////////////////////////////////////////////////////////////////////
// Decode Helper Lemmas
///////////////////////////////////////////////////////////////////////////////

let lemma_decode_utf8_scalar_one (b:UInt8.t)
  : Lemma
      (requires byte_val b <= utf8_head_1_max)
      (ensures decode_utf8_scalar_nat [b] = Some (byte_val b))
  =
    let v0 = byte_val b in
    assert (v0 <= utf8_head_1_max);
    ()

let lemma_decode_utf8_scalar_two (b0 b1:UInt8.t)
  : Lemma
      (requires canonical_utf8_scalar [b0; b1])
      (ensures
        decode_utf8_scalar_nat [b0; b1]
        = Some (Prims.op_Multiply (nat_sub (byte_val b0) utf8_head_2) 64
                + nat_sub (byte_val b1) utf8_cont_base))
  =
    lemma_canonical_two_byte_bounds b0 b1;
    let v0 = byte_val b0 in
    let v1 = byte_val b1 in
    lemma_nat_sub_bounds v0 utf8_head_2;
    lemma_nat_sub_bounds v1 utf8_cont_base;
    assert (decode_utf8_scalar_nat [b0; b1]
            = Some (Prims.op_Multiply (nat_sub v0 utf8_head_2) 64
                    + nat_sub v1 utf8_cont_base))

let lemma_decode_utf8_scalar_three (b0 b1 b2:UInt8.t)
  : Lemma
      (requires canonical_utf8_scalar [b0; b1; b2])
      (ensures
        decode_utf8_scalar_nat [b0; b1; b2]
        = Some (Prims.op_Multiply (nat_sub (byte_val b0) utf8_head_3) 4096
                + Prims.op_Multiply (nat_sub (byte_val b1) utf8_cont_base) 64
                + nat_sub (byte_val b2) utf8_cont_base))
  =
    lemma_canonical_three_byte_bounds b0 b1 b2;
    let v0 = byte_val b0 in
    let v1 = byte_val b1 in
    let v2 = byte_val b2 in
    lemma_nat_sub_bounds v0 utf8_head_3;
    lemma_nat_sub_bounds v1 utf8_cont_base;
    lemma_nat_sub_bounds v2 utf8_cont_base;
    assert (decode_utf8_scalar_nat [b0; b1; b2]
            = Some (Prims.op_Multiply (nat_sub v0 utf8_head_3) 4096
                    + Prims.op_Multiply (nat_sub v1 utf8_cont_base) 64
                    + nat_sub v2 utf8_cont_base))

let lemma_decode_utf8_scalar_four (b0 b1 b2 b3:UInt8.t)
  : Lemma
      (requires canonical_utf8_scalar [b0; b1; b2; b3])
      (ensures
        decode_utf8_scalar_nat [b0; b1; b2; b3]
        = Some (Prims.op_Multiply (nat_sub (byte_val b0) utf8_head_4) 262144
                + Prims.op_Multiply (nat_sub (byte_val b1) utf8_cont_base) 4096
                + Prims.op_Multiply (nat_sub (byte_val b2) utf8_cont_base) 64
                + nat_sub (byte_val b3) utf8_cont_base))
  =
    lemma_canonical_four_byte_bounds b0 b1 b2 b3;
    let v0 = byte_val b0 in
    let v1 = byte_val b1 in
    let v2 = byte_val b2 in
    let v3 = byte_val b3 in
    lemma_nat_sub_bounds v0 utf8_head_4;
    lemma_nat_sub_bounds v1 utf8_cont_base;
    lemma_nat_sub_bounds v2 utf8_cont_base;
    lemma_nat_sub_bounds v3 utf8_cont_base;
    assert (decode_utf8_scalar_nat [b0; b1; b2; b3]
            = Some (Prims.op_Multiply (nat_sub v0 utf8_head_4) 262144
                    + Prims.op_Multiply (nat_sub v1 utf8_cont_base) 4096
                    + Prims.op_Multiply (nat_sub v2 utf8_cont_base) 64
                    + nat_sub v3 utf8_cont_base))

///////////////////////////////////////////////////////////////////////////////
// Canonical Range Lemmas
///////////////////////////////////////////////////////////////////////////////

let lemma_canonical_two_byte_strict
  (b0 b1:UInt8.t)
  : Lemma
      (requires canonical_utf8_scalar [b0; b1])
      (ensures (
        let high = nat_sub (byte_val b0) utf8_head_2 in
        let low = nat_sub (byte_val b1) utf8_cont_base in
        2 <= high /\ high <= 31 /\ low < 64))
  =
    let v0 = byte_val b0 in
    let v1 = byte_val b1 in
    let high = nat_sub v0 utf8_head_2 in
    let low = nat_sub v1 utf8_cont_base in
    lemma_canonical_two_byte_bounds b0 b1;
    lemma_nat_sub_bounds v0 utf8_head_2;
    lemma_nat_sub_bounds v1 utf8_cont_base;
    assert (utf8_head_2 + high = v0);
    assert (utf8_cont_base + low = v1);
    (if canonical_utf8_scalar [b0; b1]
     then assert (between v0 0xC2 0xDF)
     else ());
    assert (between v0 0xC2 0xDF);
    assert (between v1 0x80 0xBF);
    assert (2 <= high);
    assert (high <= 31);
    assert (low < 64)

let lemma_canonical_three_byte_ranges
  (b0 b1 b2:UInt8.t)
  : Lemma
      (requires canonical_utf8_scalar [b0; b1; b2])
      (ensures (
        let v0 = byte_val b0 in
        let v1 = byte_val b1 in
        let high = nat_sub v0 utf8_head_3 in
        let mid = nat_sub v1 utf8_cont_base in
        0 <= high /\ high <= 15 /\
        mid < 64 /\
        (v0 = utf8_head_3 ==> 32 <= mid) /\
        (v0 = 0xED ==> mid <= 31)))
  =
    let v0 = byte_val b0 in
    let v1 = byte_val b1 in
    let high = nat_sub v0 utf8_head_3 in
    let mid = nat_sub v1 utf8_cont_base in
    lemma_canonical_three_byte_bounds b0 b1 b2;
    lemma_nat_sub_bounds v0 utf8_head_3;
    lemma_nat_sub_bounds v1 utf8_cont_base;
    assert (utf8_head_3 + high = v0);
    assert (utf8_cont_base + mid = v1);
    (if canonical_utf8_scalar [b0; b1; b2]
     then assert (between v0 0xE0 0xEF)
     else ());
    assert (between v0 0xE0 0xEF);
    assert (mid < 64);
    assert (high <= 15);
    if v0 = utf8_head_3 then
      (if canonical_utf8_scalar [b0; b1; b2]
       then assert (between v1 0xA0 0xBF)
       else ();
       assert (between v1 0xA0 0xBF);
       assert (mid >= 32))
    else ();
    if v0 = 0xED then
      (if canonical_utf8_scalar [b0; b1; b2]
       then assert (between v1 0x80 0x9F)
       else ();
       assert (between v1 0x80 0x9F);
       assert (mid <= 31))
    else ()

let lemma_canonical_four_byte_ranges
  (b0 b1 b2 b3:UInt8.t)
  : Lemma
      (requires canonical_utf8_scalar [b0; b1; b2; b3])
      (ensures (
        let high = nat_sub (byte_val b0) utf8_head_4 in
        let mid1 = nat_sub (byte_val b1) utf8_cont_base in
        let mid2 = nat_sub (byte_val b2) utf8_cont_base in
        let low = nat_sub (byte_val b3) utf8_cont_base in
        high < 5 /\ mid1 < 64 /\ mid2 < 64 /\ low < 64))
  =
    let v0 = byte_val b0 in
    let v1 = byte_val b1 in
    let v2 = byte_val b2 in
    let v3 = byte_val b3 in
    let high = nat_sub v0 utf8_head_4 in
    let mid1 = nat_sub v1 utf8_cont_base in
    let mid2 = nat_sub v2 utf8_cont_base in
    let low = nat_sub v3 utf8_cont_base in
    lemma_canonical_four_byte_bounds b0 b1 b2 b3;
    lemma_nat_sub_bounds v0 utf8_head_4;
    lemma_nat_sub_bounds v1 utf8_cont_base;
    lemma_nat_sub_bounds v2 utf8_cont_base;
    lemma_nat_sub_bounds v3 utf8_cont_base;
    assert (utf8_head_4 + high = v0);
    assert (utf8_cont_base + mid1 = v1);
    assert (utf8_cont_base + mid2 = v2);
    assert (utf8_cont_base + low = v3);
    assert (high < 5);
    assert (mid1 < 64);
    assert (mid2 < 64);
    assert (low < 64)

///////////////////////////////////////////////////////////////////////////////
// Scalar Bounds Lemmas
///////////////////////////////////////////////////////////////////////////////

let lemma_two_byte_scalar_bounds
  (b0 b1:UInt8.t)
  : Lemma
      (requires canonical_utf8_scalar [b0; b1])
      (ensures (
        let v0 = byte_val b0 in
        let v1 = byte_val b1 in
        let high = nat_sub v0 utf8_head_2 in
        let low = nat_sub v1 utf8_cont_base in
        let cp = Prims.op_Multiply high 64 + low in
        0x80 <= cp /\ cp <= 0x7FF))
  =
    lemma_canonical_two_byte_bounds b0 b1;
    let v0 = byte_val b0 in
    let v1 = byte_val b1 in
    let high = nat_sub v0 utf8_head_2 in
    let low = nat_sub v1 utf8_cont_base in
    let cp = Prims.op_Multiply high 64 + low in
    lemma_nat_sub_bounds v0 utf8_head_2;
    lemma_nat_sub_bounds v1 utf8_cont_base;
    assert (utf8_head_2 + high = v0);
    assert (between v0 0xC2 0xDF);
    assert (0xC2 <= v0);
    assert (v0 <= 0xDF);
    assert (utf8_head_2 = 0xC0);
    assert (2 <= high);
    assert (high <= 31);
    assert (utf8_cont_base + low = v1);
    assert (low < 64);
    assert (cp >= Prims.op_Multiply 2 64);
    assert_norm (Prims.op_Multiply 2 64 = 0x80);
    assert (cp >= 0x80);
    assert (cp <= Prims.op_Multiply 31 64 + 63);
    assert_norm (Prims.op_Multiply 31 64 + 63 = 0x7FF);
    assert (cp <= 0x7FF)

let lemma_three_byte_scalar_bounds
  (b0 b1 b2:UInt8.t)
  : Lemma
      (requires canonical_utf8_scalar [b0; b1; b2])
      (ensures (
        let v0 = byte_val b0 in
        let v1 = byte_val b1 in
        let v2 = byte_val b2 in
        let high = nat_sub v0 utf8_head_3 in
        let mid = nat_sub v1 utf8_cont_base in
        let low = nat_sub v2 utf8_cont_base in
        let cp =
          Prims.op_Multiply high 4096
          + Prims.op_Multiply mid 64
          + low in
        0x800 <= cp /\ cp <= 0xFFFF /\
        (v0 < 0xED ==> cp < 0xD800) /\
        (v0 = 0xED ==> cp <= 0xD7FE) /\
        (v0 >= 0xEE ==> cp > 0xDFFF)))
  =
    lemma_canonical_three_byte_bounds b0 b1 b2;
    lemma_canonical_three_byte_ranges b0 b1 b2;
    let v0 = byte_val b0 in
    let v1 = byte_val b1 in
    let v2 = byte_val b2 in
    let high = nat_sub v0 utf8_head_3 in
    let mid = nat_sub v1 utf8_cont_base in
    let low = nat_sub v2 utf8_cont_base in
    let cp =
      Prims.op_Multiply high 4096
      + Prims.op_Multiply mid 64
      + low in
    if v0 = utf8_head_3 then (
      assert (high = 0);
      assert (mid >= 32);
      assert (low < 64);
      assert (cp >= Prims.op_Multiply 32 64);
      assert (Prims.op_Multiply 32 64 = 0x800);
      assert (cp < 0xD800)
    ) else (
      assert (high >= 1);
      ()
    );
    assert (cp >= 0x800);
    assert (Prims.op_Multiply high 4096 <= Prims.op_Multiply 15 4096);
    assert (Prims.op_Multiply mid 64 <= Prims.op_Multiply 63 64);
    assert (low < 64);
    assert (cp <= Prims.op_Multiply 15 4096
                  + Prims.op_Multiply 63 64
                  + 63);
    assert (Prims.op_Multiply 15 4096
            + Prims.op_Multiply 63 64
            + 63 = 0xFFFF);
    assert (cp <= 0xFFFF);
    if v0 = 0xED then (
      assert (high = 13);
      assert (mid <= 31);
      assert (cp <= Prims.op_Multiply 13 4096
                    + Prims.op_Multiply 31 64
                    + 63);
      assert (Prims.op_Multiply 13 4096
              + Prims.op_Multiply 31 64
              + 63 = 0xD7FF);
      if v1 = 0x9F then (
        assert (byte_val b2 <= 0xBE);
        assert (utf8_cont_base + low = v2);
        assert (utf8_cont_base + 62 = 0xBE);
        assert (v2 <= utf8_cont_base + 62);
        assert (low <= 62);
        assert (cp <= Prims.op_Multiply 13 4096
                      + Prims.op_Multiply 31 64
                      + 62);
        assert (Prims.op_Multiply 13 4096
                + Prims.op_Multiply 31 64
                + 62 = 0xD7FE);
        assert (cp <= 0xD7FE)
      ) else (
        assert (mid <= 30);
        assert (cp <= Prims.op_Multiply 13 4096
                      + Prims.op_Multiply 30 64
                      + 63);
        assert (Prims.op_Multiply 13 4096
                + Prims.op_Multiply 30 64
                + 63 = 0xD7BF);
        assert (cp <= 0xD7BF);
        assert (cp <= 0xD7FE)
      );
      assert (cp < 0xD800)
    ) else if v0 >= 0xEE then (
      assert (high >= 14);
      assert (cp >= Prims.op_Multiply 14 4096);
      assert (Prims.op_Multiply 14 4096 = 0xE000);
      assert (cp > 0xDFFF)
    ) else (
      assert (high <= 12);
      assert (cp <= Prims.op_Multiply 12 4096
                    + Prims.op_Multiply 63 64
                    + 63);
      assert (Prims.op_Multiply 12 4096
              + Prims.op_Multiply 63 64
              + 63 = 0xCFFF);
      assert (cp <= 0xCFFF);
      assert (cp < 0xD800)
    );
    ()

let lemma_three_byte_mid_low_bounds
  (b0 b1 b2:UInt8.t)
  : Lemma
      (requires canonical_utf8_scalar [b0; b1; b2])
      (ensures (
        let v0 = byte_val b0 in
        let v1 = byte_val b1 in
        let v2 = byte_val b2 in
        let mid = nat_sub v1 utf8_cont_base in
        let low = nat_sub v2 utf8_cont_base in
        (v0 = 0xE0 ==> mid >= 32) /\
        (v0 = 0xED ==> mid <= 31) /\
        (v0 = 0xED /\ v1 <> 0x9F ==> mid <= 30) /\
        (v0 = 0xED /\ v1 = 0x9F ==> low <= 62) /\
        mid < 64 /\ low < 64))
  =
    lemma_canonical_three_byte_ranges b0 b1 b2;
    let v0 = byte_val b0 in
    let v1 = byte_val b1 in
    let v2 = byte_val b2 in
    let mid = nat_sub v1 utf8_cont_base in
    let low = nat_sub v2 utf8_cont_base in
    lemma_nat_sub_bounds v1 utf8_cont_base;
    lemma_nat_sub_bounds v2 utf8_cont_base;
    assert (utf8_cont_base + mid = v1);
    assert (utf8_cont_base + low = v2);
    assert (utf8_cont_base = 0x80);
    if v0 = 0xE0 then (
      assert (v1 >= 0xA0);
      assert (0xA0 = 0x80 + 32);
      assert (v1 >= utf8_cont_base + 32);
      assert (mid >= 32)
    ) else ();
    if v0 = 0xED then (
      assert (v1 <= 0x9F);
      assert (0x9F = 0x80 + 31);
      assert (v1 <= utf8_cont_base + 31);
      assert (mid <= 31);
      if v1 <> 0x9F then (
        assert (v1 < 0x9F);
        assert (v1 <= 0x9E);
        assert (0x9E = 0x80 + 30);
        assert (v1 <= utf8_cont_base + 30);
        assert (mid <= 30)
      ) else ();
      if v1 = 0x9F then (
        assert (v2 <= 0xBE);
        assert (0xBE = 0x80 + 62);
        assert (v2 <= utf8_cont_base + 62);
        assert (low <= 62)
      ) else ()
    ) else ();
    assert (v1 < utf8_cont_base + 64);
    assert (v2 < utf8_cont_base + 64);
    assert (mid < 64);
    assert (low < 64)

let lemma_four_byte_scalar_bounds
  (b0 b1 b2 b3:UInt8.t)
  : Lemma
      (requires canonical_utf8_scalar [b0; b1; b2; b3])
      (ensures (
        let v0 = byte_val b0 in
        let v1 = byte_val b1 in
        let v2 = byte_val b2 in
        let v3 = byte_val b3 in
        let high = nat_sub v0 utf8_head_4 in
        let mid1 = nat_sub v1 utf8_cont_base in
        let mid2 = nat_sub v2 utf8_cont_base in
        let low = nat_sub v3 utf8_cont_base in
        let cp =
          Prims.op_Multiply high 262144
          + Prims.op_Multiply mid1 4096
          + Prims.op_Multiply mid2 64
          + low in
        0x10000 <= cp /\ cp <= 0x10FFFF))
  =
    lemma_canonical_four_byte_bounds b0 b1 b2 b3;
    lemma_canonical_four_byte_ranges b0 b1 b2 b3;
    let v0 = byte_val b0 in
    let v1 = byte_val b1 in
    let v2 = byte_val b2 in
    let v3 = byte_val b3 in
    let high = nat_sub v0 utf8_head_4 in
    let mid1 = nat_sub v1 utf8_cont_base in
    let mid2 = nat_sub v2 utf8_cont_base in
    let low = nat_sub v3 utf8_cont_base in
    let cp =
      Prims.op_Multiply high 262144
      + Prims.op_Multiply mid1 4096
      + Prims.op_Multiply mid2 64
      + low in
    lemma_nat_sub_bounds v0 utf8_head_4;
    lemma_nat_sub_bounds v1 utf8_cont_base;
    lemma_nat_sub_bounds v2 utf8_cont_base;
    lemma_nat_sub_bounds v3 utf8_cont_base;
    assert (utf8_head_4 + high = v0);
    assert (utf8_cont_base + mid1 = v1);
    assert (utf8_cont_base + mid2 = v2);
    assert (utf8_cont_base + low = v3);
    assert (canonical_utf8_scalar [b0; b1; b2; b3]);
    if v0 = utf8_head_4 then (
      assert (high = 0);
      assert (mid1 >= 16);
      assert (mid2 < 64);
      assert (low < 64);
      assert (cp >= Prims.op_Multiply 16 4096);
      assert_norm (Prims.op_Multiply 16 4096 = 0x10000);
      assert (cp >= 0x10000)
    ) else (
      assert (high >= 1);
      assert (cp >= Prims.op_Multiply high 262144);
      assert (Prims.op_Multiply high 262144 >= Prims.op_Multiply 1 262144);
      assert_norm (Prims.op_Multiply 1 262144 = 0x40000);
      assert (cp >= 0x40000);
      assert (cp >= 0x10000)
    );
    if v0 = 0xF4 then (
      assert (high = 4);
      assert (between v1 0x80 0x8F);
      assert (mid1 <= 15);
      assert (mid2 < 64);
      assert (low < 64);
      assert (cp <= Prims.op_Multiply 4 262144
                    + Prims.op_Multiply 15 4096
                    + Prims.op_Multiply 63 64
                    + 63);
      assert_norm (Prims.op_Multiply 4 262144
                   + Prims.op_Multiply 15 4096
                   + Prims.op_Multiply 63 64
                   + 63 = 0x10FFFF);
      assert (cp <= 0x10FFFF)
    ) else (
      assert (v0 <= 0xF3);
      assert (high <= 3);
      assert (mid1 < 64);
      assert (mid2 < 64);
      assert (low < 64);
      assert (cp <= Prims.op_Multiply 3 262144
                    + Prims.op_Multiply 63 4096
                    + Prims.op_Multiply 63 64
                    + 63);
      assert_norm (Prims.op_Multiply 3 262144
                   + Prims.op_Multiply 63 4096
                   + Prims.op_Multiply 63 64
                   + 63 = 0x0FFFFF);
      assert (0x0FFFFF <= 0x10FFFF);
      assert (cp <= 0x10FFFF)
    )
