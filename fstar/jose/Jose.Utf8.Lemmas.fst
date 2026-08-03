module Jose.Utf8.Lemmas

/// Cross-cutting lemmas that depend on both Validity and Encoding.
/// Includes: decode functions, roundtrip lemmas, string helper lemmas,
/// and encoding validity lemmas.

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
open Jose.Utf8.Validity
open Jose.Utf8.Encoding

module U32 = FStar.UInt32
module Str = FStar.String

///////////////////////////////////////////////////////////////////////////////
// Encoding and Decoding Functions
///////////////////////////////////////////////////////////////////////////////

let rec decode_utf8_chars
  (bs:list UInt8.t)
  : Tot (decode_result (list char))
  (decreases (List.length bs))
  =
    match bs with
    | [] -> Ok []
    | b0::rest ->
        (match utf8_prefix_len b0 with
         | None -> Error InvalidValueUtf8
         | Some 1 ->
             if canonical_utf8_scalar [b0] then (
               let v0 = byte_val b0 in
               assert (v0 <= utf8_head_1_max);
               let _ = lemma_decode_utf8_scalar_one b0 in
              assert (is_valid_scalar v0);
               assert (v0 <= 0x10FFFF);
               assert (v0 < 0xD800 \/ v0 > 0xDFFF);
               assert (v0 < 0xD7FF);
               let _ = lemma_tail_length_one b0 rest in
               let u = U32.uint_to_t v0 in
               assert (U32.v u = v0);
               assert (U32.v u < 0xD7FF);
               assert (U32.v u <= 0x10FFFF);
               let ch = FStar.Char.char_of_u32 u in
               match decode_utf8_chars rest with
               | Ok chars -> Ok (ch :: chars)
               | Error e -> Error e
             ) else Error InvalidValueUtf8
         | Some 2 ->
             (match rest with
              | b1::rest1 ->
                  let chunk = [b0; b1] in
                  if canonical_utf8_scalar chunk then (
                    let _ = lemma_canonical_two_byte_bounds b0 b1 in
                    let _ = lemma_canonical_two_byte_strict b0 b1 in
                    let _ = lemma_decode_utf8_scalar_two b0 b1 in
                    let high = nat_sub (byte_val b0) utf8_head_2 in
                    let low = nat_sub (byte_val b1) utf8_cont_base in
                    let cp = Prims.op_Multiply high 64 + low in
                    assert (is_valid_scalar cp);
                    assert (cp <= 0x10FFFF);
                    assert (cp < 0xD800 \/ cp > 0xDFFF);
                    assert (cp < 0xD7FF);
                    let _ = lemma_tail_length_two b0 b1 rest1 in
                    let u = U32.uint_to_t cp in
                    assert (U32.v u = cp);
                    assert (U32.v u < 0xD7FF);
                    assert (U32.v u <= 0x10FFFF);
                    let ch = FStar.Char.char_of_u32 u in
                    match decode_utf8_chars rest1 with
                    | Ok chars -> Ok (ch :: chars)
                    | Error e -> Error e
                  ) else Error InvalidValueUtf8
              | _ -> Error InvalidValueUtf8)
         | Some 3 ->
             (match rest with
              | b1::b2::rest2 ->
                  let chunk = [b0; b1; b2] in
                  if canonical_utf8_scalar chunk then (
                    let _ = lemma_canonical_three_byte_bounds b0 b1 b2 in
                    let _ = lemma_canonical_three_byte_ranges b0 b1 b2 in
                    let _ = lemma_decode_utf8_scalar_three b0 b1 b2 in
                    let v0 = byte_val b0 in
                    let high = nat_sub v0 utf8_head_3 in
                    let mid = nat_sub (byte_val b1) utf8_cont_base in
                    let low = nat_sub (byte_val b2) utf8_cont_base in
                    let cp =
                      Prims.op_Multiply high 4096
                      + Prims.op_Multiply mid 64
                      + low in
                    assert (is_valid_scalar cp);
                    assert (cp <= 0x10FFFF);
                    assert (cp < 0xD800 \/ cp > 0xDFFF);
                    let _ = lemma_tail_length_three b0 b1 b2 rest2 in
                    let u = U32.uint_to_t cp in
                    assert (U32.v u = cp);
                    assert (U32.v u <= 0x10FFFF);
                    if v0 = 0xED then assert (cp <= 0xD7FE) else ();
                    if v0 < 0xED then assert (cp <= 0xCFFF) else ();
                    if v0 >= 0xEE then assert (cp > 0xDFFF) else ();
                    let ch =
                      if v0 >= 0xEE then (
                        assert (cp > 0xDFFF);
                        assert (cp >= 0xE000);
                        assert (U32.v u >= 0xE000);
                        FStar.Char.char_of_u32 u
                      ) else (
                        assert (cp <= 0xD7FE);
                        assert (cp < 0xD7FF);
                        assert (U32.v u < 0xD7FF);
                        FStar.Char.char_of_u32 u
                      ) in
                    match decode_utf8_chars rest2 with
                    | Ok chars -> Ok (ch :: chars)
                    | Error e -> Error e
                  ) else Error InvalidValueUtf8
              | _ -> Error InvalidValueUtf8)
         | Some 4 ->
             (match rest with
              | b1::b2::b3::rest3 ->
                  let chunk = [b0; b1; b2; b3] in
                  if canonical_utf8_scalar chunk then (
                    let _ = lemma_canonical_four_byte_bounds b0 b1 b2 b3 in
                    let _ = lemma_canonical_four_byte_ranges b0 b1 b2 b3 in
                    let _ = lemma_decode_utf8_scalar_four b0 b1 b2 b3 in
                    let high = nat_sub (byte_val b0) utf8_head_4 in
                    let mid1 = nat_sub (byte_val b1) utf8_cont_base in
                    let mid2 = nat_sub (byte_val b2) utf8_cont_base in
                    let low = nat_sub (byte_val b3) utf8_cont_base in
                    let cp =
                      Prims.op_Multiply high 262144
                      + Prims.op_Multiply mid1 4096
                      + Prims.op_Multiply mid2 64
                      + low in
                    assert (is_valid_scalar cp);
                    assert (cp <= 0x10FFFF);
                    assert (cp < 0xD800 \/ cp > 0xDFFF);
                    assert (cp >= 0xE000);
                    let _ = lemma_tail_length_four b0 b1 b2 b3 rest3 in
                    let u = U32.uint_to_t cp in
                    assert (U32.v u = cp);
                    assert (U32.v u >= 0xE000);
                    assert (U32.v u <= 0x10FFFF);
                    let ch = FStar.Char.char_of_u32 u in
                    match decode_utf8_chars rest3 with
                    | Ok chars -> Ok (ch :: chars)
                    | Error e -> Error e
                  ) else Error InvalidValueUtf8
              | _ -> Error InvalidValueUtf8))

let decode_utf8_bytes
  (bs:list UInt8.t)
  : decode_result string
  =
    if not (valid_utf8_bytes bs) then
      Error InvalidValueUtf8
    else
      match decode_utf8_chars bs with
      | Ok chars ->
          let s = Str.string_of_list chars in
          Ok s
      | Error e -> Error e

let decode_utf8
  (bs:list UInt8.t)
  : Pure (decode_result string)
       (requires True)
       (ensures fun r ->
         // decode_utf8 is consistent with decode_utf8_bytes
         r = decode_utf8_bytes bs)
  =
    // Use decode_utf8_bytes as the implementation
    decode_utf8_bytes bs

///////////////////////////////////////////////////////////////////////////////
// Helper Lemmas for String Operations
///////////////////////////////////////////////////////////////////////////////

// String operations proved via FStar.String.list_of_string_of_list
val lemma_list_of_string_empty
  : unit -> Lemma (ensures Str.list_of_string "" = [])
let lemma_list_of_string_empty () =
  FStar.String.list_of_string_of_list []

val lemma_list_of_string_char
  : c:char -> Lemma (ensures Str.list_of_string (str c) = [c])
let lemma_list_of_string_char c =
  FStar.String.list_of_string_of_list [c]

let lemma_list_of_string_concat
  (s1:string)
  (s2:string)
  : Lemma
      (ensures Str.list_of_string (strcat s1 s2) =
               Str.list_of_string s1 @ Str.list_of_string s2)
  =
    Str.list_of_concat s1 s2

let lemma_list_of_string_string_of_list
  (cs:list char)
  : Lemma (ensures Str.list_of_string (Str.string_of_list cs) = cs)
  = FStar.String.list_of_string_of_list cs

///////////////////////////////////////////////////////////////////////////////
// Roundtrip Lemmas
///////////////////////////////////////////////////////////////////////////////

let lemma_decode_utf8_scalar_two_roundtrip (b0 b1:UInt8.t)
  : Lemma
      (requires canonical_utf8_scalar [b0; b1])
      (ensures (
        let v0 = byte_val b0 in
        let v1 = byte_val b1 in
        let high = nat_sub v0 utf8_head_2 in
        let low = nat_sub v1 utf8_cont_base in
        let cp = Prims.op_Multiply high 64 + low in
        is_valid_scalar cp /\ encode_utf8_codepoint cp = [b0; b1]))
  =
    lemma_canonical_two_byte_bounds b0 b1;
    lemma_canonical_two_byte_strict b0 b1;
    let v0 = byte_val b0 in
    let v1 = byte_val b1 in
    let high = nat_sub v0 utf8_head_2 in
    let low = nat_sub v1 utf8_cont_base in
    let cp = Prims.op_Multiply high 64 + low in
    assert (2 <= high);
    assert (high <= 31);
    assert (low < 64);
    assert (cp >= 0x80);
    assert (cp <= 0x7FF);
    assert (cp < 0xD800);
    assert (cp <= 0x10FFFF);
    assert (is_valid_scalar cp);
    lemma_nat_sub_bounds v0 utf8_head_2;
    lemma_nat_sub_bounds v1 utf8_cont_base;
    let _ = lemma_div_mod cp 64 in
    let _ = lemma_mod_lt cp 64 in
    assert (cp / 64 = high);
    assert (cp % 64 = low);
    assert (utf8_head_2 + high = v0);
    assert (utf8_cont_base + low = v1);
    lemma_mk_u8_roundtrip b0;
    lemma_mk_u8_roundtrip b1;
    let encoded = encode_utf8_codepoint cp in
    assert (encoded =
            [ mk_u8 (utf8_head_2 + cp / 64);
              mk_u8 (utf8_cont_base + cp % 64) ]);
    assert (mk_u8 (utf8_head_2 + cp / 64) = mk_u8 v0);
    assert (mk_u8 (utf8_cont_base + cp % 64) = mk_u8 v1);
    assert (mk_u8 v0 = b0);
    assert (mk_u8 v1 = b1);
    assert (encode_utf8_codepoint cp = [b0; b1])

let lemma_decode_utf8_scalar_three_roundtrip (b0 b1 b2:UInt8.t)
  : Lemma
      (requires canonical_utf8_scalar [b0; b1; b2])
      (ensures (
        let v0 = byte_val b0 in
        let v1 = byte_val b1 in
        let v2 = byte_val b2 in
        let high = nat_sub v0 utf8_head_3 in
        let mid = nat_sub v1 utf8_cont_base in
        let low = nat_sub v2 utf8_cont_base in
        let cp = Prims.op_Multiply high 4096
                 + Prims.op_Multiply mid 64
                 + low in
        is_valid_scalar cp /\
        encode_utf8_codepoint cp = [b0; b1; b2] /\
        decode_utf8_scalar_nat [b0; b1; b2] = Some cp))
  =
    lemma_decode_utf8_scalar_three b0 b1 b2;
    lemma_three_byte_scalar_bounds b0 b1 b2;
    lemma_canonical_three_byte_bounds b0 b1 b2;
    lemma_canonical_three_byte_ranges b0 b1 b2;
    lemma_three_byte_mid_low_bounds b0 b1 b2;
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
    lemma_nat_sub_bounds v0 utf8_head_3;
    lemma_nat_sub_bounds v1 utf8_cont_base;
    lemma_nat_sub_bounds v2 utf8_cont_base;
    assert (utf8_head_3 + high = v0);
    assert (utf8_cont_base + mid = v1);
    assert (utf8_cont_base + low = v2);
    if v0 = utf8_head_3 then (
      assert (high = 0);
      assert (mid >= 32);
      assert (cp >= Prims.op_Multiply mid 64);
      assert (Prims.op_Multiply mid 64 >= Prims.op_Multiply 32 64);
      assert (Prims.op_Multiply 32 64 = 0x800);
      assert (cp >= 0x800)
    ) else ();
    if 0xE1 <= v0 && v0 <= 0xEC then (
      assert (high >= 1);
      assert (high <= 12);
      assert (cp <= Prims.op_Multiply 12 4096
                    + Prims.op_Multiply 63 64
                    + 63);
      assert (Prims.op_Multiply 12 4096
              + Prims.op_Multiply 63 64
              + 63 = 0xCFFF);
      assert (cp <= 0xCFFF);
      assert (cp < 0xD800)
    ) else ();
    if v0 = 0xED then (
      assert (high = 13);
      assert (mid <= 31);
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
    ) else ();
    if v0 >= 0xEE then (
      assert (high >= 14);
      assert (cp >= Prims.op_Multiply 14 4096);
      assert (Prims.op_Multiply 14 4096 = 0xE000);
      assert (cp >= 0xE000);
      assert (cp > 0xDFFF)
    ) else ();
    assert (mid < 64);
    assert (low < 64);
    assert (cp >= 0x800);
    assert (cp <= 0xFFFF);
    if v0 = 0xED then
      assert (cp < 0xD800)
    else if v0 >= 0xEE then
      assert (cp > 0xDFFF)
    else
      assert (cp < 0xD800);
    assert (cp <= 0x10FFFF);
    assert (is_valid_scalar cp);
    let _ = lemma_div_mod cp 64 in
    let _ = lemma_mod_lt cp 64 in
    let _ = lemma_div_mod (cp / 64) 64 in
    let _ = lemma_mod_lt (cp / 64) 64 in
    let _ = lemma_div_mod cp 4096 in
    let _ = lemma_mod_lt cp 4096 in
    assert (cp / 4096 = high);
    assert (((cp / 64) % 64) = mid);
    assert (cp % 64 = low);
    assert (0x800 <= cp);
    assert (cp <= 0xFFFF);
    if v0 = 0xED then assert (cp <= 0xD7FE) else ();
    if v0 < 0xED then assert (cp < 0xD800) else ();
    if v0 >= 0xEE then assert (cp > 0xDFFF) else ();
    assert (cp <= 0x10FFFF);
    if v0 >= 0xEE then (
      assert (cp > 0xDFFF);
      assert (is_valid_scalar cp)
    ) else (
      assert (cp < 0xD800);
      assert (is_valid_scalar cp)
    );
    lemma_mk_u8_roundtrip b0;
    lemma_mk_u8_roundtrip b1;
    lemma_mk_u8_roundtrip b2;
    let encoded = encode_utf8_codepoint cp in
    assert (encoded =
            [ mk_u8 (utf8_head_3 + cp / 4096);
              mk_u8 (utf8_cont_base + (cp / 64) % 64);
              mk_u8 (utf8_cont_base + cp % 64) ]);
    assert (mk_u8 (utf8_head_3 + cp / 4096) = mk_u8 v0);
    assert (mk_u8 (utf8_cont_base + (cp / 64) % 64) = mk_u8 v1);
    assert (mk_u8 (utf8_cont_base + cp % 64) = mk_u8 v2);
    assert (encode_utf8_codepoint cp = [b0; b1; b2]);
    // Prove that decode_utf8_scalar_nat returns Some cp
    assert (decode_utf8_scalar_nat [b0; b1; b2] = Some cp);
    ()

let lemma_decode_utf8_scalar_four_roundtrip (b0 b1 b2 b3:UInt8.t)
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
        let cp = Prims.op_Multiply high 262144
                 + Prims.op_Multiply mid1 4096
                 + Prims.op_Multiply mid2 64
                 + low in
        is_valid_scalar cp /\
        encode_utf8_codepoint cp = [b0; b1; b2; b3] /\
        decode_utf8_scalar_nat [b0; b1; b2; b3] = Some cp))
  =
    lemma_decode_utf8_scalar_four b0 b1 b2 b3;
    lemma_canonical_four_byte_bounds b0 b1 b2 b3;
    lemma_canonical_four_byte_ranges b0 b1 b2 b3;
    lemma_four_byte_scalar_bounds b0 b1 b2 b3;
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
    assert (0x10000 <= cp);
    assert (cp <= 0x10FFFF);
    assert (is_valid_scalar cp);
    lemma_utf8_four_byte_components high mid1 mid2 low;
    lemma_mk_u8_roundtrip b0;
    lemma_mk_u8_roundtrip b1;
    lemma_mk_u8_roundtrip b2;
    lemma_mk_u8_roundtrip b3;
    let encoded = encode_utf8_codepoint cp in
    assert (encoded =
            [ mk_u8 (utf8_head_4 + cp / 262144);
              mk_u8 (utf8_cont_base + (cp / 4096) % 64);
              mk_u8 (utf8_cont_base + (cp / 64) % 64);
              mk_u8 (utf8_cont_base + cp % 64) ]);
    assert (mk_u8 (utf8_head_4 + cp / 262144) = mk_u8 v0);
    assert (mk_u8 (utf8_cont_base + (cp / 4096) % 64) = mk_u8 v1);
    assert (mk_u8 (utf8_cont_base + (cp / 64) % 64) = mk_u8 v2);
    assert (mk_u8 (utf8_cont_base + cp % 64) = mk_u8 v3);
    assert (encode_utf8_codepoint cp = [b0; b1; b2; b3]);
    // Prove that decode_utf8_scalar_nat returns Some cp
    assert (decode_utf8_scalar_nat [b0; b1; b2; b3] = Some cp);
    ()

///////////////////////////////////////////////////////////////////////////////
// Helper Lemmas for decode_utf8_bytes_roundtrip
///////////////////////////////////////////////////////////////////////////////

// If s equals string_of_list chars, then list_of_string s equals chars
let lemma_string_of_list_list_of_string_eq (chars:list char) (s:string)
  : Lemma (requires s = Str.string_of_list chars)
          (ensures FStar.String.list_of_string s = chars)
  = lemma_list_of_string_string_of_list chars

// Congruence lemma for encode_utf8_bytes_aux: equal inputs give equal outputs
// This should be automatic by function extensionality
let lemma_encode_aux_congruence (cs1 cs2:list char)
  : Lemma (requires cs1 = cs2)
          (ensures encode_utf8_bytes_aux cs1 = encode_utf8_bytes_aux cs2)
  =
    ()  // If cs1 = cs2, then f(cs1) = f(cs2) for any function f

///////////////////////////////////////////////////////////////////////////////
// Final Roundtrip Lemmas
///////////////////////////////////////////////////////////////////////////////

let rec lemma_decode_utf8_chars_roundtrip
  (bs:list UInt8.t)
  : Lemma
      (ensures (match decode_utf8_chars bs with
                | Ok cs -> encode_utf8_bytes_aux cs = bs
                | Error _ -> True))
  (decreases List.length bs)
  =
    match bs with
    | [] ->
        ()
    | b0::rest ->
        let res = decode_utf8_chars (b0 :: rest) in
        match res with
        | Error _ -> ()
        | Ok chars ->
            (match utf8_prefix_len b0 with
             | None ->
                 let _ =
                   calc (==) {
                     res;
                     == {}
                     Error InvalidValueUtf8;
                   } in
                 assert False
             | Some 1 ->
                 if not (canonical_utf8_scalar [b0]) then (
                   let _ =
                     calc (==) {
                       res;
                       == {}
                       Error InvalidValueUtf8;
                     } in
                   assert False
                 ) else (
                   let tail_len = lemma_tail_length_one b0 rest in
                   let ih = lemma_decode_utf8_chars_roundtrip rest in
                   let tail_res = decode_utf8_chars rest in
                   match tail_res with
                   | Error e_tail ->
                       let _ =
                         calc (==) {
                           res;
                           == {}
                           (match decode_utf8_chars rest with
                            | Ok chars' -> Ok (FStar.Char.char_of_int (byte_val b0) :: chars')
                            | Error e' -> Error e');
                           == {}
                           Error e_tail;
                         } in
                       assert False
                   | Ok tail ->
                       let ch = FStar.Char.char_of_int (byte_val b0) in
                       let _ =
                         calc (==) {
                           Ok chars;
                           == {}
                           res;
                           == {}
                           Ok (ch :: tail);
                         } in
                       assert (chars = ch :: tail);
                       calc (==) {
                         encode_utf8_bytes_aux chars;
                         == {}
                         encode_utf8_bytes_aux (ch :: tail);
                         == {}
                         List.append [b0] rest;
                         == { lemma_append_singleton b0 rest }
                         b0 :: rest;
                       };
                       ()
                 )
             | Some 2 ->
                 (match rest with
                  | b1::rest1 ->
                      if not (canonical_utf8_scalar [b0; b1]) then (
                        let _ =
                          calc (==) {
                            res;
                            == {}
                            Error InvalidValueUtf8;
                          } in
                        assert False
                      ) else (
                        let tail_len = lemma_tail_length_two b0 b1 rest1 in
                        let ih = lemma_decode_utf8_chars_roundtrip rest1 in
                        let tail_res = decode_utf8_chars rest1 in
                        match tail_res with
                        | Error e_tail ->
                            let _ =
                              calc (==) {
                                res;
                                == {}
                                (match decode_utf8_chars rest1 with
                                 | Ok chars' -> Ok (FStar.Char.char_of_int
                                        (Prims.op_Multiply (nat_sub (byte_val b0) utf8_head_2) 64
                                         + nat_sub (byte_val b1) utf8_cont_base) :: chars')
                                 | Error e' -> Error e');
                                == {}
                                Error e_tail;
                              } in
                            assert False
                        | Ok tail ->
                            let ch = FStar.Char.char_of_int
                                       (Prims.op_Multiply (nat_sub (byte_val b0) utf8_head_2) 64
                                        + nat_sub (byte_val b1) utf8_cont_base) in
                            let _ =
                              calc (==) {
                                Ok chars;
                                == {}
                                res;
                                == {}
                                Ok (ch :: tail);
                              } in
                            assert (chars = ch :: tail);
                            calc (==) {
                              encode_utf8_bytes_aux chars;
                              == {}
                              encode_utf8_bytes_aux (ch :: tail);
                              == {}
                              List.append [b0; b1] rest1;
                              == { lemma_append_pair b0 b1 rest1 }
                              b0 :: b1 :: rest1;
                            };
                            ()
                      )
                  | [] ->
                      let _ =
                        calc (==) {
                          res;
                          == {}
                          Error InvalidValueUtf8;
                        } in
                      assert False)
             | Some 3 ->
                 (match rest with
                  | b1::b2::rest2 ->
                      if not (canonical_utf8_scalar [b0; b1; b2]) then (
                        let _ =
                          calc (==) {
                            res;
                            == {}
                            Error InvalidValueUtf8;
                          } in
                        assert False
                      ) else (
                        let tail_len = lemma_tail_length_three b0 b1 b2 rest2 in
                        let ih = lemma_decode_utf8_chars_roundtrip rest2 in
                        let tail_res = decode_utf8_chars rest2 in
                        match tail_res with
                        | Error e_tail ->
                            let _ =
                              calc (==) {
                                res;
                                == {}
                                (match decode_utf8_chars rest2 with
                                 | Ok chars' -> Ok (FStar.Char.char_of_int
                                        (Prims.op_Multiply (nat_sub (byte_val b0) utf8_head_3) 4096
                                         + Prims.op_Multiply (nat_sub (byte_val b1) utf8_cont_base) 64
                                         + nat_sub (byte_val b2) utf8_cont_base) :: chars')
                                 | Error e' -> Error e');
                                == {}
                                Error e_tail;
                              } in
                            assert False
                        | Ok tail ->
                            let cp = Prims.op_Multiply (nat_sub (byte_val b0) utf8_head_3) 4096
                                     + Prims.op_Multiply (nat_sub (byte_val b1) utf8_cont_base) 64
                                     + nat_sub (byte_val b2) utf8_cont_base in
                            let ch = FStar.Char.char_of_int cp in
                            lemma_decode_utf8_scalar_three_roundtrip b0 b1 b2;
                            // encode_utf8_scalar ch = encode_utf8_codepoint (int_of_char ch)
                            //                        = encode_utf8_codepoint (int_of_char (char_of_int cp))
                            //                        = encode_utf8_codepoint cp
                            //                        = [b0; b1; b2]
                            assert (FStar.Char.int_of_char (FStar.Char.char_of_int cp) = cp);
                            assert (encode_utf8_scalar ch = encode_utf8_codepoint (FStar.Char.int_of_char ch));
                            assert (encode_utf8_scalar ch = encode_utf8_codepoint cp);
                            assert (encode_utf8_codepoint cp = [b0; b1; b2]);
                            assert (encode_utf8_scalar ch = [b0; b1; b2]);
                            assert (encode_utf8_bytes_aux tail = rest2);
                            let _ =
                              calc (==) {
                                Ok chars;
                                == {}
                                res;
                                == {}
                                Ok (ch :: tail);
                              } in
                            assert (chars = ch :: tail);
                            calc (==) {
                              encode_utf8_bytes_aux chars;
                              == {}
                              encode_utf8_bytes_aux (ch :: tail);
                              == {}
                              List.append (encode_utf8_scalar ch) (encode_utf8_bytes_aux tail);
                              == {}
                              List.append [b0; b1; b2] rest2;
                              == { lemma_append_triple b0 b1 b2 rest2 }
                              b0 :: b1 :: b2 :: rest2;
                            };
                            ()
                      )
                  | _ ->
                      let _ =
                        calc (==) {
                          res;
                          == {}
                          Error InvalidValueUtf8;
                        } in
                      assert False)
             | Some 4 ->
                 (match rest with
                  | b1::b2::b3::rest3 ->
                      if not (canonical_utf8_scalar [b0; b1; b2; b3]) then (
                        let _ =
                          calc (==) {
                            res;
                            == {}
                            Error InvalidValueUtf8;
                          } in
                        assert False
                      ) else (
                        let tail_len = lemma_tail_length_four b0 b1 b2 b3 rest3 in
                        let ih = lemma_decode_utf8_chars_roundtrip rest3 in
                        let tail_res = decode_utf8_chars rest3 in
                        match tail_res with
                        | Error e_tail ->
                            let _ =
                              calc (==) {
                                res;
                                == {}
                                (match decode_utf8_chars rest3 with
                                 | Ok chars' -> Ok (FStar.Char.char_of_int
                                        (Prims.op_Multiply (nat_sub (byte_val b0) utf8_head_4) 262144
                                         + Prims.op_Multiply (nat_sub (byte_val b1) utf8_cont_base) 4096
                                         + Prims.op_Multiply (nat_sub (byte_val b2) utf8_cont_base) 64
                                         + nat_sub (byte_val b3) utf8_cont_base) :: chars')
                                 | Error e' -> Error e');
                                == {}
                                Error e_tail;
                              } in
                            assert False
                        | Ok tail ->
                            let cp = Prims.op_Multiply (nat_sub (byte_val b0) utf8_head_4) 262144
                                     + Prims.op_Multiply (nat_sub (byte_val b1) utf8_cont_base) 4096
                                     + Prims.op_Multiply (nat_sub (byte_val b2) utf8_cont_base) 64
                                     + nat_sub (byte_val b3) utf8_cont_base in
                            let ch = FStar.Char.char_of_int cp in
                            lemma_decode_utf8_scalar_four_roundtrip b0 b1 b2 b3;
                            // encode_utf8_scalar ch = encode_utf8_codepoint (int_of_char ch)
                            //                        = encode_utf8_codepoint (int_of_char (char_of_int cp))
                            //                        = encode_utf8_codepoint cp
                            //                        = [b0; b1; b2; b3]
                            assert (FStar.Char.int_of_char (FStar.Char.char_of_int cp) = cp);
                            assert (encode_utf8_scalar ch = encode_utf8_codepoint (FStar.Char.int_of_char ch));
                            assert (encode_utf8_scalar ch = encode_utf8_codepoint cp);
                            assert (encode_utf8_codepoint cp = [b0; b1; b2; b3]);
                            assert (encode_utf8_scalar ch = [b0; b1; b2; b3]);
                            assert (encode_utf8_bytes_aux tail = rest3);
                            let _ =
                              calc (==) {
                                Ok chars;
                                == {}
                                res;
                                == {}
                                Ok (ch :: tail);
                              } in
                            assert (chars = ch :: tail);
                            calc (==) {
                              encode_utf8_bytes_aux chars;
                              == {}
                              encode_utf8_bytes_aux (ch :: tail);
                              == {}
                              List.append (encode_utf8_scalar ch) (encode_utf8_bytes_aux tail);
                              == {}
                              List.append [b0; b1; b2; b3] rest3;
                              == { lemma_append_quad b0 b1 b2 b3 rest3 }
                              b0 :: b1 :: b2 :: b3 :: rest3;
                            };
                            ()
                      )
                  | _ ->
                      let _ =
                        calc (==) {
                          res;
                          == {}
                          Error InvalidValueUtf8;
                        } in
                      assert False))

// Direct helper: if decode_utf8_chars succeeds with chars, then encoding chars gives bs
let lemma_decode_chars_encode_aux (bs:list UInt8.t) (chars:list char)
  : Lemma (requires decode_utf8_chars bs = Ok chars)
          (ensures encode_utf8_bytes_aux chars = bs)
  = lemma_decode_utf8_chars_roundtrip bs

let lemma_decode_utf8_bytes_roundtrip (bs:list UInt8.t) (s:string)
  : Lemma (requires decode_utf8_bytes bs = Ok s)
          (ensures encode_utf8_bytes s = bs)
  =
    // Given: decode_utf8_bytes bs = Ok s
    // Need: encode_utf8_bytes s = bs

    // By definition of decode_utf8_bytes, if it returns Ok s, then:
    // - valid_utf8_bytes bs = true
    // - decode_utf8_chars bs = Ok chars for some chars
    // - s = Str.string_of_list chars

    // Call the helper lemma which proves:
    // decode_utf8_chars bs = Ok chars ==> encode_utf8_bytes_aux chars = bs
    lemma_decode_utf8_chars_roundtrip bs;

    // Pattern match to extract chars
    match decode_utf8_chars bs with
    | Ok chars ->
        // We know s = Str.string_of_list chars
        // We need to show: encode_utf8_bytes s = bs

        // Unfold encode_utf8_bytes definition
        lemma_encode_utf8_bytes_unfold s;
        // Now: encode_utf8_bytes s = encode_utf8_bytes_aux (list_of_string s)

        // Use the fact that s = string_of_list chars
        lemma_string_of_list_list_of_string_eq chars s;
        // Now: list_of_string s = chars

        // Apply congruence
        lemma_encode_aux_congruence (FStar.String.list_of_string s) chars;
        // Now: encode_utf8_bytes_aux (list_of_string s) = encode_utf8_bytes_aux chars

        // From lemma_decode_utf8_chars_roundtrip: encode_utf8_bytes_aux chars = bs
        ()
    | Error _ ->
        // This case contradicts our precondition decode_utf8_bytes bs = Ok s
        ()

let lemma_decode_utf8_roundtrip (bs:list UInt8.t) (s:string)
  : Lemma
      (requires decode_utf8 bs = Ok s)
      (ensures encode_utf8_bytes s = bs)
  =
    // Explicitly assert that decode_utf8 and decode_utf8_bytes are equivalent
    // This is guaranteed by the postcondition of decode_utf8
    assert (decode_utf8 bs = decode_utf8_bytes bs);

    // From precondition: decode_utf8 bs = Ok s
    // From above assertion: decode_utf8 bs = decode_utf8_bytes bs
    // Therefore: decode_utf8_bytes bs = Ok s
    assert (decode_utf8_bytes bs = Ok s);

    // Now call lemma_decode_utf8_bytes_roundtrip with the established precondition
    lemma_decode_utf8_bytes_roundtrip bs s

// Encoding Validation Lemmas
///////////////////////////////////////////////////////////////////////////////

let lemma_valid_two_byte_prefix
  (cp:nat{0x80 <= cp /\ cp <= 0x7FF})
  : Lemma
      (ensures
        (between (0xC0 + cp / 64) 0xC2 0xDF /\
         between (0x80 + cp % 64) 0x80 0xBF))
  =
    let q = cp / 64 in
    let r = cp % 64 in
    let _ = lemma_div_mod cp 64 in
    let _ = lemma_mod_lt cp 64 in
    let _ = lemma_div_le cp 0x7FF 64 in
    assert (2 <= q);
    assert (q <= 31);
    assert (r <= 63);
    assert (0xC2 <= 0xC0 + q);
    assert (0xC0 + q <= 0xDF);
    assert (0x80 <= 0x80 + r);
    assert (0x80 + r <= 0xBF);
    ()

let lemma_valid_three_byte_prefix
  (cp:nat{0x800 <= cp /\ cp <= 0xFFFF /\ (cp < 0xD800 \/ cp > 0xDFFF)})
  : Lemma
      (ensures
        (let q0 = cp / 4096 in
         let q1 = (cp / 64) % 64 in
         let r = cp % 64 in
         between (0xE0 + q0) 0xE0 0xEF /\
         ((0xE0 + q0 = 0xE0) ==> between (0x80 + q1) 0xA0 0xBF) /\
         ((0xE0 + q0 = 0xED) ==> between (0x80 + q1) 0x80 0x9F) /\
         between (0x80 + q1) 0x80 0xBF /\
         between (0x80 + r) 0x80 0xBF))
  =
    let q0 = cp / 4096 in
    let rem0 = cp % 4096 in
    let q = cp / 64 in
    let q1 = q % 64 in
    let r = cp % 64 in
    let _ = lemma_div_mod cp 4096 in
    let _ = lemma_mod_lt cp 4096 in
    let _ = lemma_div_le cp 0xFFFF 4096 in
    let _ = lemma_div_mod cp 64 in
    let _ = lemma_mod_lt cp 64 in
    let _ = lemma_div_mod q 64 in
    let _ = lemma_mod_lt q 64 in
    // Head byte bounds
    assert (0xE0 <= 0xE0 + q0);
    assert (q0 <= 15);
    assert (0xE0 + q0 <= 0xEF);
    // Second byte general bounds
    assert (q1 <= 63);
    assert (0x80 <= 0x80 + q1);
    assert (0x80 + q1 <= 0xBF);
    // Third byte bounds
    assert (r <= 63);
    assert (0x80 <= 0x80 + r);
    assert (0x80 + r <= 0xBF);
    // Overlong exclusion (E0 case)
    if 0xE0 + q0 = 0xE0 then
      let _ = assert (q0 = 0) in
      let _ = assert (cp / 4096 = 0) in
      let _ = assert (cp < 4096) in
      let _ = assert (q < 64) in
      let _ = small_mod q 64 in
      let _ = small_div q 64 in
      let _ = assert (q1 = q) in
      let _ = assert (32 <= q) in
      assert (0xA0 <= 0x80 + q1);
      ()
    else
      ();
    // Surrogate range exclusion (ED case)
    if 0xE0 + q0 = 0xED then
      let _ = assert (q0 = 13) in
      let base:int = 0xD000 in
      let _ = assert (base <= cp) in
      let _ = assert (cp <= base + 0x7FF) in
      let _ = assert (rem0 <= 0x7FF) in
      let rem_div:int = rem0 / 64 in
      let _ = assert (rem_div <= 31) in
      let _ = assert (q1 = rem_div) in
      assert (0x80 + q1 <= 0x9F);
      ()
    else
      ()

let lemma_valid_four_byte_prefix
  (cp:nat{0x10000 <= cp /\ cp <= 0x10FFFF})
  : Lemma
      (ensures
        (let q0 = cp / 262144 in
         let q1 = (cp / 4096) % 64 in
         let q2 = (cp / 64) % 64 in
         let r = cp % 64 in
         between (0xF0 + q0) 0xF0 0xF4 /\
         ((0xF0 + q0 = 0xF0) ==> between (0x80 + q1) 0x90 0xBF) /\
         ((0xF0 + q0 = 0xF4) ==> between (0x80 + q1) 0x80 0x8F) /\
         between (0x80 + q1) 0x80 0xBF /\
         between (0x80 + q2) 0x80 0xBF /\
         between (0x80 + r) 0x80 0xBF))
  =
    let q0 = cp / 262144 in
    let rem0 = cp % 262144 in
    let q4096 = cp / 4096 in
    let q1 = q4096 % 64 in
    let q64 = cp / 64 in
    let q2 = q64 % 64 in
    let r = cp % 64 in
    let _ = lemma_div_mod cp 262144 in
    let _ = lemma_mod_lt cp 262144 in
    let _ = lemma_div_le cp 0x10FFFF 262144 in
    let _ = lemma_div_mod cp 4096 in
    let _ = lemma_mod_lt cp 4096 in
    let _ = lemma_div_mod q4096 64 in
    let _ = lemma_mod_lt q4096 64 in
    let _ = lemma_div_mod cp 64 in
    let _ = lemma_mod_lt cp 64 in
    let _ = lemma_div_mod q64 64 in
    let _ = lemma_mod_lt q64 64 in
    // Head byte bounds
    assert (0xF0 <= 0xF0 + q0);
    assert (q0 <= 4);
    assert (0xF0 + q0 <= 0xF4);
    // Second byte general bounds
    assert (q1 <= 63);
    assert (0x80 <= 0x80 + q1);
    assert (0x80 + q1 <= 0xBF);
    // Third byte general bounds
    assert (q2 <= 63);
    assert (0x80 <= 0x80 + q2);
    assert (0x80 + q2 <= 0xBF);
    // Fourth byte general bounds
    assert (r <= 63);
    assert (0x80 <= 0x80 + r);
    assert (0x80 + r <= 0xBF);
    // Minimal value enforcement (F0 case)
    if 0xF0 + q0 = 0xF0 then
      let _ = assert (q0 = 0) in
      let _ = assert (cp < 262144) in
      let _ = assert (q4096 < 64) in
      let _ = small_mod q4096 64 in
      let _ = small_div q4096 64 in
      let _ = assert (q1 = q4096) in
      let _ = assert (16 <= q4096) in
      assert (0x90 <= 0x80 + q1);
      ()
    else
      ();
    // Maximum value enforcement (F4 case)
    if 0xF0 + q0 = 0xF4 then
      let _ = assert (q0 = 4) in
      let base:int = 0x100000 in
      let _ = assert (base <= cp) in
      let _ = assert (cp <= base + 0x0FFFF) in
      let _ = assert (rem0 <= 0x0FFFF) in
      let rem1:int = rem0 / 4096 in
      let _ = assert (rem1 <= 15) in
      let _ = assert (q1 = rem1) in
      assert (0x80 + q1 <= 0x8F);
      ()
    else
      ()

let lemma_encode_utf8_scalar_canonical (c:char)
  : Lemma (ensures canonical_utf8_scalar (encode_utf8_scalar c))
  =
    let cp = FStar.Char.int_of_char c in
    if cp <= 0x7F then
      let b0 = mk_u8 cp in
      let bs = encode_utf8_scalar c in
      assert (bs = [b0]);
      assert (byte_val b0 <= 0x7F);
      assert (canonical_utf8_scalar bs);
      ()
    else if cp <= 0x7FF then
      let b0 = mk_u8 (0xC0 + cp / 64) in
      let b1 = mk_u8 (0x80 + cp % 64) in
      let _ = lemma_valid_two_byte_prefix cp in
      let bs = encode_utf8_scalar c in
      assert (bs = [b0; b1]);
      assert (between (byte_val b0) 0xC2 0xDF);
      assert (is_cont b1);
      assert (canonical_utf8_scalar bs);
      ()
    else if cp <= 0xFFFF then
      let b0 = mk_u8 (0xE0 + cp / 4096) in
      let b1 = mk_u8 (0x80 + (cp / 64) % 64) in
      let b2 = mk_u8 (0x80 + cp % 64) in
      let _ = lemma_valid_three_byte_prefix cp in
      let bs = encode_utf8_scalar c in
      assert (bs = [b0; b1; b2]);
      assert (let v0 = byte_val b0 in
              between v0 0xE0 0xEF);
      assert (let v0 = byte_val b0 in
              let v1 = byte_val b1 in
              (if v0 = 0xE0 then between v1 0xA0 0xBF
               else if v0 = 0xED then between v1 0x80 0x9F
               else between v1 0x80 0xBF));
      assert (is_cont b2);
      assert (canonical_utf8_scalar bs);
      ()
    else
      let b0 = mk_u8 (0xF0 + cp / 262144) in
      let b1 = mk_u8 (0x80 + (cp / 4096) % 64) in
      let b2 = mk_u8 (0x80 + (cp / 64) % 64) in
      let b3 = mk_u8 (0x80 + cp % 64) in
      let _ = lemma_valid_four_byte_prefix cp in
      let bs = encode_utf8_scalar c in
      assert (bs = [b0; b1; b2; b3]);
      assert (let v0 = byte_val b0 in
              between v0 0xF0 0xF4);
      assert (let v0 = byte_val b0 in
              let v1 = byte_val b1 in
              (if v0 = 0xF0 then between v1 0x90 0xBF
               else if v0 = 0xF4 then between v1 0x80 0x8F
               else between v1 0x80 0xBF));
      assert (is_cont b2);
      assert (is_cont b3);
      assert (canonical_utf8_scalar bs);
      ()

let lemma_encode_utf8_scalar_valid
  (c:char)
  : Lemma (ensures canonical_utf8_scalar (encode_utf8_scalar c) /\
                   (let cp = FStar.Char.int_of_char c in
                    is_valid_scalar cp /\
                    encode_utf8_scalar c = encode_utf8_codepoint cp))
  =
    let cp = FStar.Char.int_of_char c in
    lemma_encode_utf8_scalar_canonical c;
    // encode_utf8_scalar and encode_utf8_codepoint produce the same result
    assert (encode_utf8_scalar c = encode_utf8_codepoint cp)
