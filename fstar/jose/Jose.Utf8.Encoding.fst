module Jose.Utf8.Encoding

/// UTF-8 encoding functions and length-bound lemmas.
///
/// Depends on Jose.Utf8 for base types/helpers.
/// Does NOT depend on Jose.Utf8.Validity — encoding is independent of validation.

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
// UTF-8 Encoding
///////////////////////////////////////////////////////////////////////////////

let encode_utf8_codepoint (cp:nat{is_valid_scalar cp}) : list UInt8.t =
  if cp <= 0x7F then
    [mk_u8 cp]
  else if cp <= 0x7FF then
    let b0 = mk_u8 (0xC0 + cp / 64) in
    let b1 = mk_u8 (0x80 + cp % 64) in
    [b0; b1]
  else if cp <= 0xFFFF then
    let b0 = mk_u8 (0xE0 + cp / 4096) in
    let b1 = mk_u8 (0x80 + (cp / 64) % 64) in
    let b2 = mk_u8 (0x80 + cp % 64) in
    [b0; b1; b2]
  else
    let b0 = mk_u8 (0xF0 + cp / 262144) in
    let b1 = mk_u8 (0x80 + (cp / 4096) % 64) in
    let b2 = mk_u8 (0x80 + (cp / 64) % 64) in
    let b3 = mk_u8 (0x80 + cp % 64) in
    [b0; b1; b2; b3]

let encode_utf8_scalar (c:char) : Tot (list UInt8.t) =
  encode_utf8_codepoint (FStar.Char.int_of_char c)

let rec encode_utf8_bytes_aux (cs:list char) : Tot (list UInt8.t) (decreases cs) =
  match cs with
  | [] -> []
  | c::cs_rest -> FStar.List.Tot.append (encode_utf8_scalar c) (encode_utf8_bytes_aux cs_rest)

let encode_utf8_bytes (s:string) : list UInt8.t =
  encode_utf8_bytes_aux (FStar.String.list_of_string s)

let lemma_encode_utf8_scalar_length_at_most_4 (c:char)
  : Lemma (List.length (encode_utf8_scalar c) <= 4)
  =
    let cp = FStar.Char.int_of_char c in
    if cp <= 0x7F then
      let bs = encode_utf8_scalar c in
      assert (bs = [mk_u8 cp]);
      assert (List.length bs = 1);
      ()
    else if cp <= 0x7FF then
      let b0 = mk_u8 (0xC0 + cp / 64) in
      let b1 = mk_u8 (0x80 + cp % 64) in
      let bs = encode_utf8_scalar c in
      assert (bs = [b0; b1]);
      assert (List.length bs = 2);
      ()
    else if cp <= 0xFFFF then
      let b0 = mk_u8 (0xE0 + cp / 4096) in
      let b1 = mk_u8 (0x80 + (cp / 64) % 64) in
      let b2 = mk_u8 (0x80 + cp % 64) in
      let bs = encode_utf8_scalar c in
      assert (bs = [b0; b1; b2]);
      assert (List.length bs = 3);
      ()
    else
      let b0 = mk_u8 (0xF0 + cp / 262144) in
      let b1 = mk_u8 (0x80 + (cp / 4096) % 64) in
      let b2 = mk_u8 (0x80 + (cp / 64) % 64) in
      let b3 = mk_u8 (0x80 + cp % 64) in
      let bs = encode_utf8_scalar c in
      assert (bs = [b0; b1; b2; b3]);
      assert (List.length bs = 4);
      ()

let lemma_encode_utf8_scalar_length_at_least_1 (c:char)
  : Lemma (1 <= List.length (encode_utf8_scalar c))
  =
    let cp = FStar.Char.int_of_char c in
    if cp <= 0x7F then
      let bs = encode_utf8_scalar c in
      assert (bs = [mk_u8 cp]);
      assert (List.length bs = 1);
      ()
    else if cp <= 0x7FF then
      let b0 = mk_u8 (0xC0 + cp / 64) in
      let b1 = mk_u8 (0x80 + cp % 64) in
      let bs = encode_utf8_scalar c in
      assert (bs = [b0; b1]);
      assert (List.length bs = 2);
      ()
    else if cp <= 0xFFFF then
      let b0 = mk_u8 (0xE0 + cp / 4096) in
      let b1 = mk_u8 (0x80 + (cp / 64) % 64) in
      let b2 = mk_u8 (0x80 + cp % 64) in
      let bs = encode_utf8_scalar c in
      assert (bs = [b0; b1; b2]);
      assert (List.length bs = 3);
      ()
    else
      let b0 = mk_u8 (0xF0 + cp / 262144) in
      let b1 = mk_u8 (0x80 + (cp / 4096) % 64) in
      let b2 = mk_u8 (0x80 + (cp / 64) % 64) in
      let b3 = mk_u8 (0x80 + cp % 64) in
      let bs = encode_utf8_scalar c in
      assert (bs = [b0; b1; b2; b3]);
      assert (List.length bs = 4);
      ()

let rec lemma_encode_utf8_bytes_aux_length_bound (cs:list char)
  : Lemma (ensures List.length (encode_utf8_bytes_aux cs) <= four_times (List.length cs))
  (decreases cs)
  =
    match cs with
    | [] -> ()
    | c :: rest ->
        lemma_encode_utf8_scalar_length_at_most_4 c;
        lemma_encode_utf8_bytes_aux_length_bound rest;
        lemma_list_length_append (encode_utf8_scalar c) (encode_utf8_bytes_aux rest);
        let len_head = List.length (encode_utf8_scalar c) in
        let len_rest = List.length (encode_utf8_bytes_aux rest) in
        let rest_len = List.length rest in
        assert (len_head <= 4);
        assert (len_rest <= four_times rest_len);
        assert (List.length (encode_utf8_bytes_aux (c :: rest)) = len_head + len_rest);
        assert (len_head + len_rest <= 4 + four_times rest_len);
        assert (4 + four_times rest_len = four_times (rest_len + 1));
        assert (List.length (c :: rest) = rest_len + 1);
        ()

let rec lemma_encode_utf8_bytes_aux_length_lower_bound (cs:list char)
  : Lemma (ensures List.length cs <= List.length (encode_utf8_bytes_aux cs))
  (decreases cs)
  =
    match cs with
    | [] -> ()
    | c :: rest ->
        lemma_encode_utf8_scalar_length_at_least_1 c;
        lemma_encode_utf8_bytes_aux_length_lower_bound rest;
        lemma_list_length_append (encode_utf8_scalar c) (encode_utf8_bytes_aux rest);
        let len_head = List.length (encode_utf8_scalar c) in
        let len_rest = List.length (encode_utf8_bytes_aux rest) in
        let rest_len = List.length rest in
        assert (len_head >= 1);
        assert (len_rest >= rest_len);
        assert (List.length (encode_utf8_bytes_aux (c :: rest)) = len_head + len_rest);
        assert (len_head + len_rest >= 1 + rest_len);
        assert (List.length (c :: rest) = rest_len + 1);
        ()

let lemma_encode_utf8_bytes_unfold (s:string)
  : Lemma (ensures encode_utf8_bytes s = encode_utf8_bytes_aux (FStar.String.list_of_string s))
  = ()

let lemma_string_list_length (s:string)
  : Lemma (ensures List.length (FStar.String.list_of_string s) = FStar.String.length s)
  =
    assert_norm (FStar.String.length s = List.length (FStar.String.list_of_string s));
    ()

let lemma_encode_utf8_bytes_length_bound (s:string)
  : Lemma (ensures List.length (encode_utf8_bytes s) <= four_times (FStar.String.length s))
  =
    let chars = FStar.String.list_of_string s in
    lemma_encode_utf8_bytes_aux_length_bound chars;
    lemma_encode_utf8_bytes_unfold s;
    lemma_string_list_length s;
    assert (List.length (encode_utf8_bytes s) = List.length (encode_utf8_bytes_aux chars));
    assert (List.length (encode_utf8_bytes_aux chars) <= four_times (List.length chars));
    assert (List.length chars = FStar.String.length s);
    ()

let lemma_encode_utf8_bytes_length_lower_bound (s:string)
  : Lemma (ensures FStar.String.length s <= List.length (encode_utf8_bytes s))
  =
    let chars = FStar.String.list_of_string s in
    lemma_encode_utf8_bytes_aux_length_lower_bound chars;
    lemma_encode_utf8_bytes_unfold s;
    lemma_string_list_length s;
    assert (List.length chars = FStar.String.length s);
    assert (FStar.String.length s <= List.length (encode_utf8_bytes_aux chars));
    assert (List.length (encode_utf8_bytes_aux chars) = List.length (encode_utf8_bytes s));
    ()
