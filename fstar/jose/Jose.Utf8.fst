module Jose.Utf8

/// Base types, constants, and helpers for the UTF-8 codec.
///
/// This module provides the foundational definitions shared by
/// Jose.Utf8.Validity, Jose.Utf8.Encoding, and Jose.Utf8.Lemmas.

open FStar.UInt8
open FStar.UInt32
open FStar.Math.Lemmas
open FStar.Pervasives
open FStar.List.Tot
open FStar.List.Tot.Properties
open FStar.String
open FStar.Char
open JoseNatLemmas

module U32 = FStar.UInt32
module Str = FStar.String

///////////////////////////////////////////////////////////////////////////////
// Error types for UTF-8 decoding
///////////////////////////////////////////////////////////////////////////////

type decode_error =
  | BufferTooShort
  | InvalidKeyEncoding
  | InvalidValueUtf8
  | UnknownKey of string
  | PolicyViolation of string

type jlresult (a:Type0) (e:Type0) : Type0 =
  | Ok: a -> jlresult a e
  | Error: e -> jlresult a e

type decode_result (a:Type0) = jlresult a decode_error

///////////////////////////////////////////////////////////////////////////////
// UTF-8 Constants
///////////////////////////////////////////////////////////////////////////////

let pow2_8 : nat = 256
let utf8_head_1_max : nat = 0x7F
let utf8_head_2 : nat = 0xC0
let utf8_head_3 : nat = 0xE0
let utf8_head_4 : nat = 0xF0
let utf8_cont_base : nat = 0x80

let four_times (n:nat) : nat = Prims.op_Multiply 4 n

///////////////////////////////////////////////////////////////////////////////
// Basic Helpers
///////////////////////////////////////////////////////////////////////////////

let mk_u8 (n:nat{n < pow2_8}) : UInt8.t = UInt8.uint_to_t n
let byte_val (u:UInt8.t) : nat = FStar.UInt8.v u
let between (x:nat) (lo:nat) (hi:nat) = lo <= x && x <= hi
let is_cont (b:UInt8.t) = between (byte_val b) 0x80 0xBF
let str (c:char) : string = Str.string_of_list [c]

let lemma_mk_u8_roundtrip (b:UInt8.t)
  : Lemma (ensures mk_u8 (byte_val b) = b)
  = ()

let rec lemma_list_length_append (#a:Type) (xs:list a) (ys:list a)
  : Lemma (ensures List.length (List.append xs ys) = List.length xs + List.length ys)
  (decreases xs)
  =
    match xs with
    | [] ->
        ()
    | _::xs_tail ->
        lemma_list_length_append xs_tail ys;
        ()

///////////////////////////////////////////////////////////////////////////////
// ASCII Helpers
///////////////////////////////////////////////////////////////////////////////

let ascii_byte (u:UInt8.t) : bool = byte_val u <= 0x7F

let ascii_to_valid_scalar (n:nat{n <= 0x7F})
  : Lemma (ensures n < 0xD800)
  = ()

let ascii_byte_to_char (b:UInt8.t{ascii_byte b}) : char =
  let n = byte_val b in
  ascii_to_valid_scalar n;
  assert (n < 0xD800);
  FStar.Char.char_of_int n

///////////////////////////////////////////////////////////////////////////////
// Unicode Scalar Validity
///////////////////////////////////////////////////////////////////////////////

let is_valid_scalar (cp:nat) : Tot bool =
  cp <= 0x10FFFF && (cp < 0xD800 || cp > 0xDFFF)
