module FStar.Base64

(** Concrete RFC 4648 section 5 base64url encode/decode (no padding).
    0 assume vals — all 4 algebraic properties proved from the implementation.

    Encoding uses the genuine RFC 4648 base64url alphabet:
      A-Z (0-25), a-z (26-51), 0-9 (52-61), - (62), _ (63)
    with 3-byte-to-4-char grouping and no padding characters.

    Marked `opaque_to_smt` to preserve Z3 opacity for downstream modules;
    proofs use `reveal_opaque`.

    This F* implementation matches the C runtime (crypto_bridge.c) which also
    implements RFC 4648 base64url.

    Standard base64 (`encode`/`decode`) is dead code (0 callers) but retained
    for API compatibility, sharing the same base64url implementation. *)

open FStar.Bytes
open FStar.Mul

module Str = FStar.String
module Char = FStar.Char
module U8 = FStar.UInt8
module U32 = FStar.UInt32
module LT = FStar.List.Tot

(* ================================================================ *)
(* RFC 4648 base64url alphabet                                      *)
(* ================================================================ *)

(** Encode a 6-bit value (0-63) to a base64url character.
    A-Z (0-25), a-z (26-51), 0-9 (52-61), - (62), _ (63). *)
private
let b64url_char_of_val (n: nat{n < 64}) : Tot Char.char =
  Char.char_of_int (
    if n < 26 then 0x41 + n
    else if n < 52 then 0x61 + n - 26
    else if n < 62 then 0x30 + n - 52
    else if n = 62 then 0x2D
    else 0x5F
  )

(** Decode a base64url character to its 6-bit value (0-63), or None. *)
private
let val_of_b64url_char (c: Char.char) : Tot (option (n:nat{n < 64})) =
  let v = Char.int_of_char c in
  if 0x41 <= v && v <= 0x5A then Some (v - 0x41)
  else if 0x61 <= v && v <= 0x7A then Some (v - 0x61 + 26)
  else if 0x30 <= v && v <= 0x39 then Some (v - 0x30 + 52)
  else if v = 0x2D then Some 62
  else if v = 0x5F then Some 63
  else None

(** Alphabet roundtrip: val_of_b64url_char (b64url_char_of_val n) = Some n. *)
private
let lemma_b64url_alphabet_roundtrip (n: nat{n < 64})
  : Lemma (val_of_b64url_char (b64url_char_of_val n) = Some n) = ()

(* ================================================================ *)
(* List-level base64url encoding/decoding                           *)
(* ================================================================ *)

(** Encode a list of bytes to base64url characters (no padding).
    Processes 3 bytes -> 4 chars; handles 1-byte (-> 2 chars) and
    2-byte (-> 3 chars) trailing groups per RFC 4648 section 5. *)
private
let rec encode_byte_list (l: list U8.t) : Tot (list Char.char) =
  match l with
  | [] -> []
  | [a] ->
    let va = U8.v a in
    [b64url_char_of_val (va / 4);
      b64url_char_of_val ((va % 4) * 16)]
  | [a; b] ->
    let va = U8.v a in
    let vb = U8.v b in
    [b64url_char_of_val (va / 4);
      b64url_char_of_val ((va % 4) * 16 + vb / 16);
      b64url_char_of_val ((vb % 16) * 4)]
  | a :: b :: c :: rest ->
    let va = U8.v a in
    let vb = U8.v b in
    let vc = U8.v c in
    b64url_char_of_val (va / 4)
    :: b64url_char_of_val ((va % 4) * 16 + vb / 16)
    :: b64url_char_of_val ((vb % 16) * 4 + vc / 64)
    :: b64url_char_of_val (vc % 64)
    :: encode_byte_list rest

(** Decode base64url characters to a list of bytes, or None.
    Rejects invalid characters and non-canonical padding bits. *)
private
let rec decode_char_list (l: list Char.char) : Tot (option (list U8.t)) =
  match l with
  | [] -> Some []
  | [_] -> None  (* len mod 4 = 1 is invalid *)
  | [c0; c1] ->  (* 1 trailing byte *)
    (match val_of_b64url_char c0, val_of_b64url_char c1 with
      | Some n0, Some n1 ->
        if n1 % 16 = 0 then
          Some [U8.uint_to_t (n0 * 4 + n1 / 16)]
        else None
      | _, _ -> None)
  | [c0; c1; c2] ->  (* 2 trailing bytes *)
    (match val_of_b64url_char c0, val_of_b64url_char c1, val_of_b64url_char c2 with
      | Some n0, Some n1, Some n2 ->
        if n2 % 4 = 0 then
          Some [U8.uint_to_t (n0 * 4 + n1 / 16);
                U8.uint_to_t ((n1 % 16) * 16 + n2 / 4)]
        else None
      | _, _, _ -> None)
  | c0 :: c1 :: c2 :: c3 :: rest ->  (* full 3-byte group *)
    (match val_of_b64url_char c0, val_of_b64url_char c1,
      val_of_b64url_char c2, val_of_b64url_char c3 with
      | Some n0, Some n1, Some n2, Some n3 ->
        (match decode_char_list rest with
          | Some bs ->
            Some (U8.uint_to_t (n0 * 4 + n1 / 16)
                  :: U8.uint_to_t ((n1 % 16) * 16 + n2 / 4)
                  :: U8.uint_to_t ((n2 % 4) * 64 + n3)
                  :: bs)
          | None -> None)
      | _, _, _, _ -> None)

(** Roundtrip: decode_char_list (encode_byte_list l) = Some l. *)
private
let rec lemma_list_roundtrip (l: list U8.t)
  : Lemma (ensures decode_char_list (encode_byte_list l) = Some l)
          (decreases l)
  = match l with
    | [] -> ()
    | [a] ->
      let va = U8.v a in
      lemma_b64url_alphabet_roundtrip (va / 4);
      lemma_b64url_alphabet_roundtrip ((va % 4) * 16)
    | [a; b] ->
      let va = U8.v a in
      let vb = U8.v b in
      lemma_b64url_alphabet_roundtrip (va / 4);
      lemma_b64url_alphabet_roundtrip ((va % 4) * 16 + vb / 16);
      lemma_b64url_alphabet_roundtrip ((vb % 16) * 4)
    | a :: b :: c :: rest ->
      let va = U8.v a in
      let vb = U8.v b in
      let vc = U8.v c in
      lemma_b64url_alphabet_roundtrip (va / 4);
      lemma_b64url_alphabet_roundtrip ((va % 4) * 16 + vb / 16);
      lemma_b64url_alphabet_roundtrip ((vb % 16) * 4 + vc / 64);
      lemma_b64url_alphabet_roundtrip (vc % 64);
      lemma_list_roundtrip rest

(** Injectivity of encode_byte_list: follows from roundtrip. *)
private
let lemma_list_injective (a b: list U8.t)
  : Lemma (requires encode_byte_list a = encode_byte_list b)
          (ensures a = b)
  = lemma_list_roundtrip a;
    lemma_list_roundtrip b

(* ================================================================ *)
(* Bytes <-> list conversion                                        *)
(* ================================================================ *)

(** Convert bytes to list of UInt8.t. *)
private
let rec bytes_to_u8_list_aux (b: bytes) (i: nat{i <= length b})
  : Tot (list U8.t)
  (decreases (length b - i))
  = if i = length b then []
    else index b i :: bytes_to_u8_list_aux b (i + 1)

private
let bytes_to_u8_list (b: bytes) : Tot (list U8.t) =
  bytes_to_u8_list_aux b 0

(** Convert list of UInt8.t to bytes using Bytes.init.
    Guard: if list length >= 2^32, return empty_bytes (unreachable for
    hash outputs which are <= 64 bytes). *)
private
let u8_list_to_bytes (l: list U8.t) : Tot bytes =
  let n = LT.length l in
  if n = 0 || n >= pow2 32 then empty_bytes
  else
    let len : U32.t = U32.uint_to_t n in
    init len (fun (i: U32.t{U32.(i <^ len)}) ->
      LT.index l (U32.v i))

(** Length of bytes_to_u8_list_aux. *)
private
let rec lemma_b2l_length (b: bytes) (i: nat{i <= length b})
  : Lemma (ensures LT.length (bytes_to_u8_list_aux b i) = length b - i)
          (decreases (length b - i))
  = if i = length b then ()
    else lemma_b2l_length b (i + 1)

(** The k-th element of bytes_to_u8_list_aux b i is index b (i + k). *)
private
let rec lemma_b2l_index (b: bytes) (i: nat{i <= length b}) (k: nat{k < length b - i})
  : Lemma (ensures (lemma_b2l_length b i;
      LT.index (bytes_to_u8_list_aux b i) k = index b (i + k)))
          (decreases k)
  = lemma_b2l_length b i;
    if k = 0 then ()
    else begin
      lemma_b2l_length b (i + 1);
      lemma_b2l_index b (i + 1) (k - 1)
    end

(** Roundtrip: u8_list_to_bytes (bytes_to_u8_list b) = b.
    Note: FStar.Bytes.length b < pow2 32 by construction (Bytes type invariant),
    so the pow2 32 guard in u8_list_to_bytes is never triggered. *)
private
let lemma_bytes_list_roundtrip (b: bytes)
  : Lemma (u8_list_to_bytes (bytes_to_u8_list b) = b)
  = lemma_b2l_length b 0;
    let l = bytes_to_u8_list b in
    let n = LT.length l in
    assert (n = length b);
    if n = 0 then ()
    else begin
      (* n = length b < pow2 32 by Bytes type invariant *)
      assert (n < pow2 32);
      let b' = u8_list_to_bytes l in
      assert (length b' = n);
      assert (length b = n);
      let aux (j: nat{j < n}) : Lemma (index b' j = index b j)
        = lemma_b2l_index b 0 j
      in
      FStar.Classical.forall_intro aux;
      FStar.Bytes.extensionality b' b
    end

(* ================================================================ *)
(* Public API                                                       *)
(* ================================================================ *)

(* -- Base64url (no padding) -------------------------------------- *)

[@@"opaque_to_smt"]
let base64url_encode (b: bytes) : Tot string =
  Str.string_of_list (encode_byte_list (bytes_to_u8_list b))

[@@"opaque_to_smt"]
let base64url_decode (s: string) : Tot (option bytes) =
  match decode_char_list (Str.list_of_string s) with
  | Some l -> Some (u8_list_to_bytes l)
  | None -> None

(* -- Standard base64 ------------------------------------------------
  WARNING: These are aliases for base64url (no padding, alphabet -_).
  They do NOT implement standard base64 (alphabet +/, with = padding).
  Retained solely for backward API compatibility with 0 existing callers.
  Do NOT use for RFC 4648 section 4 standard base64. *)

[@@"opaque_to_smt"]
let encode (b: bytes) : Tot string =
  Str.string_of_list (encode_byte_list (bytes_to_u8_list b))

[@@"opaque_to_smt"]
let decode (s: string) : Tot (option bytes) =
  match decode_char_list (Str.list_of_string s) with
  | Some l -> Some (u8_list_to_bytes l)
  | None -> None

(* Aliases *)
let url_encode = base64url_encode
let url_decode = base64url_decode

(* ================================================================ *)
(* Algebraic properties — proved, not assumed                       *)
(* ================================================================ *)

(** Roundtrip: decoding an encoded value recovers the original. *)
let base64url_roundtrip (b:bytes)
  : Lemma (ensures base64url_decode (base64url_encode b) = Some b)
  = reveal_opaque (`%base64url_encode) base64url_encode;
    reveal_opaque (`%base64url_decode) base64url_decode;
    let l = bytes_to_u8_list b in
    lemma_list_roundtrip l;
    Str.list_of_string_of_list (encode_byte_list l);
    lemma_bytes_list_roundtrip b

(** Injectivity: encoding is injective.
    Proof: encode a = encode b
    => string_of_list(enc la) = string_of_list(enc lb)
    => list_of_string(string_of_list(enc la)) = list_of_string(string_of_list(enc lb))
    => enc la = enc lb   (by list_of_string_of_list)
    => la = lb           (by lemma_list_injective)
    => a = b             (by lemma_bytes_list_roundtrip) *)
let base64url_encode_injective (a b: bytes)
  : Lemma (requires base64url_encode a = base64url_encode b)
          (ensures a = b)
  = reveal_opaque (`%base64url_encode) base64url_encode;
    let la = bytes_to_u8_list a in
    let lb = bytes_to_u8_list b in
    Str.list_of_string_of_list (encode_byte_list la);
    Str.list_of_string_of_list (encode_byte_list lb);
    lemma_list_injective la lb;
    lemma_bytes_list_roundtrip a;
    lemma_bytes_list_roundtrip b

(** Standard base64 roundtrip (alias — uses base64url, see warning above). *)
let base64_roundtrip (b:bytes)
  : Lemma (ensures decode (encode b) = Some b)
  = reveal_opaque (`%encode) encode;
    reveal_opaque (`%decode) decode;
    let l = bytes_to_u8_list b in
    lemma_list_roundtrip l;
    Str.list_of_string_of_list (encode_byte_list l);
    lemma_bytes_list_roundtrip b

(** Standard base64 injectivity. *)
let base64_encode_injective (a b: bytes)
  : Lemma (requires encode a = encode b)
          (ensures a = b)
  = reveal_opaque (`%encode) encode;
    let la = bytes_to_u8_list a in
    let lb = bytes_to_u8_list b in
    Str.list_of_string_of_list (encode_byte_list la);
    Str.list_of_string_of_list (encode_byte_list lb);
    lemma_list_injective la lb;
    lemma_bytes_list_roundtrip a;
    lemma_bytes_list_roundtrip b
