module AuthCode.RedisFlag

(* Exact ASCII representation of one boolean argument. This leaf does not
   model ARGV placement, Redis transport, or the Lua interpreter. *)
module L = FStar.List.Tot
module U8 = FStar.UInt8
module S = FStar.String
module C = FStar.Char

let encode (value:bool) : Tot (list U8.t) =
  if value then [0x31uy] else [0x30uy]

let relation (value:bool) (bytes:list U8.t) : Tot bool =
  bytes = (if value then [0x31uy] else [0x30uy])

let encode_text (value:bool) : Tot string =
  S.string_of_list [C.char_of_int (if value then 0x31 else 0x30)]

let lemma_exact_encoding (value:bool)
  : Lemma (relation value (encode value) /\ L.length (encode value) = 1)
  = ()

let lemma_ascii_text (value:bool)
  : Lemma
    (S.list_of_string (encode_text value) =
       [C.char_of_int (U8.v (L.hd (encode value)))])
  = S.list_of_string_of_list [C.char_of_int (if value then 0x31 else 0x30)]

let lemma_equality_recovers_input (value:bool)
  : Lemma ((encode value = [0x31uy]) <==> value)
  = ()

let lemma_text_equality_recovers_input (value:bool)
  : Lemma ((encode_text value = encode_text true) <==> value)
  = lemma_ascii_text value;
    lemma_ascii_text true
