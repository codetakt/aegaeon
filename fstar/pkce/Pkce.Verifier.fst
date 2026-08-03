module Pkce.Verifier

open FStar.String
module List = FStar.List.Tot

(** Code verifier per RFC 7636. The value MUST contain between 43 and 128 characters. *)
type code_verifier = s:string { String.length s >= 43 /\ String.length s <= 128 }

(** RFC 7636 unreserved character: ALPHA / DIGIT / "-" / "." / "_" / "~". *)
let unreserved_char (c:FStar.Char.char) : Tot bool =
  let n = FStar.Char.int_of_char c in
  (n >= 65 && n <= 90) ||
  (n >= 97 && n <= 122) ||
  (n >= 48 && n <= 57) ||
  n = 45 || n = 46 || n = 95 || n = 126

let code_verifier_charset_ok (s:string) : Tot bool =
  List.for_all unreserved_char (FStar.String.list_of_string s)

val validate_code_verifier : s:string ->
  Tot (b:bool{
    b <==>
      (FStar.String.length s >= 43 /\
       FStar.String.length s <= 128 /\
       code_verifier_charset_ok s)})
let validate_code_verifier s =
  FStar.String.length s >= 43 &&
  FStar.String.length s <= 128 &&
  code_verifier_charset_ok s
