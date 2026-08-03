module Jose.StringLemmas

open FStar.List.Tot
open FStar.List.Tot.Properties
open FStar.Tactics
open FStar.String
open FStar.Char
open FStar.UInt8
open FStar.Calc
open Jose.Utf8Lemmas

module List = FStar.List.Tot
module Str = FStar.String

let string_in_list (x:string) (xs:list string) : Tot bool = mem x xs

let lemma_string_in_list_append
  (x:string)
  (l1:list string)
  (l2:list string)
  : Lemma
      (requires True)
      (ensures string_in_list x (append l1 l2) =
               (string_in_list x l1 || string_in_list x l2))
  =
    append_mem l1 l2 x

let lemma_string_in_list_singleton
  (x:string)
  (y:string)
  : Lemma
      (requires True)
      (ensures string_in_list x [y] = (=) x y)
  =
    assert (string_in_list x [y] = (=) x y) by (norm [delta; iota; zeta; primops])

let lemma_cons_as_append
  (x:string)
  (xs:list string)
  : Lemma (ensures x :: xs = append [x] xs)
  =
    assert (x :: xs = append [x] xs) by (norm [delta; iota; zeta; primops])

let lemma_string_in_list_rev
  (x:string)
  (keys:list string)
  : Lemma
      (requires True)
      (ensures string_in_list x (rev keys) = string_in_list x keys)
  =
    rev_mem keys x

let lemma_rev_singleton
  (x:string)
  : Lemma (ensures List.rev [x] = [x])
  =
    assert (List.rev [x] = [x]) by (norm [delta; iota; zeta; primops])

let lemma_string_not_in_rev
  (x:string)
  (xs:list string)
  : Lemma
      (requires not (string_in_list x xs))
      (ensures not (string_in_list x (rev xs)))
  =
    lemma_string_in_list_rev x xs;
    ()

let lemma_rev_cons_eq
  (x:string)
  (xs:list string)
  : Lemma (ensures rev (x :: xs) = append (rev xs) [x])
  =
    lemma_cons_as_append x xs;
    assert (x :: xs = append [x] xs);
    rev_append [x] xs;
    assert (rev (append [x] xs) = append (rev xs) (rev [x]));
    lemma_rev_singleton x;
    assert (rev [x] = [x]);
    ()

let str (c:char) : string = Str.string_of_char c

let rec ascii_bytes_to_string (bs:list UInt8.t{List.for_all ascii_byte bs}) : string =
  match bs with
  | [] -> ""
  | b::tl -> strcat (str (ascii_byte_to_char b)) (ascii_bytes_to_string tl)

let lemma_ascii_bytes_to_string_unfold
  (b:UInt8.t{ascii_byte b})
  (tl:list UInt8.t{List.for_all ascii_byte tl})
  : Lemma
      (ensures
        ascii_bytes_to_string (b :: tl)
        = strcat (str (ascii_byte_to_char b)) (ascii_bytes_to_string tl))
  =
    assert (
      ascii_bytes_to_string (b :: tl)
      = strcat (str (ascii_byte_to_char b)) (ascii_bytes_to_string tl)
    ) by (norm [delta; iota; zeta; primops])

let lemma_ascii_bytes_to_string_cons_length
  (b:UInt8.t{ascii_byte b})
  (tl:list UInt8.t{List.for_all ascii_byte tl})
  : Lemma
      (ensures
        Str.length (ascii_bytes_to_string (b :: tl))
        = Str.length (strcat (str (ascii_byte_to_char b)) (ascii_bytes_to_string tl)))
  =
    lemma_ascii_bytes_to_string_unfold b tl;
    assert (
      Str.length (ascii_bytes_to_string (b :: tl))
      = Str.length (strcat (str (ascii_byte_to_char b)) (ascii_bytes_to_string tl))
    ) by (norm [delta; iota; zeta; primops])

let lemma_strcat_length (s1:string) (s2:string)
  : Lemma (ensures Str.length (strcat s1 s2) = Str.length s1 + Str.length s2)
  = FStar.String.concat_length s1 s2

let lemma_single_char_length (b:UInt8.t{ascii_byte b})
  : Lemma (ensures Str.length (str (ascii_byte_to_char b)) = 1)
  = assert_norm (Str.length (str (ascii_byte_to_char b)) = 1)

let lemma_list_length_cons
  (#a:Type) (x:a) (xs:list a)
  : Lemma (ensures List.length (x :: xs) = 1 + List.length xs)
  = assert (List.length (x :: xs) = 1 + List.length xs)
      by (norm [delta; iota; zeta; primops])

let lemma_list_length_cons_sym
  (#a:Type) (x:a) (xs:list a)
  : Lemma (ensures 1 + List.length xs = List.length (x :: xs))
  = assert (1 + List.length xs = List.length (x :: xs))
      by (norm [delta; iota; zeta; primops])

let lemma_nat_succ_cong (x:nat) (y:nat)
  : Lemma
      (requires x = y)
      (ensures 1 + x = 1 + y)
  = ()

let lemma_for_all_tail
  (#a:Type) (f:a -> Tot bool) (x:a) (xs:list a)
  : Lemma
      (requires List.for_all f (x :: xs))
      (ensures List.for_all f xs)
  = match xs with
    | [] -> ()
    | _ -> assert (List.for_all f xs) by (norm [delta; iota; zeta; primops])

let string_of_ascii (bs:list UInt8.t) : option string =
  if List.for_all ascii_byte bs then
    Some (ascii_bytes_to_string bs)
  else None

let rec lemma_ascii_bytes_length
  (bs:list UInt8.t{List.for_all ascii_byte bs})
  : Lemma (ensures Str.length (ascii_bytes_to_string bs) = List.length bs)
  =
    match bs with
    | [] ->
        let nil_uint8 : list UInt8.t = [] in
        assert_norm (
          Str.length (ascii_bytes_to_string [])
          = List.length nil_uint8
        );
        ()
    | b :: tl ->
        lemma_for_all_tail ascii_byte b tl;
        lemma_ascii_bytes_length tl;
        lemma_ascii_bytes_to_string_cons_length b tl;
        lemma_strcat_length (str (ascii_byte_to_char b)) (ascii_bytes_to_string tl);
        lemma_single_char_length b;
        lemma_nat_succ_cong
          (Str.length (ascii_bytes_to_string tl))
          (List.length tl);
        lemma_list_length_cons_sym b tl;
        ()

let lemma_string_of_ascii_ascii
  (bs:list UInt8.t)
  (s:string)
  : Lemma
      (requires string_of_ascii bs = Some s)
      (ensures List.for_all ascii_byte bs /\ List.length bs = Str.length s)
  =
    let ascii_ok = List.for_all ascii_byte bs in
    let ascii_str = ascii_bytes_to_string bs in
    assert (string_of_ascii bs == (if ascii_ok then Some ascii_str else None));
    assert (ascii_ok);
    assert (Some ascii_str == Some s);
    assert (s == ascii_str);
    lemma_ascii_bytes_length bs;
    ()
