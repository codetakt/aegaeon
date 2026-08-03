module FormPost

open FStar.List.Tot
open FStar.Char
module List = FStar.List.Tot
module Str = FStar.String

let is_dangerous (c:char) : Tot bool =
  c = '<' || c = '>' || c = '"' || c = '\''

let rec no_dangerous (cs:list char) : Tot bool =
  match cs with
  | [] -> true
  | h :: t -> (not (is_dangerous h)) && no_dangerous t

let escape_char (c:char) : Tot (list char) =
  if c = '&' then ['&'; 'a'; 'm'; 'p'; ';']
  else if c = '<' then ['&'; 'l'; 't'; ';']
  else if c = '>' then ['&'; 'g'; 't'; ';']
  else if c = '"' then ['&'; 'q'; 'u'; 'o'; 't'; ';']
  else if c = '\'' then ['&'; '#'; 'x'; '2'; '7'; ';']
  else [c]

let rec escape_chars (cs:list char) : Tot (list char) =
  match cs with
  | [] -> []
  | h :: t -> escape_char h @ escape_chars t

let rec lemma_no_dangerous_append (xs ys:list char) : Lemma
  (requires no_dangerous xs /\ no_dangerous ys)
  (ensures no_dangerous (xs @ ys))
= match xs with
  | [] -> ()
  | _ :: t ->
      lemma_no_dangerous_append t ys

let lemma_escape_char_safe (c:char) : Lemma (ensures no_dangerous (escape_char c)) =
  if c = '&' then ()
  else if c = '<' then ()
  else if c = '>' then ()
  else if c = '"' then ()
  else if c = '\'' then ()
  else (
    assert (c <> '<' /\ c <> '>' /\ c <> '"' /\ c <> '\'');
    assert (not (is_dangerous c));
    assert_norm (no_dangerous [c])
  )

let rec lemma_escape_chars_safe (cs:list char) : Lemma
  (ensures no_dangerous (escape_chars cs))
= match cs with
  | [] -> ()
  | h :: t ->
      lemma_escape_char_safe h;
      lemma_escape_chars_safe t;
      lemma_no_dangerous_append (escape_char h) (escape_chars t)

let escape_html (s:string) : Tot string =
  Str.string_of_list (escape_chars (Str.list_of_string s))

let lemma_escape_html_safe (s:string) : Lemma
  (ensures no_dangerous (Str.list_of_string (escape_html s)))
=
  let cs = escape_chars (Str.list_of_string s) in
  lemma_escape_chars_safe (Str.list_of_string s);
  Str.list_of_string_of_list cs

type field = string * string

let allowed_field_name (name:string) : Tot bool =
  name = "code"
  || name = "state"
  || name = "iss"
  || name = "error"
  || name = "error_description"

let rec all_allowed_fields (fields:list field) : Tot bool =
  match fields with
  | [] -> true
  | (name, _) :: t -> allowed_field_name name && all_allowed_fields t

let rec unique_field_names (fields:list field) : Tot bool =
  match fields with
  | [] -> true
  | (name, _) :: t ->
      not (List.mem name (List.map fst t)) && unique_field_names t

let form_post_invariants (fields:list field) : Tot bool =
  unique_field_names fields && all_allowed_fields fields

let csp_header (form_action:string) (nonce:string) : Tot string =
  "default-src 'none'; base-uri 'none'; form-action " ^ form_action
  ^ "; frame-ancestors 'none'; script-src 'nonce-" ^ nonce ^ "';"

let form_post_csp_enforced (form_action:string) (nonce:string) : Tot bool =
  csp_header form_action nonce
  = "default-src 'none'; base-uri 'none'; form-action " ^ form_action
    ^ "; frame-ancestors 'none'; script-src 'nonce-" ^ nonce ^ "';"
