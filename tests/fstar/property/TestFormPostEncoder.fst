module TestFormPostEncoder

open FormPost
open FStar.Tactics
module Str = FStar.String

let test_form_post_invariants_accepts_ok () : Lemma
  (ensures form_post_invariants [("code", "abc"); ("iss", "https://as.example")])
  =
  assert (form_post_invariants [("code", "abc"); ("iss", "https://as.example")])
    by (norm [delta; iota; zeta; primops])

let test_form_post_invariants_rejects_duplicates () : Lemma
  (ensures not (form_post_invariants [("code", "a"); ("code", "b")]))
  =
  assert (not (form_post_invariants [("code", "a"); ("code", "b")]))
    by (norm [delta; iota; zeta; primops])

let test_form_post_invariants_rejects_unknown_field () : Lemma
  (ensures not (form_post_invariants [("code", "a"); ("evil", "b")]))
  =
  assert (not (form_post_invariants [("code", "a"); ("evil", "b")]))
    by (norm [delta; iota; zeta; primops])

let test_escape_html_eliminates_dangerous_chars () : Lemma
  (ensures no_dangerous (Str.list_of_string (escape_html "\"<img src=x onerror=alert(1)>")))
  =
  lemma_escape_html_safe "\"<img src=x onerror=alert(1)>";
  ()
