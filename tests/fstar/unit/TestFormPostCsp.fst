module TestFormPostCsp

open FormPost

let _ =
  assert (form_post_csp_enforced "https://example.com" "nonce123")
