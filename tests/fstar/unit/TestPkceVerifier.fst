module TestPkceVerifier

open Pkce.Verification
open Pkce.Verifier
open Pkce.Challenge
open Pkce.Method_selection

assume val good_pair : unit -> Tot (p:(code_verifier * code_challenge){ base64url_encode (sha256 (fst p)) = snd p })
assume val bad_pair : unit -> Tot (p:(code_verifier * code_challenge){ base64url_encode (sha256 (fst p)) <> snd p })

let _ =
  let v, c = good_pair () in
  assert (verify_pkce v c S256)

let _ =
  let v, c = bad_pair () in
  assert (not (verify_pkce v c S256))
