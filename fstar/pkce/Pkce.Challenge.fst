module Pkce.Challenge

open FStar.String

(** Code challenge derived from a `code_verifier` using the S256 method.
    For S256 the base64url-encoded hash is always 43 characters. *)
type code_challenge = s:string{ String.length s = 43 }

(** Trivial lemma: any `code_challenge` has the expected length. *)
let lemma_code_challenge_len (c:code_challenge) : Lemma (String.length c = 43) =
  ()
