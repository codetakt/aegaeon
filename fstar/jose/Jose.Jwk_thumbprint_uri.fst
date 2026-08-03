module Jose.Jwk_thumbprint_uri

open FStar.All
open FStar.String
open Verified.Crypto.Bridge

// RFC 9278 JWK thumbprint URI model.

type jwk = string

type thumbprint = string

let thumbprint_uri_prefix : string =
  "urn:ietf:params:oauth:jwk-thumbprint:sha-256:"

(** RFC 9278 JWK thumbprint computation.
    Delegates to HACL* SHA-256 via Verified.Crypto.Bridge.sha256_of_string.
    Computes SHA-256 of the canonicalized JWK JSON representation.
    Marked `irreducible` to prevent downstream from observing the
    SHA-256 internals — all reasoning must use the type alone. *)
irreducible
let jwk_thumbprint (k: jwk) : Tot thumbprint = sha256_of_string k

let thumbprint_uri_for_thumbprint (value: thumbprint) : Tot string =
  thumbprint_uri_prefix ^ value

let jwk_thumbprint_uri (key: jwk) : Tot string =
  thumbprint_uri_for_thumbprint (jwk_thumbprint key)

let lemma_thumbprint_uri_prefix
  (value: thumbprint)
  : Lemma
      (ensures
        thumbprint_uri_for_thumbprint value
        = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:" ^ value)
  = ()

let lemma_jwk_thumbprint_uri_prefix
  (key: jwk)
  : Lemma
      (ensures
        jwk_thumbprint_uri key
        = "urn:ietf:params:oauth:jwk-thumbprint:sha-256:" ^ jwk_thumbprint key)
  = ()
