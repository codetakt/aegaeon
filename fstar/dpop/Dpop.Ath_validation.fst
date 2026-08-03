module Dpop.Ath_validation

open FStar.Bytes
open FStar.Base64
open HashComputation

(** SHA-256 hashing: delegates to HashComputation.compute_hash SHA256.

    The underlying compute_hash dispatches to HACL* SHA-256 via
    Verified.Crypto.Bridge. Real cryptographic computation. *)
val sha256 : bytes -> bytes
let sha256 b = compute_hash SHA256 b

(** Validate the `ath` claim by comparing it to the
    base64url-encoded SHA-256 hash of the access token. *)
val validate_ath : token:bytes -> claim:string -> Tot (b:bool{b <==> base64url_encode (sha256 token) = claim})
let validate_ath token claim =
  base64url_encode (sha256 token) = claim

(** Lemma: a token hashed and encoded validates against itself. *)
let lemma_validate_ath token :
  Lemma (validate_ath token (base64url_encode (sha256 token))) =
  ()
