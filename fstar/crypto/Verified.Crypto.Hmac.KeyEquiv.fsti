module Verified.Crypto.Hmac.KeyEquiv

(** Machine-checked witness that HMAC key material is not injective on the
    verification behaviour: HMAC (RFC 2104, HACL* Spec.Agile.HMAC) pads keys
    shorter than the hash block length with zero bytes before use, so a key
    and the same key with a trailing zero byte are extensionally equivalent.

    This module exists to make that fact a theorem in the assumption record.
    It refutes any statement that derives "verification fails under every
    other raw key" from raw key inequality, and it justifies phrasing MAC
    unforgeability over key equivalence classes (Jose.Jws.Verify).

    It uses `friend Spec.Agile.HMAC` to see the provider's definition of
    `wrap`/`hmac`; that exposure is recorded in the assumption graph as an
    implementation-exposing edge. *)

module FB = FStar.Bytes
module SH = Spec.Hash.Definitions
open Verified.Crypto.Bridge

(** A key strictly shorter than the SHA-256 block (64 bytes) that is
    admissible for hmac_sha256 both as is and with one zero byte appended. *)
let short_admissible_key (key: FB.bytes) : Type0 =
  0 < FB.length key /\ FB.length key < SH.block_length SH.SHA2_256 /\
  hmac_sha256_key_admissible key /\
  hmac_sha256_key_admissible (FB.append key (FB.create 1ul 0uy))

(** Any key shorter than the block length is such a key (the SHA-2 input
    limit exceeds every FStar.Bytes length). *)
val lemma_short_key_admissible
  (key: FB.bytes{0 < FB.length key /\ FB.length key < SH.block_length SH.SHA2_256})
  : Lemma (short_admissible_key key)

(** The MAC is unchanged by appending a zero byte to a short key. *)
val lemma_hmac_sha256_zero_pad
  (key: FB.bytes{short_admissible_key key})
  (data: FB.bytes{hmac_sha256_data_admissible data})
  : Lemma (hmac_sha256 key data = hmac_sha256 (FB.append key (FB.create 1ul 0uy)) data)

(** Two distinct raw keys that are HMAC-SHA-256 key equivalent. *)
val lemma_hmac_sha256_zero_pad_key_equiv
  (key: FB.bytes{short_admissible_key key})
  : Lemma (key =!= FB.append key (FB.create 1ul 0uy) /\
           hmac_sha256_key_equiv key (FB.append key (FB.create 1ul 0uy)))
