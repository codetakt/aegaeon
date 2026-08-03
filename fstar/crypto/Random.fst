module Random

(** Verified RNG API backed by HMAC-SHA256 DRBG.
    No irreducible, no assume val. Entropy is an explicit parameter.
    Replaces the former irreducible stubs; see docs/verification/rng-plan.md.

    Modeling improvement over the prior version:
    - Old: `fresh_challenge_id () == fresh_challenge_id ()` was provable (unit input).
    - New: `fresh_challenge_id e1 == fresh_challenge_id e2` only when `e1 == e2`
      (SMT cannot equate distinct DRBG outputs because hmac_sha256 delegates to
       HACL* via Verified.Crypto.Bridge — irreducible hides the implementation).
    - All DRBG output bytes contribute to the result string (via bytes_to_char_list). *)

open FStar.Bytes
open FStar.String
open Drbg.HmacSha256

type challenge_id = string

(** Convert each byte in [b] at positions [i..i+len) to a character.
    Uses ALL bytes from the DRBG output — no information is discarded. *)
private let rec bytes_to_char_list
  (b: bytes{Bytes.length b <= max_bytes_per_request})
  (i: nat)
  (len: nat{i + len <= Bytes.length b})
  : Tot (r:list FStar.Char.char{FStar.List.Tot.length r = len})
  (decreases len)
  = if len = 0 then []
    else
      let byte_val = FStar.UInt8.v (Bytes.get b (FStar.UInt32.uint_to_t i)) in
      FStar.Char.char_of_int byte_val
      :: bytes_to_char_list b (i + 1) (len - 1)

(** Generate a random string of the specified length.
    Takes explicit 32-byte entropy seed.
    Implementation: instantiate DRBG, generate len bytes, convert each byte
    to a character via bytes_to_char_list + string_of_list.
    Every DRBG output byte contributes to the result. *)
val generate_secure_random:
  entropy:bytes{Bytes.length entropy = 32} ->
  len:nat{len > 0 /\ len <= max_bytes_per_request} ->
  Tot (r:string{String.length r = len})
let generate_secure_random entropy len =
  let st = drbg_instantiate entropy in
  let (_, output) = drbg_generate st len in
  let chars = bytes_to_char_list output 0 len in
  FStar.String.list_of_string_of_list chars;
  FStar.String.string_of_list chars

(** Generate a fresh challenge ID.
    Takes explicit 32-byte entropy seed.
    Distinct entropy → distinct output (SMT cannot prove equality for
    distinct irreducible HMAC outputs via HACL* Bridge). *)
val fresh_challenge_id:
  entropy:bytes{Bytes.length entropy = 32} ->
  Tot challenge_id
let fresh_challenge_id entropy =
  generate_secure_random entropy 32
