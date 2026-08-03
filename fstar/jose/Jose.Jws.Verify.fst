module Jose.Jws.Verify

(** Shared JWS signature verification primitives.

    Provides the abstract jws_verify function used by both
    Jose.Federation (trust chain verification) and TrustMark
    (trust mark JWS verification).

    Crypto operations delegate to HACL via Verified.Crypto.Bridge:
      - HS256/HS384/HS512  -> HMAC-SHA-256/384/512 (proper MAC comparison)
      - EdDSA              -> Ed25519 verify (over signing_input + decoded sig)
      - PS256/Unsupported  -> false (compat or rejected)

    Uses Jose.Jws_serialization.parse_compact to properly split compact JWS
    into signing_input and decoded signature before verification.

    Security properties are honest crypto assumptions (assume val):
      - jws_verify_correct       : bool excluded middle (proved, SMTPat)
      - jws_verify_unforgeable   : EUF-CMA unforgeability (assume val) *)

open Jose.Jwk_structure
open Jose.Alg_policy
open Jose.Jws_serialization
open FStar.Bytes
open Verified.Crypto.Bridge
module FB = FStar.Bytes
module SH = Spec.Hash.Definitions

(* JWS signature verification via HACL.
   Parses the compact JWS via parse_compact, then:
   - HMAC: computes MAC over signing_input, compares with decoded signature
   - EdDSA: passes signing_input and decoded signature to ed25519_verify
   Real cryptographic computation -- NOT false/constant.
   Marked irreducible -- Z3 sees only the type signature.
   NOTE: HMAC comparison uses F* structural equality (=) in the spec model.
   This is NOT constant-time in the spec, but the runtime verification
   backend uses constant-time comparison. The spec model captures
   functional correctness, not timing properties. *)
irreducible
let jws_verify (key:jwk) (token:string) : Tot bool =
  match parse_compact token with
  | None -> false
  | Some parts ->
    let si = parts.signing_input in
    let sig_bytes = parts.sig_bytes in
    let key_bytes = key.k in
    let klen = FB.length key_bytes in
    let silen = FB.length si in
    match key.alg with
    | HS256 ->
      if klen > 0 && klen < sha256_max_input &&
         klen + SH.block_length SH.SHA2_256 < pow2 32 &&
         (silen + SH.block_length SH.SHA2_256) < sha256_max_input
      then
        let expected_mac = hmac_sha256 key_bytes si in
        expected_mac = sig_bytes
      else false
    | HS384 ->
      if klen > 0 && klen < sha384_max_input &&
         klen + SH.block_length SH.SHA2_384 < pow2 32 &&
         (silen + SH.block_length SH.SHA2_384) < sha384_max_input
      then
        let expected_mac = hmac_sha384 key_bytes si in
        expected_mac = sig_bytes
      else false
    | HS512 ->
      if klen > 0 && klen < sha512_max_input &&
         klen + SH.block_length SH.SHA2_512 < pow2 32 &&
         (silen + SH.block_length SH.SHA2_512) < sha512_max_input
      then
        let expected_mac = hmac_sha512 key_bytes si in
        expected_mac = sig_bytes
      else false
    | EdDSA ->
      if klen = 32 && FB.length sig_bytes = 64 &&
         FB.length si <= Lib.IntTypes.max_size_t
      then ed25519_verify key_bytes si sig_bytes
      else false
    | _ -> false  (* PS256/Unsupported: compat allowlist or rejected *)

(** Correctness: verification returns a definite result.
    Bool excluded middle -- the SMTPat provides a trigger for Z3 to case-split
    on jws_verify results, which aids proof automation in Federation/TrustMark
    lemmas. *)
let jws_verify_correct (key:jwk) (token:string)
  : Lemma (ensures jws_verify key token = true \/
                   jws_verify key token = false)
  [SMTPat (jws_verify key token)]
  = ()

(** Unforgeability: without the private key, an adversary cannot produce
    a token that verifies under a different key (honest crypto assumption).
    Precondition uses key1.k =!= key2.k (raw key material inequality).

    This is an EUF-CMA assumption -- NOT provable from first principles.
    The previous proof was vacuous (jws_verify = false -> premise contradictory
    after reveal_opaque). *)
assume val jws_verify_unforgeable:
  key1:jwk -> key2:jwk -> token:string ->
  Lemma (requires key1.k =!= key2.k /\ jws_verify key1 token = true)
        (ensures jws_verify key2 token = false)
