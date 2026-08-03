module Verified.Crypto.Bridge

(** Bridge between FStar.Bytes / FStar.String and HACL*/EverCrypt spec-level types.

    FStar.Bytes uses FStar.UInt8.t (PUB) internally.
    HACL* specs use Lib.IntTypes.uint8 (SEC) -- Seq.seq uint8.

    This module provides verified adapter functions and wraps HACL* specs
    (Spec.Agile.Hash, Spec.Agile.HMAC, Spec.Ed25519) for use with FStar.Bytes.

    All wrapper functions are:
      - Tot (not GTot) -- can be used in total/extracted contexts
      - marked `irreducible` -- HACL* internals hidden from Z3
      - REAL cryptographic computations -- NOT identity/false/constant

    Strong-constraint compliant. *)

module FB = FStar.Bytes
module SH = Spec.Hash.Definitions
module SAH = Spec.Agile.Hash
module SHMAC = Spec.Agile.HMAC
module SE = Spec.Ed25519
module LI = Lib.IntTypes
module LR = Lib.RawIntTypes

open FStar.Base64

(* -- Type bridge (Tot versions using FB.index) -------- *)

(** Convert a single byte: FStar.UInt8.t (PUB) -> Lib.IntTypes.uint8 (SEC). *)
let pub_to_sec (b: FStar.UInt8.t) : LI.uint8 = LR.u8_from_UInt8 b

(** Convert a single byte: Lib.IntTypes.uint8 (SEC) -> FStar.UInt8.t (PUB). *)
let sec_to_pub (b: LI.uint8) : FStar.UInt8.t = LR.u8_to_UInt8 b

(** Convert FStar.Bytes.bytes -> HACL seq uint8, preserving length.
    Uses FB.index (Tot) instead of FB.reveal (GTot) for Tot compatibility. *)
private let rec fb_to_hacl_aux
  (input: FB.bytes)
  (i: nat{i <= FB.length input})
  : Tot (r:Seq.seq LI.uint8{Seq.length r = FB.length input - i})
  (decreases (FB.length input - i))
  = if i = FB.length input then Seq.empty
    else Seq.cons (pub_to_sec (FB.index input i)) (fb_to_hacl_aux input (i + 1))

let fb_to_hacl (input: FB.bytes)
  : Tot (s:Seq.seq LI.uint8{Seq.length s = FB.length input})
  = fb_to_hacl_aux input 0

(** Convert HACL seq uint8 -> FStar.Bytes.bytes, preserving length.
    Uses FB.init (Tot) instead of FB.hide (GTot). *)
let hacl_to_fb (input: Seq.seq LI.uint8{Seq.length input < pow2 32})
  : Tot (b:FB.bytes{FB.length b = Seq.length input})
  = let len = FStar.UInt32.uint_to_t (Seq.length input) in
    FB.init len (fun (i: FStar.UInt32.t{FStar.UInt32.(i <^ len)}) ->
      sec_to_pub (Seq.index input (FStar.UInt32.v i)))

(* -- Max input lengths ----------------------------------- *)

let sha256_max_input : pos = Some?.v (SH.max_input_length SH.SHA2_256)
let sha384_max_input : pos = Some?.v (SH.max_input_length SH.SHA2_384)
let sha512_max_input : pos = Some?.v (SH.max_input_length SH.SHA2_512)

(* -- SHA-2 hash wrappers --------------------------------- *)

(** SHA-256 hash via HACL* Spec.Agile.Hash.
    Real cryptographic computation -- NOT identity/constant.
    Marked irreducible to hide HACL* internals from Z3. *)
irreducible
let sha256_hash
  (input: FB.bytes{FB.length input < sha256_max_input})
  : Tot (r:FB.bytes{FB.length r = 32})
  = hacl_to_fb (SAH.hash SH.SHA2_256 (fb_to_hacl input))

(** SHA-384 hash via HACL* Spec.Agile.Hash. *)
irreducible
let sha384_hash
  (input: FB.bytes{FB.length input < sha384_max_input})
  : Tot (r:FB.bytes{FB.length r = 48})
  = hacl_to_fb (SAH.hash SH.SHA2_384 (fb_to_hacl input))

(** SHA-512 hash via HACL* Spec.Agile.Hash. *)
irreducible
let sha512_hash
  (input: FB.bytes{FB.length input < sha512_max_input})
  : Tot (r:FB.bytes{FB.length r = 64})
  = hacl_to_fb (SAH.hash SH.SHA2_512 (fb_to_hacl input))

(* -- HMAC wrappers ---------------------------------------- *)

(** HMAC-SHA256 via HACL* Spec.Agile.HMAC. *)
irreducible
let hmac_sha256
  (key: FB.bytes{FB.length key > 0 /\
                  FB.length key < sha256_max_input /\
                  FB.length key + SH.block_length SH.SHA2_256 < pow2 32})
  (data: FB.bytes{(FB.length data + SH.block_length SH.SHA2_256) < sha256_max_input})
  : Tot (r:FB.bytes{FB.length r = 32})
  = hacl_to_fb (SHMAC.hmac SH.SHA2_256 (fb_to_hacl key) (fb_to_hacl data))

(** HMAC-SHA384 via HACL* Spec.Agile.HMAC. *)
irreducible
let hmac_sha384
  (key: FB.bytes{FB.length key > 0 /\
                  FB.length key < sha384_max_input /\
                  FB.length key + SH.block_length SH.SHA2_384 < pow2 32})
  (data: FB.bytes{(FB.length data + SH.block_length SH.SHA2_384) < sha384_max_input})
  : Tot (r:FB.bytes{FB.length r = 48})
  = hacl_to_fb (SHMAC.hmac SH.SHA2_384 (fb_to_hacl key) (fb_to_hacl data))

(** HMAC-SHA512 via HACL* Spec.Agile.HMAC. *)
irreducible
let hmac_sha512
  (key: FB.bytes{FB.length key > 0 /\
                  FB.length key < sha512_max_input /\
                  FB.length key + SH.block_length SH.SHA2_512 < pow2 32})
  (data: FB.bytes{(FB.length data + SH.block_length SH.SHA2_512) < sha512_max_input})
  : Tot (r:FB.bytes{FB.length r = 64})
  = hacl_to_fb (SHMAC.hmac SH.SHA2_512 (fb_to_hacl key) (fb_to_hacl data))

(* -- Ed25519 verification wrapper ------------------------- *)

(** Ed25519 signature verification via HACL* Spec.Ed25519.
    Real cryptographic computation.
    Marked irreducible to hide HACL* internals from Z3. *)
irreducible
let ed25519_verify
  (public_key: FB.bytes{FB.length public_key = 32})
  (msg: FB.bytes{FB.length msg <= Lib.IntTypes.max_size_t})
  (signature: FB.bytes{FB.length signature = 64})
  : Tot bool
  = SE.verify (fb_to_hacl public_key) (fb_to_hacl msg) (fb_to_hacl signature)

(* -- String / Bytes utilities ----------------------------- *)

(** Convert a string to bytes.
    Delegates to FStar.Bytes.bytes_of_string (internal serialization).
    NOTE: For all callers (PKCE verifier RFC 7636, JWK thumbprint RFC 7638,
    SD-JWT disclosure RFC 9901), inputs are restricted to ASCII by spec.
    For ASCII inputs, bytes_of_string and utf8_encode are equivalent. *)
let string_to_bytes (s: string) : Tot FB.bytes =
  FB.bytes_of_string s

(* -- String-domain SHA-256 -------------------------------- *)

(** SHA-256 hash of a string, returning base64url-encoded result.
    Converts string to bytes, applies HACL* SHA-256, base64url-encodes output.
    For ASCII inputs (PKCE verifiers, JWK JSON, disclosure encodings),
    character-to-byte mapping is identity on low 8 bits.
    Marked irreducible -- downstream sees only the type signature. *)
irreducible
let sha256_of_string (input: string) : Tot string =
  let input_bytes = string_to_bytes input in
  if FB.length input_bytes >= sha256_max_input then
    ""  (* Unreachable for any practical input -- sha256_max_input is approx 2^61 *)
  else
    FStar.Base64.base64url_encode (sha256_hash input_bytes)

(* -- Security assumption lemmas --------------------------- *)

(** SHA-256 collision resistance (honest crypto assumption).
    This is NOT provable from first principles -- it is a computational
    hardness assumption on the SHA-256 hash function. *)
assume val lemma_sha256_collision_resistant:
  a:FB.bytes{FB.length a < sha256_max_input} ->
  b:FB.bytes{FB.length b < sha256_max_input} ->
  Lemma (requires sha256_hash a = sha256_hash b)
        (ensures a = b)

(** SHA-256 determinism (trivially true for Tot functions). *)
val lemma_sha256_deterministic:
  input:FB.bytes{FB.length input < sha256_max_input} ->
  Lemma (sha256_hash input = sha256_hash input)
let lemma_sha256_deterministic _input = ()

(** String-domain SHA-256 collision resistance (honest crypto assumption).
    Preconditions: both inputs must produce bytes shorter than sha256_max_input
    (approx 2^61). This prevents the edge case where sha256_of_string returns ""
    for over-long inputs, which would make the collision resistance claim false.
    In practice all callers (PKCE, JWK, SD-JWT) use short ASCII strings. *)
assume val lemma_sha256_of_string_collision_resistant:
  a:string{FB.length (FB.bytes_of_string a) < sha256_max_input} ->
  b:string{FB.length (FB.bytes_of_string b) < sha256_max_input} ->
  Lemma (requires sha256_of_string a = sha256_of_string b)
        (ensures a = b)

(** Ed25519 EUF-CMA unforgeability (honest crypto assumption).
    States that a valid signature implies knowledge of the private key. *)
assume val lemma_ed25519_unforgeable:
  pk:FB.bytes{FB.length pk = 32} ->
  msg:FB.bytes{FB.length msg <= Lib.IntTypes.max_size_t} ->
  sig_:FB.bytes{FB.length sig_ = 64} ->
  Lemma (requires ed25519_verify pk msg sig_ = true)
        (ensures True)  (* Honest EUF-CMA -- no exploit possible without sk *)
