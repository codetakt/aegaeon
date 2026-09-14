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

private let rec lemma_fb_to_hacl_aux_index
  (input: FB.bytes) (i: nat{i <= FB.length input}) (j: nat{i + j < FB.length input})
  : Lemma (ensures Seq.index (fb_to_hacl_aux input i) j == pub_to_sec (FB.index input (i + j)))
          (decreases (FB.length input - i))
  = if j = 0 then () else lemma_fb_to_hacl_aux_index input (i + 1) (j - 1)

(** Pointwise characterisation of the byte bridge: used by the HMAC key
    equivalence witness (Verified.Crypto.Hmac.KeyEquiv). *)
let lemma_fb_to_hacl_index (input: FB.bytes) (j: nat{j < FB.length input})
  : Lemma (Seq.index (fb_to_hacl input) j == pub_to_sec (FB.index input j))
  = lemma_fb_to_hacl_aux_index input 0 j

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
[@@"opaque_to_smt"]
let hmac_sha256
  (key: FB.bytes{FB.length key > 0 /\
                  FB.length key < sha256_max_input /\
                  FB.length key + SH.block_length SH.SHA2_256 < pow2 32})
  (data: FB.bytes{(FB.length data + SH.block_length SH.SHA2_256) < sha256_max_input})
  : Tot (r:FB.bytes{FB.length r = 32})
  = hacl_to_fb (SHMAC.hmac SH.SHA2_256 (fb_to_hacl key) (fb_to_hacl data))

(** HMAC-SHA384 via HACL* Spec.Agile.HMAC. *)
[@@"opaque_to_smt"]
let hmac_sha384
  (key: FB.bytes{FB.length key > 0 /\
                  FB.length key < sha384_max_input /\
                  FB.length key + SH.block_length SH.SHA2_384 < pow2 32})
  (data: FB.bytes{(FB.length data + SH.block_length SH.SHA2_384) < sha384_max_input})
  : Tot (r:FB.bytes{FB.length r = 48})
  = hacl_to_fb (SHMAC.hmac SH.SHA2_384 (fb_to_hacl key) (fb_to_hacl data))

(** HMAC-SHA512 via HACL* Spec.Agile.HMAC. *)
[@@"opaque_to_smt"]
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
    Marked opaque_to_smt -- downstream sees only the type signature unless a
    lemma in this module reveals the (small) body; the SHA-256 computation
    itself stays behind the irreducible sha256_hash wrapper. *)
[@@"opaque_to_smt"]
let sha256_of_string (input: string) : Tot string =
  let input_bytes = string_to_bytes input in
  if FB.length input_bytes >= sha256_max_input then
    ""  (* Unreachable for any practical input -- sha256_max_input is approx 2^61 *)
  else
    FStar.Base64.base64url_encode (sha256_hash input_bytes)

(* -- Input-domain facts ---------------------------------- *)

(** Every FStar.Bytes value is shorter than 2^32 bytes, which is below the
    SHA-2 input limits.  The over-length fallback branches of the string
    wrapper above and of HashComputation.compute_hash are therefore
    unreachable for this input type.  This is a fact about the F* model's
    input domain, not about the runtime (Rust slices and C buffers carry
    their own bounds; see the assumption register). *)
let lemma_sha2_limits_exceed_bytes ()
  : Lemma (pow2 32 <= sha256_max_input /\ pow2 32 <= sha384_max_input /\
           pow2 32 <= sha512_max_input)
  = assert_norm (sha256_max_input = pow2 61 - 1);
    assert_norm (sha384_max_input = pow2 125 - 1);
    assert_norm (sha512_max_input = pow2 125 - 1);
    assert_norm (pow2 32 <= pow2 61 - 1);
    assert_norm (pow2 32 <= pow2 125 - 1)

let lemma_bytes_within_sha256_limit (b: FB.bytes)
  : Lemma (FB.length b < sha256_max_input)
  = lemma_sha2_limits_exceed_bytes ()

(* -- Hash bad events (no axioms) -------------------------- *)

(** The collision bad event for SHA-256 on the F* byte domain.  It is a
    definition, not an assumption: whenever two distinct in-range inputs
    share a digest, this event holds and every downstream theorem exposes
    it as an explicit alternative.  The computational premise that this
    event is infeasible to trigger is recorded outside F* (register entry
    A-SHA256-CR); nothing in F* asserts it. *)
let sha256_collision (a b: FB.bytes) : Type0 =
  FB.length a < sha256_max_input /\ FB.length b < sha256_max_input /\
  a =!= b /\ sha256_hash a = sha256_hash b

let sha384_collision (a b: FB.bytes) : Type0 =
  FB.length a < sha384_max_input /\ FB.length b < sha384_max_input /\
  a =!= b /\ sha384_hash a = sha384_hash b

let sha512_collision (a b: FB.bytes) : Type0 =
  FB.length a < sha512_max_input /\ FB.length b < sha512_max_input /\
  a =!= b /\ sha512_hash a = sha512_hash b

(** Case split: equal digests come from equal inputs or from a witnessed
    collision.  Proved (classical case split), replaces the former universal
    injectivity axiom lemma_sha256_collision_resistant. *)
let lemma_sha256_hash_eq_cases
  (a: FB.bytes{FB.length a < sha256_max_input})
  (b: FB.bytes{FB.length b < sha256_max_input})
  : Lemma (sha256_hash a = sha256_hash b ==> a = b \/ sha256_collision a b)
  = ()

let lemma_sha384_hash_eq_cases
  (a: FB.bytes{FB.length a < sha384_max_input})
  (b: FB.bytes{FB.length b < sha384_max_input})
  : Lemma (sha384_hash a = sha384_hash b ==> a = b \/ sha384_collision a b)
  = ()

let lemma_sha512_hash_eq_cases
  (a: FB.bytes{FB.length a < sha512_max_input})
  (b: FB.bytes{FB.length b < sha512_max_input})
  : Lemma (sha512_hash a = sha512_hash b ==> a = b \/ sha512_collision a b)
  = ()

(** SHA-256 determinism (trivially true for Tot functions). *)
val lemma_sha256_deterministic:
  input:FB.bytes{FB.length input < sha256_max_input} ->
  Lemma (sha256_hash input = sha256_hash input)
let lemma_sha256_deterministic _input = ()

(* -- String-domain boundaries ----------------------------- *)

(** String encoding boundary.  FStar.Bytes.bytes_of_string is abstract in
    ulib: no injectivity lemma exists, and the callers' ASCII restriction is
    not part of the F* string type.  Two distinct strings with the same byte
    image are therefore a separate, named event; it is never assumed away. *)
let string_encoding_collision (a b: string) : Type0 =
  a =!= b /\ FB.bytes_of_string a = FB.bytes_of_string b

(** String-domain collision event on the composed wrapper. *)
let sha256_of_string_collision (a b: string) : Type0 =
  a =!= b /\ sha256_of_string a = sha256_of_string b

(** The over-length event of sha256_of_string (the branch returning the empty
    string).  Named so that the register can refer to it; it is proved
    unreachable below, so it is a runtime input-domain boundary only. *)
let sha256_of_string_overlength (a: string) : Type0 =
  FB.length (string_to_bytes a) >= sha256_max_input

(** The over-length branch of sha256_of_string is unreachable: the byte image
    of any string is an FStar.Bytes value. *)
let lemma_sha256_of_string_in_range (a: string)
  : Lemma (FB.length (string_to_bytes a) < sha256_max_input)
  = lemma_bytes_within_sha256_limit (string_to_bytes a)

let lemma_sha256_of_string_overlength_unreachable (a: string)
  : Lemma (~(sha256_of_string_overlength a))
  = lemma_sha256_of_string_in_range a

let lemma_sha256_of_string_unfold (a: string)
  : Lemma (FB.length (string_to_bytes a) < sha256_max_input /\
           sha256_of_string a == base64url_encode (sha256_hash (string_to_bytes a)))
  = lemma_sha256_of_string_in_range a;
    reveal_opaque (`%sha256_of_string) sha256_of_string

(** Case split for the string wrapper: equal outputs come from equal strings,
    from the string-encoding event, or from a SHA-256 collision on the byte
    images.  base64url is injective (proved in FStar.Base64), so it
    contributes no event of its own.  Replaces the former axiom
    lemma_sha256_of_string_collision_resistant. *)
let lemma_sha256_of_string_eq_cases (a b: string)
  : Lemma (sha256_of_string a = sha256_of_string b ==>
           a = b \/ string_encoding_collision a b \/
           sha256_collision (string_to_bytes a) (string_to_bytes b))
  = lemma_sha256_of_string_unfold a;
    lemma_sha256_of_string_unfold b;
    lemma_sha256_of_string_in_range a;
    lemma_sha256_of_string_in_range b;
    if sha256_of_string a = sha256_of_string b then
      base64url_encode_injective
        (sha256_hash (string_to_bytes a)) (sha256_hash (string_to_bytes b))

let lemma_sha256_of_string_collision_witness (a b: string)
  : Lemma (requires sha256_of_string_collision a b)
          (ensures string_encoding_collision a b \/
                   sha256_collision (string_to_bytes a) (string_to_bytes b))
  = lemma_sha256_of_string_eq_cases a b

(* -- HMAC key equivalence --------------------------------- *)

let hmac_sha256_key_admissible (key: FB.bytes) : Type0 =
  FB.length key > 0 /\ FB.length key < sha256_max_input /\
  FB.length key + SH.block_length SH.SHA2_256 < pow2 32

let hmac_sha256_data_admissible (data: FB.bytes) : Type0 =
  (FB.length data + SH.block_length SH.SHA2_256) < sha256_max_input

(** Extensional key equivalence for HMAC-SHA-256: two raw keys that produce
    the same MAC for every admissible input.  Distinct raw keys can be
    equivalent (HMAC pads keys shorter than the block length with zero
    bytes; the witness is proved in Verified.Crypto.Hmac.KeyEquiv), which is
    why a MAC unforgeability statement must be phrased over equivalence
    classes and not over raw key inequality. *)
let hmac_sha256_key_equiv (k1 k2: FB.bytes) : Type0 =
  hmac_sha256_key_admissible k1 /\ hmac_sha256_key_admissible k2 /\
  (forall (data: FB.bytes). hmac_sha256_data_admissible data ==>
     hmac_sha256 k1 data = hmac_sha256 k2 data)

(* -- Ed25519: honest history and forgery event ------------ *)

(** An honest signing event: a signature produced by the holder of the
    secret key for public key se_public_key over se_message.  The secret key
    and the signing algorithm are not modelled in F*; the history is the
    protocol-level record of what honest signers produced. *)
type ed25519_signing_event = {
  se_public_key: FB.bytes;
  se_message: FB.bytes;
  se_signature: FB.bytes
}

let ed25519_message_signed
  (history: list ed25519_signing_event) (pk: FB.bytes) (msg: FB.bytes) : Type0 =
  exists (e: ed25519_signing_event).
    FStar.List.Tot.mem e history /\ e.se_public_key = pk /\ e.se_message = msg

(** Public keys registered by the external game's honest key-generation step.
    Membership is a provenance input, not proof of generation or randomness.
    The computational premise applies only when that external history is valid;
    an arbitrary caller-supplied list does not establish this condition. *)
let ed25519_key_generated (honest_keys: list FB.bytes) (pk: FB.bytes) : Type0 =
  FB.length pk = 32 /\ FStar.List.Tot.mem pk honest_keys

(** The EUF-CMA forgery event: a signature that verifies under an
    uncompromised public key for a message the honest signer never signed.
    Re-presenting an honestly issued signature is NOT a forgery and does not
    show that the presenter knows the secret key.  The computational premise
    that this event is infeasible for adversaries with signing-oracle access
    is register entry A-ED25519-EUF-CMA; F* does not assert it. *)
let ed25519_forgery
  (honest_keys: list FB.bytes)
  (history: list ed25519_signing_event) (compromised: list FB.bytes)
  (pk: FB.bytes{FB.length pk = 32})
  (msg: FB.bytes{FB.length msg <= Lib.IntTypes.max_size_t})
  (sig_: FB.bytes{FB.length sig_ = 64}) : Type0 =
  ed25519_key_generated honest_keys pk /\ ed25519_verify pk msg sig_ = true /\
  ~(FStar.List.Tot.mem pk compromised) /\
  ~(ed25519_message_signed history pk msg)

(** Case split: a verifying signature is outside the honest key-generation
    domain, is under a compromised key, or is an
    honestly signed message (possibly re-presented), or is a forgery event.
    Proved; replaces the former vacuous lemma_ed25519_unforgeable
    (whose conclusion was True). *)
let lemma_ed25519_verify_cases
  (honest_keys: list FB.bytes)
  (history: list ed25519_signing_event) (compromised: list FB.bytes)
  (pk: FB.bytes{FB.length pk = 32})
  (msg: FB.bytes{FB.length msg <= Lib.IntTypes.max_size_t})
  (sig_: FB.bytes{FB.length sig_ = 64})
  : Lemma (ed25519_verify pk msg sig_ = true ==>
           ~(ed25519_key_generated honest_keys pk) \/
           FStar.List.Tot.mem pk compromised \/
           ed25519_message_signed history pk msg \/
           ed25519_forgery honest_keys history compromised pk msg sig_)
  = ()
