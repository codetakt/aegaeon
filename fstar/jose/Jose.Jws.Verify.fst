module Jose.Jws.Verify

(** Shared cryptographic signing-input verification primitive.

    Provides the abstract jws_verify function used by both
    Jose.Federation (trust chain verification) and TrustMark
    (trust mark JWS verification).

    Crypto operations delegate to HACL via Verified.Crypto.Bridge:
      - HS256/HS384/HS512  -> HMAC-SHA-256/384/512 (proper MAC comparison)
      - EdDSA              -> Ed25519 verify (over signing_input + decoded sig)
      - PS256/Unsupported  -> false (compat or rejected)

    Uses Jose.Jws_serialization.parse_compact to properly split compact JWS
    into signing_input and decoded signature before verification.

    Model boundary: this primitive dispatches on key.alg without decoding the
    protected JSON header or checking its alg. Its lemmas and named events do
    not establish wire-level JWS algorithm binding. Federation and TrustMark
    inherit that open obligation. The repository's FStar.Json.parse is a stub;
    inserting it as a guard would remove every successful path. A concrete
    decoder and reachable matching-algorithm controls remain required, as
    recorded in docs/verification/claims/model-fidelity-register.md.

    Security-relevant statements in this module are all proved; the module
    declares no axiom:
      - jws_verify_correct           : bool excluded middle (proved, SMTPat)
      - lemma_jws_verify_hs_key_equiv: key-equivalent HMAC keys verify alike
      - lemma_jws_verify_hs_accepts_mac: the honest MAC is accepted
      - lemma_jws_verify_cases       : a verifying token is outside the key-generation
                                       security domain, under a compromised
                                       key, honestly issued, or a named forgery
                                       event (jws_mac_forgery / jws_eddsa_forgery)
    The computational premises that the forgery events are infeasible
    (HMAC-SHA-2 PRF/EUF-CMA, Ed25519 EUF-CMA) are recorded outside F* in the
    assumption register; F* asserts nothing about them.  The former
    jws_verify_unforgeable axiom (raw-key inequality implies verification
    failure) was false: HMAC pads short keys with zero bytes
    (Verified.Crypto.Hmac.KeyEquiv), so distinct raw keys can verify the same
    token. *)

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
   Marked opaque_to_smt -- Z3 sees only the type signature unless a lemma in
   this module reveals the dispatch body; the HACL* computations stay behind
   the Bridge wrappers.
   NOTE: HMAC comparison uses F* structural equality (=) in the spec model.
   This is NOT constant-time in the spec, but the runtime verification
   backend uses constant-time comparison. The spec model captures
   functional correctness, not timing properties. *)
[@@"opaque_to_smt"]
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

(* -- HMAC key admissibility and key equivalence ---------- *)

let is_hs (a:alg) : bool = HS256? a || HS384? a || HS512? a

(** The key guards of jws_verify, per HMAC algorithm. *)
let hs_key_admissible (a:alg) (k:FB.bytes) : bool =
  let klen = FB.length k in
  match a with
  | HS256 -> klen > 0 && klen < sha256_max_input &&
             klen + SH.block_length SH.SHA2_256 < pow2 32
  | HS384 -> klen > 0 && klen < sha384_max_input &&
             klen + SH.block_length SH.SHA2_384 < pow2 32
  | HS512 -> klen > 0 && klen < sha512_max_input &&
             klen + SH.block_length SH.SHA2_512 < pow2 32
  | _ -> false

(** The signing-input guards of jws_verify, per HMAC algorithm. *)
let hs_data_admissible (a:alg) (d:FB.bytes) : bool =
  let dlen = FB.length d in
  match a with
  | HS256 -> (dlen + SH.block_length SH.SHA2_256) < sha256_max_input
  | HS384 -> (dlen + SH.block_length SH.SHA2_384) < sha384_max_input
  | HS512 -> (dlen + SH.block_length SH.SHA2_512) < sha512_max_input
  | _ -> false

(** The MAC that jws_verify compares against, per HMAC algorithm. *)
let hs_mac (a:alg) (k:FB.bytes{hs_key_admissible a k}) (d:FB.bytes{hs_data_admissible a d})
  : Tot FB.bytes =
  match a with
  | HS256 -> hmac_sha256 k d
  | HS384 -> hmac_sha384 k d
  | HS512 -> hmac_sha512 k d
  | _ -> FB.empty_bytes

(** Extensional key equivalence for an HMAC algorithm: two admissible raw
    keys that produce the same MAC for every admissible signing input.
    Distinct raw keys can be equivalent (zero padding of short keys, proved
    in Verified.Crypto.Hmac.KeyEquiv); unforgeability is therefore stated
    over equivalence classes, never over raw key inequality. *)
let mac_key_equiv (a:alg) (k1 k2:FB.bytes) : Type0 =
  hs_key_admissible a k1 /\ hs_key_admissible a k2 /\
  (forall (d:FB.bytes). hs_data_admissible a d ==> hs_mac a k1 d = hs_mac a k2 d)

let lemma_mac_key_equiv_hs256 (k1 k2:FB.bytes)
  : Lemma (requires hmac_sha256_key_equiv k1 k2)
          (ensures mac_key_equiv HS256 k1 k2)
  = ()

(** Key-equivalent keys verify exactly the same tokens. *)
let lemma_jws_verify_hs_key_equiv (key1 key2:jwk) (token:string)
  : Lemma (requires key1.alg = key2.alg /\ is_hs key1.alg /\
                    mac_key_equiv key1.alg key1.k key2.k)
          (ensures jws_verify key1 token = jws_verify key2 token)
  = reveal_opaque (`%jws_verify) jws_verify;
    match parse_compact token with
    | None -> ()
    | Some parts ->
      if hs_data_admissible key1.alg parts.signing_input then
        assert (hs_mac key1.alg key1.k parts.signing_input =
                hs_mac key1.alg key2.k parts.signing_input)
      else ()

(* -- Success path ----------------------------------------- *)

(** The honest MAC over the signing input is accepted: the verifier is a real
    computation with a reachable positive path. *)
let lemma_jws_verify_hs_accepts_mac (key:jwk) (token:string)
  : Lemma (requires is_hs key.alg /\ hs_key_admissible key.alg key.k /\
                    (match parse_compact token with
                     | Some p -> hs_data_admissible key.alg p.signing_input /\
                                p.sig_bytes = hs_mac key.alg key.k p.signing_input
                     | None -> False))
          (ensures jws_verify key token = true)
  = reveal_opaque (`%jws_verify) jws_verify

(** What a verifying token looks like: a parsed compact JWS whose signature is
    the MAC under the key (HMAC algorithms) or an Ed25519 signature over the signing
    input that verifies under the key (EdDSA).  PS256 and unsupported
    algorithms never verify here. *)
let lemma_jws_verify_true_shape (key:jwk) (token:string)
  : Lemma (requires jws_verify key token = true)
          (ensures Some? (parse_compact token) /\
                   (is_hs key.alg \/ key.alg = EdDSA) /\
                   (let p = Some?.v (parse_compact token) in
                    (is_hs key.alg ==>
                      hs_key_admissible key.alg key.k /\
                      hs_data_admissible key.alg p.signing_input /\
                      p.sig_bytes = hs_mac key.alg key.k p.signing_input) /\
                    (key.alg = EdDSA ==>
                      FB.length key.k = 32 /\ FB.length p.sig_bytes = 64 /\
                      FB.length p.signing_input <= Lib.IntTypes.max_size_t /\
                      ed25519_verify key.k p.signing_input p.sig_bytes = true)))
  = reveal_opaque (`%jws_verify) jws_verify

(* -- Forgery events (definitions, no axioms) --------------- *)

(** An honest MAC computation by a key holder. *)
type mac_event = {
  me_alg: alg;
  me_key: FB.bytes;
  me_input: FB.bytes
}

(** The signing input was MACed by an honest holder of a key equivalent to k. *)
let mac_issued (history:list mac_event) (a:alg) (k:FB.bytes) (input:FB.bytes) : Type0 =
  exists (e:mac_event).
    FStar.List.Tot.mem e history /\ e.me_alg = a /\
    mac_key_equiv a e.me_key k /\ e.me_input = input

(** Compromise is closed under the same key equivalence used for issuance.
    A leaked zero-padded equivalent key also reveals the MAC authority. *)
let mac_key_compromised (compromised:list FB.bytes) (a:alg) (k:FB.bytes) : Type0 =
  exists (known:FB.bytes).
    FStar.List.Tot.mem known compromised /\ mac_key_equiv a known k

let jws_key_compromised (compromised:list FB.bytes) (key:jwk) : Type0 =
  if is_hs key.alg then mac_key_compromised compromised key.alg key.k
  else FStar.List.Tot.mem key.k compromised

(** The external HMAC game's key-length domain (RFC 7518 section 3.2).
    Primitive admissibility alone only checks nonempty input. Minimum length
    does not establish uniform selection; the generation history below remains
    an external provenance obligation. *)
let hs_security_key_admissible (a:alg) (k:FB.bytes) : bool =
  hs_key_admissible a k &&
  (match a with
   | HS256 -> FB.length k >= 32
   | HS384 -> FB.length k >= 48
   | HS512 -> FB.length k >= 64
   | _ -> false)

(** Entries supplied by the external game's honest, uniform key generation.
    These records model provenance; constructing a record is not an attestation. *)
type mac_key_generation_event = {
  kg_alg: alg;
  kg_key: FB.bytes
}

let mac_key_generated (honest_keys:list mac_key_generation_event)
  (a:alg) (k:FB.bytes) : Type0 =
  hs_security_key_admissible a k /\
  (exists (e:mac_key_generation_event).
    FStar.List.Tot.mem e honest_keys /\ e.kg_alg = a /\
    hs_security_key_admissible a e.kg_key /\ mac_key_equiv a e.kg_key k)

let jws_key_generated (mac_keys:list mac_key_generation_event)
  (signing_keys:list FB.bytes) (key:jwk) : Type0 =
  if is_hs key.alg then mac_key_generated mac_keys key.alg key.k
  else key.alg = EdDSA /\ ed25519_key_generated signing_keys key.k

(** HMAC forgery event: an HS* token verifies inside the honest key-generation
    security domain under an uncompromised key
    whose equivalence class never MACed that signing input. *)
let jws_mac_forgery (honest_keys:list mac_key_generation_event)
  (history:list mac_event) (compromised:list FB.bytes)
  (key:jwk) (token:string) : Type0 =
  mac_key_generated honest_keys key.alg key.k /\
  is_hs key.alg /\ jws_verify key token = true /\
  ~(mac_key_compromised compromised key.alg key.k) /\
  (match parse_compact token with
   | Some p -> ~(mac_issued history key.alg key.k p.signing_input)
   | None -> False)

(** Ed25519 forgery event on a JWS: the signing input was never signed by
    the honest holder of the key (Verified.Crypto.Bridge history). *)
let jws_eddsa_forgery (honest_keys:list FB.bytes)
  (history:list ed25519_signing_event) (compromised:list FB.bytes)
  (key:jwk) (token:string) : Type0 =
  ed25519_key_generated honest_keys key.k /\
  key.alg = EdDSA /\ jws_verify key token = true /\
  ~(FStar.List.Tot.mem key.k compromised) /\
  (match parse_compact token with
   | Some p -> ~(ed25519_message_signed history key.k p.signing_input)
   | None -> False)

(** Case split for verification success.  Re-presenting an honestly issued
    token is the second/third case and does not show that the presenter
    knows the key.  Proved; replaces the former false axiom
    jws_verify_unforgeable. *)
let lemma_jws_verify_cases (mac_keys:list mac_key_generation_event) (signing_keys:list FB.bytes)
  (macs:list mac_event) (sigs:list ed25519_signing_event)
  (compromised:list FB.bytes) (key:jwk) (token:string)
  : Lemma (jws_verify key token = true ==>
           ~(jws_key_generated mac_keys signing_keys key) \/
           jws_key_compromised compromised key \/
           (Some? (parse_compact token) /\ is_hs key.alg /\
            mac_issued macs key.alg key.k (Some?.v (parse_compact token)).signing_input) \/
           (Some? (parse_compact token) /\ key.alg = EdDSA /\
            ed25519_message_signed sigs key.k (Some?.v (parse_compact token)).signing_input) \/
           jws_mac_forgery mac_keys macs compromised key token \/
           jws_eddsa_forgery signing_keys sigs compromised key token)
  = if jws_verify key token then lemma_jws_verify_true_shape key token else ()
