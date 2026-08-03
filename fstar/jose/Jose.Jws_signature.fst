module Jose.Jws_signature

open Jose.Jwk_structure
open Jose.Hmac_verification
open Jose.Jws_serialization
open Jose.Jws_header
open Jose.Alg_policy
open Jose.Rsa_signatures
open FStar.Bytes
open FStar.UInt32

(** Low-level HMAC verification on already parsed inputs. *)
val verify_hmac_raw : key:bytes -> alg:alg -> data:bytes -> signature:bytes -> Tot bool
let verify_hmac_raw key alg data signature =
  verify key alg data signature

(** Low-level RSA-PSS verification on already parsed inputs. *)
val verify_rsa_pss_raw : key:bytes -> data:bytes -> signature:bytes -> Tot bool
let verify_rsa_pss_raw key data signature =
  let klen = UInt32.uint_to_t (FStar.Bytes.length key) in
  let dlen = UInt32.uint_to_t (FStar.Bytes.length data) in
  let slen = UInt32.uint_to_t (FStar.Bytes.length signature) in
  verify_rsa_pss key klen data dlen signature slen

(** Low-level Ed25519 verification on already parsed inputs. *)
val verify_ed25519_raw : key:bytes -> data:bytes -> signature:bytes -> Tot bool
let verify_ed25519_raw key data signature =
  let dlen = UInt32.uint_to_t (FStar.Bytes.length data) in
  verify_ed25519 key dlen data signature

(** Verify a compact JWS using an HMAC based key. This high-level parsing
    logic is not constant-time and is excluded from extraction. *)
val verify_hmac : jwk -> string -> Tot bool
let verify_hmac key token =
  if not (Jwk_structure.validate key) then false
  else
    match parse_compact token with
    | None -> false
    | Some parts ->
        (match Jws_header.parse_bytes parts.header with
         | Some h ->
             if Jws_header.validate h && h.alg = key.alg then
               verify_hmac_raw key.k h.alg parts.signing_input parts.sig_bytes
             else false
         | None -> false)

(** Generic verification dispatching on the JWK key type and algorithm. *)
val verify : jwk -> string -> Tot bool
let verify key token =
  if not (Jwk_structure.validate key) then false
  else
    match parse_compact token with
    | None -> false
    | Some parts ->
        (match Jws_header.parse_bytes parts.header with
         | Some h ->
             if Jws_header.validate h && h.alg = key.alg then
               match key.kty with
               | "oct" ->
                   verify_hmac_raw key.k h.alg parts.signing_input parts.sig_bytes
               | "RSA" ->
                   verify_rsa_pss_raw key.k parts.signing_input parts.sig_bytes
               | "OKP" ->
                   verify_ed25519_raw key.k parts.signing_input parts.sig_bytes
               | _ -> false
             else false
         | None -> false)
