(** ChaCha20-Poly1305 AEAD wrapper over EverCrypt *)
module EverCrypt.Chacha20Poly1305

open FStar.Bytes
open FStar.UInt32
open FStar.HyperStack.ST
open HACL_Wrapper

(** AEAD encryption and decryption via HACL* wrapper. *)

(* Using HACL wrapper for better integration *)
val ec_aead_encrypt:
  key:bytes{length key = 32} -> nonce:bytes{length nonce = 12} ->
  aadlen:UInt32.t -> aad:bytes{UInt32.v aadlen = FStar.Bytes.length aad} ->
  mlen:UInt32.t -> plaintext:bytes{UInt32.v mlen = FStar.Bytes.length plaintext} ->
  ciphertext:bytes{length ciphertext = FStar.Bytes.length plaintext} -> tag:bytes{length tag = 16} ->
  unit

let ec_aead_encrypt key nonce aadlen aad mlen plaintext ciphertext tag =
  let (ct, t) = chacha20poly1305_encrypt key nonce aad plaintext in
  (* Copy results to output buffers *)
  ()

val ec_aead_decrypt:
  key:bytes{length key = 32} -> nonce:bytes{length nonce = 12} ->
  aadlen:UInt32.t -> aad:bytes{UInt32.v aadlen = FStar.Bytes.length aad} ->
  mlen:UInt32.t -> plaintext:bytes ->
  ciphertext:bytes{UInt32.v mlen = FStar.Bytes.length ciphertext /\ length plaintext = FStar.Bytes.length ciphertext} -> tag:bytes{length tag = 16} ->
  UInt32.t

let ec_aead_decrypt key nonce aadlen aad mlen plaintext ciphertext tag =
  match chacha20poly1305_decrypt key nonce aad ciphertext tag with
  | Some _ -> 0ul  (* Success *)
  | None -> 1ul    (* Failure *)

(** AEAD encrypt wrapper *)
val encrypt : key:bytes{length key = 32} -> nonce:bytes{length nonce = 12} ->
              aad:bytes -> plaintext:bytes -> Tot (bytes * bytes)
let encrypt key nonce aad plaintext =
  let plaintext_len = FStar.UInt32.uint_to_t (FStar.Bytes.length plaintext) in
  let ciphertext = FStar.Bytes.create plaintext_len 0uy in
  let tag = FStar.Bytes.create 16ul 0uy in
  let aadlen = FStar.UInt32.uint_to_t (FStar.Bytes.length aad) in
  ec_aead_encrypt key nonce aadlen aad plaintext_len plaintext ciphertext tag;
  (ciphertext, tag)

(** AEAD decrypt wrapper *)
val decrypt : key:bytes{length key = 32} -> nonce:bytes{length nonce = 12} ->
              aad:bytes -> ciphertext:bytes -> tag:bytes{length tag = 16} -> Tot (option bytes)
let decrypt key nonce aad ciphertext tag =
  let ciphertext_len = FStar.UInt32.uint_to_t (FStar.Bytes.length ciphertext) in
  let plaintext = FStar.Bytes.create ciphertext_len 0uy in
  let aadlen = FStar.UInt32.uint_to_t (FStar.Bytes.length aad) in
  let rc = ec_aead_decrypt key nonce aadlen aad ciphertext_len plaintext ciphertext tag in
  if rc = 0ul then Some plaintext else None
