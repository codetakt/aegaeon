module Jose.Jwe_chacha20poly1305

open FStar.Bytes
open FStar.Seq
open FStar.UInt8
open FStar.HyperStack.All
open EverCrypt.Chacha20Poly1305

(** AEAD encryption using verified EverCrypt Chacha20-Poly1305.  The
    implementation is a thin wrapper around the EverCrypt primitives and
    is written in Low* style for constant-time extraction. *)

val encrypt :
  key:bytes{FStar.Bytes.length key = 32} ->
  nonce:bytes{FStar.Bytes.length nonce = 12} ->
  aad:bytes ->
  plaintext:bytes ->
  Tot (bytes * bytes)
let encrypt key nonce aad plaintext =
    EverCrypt.Chacha20Poly1305.encrypt key nonce aad plaintext

val decrypt :
  key:bytes{FStar.Bytes.length key = 32} ->
  nonce:bytes{FStar.Bytes.length nonce = 12} ->
  aad:bytes ->
  ciphertext:bytes ->
  tag:bytes{FStar.Bytes.length tag = 16} ->
  Tot (option bytes)
let decrypt key nonce aad ciphertext tag =
    EverCrypt.Chacha20Poly1305.decrypt key nonce aad ciphertext tag
