module VerifiedCore.Crypto.Hacl

(**
 * Low* interface to HACL* verified crypto functions.
 *
 * Declares SHA-256 hash and Ed25519 signature verification as assume vals
 * with Stack pre/post conditions. At link time, these are provided by the
 * HACL* pre-extracted C code (Hacl_Hash_SHA2, Hacl_Ed25519) already compiled
 * into the WASM binary.
 *
 * This module is marked -library in KaRaMeL. A thin C wrapper
 * (c/verified-core/hacl_bridge.c) maps the KaRaMeL-generated extern names
 * to the actual HACL* C function names.
 *
 * Callers: VerifiedCore.Api.Claims.Runtime (dpop_verify_claims_impl,
 *          jwt_verify_claims_impl).
 *)

open FStar.HyperStack.ST

module U8 = FStar.UInt8
module U32 = FStar.UInt32
module B = LowStar.Buffer

(** SHA-256 hash via HACL* Hacl_Hash_SHA2_hash_256.
    Writes exactly 32 bytes to output buffer.
    Parameter order matches HACL* C API: output, input, input_len. *)
assume val hacl_sha256:
  output: B.buffer U8.t ->
  input: B.buffer U8.t ->
  input_len: U32.t ->
  Stack unit
  (requires fun h ->
    B.live h output /\ B.live h input /\
    B.length output >= 32 /\
    U32.v input_len <= B.length input /\
    B.disjoint output input)
  (ensures fun h0 _ h1 ->
    B.modifies (B.loc_buffer output) h0 h1)

(** Ed25519 signature verification via HACL* Hacl_Ed25519_verify.
    Returns true iff the signature is valid for the given public key and message.
    Parameter order matches HACL* C API: pk, msg_len, msg, sig. *)
assume val hacl_ed25519_verify:
  pk: B.buffer U8.t ->
  msg_len: U32.t ->
  msg: B.buffer U8.t ->
  sig_: B.buffer U8.t ->
  Stack bool
  (requires fun h ->
    B.live h pk /\ B.live h msg /\ B.live h sig_ /\
    B.length pk >= 32 /\
    U32.v msg_len <= B.length msg /\
    B.length sig_ >= 64 /\
    B.disjoint pk msg /\ B.disjoint pk sig_ /\ B.disjoint msg sig_)
  (ensures fun h0 _ h1 -> h0 == h1)
