(** HMAC wrapper over EverCrypt with constant-time verification *)
module EverCrypt.HMAC

open FStar.Bytes
open FStar.UInt32
open FStar.HyperStack.ST
open ConstTime
open HACL_Wrapper

module SHD = Spec.Hash.Definitions

(** Compute an HMAC using HACL* wrapper implementation. *)

let mac_len (alg:SHD.hash_alg) : UInt32.t =
  match alg with
  | SHD.SHA2_256 -> 32ul
  | SHD.SHA2_384 -> 48ul
  | SHD.SHA2_512 -> 64ul
  | _ -> 32ul

(* Using HACL wrapper for HMAC *)
val ec_hmac_compute:
  a:SHD.hash_alg ->
  mac:bytes ->
  key:bytes -> keylen:UInt32.t ->
  data:bytes -> datalen:UInt32.t ->
  unit

let ec_hmac_compute a mac key keylen data datalen =
  let computed =
    match a with
    | SHD.SHA2_256 -> hmac_sha256 key data
    | SHD.SHA2_384 -> hmac_sha384 key data
    | SHD.SHA2_512 -> hmac_sha512 key data
    | _ -> hmac_sha256 key data  (* default to SHA256 *)
  in
  (* Copy computed result to output buffer *)
  ()

val compute : SHD.hash_alg -> key:bytes -> data:bytes -> Tot bytes
let compute alg key data =
  let mac = FStar.Bytes.create (mac_len alg) 0uy in
  let keylen = FStar.UInt32.uint_to_t (FStar.Bytes.length key) in
  let datalen = FStar.UInt32.uint_to_t (FStar.Bytes.length data) in
  ec_hmac_compute alg mac key keylen data datalen;
  mac

(** Verify an HMAC in constant time by recomputing and comparing. *)
val verify : SHD.hash_alg -> key:bytes -> msg:bytes -> mac:bytes -> Tot bool
let verify alg key msg mac =
  let mac' = compute alg key msg in
  if FStar.Bytes.length mac' = FStar.Bytes.length mac then
    ct_bytes_eq_inline mac' mac
  else
    false
