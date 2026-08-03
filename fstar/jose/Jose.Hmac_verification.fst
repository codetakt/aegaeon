module Jose.Hmac_verification

open Jose.Alg_policy
open FStar.Bytes
open FStar.Seq
open FStar.UInt8
open FStar.UInt32
open FStar.HyperStack.All
open EverCrypt.HMAC

module SHD = Spec.Hash.Definitions

(** Helper function for constant-time comparison loop.
    Defined at module level to avoid inner let-rec warning. *)
private let rec ct_eq_loop
  (a:bytes)
  (b:bytes)
  (len:nat{len = FStar.Bytes.length a /\ len = FStar.Bytes.length b})
  (i:FStar.UInt32.t{FStar.UInt32.v i <= len})
  (acc:UInt8.t)
  : Tot UInt8.t (decreases (len - FStar.UInt32.v i)) =
  if FStar.UInt32.v i < len then
    let ai = FStar.Bytes.get a i in
    let bi = FStar.Bytes.get b i in
    let acc' = UInt8.logor acc (UInt8.logxor ai bi) in
    ct_eq_loop a b len (FStar.UInt32.add i 1ul) acc'
  else acc

(** Constant-time byte array comparison for MAC verification.
    Written in a Low* friendly style to ensure constant-time behaviour
    when extracted to C. *)
let ct_eq (a:bytes) (b:bytes) : Tot bool =
  let len_a = FStar.Bytes.length a in
  let len_b = FStar.Bytes.length b in
  if len_a = len_b then
    ct_eq_loop a b len_a 0ul 0uy = 0uy
  else false

(** Verify an HMAC based JWS signature using EverCrypt. *)
val verify : key:bytes -> alg:alg -> data:bytes -> signature:bytes -> Tot bool
let verify key alg data signature =
  if not (allowed alg) then false
  else
    let hacl_alg =
      match alg with
      | HS256 -> SHD.SHA2_256
      | HS384 -> SHD.SHA2_384
      | HS512 -> SHD.SHA2_512
      | _ -> SHD.SHA2_256  (* Should never happen due to allowed check *)
    in
    let mac = EverCrypt.HMAC.compute hacl_alg key data in
    ct_eq mac signature
