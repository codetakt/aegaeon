(* Constant-time utilities *)
module ConstTime

open FStar.Bytes
open FStar.UInt8

(** Constant-time byte-sequence equality test. Returns true iff b1 and b2 are equal. *)
val ct_bytes_eq_aux :
  b1:bytes ->
  b2:bytes{length b1 = length b2} ->
  len:nat{len = FStar.Bytes.length b1} ->
  i:nat{i <= len} ->
  acc:UInt8.t ->
  Tot UInt8.t (decreases (len - i))
let rec ct_bytes_eq_aux b1 b2 len i acc =
  if i = len then acc
  else
    let x = FStar.Bytes.index b1 i in
    let y = FStar.Bytes.index b2 i in
    ct_bytes_eq_aux b1 b2 len (i + 1) (UInt8.logxor acc (UInt8.logxor x y))

val ct_bytes_eq: b1:bytes -> b2:bytes{length b1 = length b2} -> Tot bool
let ct_bytes_eq b1 b2 =
  let len = FStar.Bytes.length b1 in
  ct_bytes_eq_aux b1 b2 len 0 (uint_to_t 0) = uint_to_t 0

(* Inline to ensure constant-time extraction *)
val ct_bytes_eq_inline: b1:bytes -> b2:bytes{length b1 = length b2} -> Tot bool
let ct_bytes_eq_inline b1 b2 = ct_bytes_eq b1 b2
