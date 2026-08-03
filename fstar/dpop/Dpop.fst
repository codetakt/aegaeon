module Dpop

open FStar.All
module U64 = FStar.UInt64

// Policy predicates (ghost)
val window_ok: iat:U64.t -> bool
let window_ok _ = true
val method_ok: htm:string -> bool
let method_ok _ = true
val url_ok: htu:string -> bool
let url_ok _ = true

// Compatibility helper: simple boolean verifier (without replay tracking)
val verify_dpop: htm:string -> htu:string -> iat:U64.t -> Tot bool
let verify_dpop htm htu iat =
  method_ok htm && url_ok htu && window_ok iat
