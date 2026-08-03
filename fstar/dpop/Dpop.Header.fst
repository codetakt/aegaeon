module Dpop.Header

(** Validate the DPoP JWT type header required by RFC 9449. *)
val validate_typ : t:string -> Tot (b:bool{b <==> t = "dpop+jwt"})
let validate_typ t =
  t = "dpop+jwt"
