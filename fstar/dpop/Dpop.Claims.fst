module Dpop.Claims

module U64 = FStar.UInt64

(** Claims carried inside a DPoP proof JWT. *)
type claims = {
  htm: string;  (** HTTP method of the request *)
  htu: string;  (** HTTP URI of the request *)
  iat: U64.t;   (** Issued-at timestamp (seconds since epoch) *)
  jti: string   (** Unique token identifier *)
}
