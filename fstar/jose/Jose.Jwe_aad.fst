module Jose.Jwe_aad

open FStar.String
open FStar.Math.Lib

(** Compute the Additional Authenticated Data string as specified in RFC 7516. *)
val compute_spec : string -> option string -> string
let compute_spec header_b64 aad_opt =
  match aad_opt with
  | None -> header_b64
  | Some a -> header_b64 ^ "." ^ a

(** Low\*-friendly alias exposed through Jose.LowStar. *)
val compute : string -> option string -> string
let compute = compute_spec
