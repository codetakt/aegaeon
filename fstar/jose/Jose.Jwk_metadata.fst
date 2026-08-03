module Jose.Jwk_metadata

open FStar.String

(** Validate the JWK "use" parameter. Only "sig" is accepted when present. *)
val valid_use : option string -> Tot bool
let valid_use u =
  match u with
  | None -> true
  | Some s -> s = "sig"

(** Validate the JWK "kid" parameter. It must be non-empty when present. *)
val valid_kid : option string -> Tot bool
let valid_kid k =
  match k with
  | None -> true
  | Some s -> length s > 0
