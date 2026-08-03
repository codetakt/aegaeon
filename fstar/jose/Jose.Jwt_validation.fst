module Jose.Jwt_validation

open Jose.Jwt_claims
open Jose.Jws_signature
open Jose.Jws_serialization
open Jose.Jwk_structure
open FStar.String

let rec all_nonempty l =
  match l with
  | [] -> true
  | hd::tl -> String.length hd > 0 && all_nonempty tl

(** Validate temporal and structural properties of JWT claims. The
    `now` parameter is expressed in seconds since the epoch. *)
val validate_claims : now:int -> jwt_claims -> Tot bool
let validate_claims now c =
  (match c.exp with | Some e -> e > now | None -> true) &&
  (match c.nbf with | Some n -> n <= now | None -> true) &&
  (match c.iat with | Some i -> i <= now | None -> true) &&
  (match c.iss with | Some s -> String.length s > 0 | None -> true) &&
  (match c.sub with | Some s -> String.length s > 0 | None -> true) &&
  (match c.jti with | Some s -> String.length s > 0 | None -> true) &&
  all_nonempty c.aud

(** Validate a JWT using a JWK for signature verification and perform
    basic claim checks. The token is expected in compact JWS form. *)
val validate_jwt : jwk -> string -> now:int -> Tot bool
let validate_jwt key token now =
  if not (verify key token) then false
  else
    match parse_compact token with
    | None -> false
    | Some parts ->
        (match Jwt_claims.parse_bytes parts.payload with
         | Some c -> validate_claims now c
         | None -> false)
