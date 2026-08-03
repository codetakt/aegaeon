module Jose.Alg_policy

(** Algorithm identifiers for JWS/JWT that we currently support *)
type alg =
  | HS256
  | HS384
  | HS512
  | PS256
  | EdDSA
  | Unsupported

(** [alg_of_string s] parses the textual representation of an algorithm.
    "none" and unknown algorithms map to [Unsupported]. *)
let alg_of_string (s:string) : alg =
  if s = "HS256" then HS256
  else if s = "HS384" then HS384
  else if s = "HS512" then HS512
  else if s = "PS256" then PS256
  else if s = "EdDSA" then EdDSA
  else Unsupported

(** Allow‑list enforcing that "none" and unknown algorithms are rejected. *)
let allowed (a:alg) : Tot bool =
  match a with
  | HS256 -> true
  | HS384 -> true
  | HS512 -> true
  | PS256 -> true
  | EdDSA -> true
  | Unsupported -> false

let is_supported_alg (s:string) : Tot bool =
  allowed (alg_of_string s)

(** Verified allow-list for the strong-constraint crypto boundary.
    This list must be implementable via HACL*/EverCrypt only.
    PS256 verification is wired to Hacl_RSAPSS (extracted C / libevercrypt). *)
let verified_allowed (a:alg) : Tot bool =
  match a with
  | HS256 -> true
  | HS384 -> true
  | HS512 -> true
  | EdDSA -> true
  | PS256 -> true
  | Unsupported -> false

let is_verified_alg (s:string) : Tot bool =
  verified_allowed (alg_of_string s)
