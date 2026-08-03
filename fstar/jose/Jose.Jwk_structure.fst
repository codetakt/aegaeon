module Jose.Jwk_structure

open Jose.Alg_policy
open FStar.Bytes
open FStar.Seq
open FStar.Json
open FStar.Base64

(** Representation of a minimal JSON Web Key. *)
type jwk = {
  kty: string;
  alg: alg;
  k: bytes
}

(** Lookup a field in a JSON object. *)
val field_lookup: k:string -> fields:list (string * json) -> Tot (option json)
let rec field_lookup k fields =
  match fields with
  | [] -> None
  | (x, v)::tl -> if x = k then Some v else field_lookup k tl


(** Parse a symmetric ("oct") JWK. *)
val parse_oct : json -> option jwk
let parse_oct j =
  match j with
  | Object fields ->
      (match field_lookup "kty" fields,
             field_lookup "alg" fields,
             field_lookup "k" fields with
       | Some (String kty_s),
         Some (String alg_s),
         Some (String k_s) ->
           let a = alg_of_string alg_s in
           if not (kty_s = "oct" && allowed a) then None
           else
             (match Base64.url_decode k_s with
              | Some k_bytes ->
                  if FStar.Bytes.length k_bytes > 0 then
                    let j = { kty = kty_s; alg = a; k = k_bytes } in
                    Some j
                  else None
              | _ -> None)
       | _ -> None)
  | _ -> None

(** Parse an RSA public JWK. The modulus ("n") and exponent ("e")
    parameters are Base64url decoded and concatenated for use with
    downstream verification routines. *)
val parse_rsa : json -> option jwk
let parse_rsa j =
  match j with
  | Object fields ->
      (match field_lookup "kty" fields,
             field_lookup "alg" fields,
             field_lookup "n" fields,
             field_lookup "e" fields with
       | Some (String kty_s),
         Some (String alg_s),
         Some (String n_s),
         Some (String e_s) ->
           let a = alg_of_string alg_s in
           if not (kty_s = "RSA" && allowed a) then None
           else
             (match Base64.url_decode n_s, Base64.url_decode e_s with
              | Some n_bytes, Some e_bytes ->
                  if FStar.Bytes.length e_bytes + FStar.Bytes.length n_bytes < pow2 32 then
                    let k_bytes = FStar.Bytes.append e_bytes n_bytes in
                    if FStar.Bytes.length k_bytes > 0 then
                      let j = { kty = kty_s; alg = a; k = k_bytes } in
                      Some j
                    else None
                  else None
              | _ -> None)
       | _ -> None)
  | _ -> None

(** Parse an OKP (Ed25519) JWK. The "x" coordinate is Base64url decoded
    to raw public key bytes. *)
val parse_okp : json -> option jwk
let parse_okp j =
  match j with
  | Object fields ->
      (match field_lookup "kty" fields,
             field_lookup "alg" fields,
             field_lookup "x" fields with
       | Some (String kty_s),
         Some (String alg_s),
         Some (String x_s) ->
           let a = alg_of_string alg_s in
           if not (kty_s = "OKP" && allowed a) then None
           else
             (match Base64.url_decode x_s with
              | Some x_bytes ->
                  if FStar.Bytes.length x_bytes > 0 then
                    let j = { kty = kty_s; alg = a; k = x_bytes } in
                    Some j
                  else None
              | _ -> None)
       | _ -> None)
  | _ -> None

(** Attempt to parse a JWK of any supported type. *)
val parse : json -> option jwk
let parse j =
  match parse_oct j with
  | Some k -> Some k
  | None ->
      (match parse_rsa j with
       | Some k -> Some k
       | None -> parse_okp j)

(** Validate basic structural properties of a JWK. *)
val validate : jwk -> Tot bool
let validate j =
  (j.kty = "oct" || j.kty = "RSA" || j.kty = "OKP") &&
  allowed j.alg && FStar.Bytes.length j.k > 0
