module Jose.Jws_serialization

open FStar.Bytes
open FStar.String
open FStar.List.Tot
open FStar.Base64

(** Representation of a compact JWS after parsing. *)
type jws_parts = {
  header: bytes;
  payload: bytes;
  sig_bytes: bytes;
  signing_input: bytes
}

(** Parse the compact JWS form (Base64URL segments separated by '.'). *)
val parse_compact : string -> option jws_parts
let parse_compact s =
  let segments = String.split ['.'] s in
  match segments with
    | [h; p; sig_b64] ->
        (match Base64.url_decode h,
               Base64.url_decode p,
               Base64.url_decode sig_b64 with
         | Some hb, Some pb, Some sb ->
             let si = FStar.Bytes.bytes_of_string (h ^ "." ^ p) in
             let parts = {
               header = hb;
               payload = pb;
               sig_bytes = sb;
               signing_input = si
             } in
             Some parts
         | _ -> None)
  | _ -> None
