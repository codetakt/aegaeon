module Response

open Request_uri

(** PAR response as defined in RFC 9126 section 2.2. *)
type par_response =
  | Success: request_uri -> expires_in:nat -> par_response
  | Error: error:string -> error_description:option string -> par_response
