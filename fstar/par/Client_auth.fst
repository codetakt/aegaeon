module Client_auth

open Authorization

(** A very small in-memory registry used for examples. *)
let registered_client : client_id = "client_a"
let registered_redirect : string = "https://client.example/cb"

val validate_client: client_id -> Tot bool
let validate_client cid = cid = registered_client

val validate_redirect_uri: client_id -> string -> Tot bool
let validate_redirect_uri cid uri =
  cid = registered_client && uri = registered_redirect

(** Lemma: validating a redirect URI implies the client itself is valid. *)
let lemma_redirect_implies_client cid uri :
  Lemma (requires validate_redirect_uri cid uri)
        (ensures validate_client cid) =
  ()
