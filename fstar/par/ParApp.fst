module ParApp

open Authorization
open ParBinding
open Client_auth
open Response
open Request_uri

(** Main PAR endpoint handler.  This function validates the client and
    redirect URI before storing the request and issuing a `request_uri`. *)
val handle_par_request: store:par_store -> req:par_request -> Tot (par_store * par_response)
let handle_par_request store req =
  if not (validate_client req.client_id) then
    (store, Error "invalid_client" (Some "Client authentication failed"))
  else if not (validate_redirect_uri req.client_id req.redirect_uri) then
    (store, Error "invalid_request" (Some "Invalid redirect_uri"))
  else
    store_request store req

val exchange_request_uri: par_store -> request_uri -> Tot (option par_request)
let exchange_request_uri store uri = lookup_request store uri
