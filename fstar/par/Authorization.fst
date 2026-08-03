module Authorization

type client_id = string

(** Request parameters as per RFC 9126 Section 2. *)
type par_request = {
  client_id: client_id;
  redirect_uri: string;
  response_type: string;
  state: option string;
  code_challenge: option string;
  code_challenge_method: option string;
  scope: option string;
  nonce: option string;
}
