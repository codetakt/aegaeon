module Pkce.Method_selection

(** Supported PKCE code challenge methods. At the moment only S256 is allowed. *)
type code_challenge_method = | S256
