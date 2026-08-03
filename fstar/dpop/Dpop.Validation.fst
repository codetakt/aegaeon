module Dpop.Validation

open Dpop.Claims
open Dpop.Htm_validation
open Dpop.Htu_validation
open Dpop.Iat_validation
open Dpop.Signature
open Dpop.Replay
module U64 = FStar.UInt64

(** Verify a DPoP proof given the expected request properties.

    The function performs semantic checks (method/URI/iat window/signature) and,
    on success, returns a replay ticket. The caller is responsible for passing
    the ticket to the replay store (Redis) using the surrounding environment
    identifier. *)
val verify_dpop :
  token:claims ->
  method:string ->
  uri:string ->
  now:U64.t ->
  window:U64.t ->
  key:public_key ->
  header:string ->
  payload:string ->
  sig:signature ->
  Tot (o:option replay_ticket{
    match o with
    | Some ticket ->
        validate_htm method token.htm &&
        validate_htu uri token.htu &&
        validate_iat now token.iat window &&
        verify_signature key header payload sig &&
        ticket.jti = token.jti
    | None ->
        not (validate_htm method token.htm &&
             validate_htu uri token.htu &&
             validate_iat now token.iat window &&
             verify_signature key header payload sig)
  })
let verify_dpop token method uri now window key header payload sig =
  if not (validate_htm method token.htm)
  then None
  else if not (validate_htu uri token.htu)
  then None
  else if not (validate_iat now token.iat window)
  then None
  else if not (verify_signature key header payload sig)
  then None
  else Some (make_ticket token.jti)
