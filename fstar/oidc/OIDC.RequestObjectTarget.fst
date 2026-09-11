module OIDC.RequestObjectTarget

(* Parsed and cryptographically checked input abstraction. Booleans stand for
   client-key and JWT validation; this is not a proof of JOSE or Rust code. *)
type input = { client_key_valid: bool; jwt_valid: bool; expected_client: string;
               signed_client: string; jwt_issuer: option string;
               audience: list string; expected_issuer: string }

let rec contains (value:string) (values:list string) : Tot bool =
  match values with | [] -> false | head::tail -> head = value || contains value tail

let admit (r:input) (outer_issuer:option string) : Tot (option string) =
  if r.client_key_valid && r.jwt_valid && r.signed_client = r.expected_client
     && contains r.expected_issuer r.audience
  then Some r.expected_issuer else None

let lemma_bad_client_key_rejected (r:input) (outer:option string)
  : Lemma (requires (not r.client_key_valid)) (ensures (admit r outer = None)) = ()
let lemma_invalid_jwt_rejected (r:input) (outer:option string)
  : Lemma (requires (not r.jwt_valid)) (ensures (admit r outer = None)) = ()
let lemma_client_mismatch_rejected (r:input) (outer:option string)
  : Lemma (requires (r.signed_client <> r.expected_client))
          (ensures (admit r outer = None)) = ()
let lemma_wrong_target_rejected (r:input) (outer:option string)
  : Lemma (requires (not (contains r.expected_issuer r.audience)))
          (ensures (admit r outer = None)) = ()
let lemma_admitted_target_is_recipient (r:input) (outer:option string)
  : Lemma (match admit r outer with
           | Some target -> target = r.expected_issuer | None -> True) = ()
let lemma_jwt_issuer_is_not_recipient (r:input) (issuer:option string) (outer:option string)
  : Lemma (admit {r with jwt_issuer=issuer} outer = admit r outer) = ()
let lemma_outer_issuer_is_not_recipient (r:input) (outer:option string) (other:option string)
  : Lemma (admit r outer = admit r other) = ()
let lemma_valid_request_is_accepted (r:input) (outer:option string)
  : Lemma (requires (r.client_key_valid /\ r.jwt_valid /\
                    r.signed_client = r.expected_client /\ contains r.expected_issuer r.audience))
          (ensures (admit r outer = Some r.expected_issuer)) = ()

(* RFC 8725 section 3.12: AS audiences can coincide across JWT uses. Token
   assertions must reject explicit Request Object types and authorization
   response_type claims, even when their other assertion checks would pass. *)
let assertion_admissible (request_object_type:bool) (response_type_present:bool)
  (other_assertion_checks:bool) : Tot bool =
  not request_object_type && not response_type_present && other_assertion_checks

let lemma_typed_request_not_assertion (response_type_present:bool) (other:bool)
  : Lemma (not (assertion_admissible true response_type_present other)) = ()
let lemma_authorization_request_not_assertion (request_object_type:bool) (other:bool)
  : Lemma (not (assertion_admissible request_object_type true other)) = ()
let lemma_assertion_checks_still_required (typed:bool) (response_type_present:bool)
  : Lemma (not (assertion_admissible typed response_type_present false)) = ()
let lemma_ordinary_assertion_reachable ()
  : Lemma (assertion_admissible false false true) = ()
