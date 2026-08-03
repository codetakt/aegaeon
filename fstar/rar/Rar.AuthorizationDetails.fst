module Rar.AuthorizationDetails

open FStar.All
module List = FStar.List.Tot

// Minimal model for RFC 9396 authorization_details handling.

type authorization_detail = {
  detail_type: string
}

type authorization_details = list authorization_detail

let detail_type_non_empty (detail: authorization_detail) : Tot bool =
  detail.detail_type <> ""

let rec authorization_details_well_formed (details: authorization_details) : Tot bool =
  match details with
  | [] -> true
  | d :: rest -> detail_type_non_empty d && authorization_details_well_formed rest

let detail_type_supported (supported: list string) (detail: authorization_detail) : Tot bool =
  List.mem detail.detail_type supported

let rec authorization_details_supported
  (supported: list string)
  (details: authorization_details)
  : Tot bool =
  match details with
  | [] -> true
  | d :: rest ->
      detail_type_non_empty d &&
      detail_type_supported supported d &&
      authorization_details_supported supported rest

let accept_authorization_details
  (supported: list string)
  (details: option authorization_details)
  : Tot (option authorization_details) =
  match details with
  | None -> None
  | Some ds ->
      if authorization_details_supported supported ds then
        Some ds
      else
        None

let select_authorization_details
  (request_object: option authorization_details)
  (request_parameters: option authorization_details)
  : Tot (option authorization_details) =
  match request_object with
  | Some details -> Some details
  | None -> request_parameters

let lemma_request_object_precedence
  (details: authorization_details)
  (request_parameters: option authorization_details)
  : Lemma
    (ensures (select_authorization_details (Some details) request_parameters = Some details))
  = ()

let lemma_request_parameters_fallback
  (request_parameters: option authorization_details)
  : Lemma
    (ensures (select_authorization_details None request_parameters = request_parameters))
  = ()

let select_par_authorization_details
  (request_object: option authorization_details)
  (form: option authorization_details)
  : Tot (option authorization_details) =
  select_authorization_details request_object form

let select_direct_authorization_details
  (request_object: option authorization_details)
  (query: option authorization_details)
  (form: option authorization_details)
  : Tot (option authorization_details) =
  match request_object with
  | Some details -> Some details
  | None ->
      match query with
      | Some details -> Some details
      | None -> form

let select_authorization_details_final
  (par_request_object: option authorization_details)
  (par_form: option authorization_details)
  (direct_request_object: option authorization_details)
  (direct_query: option authorization_details)
  (direct_form: option authorization_details)
  : Tot (option authorization_details) =
  match select_par_authorization_details par_request_object par_form with
  | Some details -> Some details
  | None -> select_direct_authorization_details direct_request_object direct_query direct_form

let lemma_par_request_object_precedence
  (details: authorization_details)
  (form: option authorization_details)
  : Lemma
    (ensures (select_par_authorization_details (Some details) form = Some details))
  = ()

let lemma_par_form_fallback
  (form: option authorization_details)
  : Lemma
    (ensures (select_par_authorization_details None form = form))
  = ()

let lemma_direct_request_object_precedence
  (details: authorization_details)
  (query: option authorization_details)
  (form: option authorization_details)
  : Lemma
    (ensures (select_direct_authorization_details (Some details) query form = Some details))
  = ()

let lemma_direct_query_precedence
  (details: authorization_details)
  (form: option authorization_details)
  : Lemma
    (ensures (select_direct_authorization_details None (Some details) form = Some details))
  = ()

let lemma_direct_form_fallback
  (form: option authorization_details)
  : Lemma
    (ensures (select_direct_authorization_details None None form = form))
  = ()

let lemma_par_overrides_direct
  (par_request_object: option authorization_details)
  (par_form: option authorization_details)
  (direct_request_object: option authorization_details)
  (direct_query: option authorization_details)
  (direct_form: option authorization_details)
  (details: authorization_details)
  : Lemma
    (requires (select_par_authorization_details par_request_object par_form = Some details))
    (ensures
      (select_authorization_details_final
        par_request_object
        par_form
        direct_request_object
        direct_query
        direct_form = Some details))
  = ()

let lemma_no_par_falls_back_to_direct
  (direct_request_object: option authorization_details)
  (direct_query: option authorization_details)
  (direct_form: option authorization_details)
  : Lemma
    (ensures
      (select_authorization_details_final
        None
        None
        direct_request_object
        direct_query
        direct_form
        = select_direct_authorization_details
            direct_request_object
            direct_query
            direct_form))
  = ()

let lemma_accept_requires_supported
  (supported: list string)
  (details: authorization_details)
  : Lemma
    (requires (accept_authorization_details supported (Some details) = Some details))
    (ensures (authorization_details_supported supported details))
  = ()

let lemma_accept_rejects_unsupported
  (supported: list string)
  (details: authorization_details)
  : Lemma
    (requires (not (authorization_details_supported supported details)))
    (ensures (accept_authorization_details supported (Some details) = None))
  = ()
