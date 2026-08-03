module ResourceIndicators

open FStar.All
open FStar.String
open FStar.Char
open StringHelpers
module List = FStar.List.Tot

// RFC 8707 resource indicator model (single-value profile).

type resource = string

// ── String helpers for URI validation ──

let rec contains_substr_chars (s:list char) (sub:list char) : Tot bool (decreases s) =
  if StringHelpers.starts_with_chars s sub then true
  else match s with
  | [] -> false
  | _ :: rest -> contains_substr_chars rest sub

let rec contains_char (s:list char) (c:char) : Tot bool (decreases s) =
  match s with
  | [] -> false
  | hd :: tl -> hd = c || contains_char tl c

// Concrete URI validation: absolute URI (contains "://"), no fragment ("#").
let resource_indicator_wellformed (r:resource) : Tot bool =
  let chars = list_of_string r in
  let scheme_sep = list_of_string "://" in
  let hash = char_of_int 35 in
  contains_substr_chars chars scheme_sep && not (contains_char chars hash)

let validate_resource_indicator (value: resource) : Tot bool =
  resource_indicator_wellformed value

let parse_single_resource_indicator (values: list resource) : Tot (option resource) =
  match values with
  | [] -> None
  | [value] ->
      if validate_resource_indicator value then Some value else None
  | _ -> None

let resource_request_matches_grant
  (grant: option resource)
  (requested: option resource)
  : Tot bool =
  match grant, requested with
  | Some g, Some r -> g = r
  | _, _ -> true

let select_resource_indicator
  (grant: option resource)
  (requested: option resource)
  : Tot (option resource) =
  match requested with
  | Some r -> Some r
  | None -> grant

let select_audience (client_id: string) (resource: option resource) : Tot string =
  match resource with
  | Some r -> r
  | None -> client_id

let lemma_parse_single_resource_empty ()
  : Lemma (ensures (parse_single_resource_indicator [] = None))
  = ()

let lemma_parse_single_resource_rejects_multiple
  (first: resource)
  (second: resource)
  (rest: list resource)
  : Lemma
    (ensures
      (parse_single_resource_indicator (first :: second :: rest) = None))
  = ()

let lemma_resource_mismatch_rejected
  (grant: resource)
  (requested: resource)
  : Lemma
    (requires (grant <> requested))
    (ensures
      (resource_request_matches_grant (Some grant) (Some requested) = false))
  = ()

let lemma_resource_selection_prefers_request
  (grant: option resource)
  (requested: resource)
  : Lemma
    (ensures (select_resource_indicator grant (Some requested) = Some requested))
  = ()

let lemma_resource_selection_falls_back_to_grant
  (grant: option resource)
  : Lemma
    (ensures (select_resource_indicator grant None = grant))
  = ()

let lemma_audience_binds_to_resource
  (client_id: string)
  (resource: resource)
  : Lemma
    (ensures (select_audience client_id (Some resource) = resource))
  = ()

let lemma_audience_falls_back_to_client
  (client_id: string)
  : Lemma
    (ensures (select_audience client_id None = client_id))
  = ()
