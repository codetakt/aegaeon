module Jose.Metadata

open FStar.List.Tot
open FStar.String

module List = FStar.List.Tot
module Str = FStar.String

let string_non_empty (s:string) : Tot bool = Str.length s > 0

let list_non_empty (#a:Type) (xs:list a) : Tot bool =
  match xs with
  | [] -> false
  | _ -> true

noeq type metadata_required = {
  issuer: string;
  authorization_endpoint: string;
  token_endpoint: string;
  response_types_supported: list string;
}

let metadata_rfc8414_required (meta:metadata_required) : Tot bool =
  string_non_empty meta.issuer &&
  string_non_empty meta.authorization_endpoint &&
  string_non_empty meta.token_endpoint &&
  list_non_empty meta.response_types_supported &&
  List.for_all string_non_empty meta.response_types_supported

let lemma_metadata_required_fields
  (meta:metadata_required)
  : Lemma
      (requires metadata_rfc8414_required meta)
      (ensures metadata_rfc8414_required meta)
  = ()

noeq type metadata_runtime = {
  runtime_issuer: string;
  runtime_authorization_endpoint: string;
  runtime_token_endpoint: string;
  runtime_response_types_supported: list string;
}

let metadata_required_of_runtime (meta:metadata_runtime) : metadata_required = {
  issuer = meta.runtime_issuer;
  authorization_endpoint = meta.runtime_authorization_endpoint;
  token_endpoint = meta.runtime_token_endpoint;
  response_types_supported = meta.runtime_response_types_supported;
}

let metadata_runtime_core_ok (meta:metadata_runtime) : Tot bool =
  string_non_empty meta.runtime_issuer &&
  string_non_empty meta.runtime_authorization_endpoint &&
  string_non_empty meta.runtime_token_endpoint &&
  list_non_empty meta.runtime_response_types_supported &&
  List.for_all string_non_empty meta.runtime_response_types_supported

let lemma_metadata_runtime_core_fields
  (meta:metadata_runtime)
  : Lemma
      (requires metadata_runtime_core_ok meta)
      (ensures metadata_rfc8414_required (metadata_required_of_runtime meta))
  = ()
