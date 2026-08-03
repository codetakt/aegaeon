module ProtectedResourceMetadata

open FStar.All
open FStar.String
open FStar.Char
open StringHelpers
module List = FStar.List.Tot

/// RFC 9728 — OAuth 2.0 Protected Resource Metadata
///
/// Formal model of the metadata document published at
/// /.well-known/oauth-protected-resource.
///
/// Security invariants:
///   1. `resource` field is REQUIRED and must be a valid HTTPS URI.
///   2. Every entry in `authorization_servers` must be a known AS issuer.
///   3. `bearer_methods_supported` must not include "query" when DPoP or
///      mTLS sender-constraint is required (RFC 9449 §10, RFC 9700 §2.1.2).
///   4. Cross-tenant isolation: resource metadata must not leak environment
///      identifiers or expose configuration from sibling tenants.

type url = string
type scope = string
type alg = string
type bearer_method = string

(** Check whether a URL is a known AS issuer (concrete: list membership). *)
let is_known_as_issuer (known: list url) (u: url) : Tot bool =
  List.mem u known

(** Core metadata record. *)
noeq type protected_resource_metadata = {
  resource                : url;     (* REQUIRED *)
  authorization_servers   : option (list url);
  scopes_supported        : option (list scope);
  bearer_methods_supported: option (list bearer_method);
  dpop_signing_alg_values : option (list alg);
  dpop_bound_required     : option bool;
  tls_cert_bound          : option bool;
}

(** Validity: REQUIRED field must be present and well-formed. *)
let metadata_valid (m: protected_resource_metadata) : Tot bool =
  is_https_url m.resource

(** All listed authorization servers must be known issuers. *)
let authorization_servers_trusted (known_issuers: list url) (m: protected_resource_metadata) : Tot bool =
  match m.authorization_servers with
  | None -> true
  | Some servers -> List.for_all (is_known_as_issuer known_issuers) servers

(** Security: when sender-constraint is required, "query" MUST NOT appear
    in bearer_methods_supported (token leakage via URL). *)
let no_query_when_sender_constrained
  (m: protected_resource_metadata)
  : Tot bool =
  let sender_required =
    (match m.dpop_bound_required with Some true -> true | _ -> false) ||
    (match m.tls_cert_bound with Some true -> true | _ -> false)
  in
  if sender_required then
    match m.bearer_methods_supported with
    | None -> true
    | Some methods -> not (List.mem "query" methods)
  else
    true

(** Full security check combining all invariants. *)
let metadata_secure (known_issuers: list url) (m: protected_resource_metadata) : Tot bool =
  metadata_valid m &&
  authorization_servers_trusted known_issuers m &&
  no_query_when_sender_constrained m

// ──── Lemmas ────

let lemma_empty_resource_invalid ()
  : Lemma (requires (not (is_https_url "")))
          (ensures (metadata_valid { resource = "";
                                     authorization_servers = None;
                                     scopes_supported = None;
                                     bearer_methods_supported = None;
                                     dpop_signing_alg_values = None;
                                     dpop_bound_required = None;
                                     tls_cert_bound = None } = false))
  = ()

let lemma_no_servers_is_trusted (known_issuers: list url)
  : Lemma (ensures (authorization_servers_trusted known_issuers
                      { resource = "https://rs.example.com/resource";
                        authorization_servers = None;
                        scopes_supported = None;
                        bearer_methods_supported = None;
                        dpop_signing_alg_values = None;
                        dpop_bound_required = None;
                        tls_cert_bound = None } = true))
  = ()

let lemma_query_rejected_when_dpop_required
  (r: url)
  : Lemma
    (ensures (
      no_query_when_sender_constrained
        { resource = r;
          authorization_servers = None;
          scopes_supported = None;
          bearer_methods_supported = Some ["header"; "query"];
          dpop_signing_alg_values = None;
          dpop_bound_required = Some true;
          tls_cert_bound = None } = false))
  = ()

let lemma_header_only_passes_with_dpop
  (r: url)
  : Lemma
    (ensures (
      no_query_when_sender_constrained
        { resource = r;
          authorization_servers = None;
          scopes_supported = None;
          bearer_methods_supported = Some ["header"];
          dpop_signing_alg_values = None;
          dpop_bound_required = Some true;
          tls_cert_bound = None } = true))
  = ()

let lemma_query_allowed_without_sender_constraint
  (r: url)
  : Lemma
    (ensures (
      no_query_when_sender_constrained
        { resource = r;
          authorization_servers = None;
          scopes_supported = None;
          bearer_methods_supported = Some ["header"; "query"];
          dpop_signing_alg_values = None;
          dpop_bound_required = None;
          tls_cert_bound = None } = true))
  = ()
