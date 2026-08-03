module JwtAccessToken

open FStar.List.Tot
open FStar.String

module List = FStar.List.Tot
module Str = FStar.String

// RFC 9068 JWT access token profile (normalized claim representation).

type audience = list string

/// Confirmation method discriminator (RFC 9068 §3.1):
///   DPoP → cnf.jkt (JWK Thumbprint)
///   mTLS → cnf.x5t#S256 (X.509 certificate SHA-256 thumbprint)
type cnf_method =
  | CnfJkt     : thumbprint:string -> cnf_method
  | CnfX5tS256 : thumbprint:string -> cnf_method

noeq type jwt_access_token_claims = {
  iss: string;
  sub: string;
  aud: audience;
  exp: nat;
  iat: nat;
  jti: option string;
  scope: option string;
  client_id: option string;
  cnf: option cnf_method;
}

/// RFC 9068 §2.2: required claims — iss, sub, aud must all be non-empty.
let has_required_claims (claims:jwt_access_token_claims) : Tot bool =
  Str.length claims.iss > 0 &&
  Str.length claims.sub > 0 &&
  List.length claims.aud > 0

/// Lemma 1: If `has_required_claims` holds, all three mandatory fields are non-empty.
let lemma_required_claims_present
  (claims:jwt_access_token_claims)
  : Lemma
      (requires has_required_claims claims)
      (ensures
        Str.length claims.iss > 0 /\
        Str.length claims.sub > 0 /\
        List.length claims.aud > 0)
  = ()

/// RFC 9068 §2.2: exp must be strictly after iat.
let temporal_validity (claims:jwt_access_token_claims) : Tot bool =
  claims.exp > claims.iat

/// Lemma 2: Temporal validity ensures exp > iat.
let lemma_temporal_validity
  (claims:jwt_access_token_claims)
  : Lemma
      (requires temporal_validity claims)
      (ensures claims.exp > claims.iat)
  = ()

/// Extract the thumbprint from a cnf method (regardless of DPoP or mTLS).
let cnf_thumbprint (m:cnf_method) : Tot string =
  match m with
  | CnfJkt tp -> tp
  | CnfX5tS256 tp -> tp

/// A token is sender-constrained if `cnf` is present with a non-empty thumbprint.
let is_sender_constrained (claims:jwt_access_token_claims) : Tot bool =
  match claims.cnf with
  | Some m -> Str.length (cnf_thumbprint m) > 0
  | None -> false

/// Lemma 3: Sender-constrained tokens have a non-empty confirmation thumbprint.
let lemma_cnf_binding_present
  (claims:jwt_access_token_claims)
  : Lemma
      (requires is_sender_constrained claims)
      (ensures Some? claims.cnf /\ Str.length (cnf_thumbprint (Some?.v claims.cnf)) > 0)
  = ()

/// A well-formed RFC 9068 JWT AT satisfies all structural invariants.
let is_well_formed (claims:jwt_access_token_claims) : Tot bool =
  has_required_claims claims &&
  temporal_validity claims &&
  Some? claims.jti &&
  (match claims.client_id with | Some cid -> Str.length cid > 0 | None -> false)

/// Lemma 4: Well-formedness implies all sub-properties.
let lemma_well_formed_implies_all
  (claims:jwt_access_token_claims)
  : Lemma
      (requires is_well_formed claims)
      (ensures
        has_required_claims claims /\
        temporal_validity claims /\
        Some? claims.jti /\
        Some? claims.client_id /\
        Str.length (Some?.v claims.client_id) > 0)
  = ()

/// Lemma 5: If a token is both well-formed and sender-constrained,
///           the cnf binding is verifiable alongside all other claims.
let lemma_sender_constrained_well_formed
  (claims:jwt_access_token_claims)
  : Lemma
      (requires is_well_formed claims /\ is_sender_constrained claims)
      (ensures
        has_required_claims claims /\
        temporal_validity claims /\
        Some? claims.cnf /\
        Str.length (cnf_thumbprint (Some?.v claims.cnf)) > 0 /\
        Some? claims.client_id)
  = ()
