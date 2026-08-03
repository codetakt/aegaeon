module Bearer

open FStar.String
open FStar.Option
open FStar.List.Tot

// RFC 6750 Bearer Token Usage with RFC 9700 BCP requirements

// Define result type
type result (a:Type) (e:Type) =
  | Ok: v:a -> result a e
  | Error: err:e -> result a e

// Bearer token claims structure
noeq type bearer_claims = {
  iss: string;        // Issuer (REQUIRED per BCP)
  sub: string;        // Subject
  aud: list string;   // Audience(s)
  exp: nat;           // Expiration time
  nbf: option nat;    // Not before
  iat: nat;           // Issued at
  jti: string;        // JWT ID
  scope: list string; // OAuth scopes
  azp: option string; // Authorized party
  client_id: string;  // Client identifier
}

// Accessor functions
let get_iat (claims: bearer_claims) : nat = claims.iat
let get_exp (claims: bearer_claims) : nat = claims.exp

// Token validation context
noeq type validation_context = {
  current_time: nat;
  expected_issuer: string;
  expected_audience: list string;
  required_scopes: list string;
  max_token_lifetime: nat; // seconds
  clock_skew: nat;        // allowed clock skew in seconds
}

// Validation errors
type validation_error =
  | ExpiredToken
  | TokenNotYetValid
  | InvalidIssuer
  | InvalidAudience
  | InsufficientScope
  | TokenTooOld
  | InvalidIssuedAt
  | ClockSkewExceeded
  | MissingRequiredClaim

// Check if token is within valid time window
let is_token_valid_time (ctx: validation_context) (claims: bearer_claims) : bool =
  let current = ctx.current_time in
  let exp_valid = current <= claims.exp + ctx.clock_skew in
  let nbf_valid = match claims.nbf with
    | None -> true
    | Some nbf -> current >= nbf - ctx.clock_skew
  in
  exp_valid && nbf_valid

// Check token age based on iat
let is_token_fresh (ctx: validation_context) (claims: bearer_claims) : bool =
  let age = ctx.current_time - claims.iat in
  age >= 0 && age <= ctx.max_token_lifetime

// Verify issuer matches expected
let verify_issuer (ctx: validation_context) (claims: bearer_claims) : bool =
  claims.iss = ctx.expected_issuer

// Check if any expected audience matches
let verify_audience (ctx: validation_context) (claims: bearer_claims) : bool =
  existsb (fun expected_aud ->
    mem expected_aud claims.aud
  ) ctx.expected_audience

// Verify all required scopes are present
let verify_scopes (ctx: validation_context) (claims: bearer_claims) : bool =
  for_all (fun required_scope ->
    mem required_scope claims.scope
  ) ctx.required_scopes

// RFC 9700 BCP Policy Gates
type bcp_policy = {
  require_pkce: bool;           // MUST be true per BCP
  require_exact_redirect: bool; // MUST be true per BCP
  require_sender_constrained: bool; // SHOULD be true (DPoP or mTLS)
  forbid_implicit_flow: bool;  // MUST be true per BCP
  forbid_ropc: bool;           // MUST be true per BCP
  require_state_parameter: bool; // MUST be true for auth code flow
  min_state_entropy_bits: nat; // Minimum 128 bits recommended
}

// Default BCP-compliant policy
let bcp_compliant_policy : bcp_policy = {
  require_pkce = true;
  require_exact_redirect = true;
  require_sender_constrained = true;
  forbid_implicit_flow = true;
  forbid_ropc = true;
  require_state_parameter = true;
  min_state_entropy_bits = 128;
}

// Core validation invariants
let validate_temporal_consistency (claims: bearer_claims) : bool =
  // iat must be before exp
  claims.iat < claims.exp &&
  // If nbf exists, it must be >= iat and < exp
  (match claims.nbf with
   | None -> true
   | Some nbf -> nbf >= claims.iat && nbf < claims.exp)

// -----------------------------------------------------------------------------
// RFC 8693 Token Exchange (Aegaeon MVP profile)
// -----------------------------------------------------------------------------

// Model the exchanged token expiry as:
//   exp_out = min(subject_exp, now + max_lifetime)
// This matches the runtime policy "expires_in = min(remaining, 3600)".
let token_exchange_exp (now:nat) (subject_exp:nat) (max_lifetime:nat) : nat =
  if subject_exp <= now + max_lifetime then subject_exp else now + max_lifetime

let lemma_token_exchange_exp_not_extended
  (now:nat)
  (subject_exp:nat)
  (max_lifetime:nat)
  : Lemma
      (ensures token_exchange_exp now subject_exp max_lifetime <= subject_exp)
  = ()

// Main validation function with all BCP requirements
let validate_bearer_token
  (ctx: validation_context)
  (claims: bearer_claims)
  : result unit validation_error =
  // RFC 9700 BCP: iss parameter MUST be included and validated
  if not (verify_issuer ctx claims) then
    Error InvalidIssuer
  // Check temporal consistency invariants
  else if not (validate_temporal_consistency claims) then
    Error InvalidIssuedAt
  // Check expiration
  else if not (is_token_valid_time ctx claims) then
    if ctx.current_time > claims.exp + ctx.clock_skew then
      Error ExpiredToken
    else
      Error TokenNotYetValid
  // Check token freshness
  else if not (is_token_fresh ctx claims) then
    Error TokenTooOld
  // Validate audience
  else if not (verify_audience ctx claims) then
    Error InvalidAudience
  // Validate scopes
  else if not (verify_scopes ctx claims) then
    Error InsufficientScope
  else
    Ok ()

// Lemma: temporal consistency ensures no time travel
let lemma_temporal_consistency_no_time_travel (claims: bearer_claims) :
  Lemma (requires validate_temporal_consistency claims)
        (ensures (get_iat claims < get_exp claims)) = ()

// Lemma: valid token time with fresh token implies not expired
let lemma_valid_and_fresh_not_expired
  (ctx: validation_context)
  (claims: bearer_claims) :
  Lemma (requires is_token_valid_time ctx claims &&
                  is_token_fresh ctx claims &&
                  validate_temporal_consistency claims)
        (ensures ctx.current_time <= claims.exp + ctx.clock_skew) = ()

// Policy validation
let validate_bcp_policy (policy: bcp_policy) : bool =
  policy.require_pkce &&
  policy.require_exact_redirect &&
  policy.forbid_implicit_flow &&
  policy.forbid_ropc &&
  policy.require_state_parameter &&
  policy.min_state_entropy_bits >= 128

// Lemma: BCP compliant policy is always valid
let lemma_bcp_compliant_policy_valid () :
  Lemma (ensures validate_bcp_policy bcp_compliant_policy) = ()
