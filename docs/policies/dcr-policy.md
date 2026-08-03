# Dynamic Client Registration (DCR) — BCP Policy Gates

Last updated: 2026-07-07

Status: current implementation baseline

Owner: Governance

Audience: contributors, maintainers

## Ownership
- Owner: Security/Verification
- Review by: Core/Server

## Overview
- This document describes early-time policy gates enforced during Dynamic Client Registration.
- Goals: Enforce OAuth 2.0 Security BCP (RFC 9700), prevent insecure profiles from being registered.
- DCR is an environment-scoped database policy capability. `policy.dcrEnabled=false` means the
  server does not advertise `registration_endpoint` and public DCR routes return JSON 404.
- Verification-boundary note: `id_token_signed_response_alg=RS256` is enforced at runtime today, but the stronger formal closure of that OIDC-mandated `RS256` surface is tracked separately as `RS256 Required Slice`.

## BCP Checks (Implemented)
- Implicit/ROPC prohibited
  - grant_types MUST NOT contain "implicit" or "password"
- Response types consistency
  - response_types MUST be ["code"]
  - If grant_types contains "refresh_token", it MUST also contain "authorization_code"
- OIDC ID Token signing algorithm declaration (OIDC DCR)
  - If `id_token_signed_response_alg` is provided, it MUST be `RS256` (server issues RS256 ID Tokens).
- PKCE enforcement declaration at registration time (operational policy)
  - Public clients (no client_secret): require pkce_required=true when `policy.dcrRequirePkceForPublic=true`
  - Confidential clients: require pkce_required=true when `policy.dcrRequirePkceForConfidential=true`
  - Field accepted: pkce_required (boolean), with aliases require_pkce, oauth_pkce_required
- Sender-constrained tokens declaration
  - `policy.dcrRequireSenderConstrained=true` requires sender_constrained declaration at DCR.
  - Methods allowed via `policy.dcrAllowedSenderMethods`; the only implemented sender method for
    this DCR surface is currently `dpop`.
  - DPoP sender-constrained registration is implemented.
  - mTLS sender-constrained DCR is intentionally fail-closed until RFC 8705 client authentication /
    registration support is implemented for this surface. This does not change the separate runtime
    support for mTLS certificate-bound access-token validation.
  - Fields accepted:
    - require_sender_constrained_tokens (boolean), aliases: sender_constrained_tokens, tls_client_certificate_bound_access_tokens
    - sender_constrained_methods: ["dpop"] accepted; ["mtls"] is parsed and rejected as unimplemented
    - require_dpop / require_mtls (boolean), aliases: dpop_bound_access_tokens / mtls_bound_access_tokens
- private_key_jwt algorithm allow-list + kid presence
  - token_endpoint_auth_signing_alg MUST be in allow-list
  - When kid is required by policy, jwks_uri OR jwks with kid (unique) is required

## Request Fields (subset)
- token_endpoint_auth_method: string (e.g., none, client_secret_basic, private_key_jwt)
- grant_types: [string]
- response_types: [string]
- id_token_signed_response_alg: string (OIDC DCR; if present must be RS256)
- redirect_uris: [string]
- post_logout_redirect_uris: [string] (OIDC RP-Initiated Logout; exact-match whitelist for `post_logout_redirect_uri`)
- backchannel_logout_uri: string (OIDC Back-Channel Logout; RP endpoint for logout token delivery)
- backchannel_logout_session_required: boolean (OIDC Back-Channel Logout; if true, OP omits `sub` and relies on `sid`)
- jwks_uri: string | jwks: { keys: [...] }
- pkce_required: boolean (aliases: require_pkce, oauth_pkce_required)
- software_statement: string (optional, RS256 supported)

## Management Policy Fields
- `policy.dcrEnabled`
  - Publishes `registration_endpoint` and admits `/register` plus `/register/{client_id}` when true.
- `policy.dcrRequirePkceForPublic`
  - Enforces pkce_required=true for public clients (token_endpoint_auth_method=none).
- `policy.dcrRequirePkceForConfidential`
  - Enforces pkce_required=true for confidential clients.
- `policy.dcrRequireSenderConstrained`
  - Enforces declaration of sender-constrained tokens at DCR. Current accepted method: DPoP.
- `policy.dcrAllowedSenderMethods`
  - Restricts which sender-constrained methods are acceptable. Current valid value set: `["dpop"]`.
    Values such as `mtls` are rejected at management policy validation until DCR mTLS support is
    implemented.
- `policy.clientJwtAllowedAlgs`
  - Restricts `token_endpoint_auth_signing_alg`.
- `policy.clientJwtRequireKid`
  - Requires a unique `kid` through `jwks_uri` or inline `jwks` for private-key clients.
- `policy.ssaJwtPem`
  - Configures optional SSA verification public key material.

## Runtime Policy Toggle
- `policy.dcrEverparseRuntimeEnabled=true`
  - Enables EverParse self-check of a canonical binary encoding derived from Rust-decoded DCR fields.
  - NOTE: This does NOT validate raw RFC 7591 JSON input; it is defense-in-depth against encoder/schema drift before FFI boundaries.
  - When enabled, failures are treated as internal errors (500 server_error), not client errors.
  - See: docs/policies/dcr-everparse-self-check.md

## Default/Recommended Policy
- Keep `policy.dcrEnabled=false` unless the deployment intentionally offers public DCR.
- When DCR is enabled, enable both PKCE gates for strongest posture:
  - `policy.dcrRequirePkceForPublic=true`
  - `policy.dcrRequirePkceForConfidential=true`
- Keep response_types=["code"], prohibit implicit/password

## Responses
- On violation: 400 invalid_client_metadata with error_description
- On EverParse self-check failure (`policy.dcrEverparseRuntimeEnabled=true`): 500 server_error (fail-close; indicates an internal bug or misconfiguration)
- Metrics: dcr_bcp_noncompliant_total{reason}
  - reasons include: redirect_invalid, alg_not_allowed, kid_missing, dup_kid, ropc_disallowed, implicit_disallowed, response_types_not_allowed, refresh_requires_code, unsupported_grant, public_pkce_required, confidential_pkce_required
  - and: post_logout_redirect_invalid
  - and: backchannel_logout_uri_invalid
  - and: oidc_id_token_alg_blank, oidc_id_token_alg_not_allowed
  - and: sender_required_missing, sender_method_not_allowed, token_method_unknown,
    token_method_unimplemented, sender_method_unknown, sender_method_unimplemented
    (fail-close before FFI)

## Optional EverParse Self-Check (Runtime)
- Implementation:
  - Canonical encoder: crates/server/src/dcr/everparse.rs (everparse_self_check_registration_with_runtime)
  - EverParse wrapper: crates/ffi/src/dcr_parser.rs (DcrCheck* entrypoints)
- Purpose:
  - Detect internal encoding bugs and schema drift (Rust decode → canonical binary → EverParse validation).
  - This is not a replacement for JSON validation; it runs after serde decoding and policy checks.
- Current limitation:
  - `fstar/lowparse/DcrRegistration.3d` is generated and compiled, but there is no Rust call path to its entrypoint yet; the runtime self-check uses the `DCR.3d` schema via `DcrCheck*`.

## Low*/FFI Boundary (Implementation Note)
- The verified policy core operates over a Low*-friendly record (`dcr_metadata_c`) and enums/bitmasks (no lists/options) in `fstar/jose/Jose.Dcr.fst` (`validate_dcr_metadata_c`).
- Rust normalises decoded JSON into this representation and fails closed on unknown values before crossing the FFI boundary:
  - Server: `crates/server/src/dcr.rs`
  - FFI wrapper: `crates/ffi/src/dcr.rs`

## Examples
1) Public client (accepted)
```json
{
  "token_endpoint_auth_method": "none",
  "pkce_required": true,
  "grant_types": ["authorization_code","refresh_token"],
  "response_types": ["code"],
  "redirect_uris": ["https://app.example/callback"]
}
```

1) Confidential client (accepted)
```json
{
  "token_endpoint_auth_method": "client_secret_basic",
  "pkce_required": true,
  "grant_types": ["authorization_code","refresh_token"],
  "response_types": ["code"],
  "redirect_uris": ["https://app.example/callback"]
}
```

1) Public client missing pkce_required (rejected when `policy.dcrRequirePkceForPublic=true`)
```json
{
  "token_endpoint_auth_method": "none",
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "redirect_uris": ["https://app.example/callback"]
}
```

1) Sender-constrained tokens required (rejected when missing)
```json
{
  "token_endpoint_auth_method": "client_secret_basic",
  "pkce_required": true,
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "redirect_uris": ["https://app.example/callback"]
}
```
→ rejected when `policy.dcrRequireSenderConstrained=true` (reason: `sender_required_missing`)

1) mTLS sender-constrained registration (rejected until RFC 8705 DCR support is implemented)
```json
{
  "token_endpoint_auth_method": "client_secret_basic",
  "pkce_required": true,
  "sender_constrained_methods": ["mtls"],
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "redirect_uris": ["https://app.example/callback"]
}
```
→ rejected (reason: `sender_method_unimplemented`)

1) mTLS client authentication method (rejected until endpoint client auth is implemented)
```json
{
  "token_endpoint_auth_method": "tls_client_auth",
  "pkce_required": true,
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "redirect_uris": ["https://app.example/callback"]
}
```
→ rejected (reason: `token_method_unimplemented`)
