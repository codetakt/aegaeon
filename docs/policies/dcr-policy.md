# Dynamic Client Registration (DCR) — BCP Policy Gates

Last updated: 2026-10-02

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

## Owner update credentials

After registration access token authentication, `PUT /register/{client_id}`
requires a string `client_id` equal to the registered identifier in the path,
as specified by [RFC 7592 section 2.2](https://www.rfc-editor.org/rfc/rfc7592#section-2.2).
Missing, null, empty, nonstring, or mismatched identifiers return
`400 invalid_client_metadata`.

An optional string `client_secret` asserts possession of a currently eligible
issued credential. Its exact bytes are compared with the client's active,
unexpired Argon2id credentials within the locked update transaction. Any eligible
credential in an overlapping rotation period may match, including credentials
issued under an earlier configuration for the same stable client. Null or other
nonstring values return `400 invalid_client_metadata` during input admission.
A string assertion matching no currently eligible credential returns that error
after preparation currentness succeeds. For an admitted update, a change to
eligible-secret presence since authentication instead returns 409 as described
below. An absent assertion adds no secret comparison condition.
The supplied value cannot select or replace the server-generated secret and is
never included in registration metadata, responses, or audit records.

Rust callers of `update_dynamic_registration` must now pass the optional
`client_secret_assertion` argument before `request_id`. Forward any received
assertion unchanged; pass `None` only when no assertion was supplied.

Aegaeon rejects `registration_access_token`, `registration_client_uri`,
`client_secret_expires_at`, and `client_id_issued_at` by presence, including null,
with `400 invalid_client_metadata`. This is Aegaeon's rejection policy for the
client-side exclusions in RFC 7592 section 2.2. Unknown other metadata remains
ignored, and duplicate JSON keys or recognized aliases remain rejected.

Credential comparison occurs after the current owner token, client and
environment are locked and before any writes. The database clock is sampled
after a lock wait. A failed assertion leaves metadata, credentials, the owner
token and audit state unchanged. Concurrent use of a rotated owner token retains
the existing conflict behavior. Expiry after the protected comparison is not a
retroactive cancellation of an admitted update.

Omitted/null metadata retention, token rotation and server secret generation
retain their existing behavior. Complete metadata response/clearability and
credential delivery/retry/recovery remain separate work: a committed mutation
can still be followed by runtime synchronization or response-delivery failure.
These request checks do not establish complete RFC 7592 conformance.

## Owner update preparation currentness

Aegaeon captures the persisted client and registration state while authenticating
an owner PUT. After locking environment, client and registration in that order,
it compares the current semantic values and eligible-secret presence before any
assertion check or write. Concurrent changes to inherited metadata, explicit
OAuth profile assignment or secret presence return HTTP 409. This local
concurrency contract supplements RFC 7592 section 2.2; it is not a new RFC MUST.

A refused stale preparation leaves metadata, registration token, credentials,
audit and runtime projection unchanged. Read current metadata and deliberately
resubmit the intended update after resolving the conflict. The server does not
rebuild or retry it automatically. An owner token already invalid when the
request authenticates still returns 401; invalidation after that load returns 409.

Eligibility uses the post-lock statement time, including when a lock wait crosses
secret expiry. Adding another eligible overlapping credential while at least one
remains eligible does not itself cause a conflict. Any supplied secret assertion
still checks all currently eligible credentials. Issuance configuration remains
provenance. Expiry is checked at the protected database read, not response delivery.

Only bookkeeping creation/update times are excluded from the comparison.
Semantic timestamps retain exact precision and are independent of connection
TimeZone. Identical semantic state is sufficient; this is not a historical
revision/ABA detector. DELETE uses the ordered owner/membership locks without a
metadata-equality requirement, and GET remains read-only.

Rust API compatibility: `DcrStoredClient` now contains private preparation state;
external struct literals are no longer supported. Obtain it through
`load_dynamic_registration_by_token` and pass that authenticated value to update
or delete. Cloning remains supported. Debug output contains only environment and
database client IDs; preparation contents never enter responses or audit events.
No database migration, persisted revision, public ETag or configuration is added.
Successful update token rotation and postcommit synchronization retain their
existing behavior, including the possibility of a failure after commit.

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

## Durable client DPoP requirement

RFC 9449 §5.2 `dpop_bound_access_tokens` is stored on the client and reported as a
boolean in registration POST, GET and PUT responses, including false. Input aliases
`require_dpop` and `dpop_required` remain accepted; collisions and nonboolean values
are rejected. POST omission/null defaults to false. Owner PUT omission/null retains
the stored value; explicit true/false replaces it under normal owner authority.

True requires a verified DPoP proof on all six token grants. NONE/DPoP profiles are
compatible; an effective mTLS policy conflicts and fails closed. The independent
minimum remains subject to the global DPoP capability allowlist and does not satisfy
the separate `require_sender_constrained_tokens` declaration requirement. Generic
sender metadata retains its existing profile validation. Owner updates check the
existing client's actual assigned/default profile for a known mTLS conflict.

False cannot lower environment/profile requirements or erase existing token/grant
bindings. Requiring a proof does not invent a prior binding on a legacy unbound
refresh grant: a valid proof can bind the newly issued access/refresh tokens.
The authenticated client is captured for each request; later edits affect subsequent
requests, subject to existing stronger currentness checks. The profile remains a
separate database observation. This metadata adds no code/PAR key-binding behavior.

Existing deployments must follow the stopped-writer [explicit legacy resolution
procedure](../operations/client-dpop-minimum-upgrade.md). Unresolved authority never
becomes false. Existing software-statement selection and verifier retention limits
remain separate from this metadata behavior.
