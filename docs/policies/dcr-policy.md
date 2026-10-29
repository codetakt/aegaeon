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

## Software Statement Trust and Identity

DCR software statements use RS256 and the single RSA verification key in
`policy.ssaJwtPem`. RFC 7591 section 2.3 requires an issuer for a signed
statement. Aegaeon requires a present, nonempty string `iss` even when
`policy.ssaExpectedIss` is absent, and locally rejects whitespace-only issuers.
Signed values are preserved without trimming, case folding or URL normalization.
An optional `policy.ssaExpectedIss` pins an exact issuer. Configuring only a
trusted key accepts statements from that key with any otherwise valid issuer;
it does not establish a fixed issuer allowlist or perform key discovery.

For audience-bearing statements, configure `policy.ssaExpectedAud` to the intended
recipient, for example `https://registration.example/register`. Both the initial
signature/JWT admission and the later surface-aware claims validation use that
same immutable policy snapshot. The audience must be an exact matching string
or an array of strings containing the configured value, as in RFC 7519 section
4.1.3. Other array entries and duplicates are permitted; malformed, empty,
mismatched, missing and null audiences are refused when a recipient is configured.
With no expected audience, absent/null `aud` remains optional and a present
non-null audience is rejected. This is Aegaeon's local recipient policy, not a
standard requirement to omit `aud`. No issuer or endpoint alias is inferred.
Existing policy admission trims configured expected issuer/audience strings and
rejects blank settings; it never rewrites signed claim values.

Upgrade: previously accepted statements missing `iss` now return
`invalid_software_statement`. Correctly addressed statements now pass the initial
JWT audience gate when `ssaExpectedAud` is configured. These checks apply to
POST registration and authenticated owner PUT before persistence. A refusal
preserves the registration and its current registration access token; owner
authentication precedes statement validation. Requests without a statement retain
the existing registration policy. Missing verification configuration returns
`unapproved_software_statement`; key/backend/clock failures remain operational
errors with bounded public descriptions.

Signature/protected-header checks, raw duplicate/shape rejection, the header
size limit, and current metadata-consistency checks remain in force. This change
does not promote, persist or echo trusted statement metadata, or complete owner
registration roundtripping. Existing library and local time validators retain
their separate expiration/nbf/leeway behavior; full temporal conformance is not
established here. No schema migration, dependency or configuration field is added.

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
nonstring values, expired or revoked credentials, and mismatches return
`400 invalid_client_metadata`. An absent assertion adds no comparison condition.
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

### Active client-secret capacity upgrade

Apply `20261029020000_client_secret_active_slots.sql` in a **full service maintenance
window** after stopping and draining all server processes, readers, writers, workers
and other database consumers. The migration takes `ACCESS EXCLUSIVE` on
`client_secrets` throughout backfill and constraint installation; reads also block.
Keep traffic stopped through any repair, migration and deployment of the matching
server. Resume only after migration and startup checks succeed. This is an offline
upgrade, with a verified backup and a reviewed interruption window.

The migration preserves existing slot assignments, hashes, status, expiration and
provenance; it only fills missing slot assignments. It aborts atomically if any client
has more than two ACTIVE rows, including expired credentials and clients that are
deleted or belong to an inactive configuration. The migration never chooses a
credential to invalidate. Do not rename an applied migration version.

Inventory excess rows before maintenance. Explicit revocation through the existing
management operation is available only for clients admitted by that operation's
current active-configuration/status checks. A 404 for a deleted or old-configuration
client does not remove its credentials from the migration's inventory.

```sql
SELECT environment_id, client_id, count(*) AS active_credentials
FROM aegaeon.client_secrets
WHERE status = 'ACTIVE'
GROUP BY environment_id, client_id
HAVING count(*) > 2;
```

Owner-update assertions check both eligible overlapping credentials on a blocking
worker, then recheck matched credential status and expiration using a fresh database
statement clock before the metadata/token mutation. A third eligible row is refused
before hashing even against an unupgraded schema. Registration, client, and environment
locks preserve the existing update-currentness and single-winner token rotation rules.
Management issuance now returns HTTP 409 `client_secret_capacity_exceeded` when both
ACTIVE slots are occupied; an expired credential must be explicitly revoked to free
its slot. This changes capacity enforcement, not secret rotation or revocation policy.

For credentials inaccessible to management, use
[`client-secret-capacity-repair.sql`](../../scripts/operations/client-secret-capacity-repair.sql)
under database administrator authority during the same full maintenance window.
Record the operator, approval reference, exact environment/client/credential IDs,
observed client status, client configuration and active environment configuration.
Choose which credential to revoke after reviewing its consumers; there is no
oldest-first or expired-first automatic selection. Keep the inventory, backup,
reviewed input, script hash and execution receipt privately.

On one administrative connection, create `TEMP TABLE client_secret_repair_input
(request jsonb NOT NULL)` and insert exactly one reviewed object with string fields
`operator`, `approval_reference`, `environment_id`, `client_id`, `client_secret_id`,
`expected_client_status`, `expected_client_configuration_version_id`, and
`expected_active_configuration_version_id`. Every key is required; for an environment
without an active configuration, the last field must be an explicit JSON `null`,
not an omitted key. Read those IDs/status values from the
retained inventory; do not put plaintext or credential hashes in the input.
The script locks and rechecks scope/status/configuration, revokes only that ACTIVE
credential, and appends an `operations.clientSecret.revoked.v1` audit event in the
same transaction. It works for deleted and inactive-configuration clients without
reactivating them. Its default final `ROLLBACK` is the review run. After reviewing
that result, an approved copy may replace only the final `ROLLBACK` with `COMMIT`.
A refusal or audit failure rolls back revocation. Repeat only with separately
reviewed selections, rerun the excess inventory, and retry the unchanged migration
when no client exceeds capacity. Never delete or rewrite historical audit events.

All HTTP owner PUTs share a process-wide limit of two admitted requests, acquired
without waiting before any database-using middleware, authentication lookup or
body parsing. Saturation returns no-cache HTTP 503 `temporarily_unavailable`
before authentication, independently of credential validity or body contents.
Once admitted, authentication still precedes metadata parsing and its errors.
Transport-security rejection retains precedence over capacity admission. Other
HTTP methods and routes are unaffected. Direct persistence calls with a secret
assertion join the same budget; HTTP persistence reuses its request admission.

An owned transaction task retains admission through commit or explicit rollback
and completed SQLx pool return. Caller cancellation and commit admission use a
shared atomic transition after mutation. Cancellation that wins this transition
requires rollback, including cancellation during the final mutation poll. Once
commit admission wins, completion is allowed. If the update committed and its
response was lost, the old registration access token is invalid and the stored
replacement hash cannot recover the new token. State inspection then requires
authorized operator assistance; owner-token recovery is not provided by this
change. Do not retry an ambiguous update assuming that the old token can still
read the registration. Blocking
verification shares the admission lease until its actual exit, even if rollback
finishes earlier. This bounds admitted owner-update work in this process; it is
not a general database fairness or cross-process rate-limit guarantee.

Admitted owner PUT bodies must finish within an absolute 10-second deadline and
remain within the existing 2 MiB limit. Receiving another chunk does not extend
the deadline. Incomplete bodies return no-cache HTTP 408 `invalid_request` and
release admission without starting database work.

During admitted owner updates, authority, registration-token, profile and client
projection reads carry the request lease through cancelled statement cleanup and
completed connection return. A cancelled authority statement inside this owner
update budget refuses that request with no-cache HTTP 503 without latching a
process restart; this also applies to the pre-mutation client projection reload
after a changed fingerprint, including statement timeouts during admitted
connection setup. The next request must check current authority again.
Post-commit synchronization failures retain their process restart policy. Other
authority failures retain their restart policy. Cancellation while waiting for
SQLx checkout retains admission until the configured pool acquisition deadline
or completed checkout and cleanup. SQLx may already be running connection hooks
inside acquisition, so dropping the whole acquisition future cannot establish
completed cleanup. This bound is distinct from the SQL statement timeout.

Each such connection temporarily uses a 5-second server
statement timeout (or a stricter existing limit), restoring the previous setting
before reuse. The mutation
transaction uses the same 5-second statement timeout locally. A blocked statement
therefore ends even while an external lock remains held; rollback and connection
cleanup still retain admission. These server deadlines do not claim an overall
request deadline or bounded recovery from a failed database/network/runtime.

Runtime shutdown or an aborted owned worker is different from ordinary caller
cancellation. If acquisition, mutation or connection cleanup is interrupted,
the attached process admission class closes until process restart. Connection
cleanup has a separate owner that never schedules itself from its destructor;
an interrupted cleanup detaches and drops its transport without returning it
to the pool. Closing admission is fail-closed handling, not proof that a remote
statement has already stopped or that an interrupted commit did not happen.

Cancellation after commit admission can leave the in-memory client projection at
its preceding revision because the HTTP continuation no longer runs. The commit
is retained. Before a subsequent protected request reaches its handler, the
runtime authority guard reads the current primary revision and synchronizes the
client projection, or refuses the request with no-cache HTTP 503 and requests a
restart on authority failure. Health and readiness probes are excluded; requests
already admitted before the update are not retroactively cancelled. A lost
response still requires the credential recovery procedure described above.
