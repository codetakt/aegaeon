# OAuth authentication errors, sender binding and authorization details

Last updated: 2026-10-02

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

## Client authentication errors

For recognized Basic, client_secret_post and private_key_jwt authentication,
`/token`, `/device_authorization`, `/par`, `/introspect` and `/revoke` return
`401 invalid_client` with one Basic `WWW-Authenticate` challenge when client
authentication fails. Token and device authorization now include this challenge;
their existing JSON envelope and no-cache headers are preserved. A Basic challenge
on a body-authentication failure advertises a supported HTTP scheme, as permitted
by RFC 6749 §5.2; it does not change the client's registered authentication method.
RFC 7662 §2.3 also requires 401 for invalid introspection client credentials.

After form and header admission, Basic combined with a nonempty client_secret
and no client assertion returns `400 invalid_request` without a challenge.
Clients that previously received `401 invalid_client` for this combination at
PAR, introspection or revocation must handle the corrected category. A client
assertion combined with Basic, client_secret_post, or both returns
`401 invalid_client` with a Basic challenge (RFC 7521 §4.2.1). Either remaining
client assertion field counts; empty form values are omitted and whitespace
remains a supplied value. The JWT bearer grant's `assertion` field is separate.

Mixtures are rejected before assertion validation and replay reservation.
An assertion authenticated successfully before a later profile rejection remains
consumed; clients need a fresh assertion when retrying. Internal backend errors
remain generic server errors without an authentication challenge.

A supplied Basic scheme is an authentication attempt even when its payload is
missing or undecodable. Bare `Basic`, mixed-case variants and Basic followed only
by spaces or tabs participate in the same mixture checks. With Basic alone, these
requests return `401 invalid_client` and the endpoint's Basic challenge before
client identity selection. Malformed Basic now precedes a missing outer
`client_id` at plain PAR and registration snapshot errors at introspection.
Earlier transport, URI and form admission still takes precedence. Valid Basic
retains existing identity, registration and secret checks.

On upgrade, clients sending incomplete Basic alongside body credentials or public
client requests must remove that header or supply valid credentials for their
registered method. A rejected assertion mixture does not consume the assertion.
Existing leading/separator whitespace acceptance and rejection of trailing
payload whitespace remain; these application checks do not define proxy or wire
normalization. An entirely empty Authorization value is distinct from bare Basic.

Duplicate/nontext headers, entirely empty values, malformed scheme syntax and
unsupported schemes retain their prior behavior and remain outside this bounded
correction. Their challenge classification is not certified here. Existing
profile-error realms and late revocation/JWT-introspection refusals retain their
behavior.

## Error field encoding

Outgoing OAuth `error` and `error_description` values use the ASCII alphabet
in RFC 6749 §§4.1.2.1, 4.2.2, 5.2 and appendices A.7/A.8, also used by
RFC 6750 §3 challenge attributes. Valid nonempty error codes and descriptions
are preserved. Each disallowed description character becomes one `?`, including
quotes, backslashes, controls and non-ASCII Unicode characters. Absent or empty
descriptions are omitted. An empty or malformed error code becomes `server_error`.

This happens before JSON, query, form-post or challenge encoding. Ordinary
transport escaping still applies to valid punctuation. The same rule applies to
registration diagnostics, upstream error passthrough, public error helpers and
direct serialization of `ParError` and `TokenResponse::Error`. Their stored and
in-memory values are preserved. State and issuer values, destinations, response
modes, HTTP status and authentication/replay/storage behavior are unchanged.

Consumers that display diagnostics will see question marks in place of invalid
characters and must tolerate an omitted empty description. Normalization does
not redact secrets; internal failures continue to use fixed public descriptions.
This correction does not establish all OAuth error categories, header admission
or resource-server challenge composition. No configuration or storage migration
is required.

## Dynamic registration validation errors

POST `/register` and authenticated PUT `/register/:client_id` preserve the
RFC 7591 §3.2.2 validation category. Malformed `redirect_uris` arrays or rejected
redirect values return `400 invalid_redirect_uri`; other client metadata,
including logout URI fields, returns `400 invalid_client_metadata`. Duplicate
members retain the metadata-error category and malformed JSON remains
`invalid_request`. Existing validation rules and ordering still apply.

An invalid submitted software statement returns `400 invalid_software_statement`.
A verified statement with a validly shaped but unacceptable redirect URI returns
`invalid_redirect_uri`; conflicts with the request metadata remain
`invalid_client_metadata`. When optional software-statement verification is not
configured, a submitted statement returns `400 unapproved_software_statement`,
including malformed statement input. This local approval policy preserves the
existing refusal; requests that omit the optional statement retain their behavior.

Parser backend, self-check, clock and defensive verifier configuration failures
return `500 server_error` with fixed public descriptions. Metadata and internal
errors include no-store/no-cache and do not add an authentication challenge.
Initial-token and registration-token authentication errors, full software-statement
metadata semantics, and registration replacement rules are separate contracts.
A synchronization failure after a database commit still returns 503; it does not
mean the registration or rotated registration token was rolled back.

Rust callers must update exhaustive matches for the new
`ClientRegistrationParseError::InvalidRedirectUri` and
`SoftwareStatementVerificationError::{Unapproved, Internal}` variants. The existing
`Invalid` and `BackendPolicy` variants remain. Public String-returning registration
and redirect validation functions retain their signatures and diagnostics, while
HTTP handlers consume typed causes from the same validation pass. No storage or
configuration migration is required for this error-category change.

## Dynamic registration Bearer authentication

Required initial-access-token checks on POST `/register` and owner-token checks
on GET, HEAD, PUT and DELETE `/register/:client_id` use the RFC 6750 sections 2–3
response contract (see also RFC 7592 sections 2.1–2.3 and OIDC Registration
section 4.4). Missing or whitespace-only Authorization, or a single textual
unsupported scheme, returns an empty 401 with exactly
`WWW-Authenticate: Bearer realm="aegaeon"`. Duplicate/nontext Authorization,
bare Bearer and extra Bearer token words return `400 invalid_request`; a
structurally admitted but nonmatching token returns `401 invalid_token`.
Error-bearing responses have one Bearer realm/error challenge, fixed JSON
description, issuer and no-store/no-cache. The empty 401 also has no-store/no-cache.

Rejected `access_token` query parameters, including empty values and aliases
already rejected by URI admission, receive a Bearer `invalid_request` challenge
on enabled protected DCR routes and their supported methods. Query tokens never
authenticate. Other forbidden credential keys, generic query limits, unrelated
routes, lookalike paths and unsupported methods retain generic URI refusal.
Open initial registration retains its behavior, including ignoring unused
Authorization headers. Disabled DCR remains a handler-level 404; outer transport
or URI admission can still reject a request first.

Transport, runtime, body-limit, path and content-type checks keep their existing
precedence. Authenticated metadata errors and internal failures do not acquire
Bearer challenges. A matching owner token still authorizes read/update/delete;
unknown clients and wrong client/issuer/token combinations return the same 401.
Initial and owner tokens are distinct credentials. No new permission policy or
recovery after a committed mutation is established by these error responses.

Upgrade clients to inspect status and `WWW-Authenticate` before assuming an
error body is JSON: missing or unsupported authentication now has an empty body.
Existing case-insensitive Bearer names, accepted whitespace and token formats
remain unchanged. No configuration or database migration is required.

## DPoP responses

RFC 9449 §§5, 7.1 and 9 distinguish authorization-server and resource-server
responses. The token endpoint returns `400 invalid_dpop_proof` for malformed,
invalid or replayed proofs, and `400 use_dpop_nonce` with `DPoP-Nonce` for nonce
challenges. Resource endpoints return 401 with a DPoP `WWW-Authenticate`
challenge including `algs="EdDSA"`. Their nonce challenges also include `DPoP-Nonce`.
See [protected-resource authentication errors](resource-authentication-errors.md) for
the empty unauthenticated response, malformed credentials and proof-effect order.

Empty proof identifiers are refused before nonce/replay-store access. Valid
identifiers still undergo replay detection; the server does not claim to infer
the randomness of a client-generated identifier.

Nonce records are scoped separately to the AS and RS within each runtime
namespace. One expiring Redis record per role retains only the current and previous
values. Concurrent challenges reuse the current value until its TTL elapses;
traffic never extends its deadline. Redis time governs rotation, and the previous
value is accepted for at most one additional TTL. Long idle periods do not renew
expired nonces. Value and expiry are stored atomically with `SET ... PX`; a
record without a retained expiry is refused as a backend error. Clients must keep separate nonce state for each issuer and role.
After upgrading, previously issued nonce values may receive a new challenge;
retry with a fresh proof and the nonce from the applicable endpoint. Backend
failures return 503 without misclassifying them as invalid credentials.

A DPoP-bound token presented with Bearer authentication is rejected even when
the request also includes a valid proof. A Bearer `invalid_token` challenge for
that attempted scheme is consistent with RFC 9449 §7.2. Certificate-bound
tokens use Bearer authentication with `cnf.x5t#S256`, as specified by RFC 8705.
The scheme check also applies to the upstream-refresh resource. When explicit
ingress policy requires a certificate, missing or malformed certificate metadata
returns `401 invalid_token` with a Bearer challenge on UserInfo, `/resource` and
`/oauth/upstream/refresh` (RFC 8705 §3.1 and RFC 6750 §3.1). UserInfo GET
and POST preserve the attempted scheme in the challenge even when a proof is
present. Structurally admitted DPoP credentials without their proof return
`invalid_dpop_proof` for every header separator accepted by the resource parser.
A bare DPoP scheme is malformed credentials and returns 400 `invalid_request`
before proof or nonce processing.

Device-code responses and saved access-token records use the confirmation
actually issued: `DPoP` for `cnf.jkt`, and `Bearer` for certificate-bound or
unbound tokens. Clients must use the returned scheme when presenting the token.

## Mixed DPoP and certificate-bound clients

Keep the environment's DPoP default and nonce enforcement. Enable `mtlsEnabled`
and select `senderConstrained: MTLS` on an administrative OAuth profile for
clients that use certificate binding. Other profiles continue to use DPoP.
Disabling the refresh-policy option cannot remove a binding from an already
bound refresh token. Such tokens always require the original key or certificate.
Setting a profile to NONE does not remove an environment binding requirement.
DPoP and mTLS are alternative mechanisms; a resource checks the binding stored
in each token, independently of the default selected for new issuance.

Terminate TLS at a trusted proxy that verifies client certificates, removes all
client-supplied certificate forwarding headers, and forwards only the verified
certificate's SHA-256 fingerprint. Configure an explicit trusted proxy range
and HTTPS enforcement. A client-supplied header or an untrusted direct
connection is not certificate evidence.

An environment's mTLS token policy no longer enables certificate requirements
for browser login, consent and management routes. Operators who require client
certificates on every ingress request must explicitly set
`AEGAEON_REQUIRE_MTLS_FROM_PROXY=1`. That transport policy remains enforced.
Separate mTLS endpoint aliases/hosts can require certificates during the TLS
handshake while the browser-facing listener permits ordinary HTTPS. A failed
TLS handshake has no OAuth HTTP error response. When an HTTP resource request
reaches the server without the certificate required for its token, it receives
401 `invalid_token`.

This profile support implements certificate-bound tokens, not OAuth
`tls_client_auth` or `self_signed_tls_client_auth`. Those authentication methods
and mTLS DCR admission remain unsupported and are rejected. DCR's standard
`tls_client_certificate_bound_access_tokens` flag denotes mTLS specifically;
it is not an alias for generic sender binding or DPoP. Management-created mTLS
clients use a supported client authentication method in addition to binding.

## RAR support boundary and upgrades

No runtime RAR type currently implements semantic validation, attenuation and
resource authorization. A type name alone cannot enable these semantics.
Activation and startup reject nonempty `authorizationDetailsTypesSupported`.
The token endpoint rejects nonempty `authorization_details` with 400
`invalid_authorization_details` before consuming a code, rotating a refresh
token or publishing access tokens. Duplicates return `invalid_request`, even
if both values are empty. A single empty form value is omitted per RFC 6749
§3.2; unknown unrelated OAuth extensions remain ignored.

Stored RAR-bearing codes and refresh grants are rejected with `invalid_grant`
before consumption or rotation. Exchange refuses such subjects with
`invalid_request`, including legacy same-audience exchange. Resources reject
stored details they cannot enforce with `invalid_token`. Existing constraints
are retained in storage; clients must obtain new authorization after their
intended permissions can be expressed by supported mechanisms. Removing the
request parameter cannot remove constraints from an existing grant.

Before upgrading an environment with a nonempty type allowlist, remove that
allowlist through the old binary's management API using an audited
configuration activation. Coordinate clients relying on RAR: new constrained
requests will be refused. Keep the prior binary and configuration evidence
for rollback planning; do not modify the migration ledger or silently erase
constraints from tokens. The protocol-only repair did not change migrations. The application adapter described below adds a migration; use its upgrade procedure.

The RAR matrix remains partial: structural models and persistence tests do not
establish full endpoint conformance or type-specific authorization. Internal
tests of fabricated stored details do not prove such subjects are issuable
over supported HTTP endpoints.

## Authorization diagnostics

Consent errors return the general description `consent request could not be validated; restart authorization`.
Missing Origin does not assert that a stored transaction is expired or already used.
Each consent submission receives a server-generated `x-request-id`; structured warning events carry
that identifier and a stable reason for Origin, session, snapshot, or transaction admission failures.
Storage failures remain `503 temporarily_unavailable`. Authorization-code refusals log a stable
reason including `state_reused` or `nonce_reused` with the authorization request identifier.
Events do not include raw state, nonce, code, consent token, Request Object, or database payloads.
The public OAuth error categories and redirect validation remain unchanged.

## Optional application authority

The adapter is an explicit application extension, not an OIDC profile claim mapper.
An empty `application_authorizations` table releases no application authority.
User-editable profile attributes, OAuth scope names and client-supplied organization
headers never grant roles. The privileged projection accepts only the contract's
USER/SUPER_ADMIN global roles and ORGANIZATION_ADMIN/ORGANIZATION_STAFF memberships.
These roles have no implicit hierarchy.

An interactive OWNER or ADMINISTRATOR with valid Origin/CSRF submits
`POST /api/v1/teams/{teamId}/environments/{environmentId}/application-authorizations`.
The generated management OpenAPI documents its typed request and the required
integer `revision` in its successful JSON response. `baseRevision: 0`
creates an entry; updates require the current revision, the same `authority` label,
a strictly increasing `sourceRevision`, and an audit reason. Each entry identifies
one registered client, one subject, and explicit claim-release audiences.
Creating or enabling an entry requires active identities. Disabling an existing
entry remains possible after client deletion or subject suspension/deletion, with
the same management authorization, revision, authority and audit requirements.
A disable request cannot create a new entry. Reactivating identities does not
restore an old grant; enabling the projection requires a fresh revision.
The audit event and update commit together. A service principal has subject equal
to client ID and both role arrays empty; human code issuance rejects that ambiguous
identity. Management API keys cannot write projections.

Application grants capture the projection revision at authorization. Approved
device issuance also captures the approved client and subject's current projection,
keeps its publication lock until token storage completes, and records the same
snapshot in the JWT mint input and token metadata. Code exchange, refresh, token
exchange, introspection and local resources recheck current authority.
Changing or disabling a projection invalidates old grants; adding permissions never
upgrades an old token or refresh family. Obtain new interactive authorization.
For token exchange, `organization_id` selects exactly one existing membership and
removes SUPER_ADMIN. A parent with organization claims that has not yet selected
an organization requires a canonical selector. An already-selected parent retains
that organization when the selector is omitted; an explicit different organization
is rejected. A subsequent exchange cannot widen scope or add audiences.
This application contract is configured explicitly by the relying application:
use `GET /application/authorization` at the configured issuer and the documented
`organization_id` request parameter. OIDC discovery does not advertise this
application-specific contract. The two earlier experimental application
metadata keys have been removed; consumers of that candidate must use explicit
configuration. Any future discovery extension requires an `aeg_*` name and an
explicit, default-off policy toggle; none is introduced by this change.

The token endpoint ignores unknown request names, including `organizationId`;
it is not an alias for `organization_id`. Repeated unknown fields remain ignored.
This follows RFC 6749 §3.2 without discarding a recognized authorization
restriction: nonempty canonical `organization_id` is supported only by token
exchange and returns `400 invalid_request` on other grants. Parameter names are
case-sensitive. Empty or valueless canonical fields are omitted before applicability
and duplicate checks; one nonempty plus empty fields is one selector, while two
nonempty canonical fields are rejected, even when equal or percent-encoded to
the same name.

Consumers requiring organization selection must send the canonical name.
Ignoring `organizationId` means the request behaves as if that field were absent;
it does not mean the caller's intended restriction was applied. Canonical A plus
an unknown camelCase B still selects A. A camelCase-only request cannot select
an unselected organization-bearing parent, cannot switch a preselected parent,
and can retain existing global-only roles on an otherwise valid exchange just
as an omitted selector can. A request cannot invent application authority or
membership. This compatibility correction preserves the known grant restriction,
existing authority/currentness checks and grant consumption rules.

The context endpoint uses the original UserInfo token and sender proof, returning
issuer/subject/client ID with authoritative application claims. This does not let
an OAuth client infer privileges by decoding an unverified access token.

The projection's audience list controls application claim release. A valid token
for another OAuth audience may still authorize ordinary OAuth resource access,
but its JWT and introspection response omit application claims, and the application
context endpoint rejects it. Token metadata retains the projection even when
claims are omitted, so later projection changes still invalidate online use.
UserInfo and ordinary resource responses do not copy application projection claims.

Organization memberships also require a configured, live membership authority.
Configure `AEGAEON_INORII_AUTHORITY_DATABASE_URL` with separate SELECT-only credentials
for `authorization_subject_bindings`, `organization_users` and `organizations`.
The adapter requires an exact HTTPS issuer/subject mapping to the authority's
user identifier. Provision that mapping through the authority's privileged,
audited administration. A projection cannot create a membership, reactivate an inactive member or
invent a role. Membership removal is checked on every use with no positive cache
and a two-second lookup deadline. Unavailable authority fails closed with 503;
removed or changed authority rejects the credential. Concurrent operations may
have authorized before removal commits; subsequent online checks reject the token.
A projection-row shared lock serializes publication with projection updates only.
The external membership DB and Redis are not claimed to form a distributed transaction.

Remote DB connections require `sslmode=verify-full`; the effective SQLx settings,
including query overrides, are validated. Loopback and local sockets are allowed
for isolated tests. Give Aegaeon's authority reader dedicated SELECT-only credentials
and keep administrative binding credentials out of its runtime environment.

## Application migration and recovery

This version adds two migrations after the existing four, in this order:

1. `20260911090000_application_authorizations.sql` creates the projection table.
2. `20260913090000_application_authorization_identities.sql` binds projections to
   stable client and end-user records.

All six migration files and the updated `atlas.sum` must travel together. The
resulting migration head is `20260913090000`.
Before applying them, back up PostgreSQL and save the matching binaries, configuration,
key-encryption material and token-store state under the existing secret controls.
Stop old runtime replicas, apply migrations through Atlas, start the matching new
binary, and check management health and a complete authenticated request.

The identity migration leaves existing projections unbound and therefore rejected.
Review their retained authority and explicitly reauthorize the intended identities
through the audited management API, then obtain fresh OAuth grants. Do not infer
UUID bindings from reused textual identifiers or reset revisions in SQL. Follow
[Upgrading existing projections](../configurations/environment/management-plane.md#upgrading-existing-projections)
for the reauthorization procedure.

The startup verifier requires the compiled migration head. Once the new head is
applied, the old binary cannot restart against that database. There is no down
migration. Prefer a tested forward correction; rollback requires restoring the
pre-upgrade database and compatible runtime/token state with the old binary during
a coordinated outage. Never edit the migration ledger or delete authority rows
to make an old binary start. Before enabling the adapter, provision the documented
authority tables and read-only credentials. Missing authority schema or credentials
is a preparation failure.

Unit, PostgreSQL/Redis and HTTP evidence establish only their executed cases.
They do not establish a proof of the adapter's production behavior or its
composition with the authority database and token store.

## PAR authentication and stored credentials

Under RFC 9126 section 2.1, clients registered with `client_secret_basic`,
`client_secret_post`, or `private_key_jwt` must authenticate at `/par` with their
registered method. Disabling `requireClientAuthPar` or `requireClientAuthToken`
does not waive that requirement. A client registered with `none` can push a
request only when the PAR policy and downstream profile allow unauthenticated
clients. Unknown clients and incorrect or multiple authentication methods fail
before a request URI is stored.

New PAR records contain the validated authorization request and the internal
authentication outcome, without the plaintext `client_secret`. Later
reservation and login continuation use this outcome without carrying a password
forward; authorization still applies current client policy. This credential
minimization does not redefine signed Request Object contents.

Upgrade all PAR writers together. Older writers can still put plaintext secrets
in Redis during a mixed-version rollout. Readers accept legacy records but
discard their `client_secret`; reads and reservations do not scrub the existing
Redis bytes. Existing records expire within their original configured
`policy.parExpiresInSeconds` lifetime (default 90 seconds, maximum 600 seconds),
measured from the last old-writer insertion. This change does not establish that
an existing deployment has purged old secrets. Include retained Redis backups
and snapshots in the deployment's credential-retention review. No key rotation,
configuration change, or persistent schema migration is required by the format
change itself.
