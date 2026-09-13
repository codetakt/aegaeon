# OAuth sender binding and unsupported authorization details

Last updated: 2026-09-11

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

## DPoP responses

RFC 9449 §§5, 7.1 and 9 distinguish authorization-server and resource-server
responses. The token endpoint returns `400 invalid_dpop_proof` for malformed,
invalid or replayed proofs, and `400 use_dpop_nonce` with `DPoP-Nonce` for nonce
challenges. Resource endpoints return 401 with a DPoP `WWW-Authenticate`
challenge. Their nonce challenges also include `DPoP-Nonce`.

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
present. A DPoP scheme without its proof returns `invalid_dpop_proof` for every
header separator accepted by the resource parser.

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
removes SUPER_ADMIN. Selection is required when the parent has organization claims.
A subsequent exchange cannot switch organizations, widen scope or add audiences.
This application contract is configured explicitly by the relying application:
use `GET /application/authorization` at the configured issuer and the documented
`organization_id` request parameter. OIDC discovery does not advertise this
application-specific contract. The two earlier experimental application
metadata keys have been removed; consumers of that candidate must use explicit
configuration. Any future discovery extension requires an `aeg_*` name and an
explicit, default-off policy toggle; none is introduced by this change.
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
