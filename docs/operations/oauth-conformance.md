# OAuth authentication errors, sender binding and authorization details

Last updated: 2026-10-27

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

This correction does not establish conformance for bare/empty Basic, unsupported
schemes, duplicate/nontext headers or their admission ordering. Resource-server
errors, diagnostic character restrictions and dynamic registration error
classification have separate contracts. Existing profile-error realms and late
revocation/JWT-introspection refusals retain their behavior.

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
token or publishing access tokens. Duplicate nonempty token form parameters
return `invalid_request`. Empty values are omitted before duplicate checks per
RFC 6749 §3.2; unknown unrelated OAuth extensions remain ignored.

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
reason with the authorization request identifier.
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
the same name. Empty `scope` therefore preserves the grant-specific omission
behavior, including the original refresh grant scope. Empty
`authorization_details` is absent; any nonempty value remains unsupported and
is rejected before a code is consumed or a refresh token is rotated.

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
The [machine-readable reader contract](../../spec/application-membership-reader-contract.json)
records the three required relations and columns, compatible join operations,
exact issuer/subject matching, role/status values and NULL behavior. It specifies
the existing read interface, not an external production schema or migration.
The PostgreSQL token-route fixture consumes it to construct an owned schema;
its bigint, UUID and timestamp types are finite test witnesses, not mandated
external storage types. Reader relations resolve through the dedicated connection's
trusted search path. Matching binding rows contribute their union; the reader
does not detect ambiguous mappings or enforce external uniqueness constraints.
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

## Introspection authentication and optional scope

`/introspect` requires successful authentication by a registered client using a
supported method. A client identifier or public registration is insufficient,
even with a profile allowing `none`. The legacy management setting
`requireClientAuthIntrospection=false` still round-trips unchanged, but its
effective runtime value is true. Upgrading requires credentialless introspection
callers to use registered credentials; no database rewrite or new migration is
required. Existing target and reader permissions continue to apply.

When `jwtIntrospectionEnabled=true`, requests without effective credentials return
HTTP 400 JSON `invalid_client`, an issuer, no `WWW-Authenticate`, and no-cache
headers, regardless of `Accept`. With that capability disabled, the ordinary
HTTP 401 `invalid_client` response retains its Basic challenge. Missing credentials
include a bare `client_id` and empty credential form fields. Whitespace remains
a supplied credential and follows the attempted-authentication error path. Existing
header admission and attempted-credential errors retain their categories.
Recognized invalid credentials, assertion mixtures and authenticated profile refusal
retain their existing HTTP 401 behavior. Basic authentication combined with
`client_secret_post` and no assertion instead returns HTTP 400 `invalid_request`
without `WWW-Authenticate`, including when JWT introspection is enabled. This
conflict is rejected before any token lookup.

This follows RFC 7662 §§2.1, 2.2, 2.3 and 4 and RFC 9701 §§5 and 8.2 for the
credentialless case. RFC 9701's broader failed-authentication wording versus
RFC 7662's explicit invalid-credential 401 rule remains a separate profile
interpretation; this change does not establish complete RFC 9701 conformance.
Recipient entitlement and response-protection profiles remain separate obligations.
Stored JWT validation is described below.

Active responses omit `scope` when it is unavailable. A stored string, including
an empty string, is preserved exactly in JSON and the signed response's inner
`token_introspection` object. Inactive responses remain exactly `{"active":false}`
inside the selected response format. Sender type and confirmation claims retain
their existing meaning; the introspector does not present the original token
sender's proof.

The public `TokenValidator::introspect_token` helper applies the same optional
scope rule and returns the stored token type instead of hardcoded `Bearer`.
It remains a local stored-status API: it does not authenticate a requester or
supply online resource-server authority, and refuses client-credentials records
and lookup errors with a false-only result. Use `/introspect` for authenticated
current-policy evaluation.

## Stored access-token signature verification

Under RFC 7662 §4, `/introspect` validates stored signed access tokens even after
`jwtAccessTokensEnabled` is disabled. Aegaeon's opaque tokens contain no periods;
any stored token containing a period must pass compact JWT parsing, signature,
access-token type, issuer, required-claim and time checks. When metadata exists,
the JWT audience must match its stored resource audience. Malformed dotted values
cannot fall back to opaque status. Existing requester visibility, grant-family,
parent and current-authority checks run before this additional verification.
Signature validity alone does not make a token active.

The requested token must exactly match the token inside its stored record,
including for opaque tokens. A second lookup key pointing to another token's
record is rejected without rewriting either record. JWT expiration is exclusive:
the current time must be strictly less than `exp` plus the configured leeway;
checked arithmetic rejects overflow.

Production verification uses only public material for `JWT_ACCESS_TOKEN_SIGNING`.
Active keys and retiring keys strictly before their configured expiry are eligible;
NEXT, REVOKED, expired or other-purpose keys are excluded. A retiring-only set works
without an active access signer or private-handle decryption. Empty access-key sets
support opaque deployments but cannot validate a JWT. The introspection response
signer cannot substitute for an access verification key. Invalid configured public
material prevents initialization. Retention policy and in-flight configuration
currentness retain their existing contracts.

`/jwks` publishes the same eligible public access-verification keys even while
new JWT issuance is disabled, alongside existing OIDC and introspection response
keys. Retiring access keys disappear at their expiry. An unavailable verification
clock or public-key backend returns HTTP 503 instead of a partial key set. This
does not extend a resource server's cached-key lifetime or change key retention.

Visible invalid JWTs produce the false-only inner object in JSON or a signed
introspection response. Verification/backend/parser-policy or clock unavailability
returns HTTP 503 without an active assertion or success metric. Invisible callers
receive the existing inactive result before protected verification work.

The built-in resource validator retains its strict mode: enabling JWT access-token
validation requires JWTs, while disabling it still verifies dotted tokens. Both
synchronous and asynchronous methods use this rule. Introspection accepts genuine
stored opaque tokens in either issuance mode. The local `introspect_token` helper
also verifies dotted tokens and collapses failures to false-only, while retaining
its limited authority described above. Existing library constructors adapt the
explicitly supplied `KeyManager`; `with_access_token_verifier` can supply a separate
verification capability. Production startup always installs the purpose-restricted
runtime access verifier.

Custom library verifiers with locally publishable keys should implement
`AccessTokenVerifier::access_token_public_jwks`. Its default returns no keys for
verifiers whose publication is managed elsewhere; supplying a custom verifier
does not automatically configure that external publication.

No storage migration or token rewriting is required. Custom library consumers
must stop injecting dotted opaque tokens; their existing bytes remain stored but
now fail closed unless they are valid JWT access tokens. This change does not
expand recipient entitlement or sender permissions, or establish complete JWT
parser, numerical, protection-profile or product assurance.

## OAuth Basic credential encoding

RFC 6749 section 2.3.1 and Appendix B require each logical client ID and secret
to be independently encoded with `application/x-www-form-urlencoded` before
joining them with a colon and applying Basic base64 encoding. A space becomes
`+`; a literal plus becomes `%2B`, a colon `%3A`, and a percent sign `%25`.
UTF-8 bytes use percent encoding. For example, client ID `client+id` and secret
`s: %` produce the pre-base64 value `client%2Bid:s%3A+%25`.

Aegaeon's Basic authentication consumers split the decoded Basic payload at its
first literal colon and decode each component exactly once. Malformed percent
escapes and invalid UTF-8 fail authentication. Neither a decoding failure nor an
authentication failure triggers a retry using raw credentials. Registrations
continue to store logical credentials; do not rename clients or rewrite stored
secrets to their encoded wire representation.

Clients that previously sent raw reserved characters must switch to this RFC
encoding. Ordinary generated credentials using ASCII letters, digits, hyphens
and underscores continue to work unchanged. Aegaeon also encodes its configured
logical credentials for Basic authentication on both upstream authorization-code
and refresh-token requests. `client_secret_post` continues to use the request's
normal form serialization. No storage migration or new configuration is needed.

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

## RP state and nonce observations

Distinct authorization transactions may carry the same admissible RP-supplied
`state` or `nonce`, including requests from the same client. Aegaeon preserves
both decoded values in their own authorization-code context, echoes `state` in
the authorization response, and includes `nonce` in the ID Token. This removes an unnecessary AS-wide uniqueness restriction; RFC 6749
sections 4.1.1, 4.1.2 and 10.12 and OpenID Connect Core sections 3.1.2.1 and
3.1.3.7 leave the RP responsible for its state/nonce validation and
unpredictability obligations. Existing required-presence, encoding, length and
profile checks still apply.

Redis and the process-local test backend retain distinct recently observed
state/nonce markers. Successful repeated values refresh the existing marker's
last-observation TTL and Redis sorted-index expiry. The TTL continues to derive
from `policy.authorizationCodeTimeToLiveSeconds`. `try_state_count`,
`try_nonce_count` and the historical `AuthCodeSnapshot.used_states`/`used_nonces`
fields describe retained observations, not transaction totals, accepted code
counts or prevented attacks. Membership never authorizes or rejects issuance.
The public `AuthorizationCodeIssueError::StateUsed` and `NonceUsed` variants
remain for source compatibility; normal issuance no longer emits them.

Authorization codes remain distinct and single-use, bound to their original
client, redirect URI and PKCE verifier. Repeating state/nonce does not permit
reuse of a PAR handle or a signed Request Object's `jti`. The existing Redis
code/PAR/JTI commit preflights version-counter and index errors before mutation.
No extra replay store or configuration variable is introduced.

Stored codes and the Redis keyspace remain readable without a flush, backfill
or identifier change. Update every authorization-serving instance for consistent
repeat acceptance: older instances still reject repeated values. Finite router
and Redis regressions cover repeated values and transaction isolation; older
proof-model assumptions of globally unique RP values are not evidence for this
behavior and require separate reassessment.

## Encrypted Request Object headers

When Request Object encryption is configured, `/authorize` and `/par` accept a
single RSA-OAEP/A256GCM compact JWE containing a signed compact Request Object.
Its protected header must explicitly contain `alg: "RSA-OAEP"`,
`enc: "A256GCM"`, and `cty: "JWT"`. The JWT content type also accepts
`application/jwt` and ASCII case variants; no whitespace or media-type parameters
are accepted. The inner signed Request Object still undergoes all normal client,
key, signature, claims, redirect and PKCE validation before authorization.

Clients with missing algorithm or content-type metadata must send a newly
signed/encrypted valid request. Editing a protected header invalidates its
authentication tag. This correction requires no database or key migration.
See the [JOSE header policy](../policies/jose-header-policy.md#jwe-and-encrypted-request-objects)
for library compatibility and generic non-JWT JWE behavior.

## RP-initiated logout confirmation

Aegaeon policy always requests explicit browser confirmation for both GET and
`application/x-www-form-urlencoded` POST requests at `/logout`.
[RP-Initiated Logout 1.0 section 2](https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout)
requires asking when no hint is provided or when the hint does not belong to the
current OP/RP session and/or current End-User, and generally recommends asking.
The unconditional confirmation policy also covers a matching hint.

POST parameters belong exclusively in the body; a nonempty query on POST is rejected. Input is strictly decoded and bounded
before use, including malformed encoding and duplicate singleton rejection.
`id_token_hint` retains the current signature, own-issuer and time checks.
If `client_id` is also supplied, it must match the client identified by the hint.
A registered `client_id` alone can identify an exact registered
`post_logout_redirect_uri`. A redirect without any client identity is rejected.

A valid initial request responds with a 303 to `/logout/confirm`. It does not
end sessions, create an upstream relay, send logout notifications or redirect to
the RP. This extra top-level GET permits a browser returning from a cross-site
POST to send its ordinary SameSite session cookie. A single fixed-name
`__Host-aegaeon-logout` cookie is Secure, HttpOnly, SameSite=Lax, Path=/ and has no Domain.
The transaction and cookie secrets are independent 32-byte random values; only
their digests are stored. The continuation expires after five minutes. Each accepted start replaces the
cookie secret; only the transaction matching the browser's current cookie can
proceed. Older tabs must restart. Concurrent responses can replace or clear the
cookie and require a fresh request, but cannot approve a different transaction.
This bounds confirmation-cookie storage to one slot. The page uses neutral
requester wording: a public `client_id`, or possession of an ID Token hint,
does not authenticate the party that initiated the browser request.

The confirmation page binds its first display to the current browser session
and subject, or explicitly to no active session. A changed session requires a
fresh logout request. Confirm and Cancel require the same browser binding and
an exact same-origin POST, and only one decision can consume the transaction.
The form uses `Referrer-Policy: same-origin` so browser POSTs retain their
Origin while cross-origin referrers remain suppressed. Missing, null, foreign
and duplicate Origin headers are rejected.
Cancel leaves the sessions unchanged and returns a local cancellation page.
Confirm ends only the presented browser session and its associated OIDC session
and RP set. A hint for another subject cannot select that subject's sessions.
No current session means an idempotent no-op; it never triggers user-wide logout.
HEAD does not end a session or create a new confirmation transaction.

The server revalidates current policy, registration, redirect and any supplied
hint before consuming the decision. After confirmation, return-target and
upstream-relay preparation precede OIDC session termination and browser-session
deletion. Existing backchannel dispatch remains best-effort before the success
redirect. These stores and remote recipients do not share a transaction: a
backend error after approval returns unavailable, and some local steps may have
completed. Start a fresh logout request after recovery; the consumed decision
cannot be replayed. This flow does not promise atomic remote logout or delivery
retries. Only the relevant browser and confirmation cookies are cleared.

Apply `20261012000000_logout_confirmations.sql` before running the updated
server. Existing direct logout callers will now encounter confirmation. Replace
all serving instances that can handle logout together: old instances retain
the previous behavior, so the migration alone does not make a mixed deployment
safe. No client or session identifiers are renamed.

The new PostgreSQL table uses the existing per-environment, per-table
`AEGAEON_AUTHORIZATION_TRANSACTION_CAPACITY` and
`AEGAEON_AUTHORIZATION_TRANSACTIONS_PER_MINUTE` limits. Completed decisions remain
counted until expiry. Admission and bounded expiry pruning use the same
transaction/advisory-lock pattern as login and consent; background cleanup also
prunes expired logout confirmations in batches of 512. Initial logout requests
share `AEGAEON_AUTHORIZATION_REQUESTS_PER_SOURCE_MINUTE` with authorization
requests using the transport-validated source and shared Redis bucket. There is
no new environment setting.

Expiry cleanup for login, consent and logout materializes each batch of at most
512 candidate IDs before deletion. Without that fixed candidate set, PostgreSQL
can rescan a locking subquery in a nested-loop plan and delete more rows than
its `LIMIT` specifies. Cleanup continues to skip rows locked by other requests
and preserves live records and other environments.

## Mandatory upstream authorization request modes

Aegaeon's upstream OIDC client sends ordinary authorization-code requests. If
ordinary Discovery or the selected Federation OP metadata sets
`require_pushed_authorization_requests` or `require_signed_request_object` to
`true`, new authorization returns HTTP 502 `server_error` before storing state
or returning an authorization redirect. The description identifies the required
mode. Correct the upstream connection's request-mode compatibility before
retrying; this client does not implement upstream PAR or signed Request Objects.

Successfully parsed metadata remains cached until its normal expiry even when
these flags require an unsupported mode. Repeated rejected authorization attempts
do not evict the cache or force new Discovery requests.

Missing flags and explicit `false` allow the existing flow. Optional Request
Object support, algorithm lists and PAR endpoint presence alone do not require
those modes. Both recognized flags must be JSON Booleans when present: `null`,
strings, numbers, arrays and objects are refused, as are duplicate JSON members.
This stricter parsing also applies to shared metadata consumers. A `true` flag
alone does not block completion of an already issued code, refresh or logout.

RFC 9126 section 5 and RFC 9101 section 10.5 define these Boolean advertisements
and omission defaults. The latter's rejection MUST addresses the remote
authorization server. Aegaeon's refusal is a local compatibility policy; it does
not assert a universal requirement for clients to implement PAR or JAR.

The public Rust `OidcDiscovery` struct adds
`require_signed_request_object: Option<bool>`; callers using struct literals must
initialize it, normally to `None`. Aegaeon's Discovery producer initializes it
to `None` and preserves its existing PAR advertisement. This change adds no
runtime setting or storage migration.

## Signed introspection recipients

A selected JWT introspection response discloses active token claims only to an
eligible authenticated recipient. For an ordinary token, stored metadata must
identify that requester by exact audience equality. This is Aegaeon's local
direct-identifier convention; OAuth does not generally require a resource
indicator to equal a resource server's client identifier.

For a client-credentials token, the requester must be an explicit reader retained
in that token's grant, and the existing current policy, context and registration
identity checks must succeed. A mapped reader may have a client identifier that
differs from the token's resource audience. Audience equality alone does not add
a client-credentials reader, and those mappings do not apply to other grants.

Token ownership alone and missing metadata do not establish signed recipient
authority. Such requests receive a signed response addressed to the authenticated
requester with `token_introspection` exactly `{"active":false}`. The early denial
precedes later protected grant, application and access-signature checks. Eligible
readers retain existing state and signature checks and operational errors; an
inactive response can itself fail if signing is unavailable. The introspector
does not present the original sender's DPoP or mTLS proof.

Upgrade signed-response consumers that previously relied only on token ownership
to the supported recipient configuration. For client credentials, an owner may be
explicitly configured as a reader before issuance. No storage rewrite or migration
is required. Plain JSON visibility is unchanged, including a JSON fallback when
the JWT capability is disabled. This restriction uses the existing response
selection; it does not change Accept negotiation.

This implements a bounded signed-recipient check from RFC 9701 §§3 and 5.
Plain JSON resource-server entitlement, username semantics, failed-authentication
status interpretation, scope narrowing, data-release privacy and negotiated
response protection remain separate obligations. Finite tests do not establish
full RFC 7662/RFC 9701 or product assurance.
