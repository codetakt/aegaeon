# Authorization-code and refresh state transitions

Last updated: 2026-09-10

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers, OAuth client developers

## Explicit authorization consent

OIDC Core §§3.1.2.1 and 11 require consent for offline access. This deployment
uses explicit consent per authorization request and has no configured alternative
offline-consent contract. Clients requesting `offline_access` must send
`prompt=consent`. Otherwise the server ignores `offline_access`, issues only the
remaining granted scopes, and does not issue an offline refresh token. A login
session alone is not consent. `prompt=none` combined with another prompt value
returns `invalid_request`.

With PAR (RFC 9126), send `prompt` in the pushed request. The stored value is
used when authorization starts and when the consent form resumes it. A later
outer `prompt` query is rejected; it cannot replace a missing pushed value.
Duplicate prompt fields and conflicting silent prompts are rejected before
storage. For PAR with a Request Object, authorization parameters belong inside
the JWT; a form-level prompt is rejected. Legacy stored PAR records without
prompt mean no prompt. Restart authorization to obtain explicit offline consent
for those requests. Old workers discard this new field, so the worker drain
described below also applies to PAR records.

For signed Request Objects, use the canonical AS issuer as the JWT audience
(RFC 9101 §4), including when the object is pushed through PAR. An audience
containing only the `/authorize` endpoint is rejected. The JWT issuer identifies
the object issuer (normally the client); it is retained as signed and is not
compared with the AS issuer. The server still verifies the registered client's
key, JWT validity and matching signed client ID. It does not add a new mandatory
JWT issuer/client equality policy. Downstream issuer checks use the independently
validated AS recipient, and direct JAR never derives it from an outer `iss`.
With PAR+JAR, only `request` and client-authentication parameters may appear in
the form body; authorization parameters belong inside the signed object.

Stored signed PAR requests must also carry the canonical recipient binding and
include that issuer in their signed audience. Records admitted under the former
endpoint-audience policy are rejected with `invalid_request`; push a fresh
request. The server does not rewrite their JWT issuer into a recipient.

The issuer audience can overlap with the optional JWT-bearer client-subject
profile. To separate JWT uses (RFC 8725 §3.12), `private_key_jwt` and JWT-bearer
assertions reject the Request Object media type and any `response_type` claim.
The latter rule also covers untyped Request Objects. Ordinary assertions retain
their existing signature, claim, policy and replay checks.

After request validation and authentication, `prompt=consent` displays the
application, resource and requested permissions. The browser submits approval
or denial to `/auth/consent`. A five-minute, single-use transaction binds the
form to the issuer, environment, subject, browser session and complete effective
request. The POST requires the same origin and live session. It revalidates the
retained authorization request against current policy before atomically storing
the decision in `aegaeon.authorization_consents`. Code issuance follows durable
approval. Denial returns `access_denied`; expired, mismatched or replayed
transactions cannot issue a code. No remembered consent is reused across
requests, clients or resources.

Apply the authorization-consent database migration before starting the updated
server. Only hashes of the form token and session identifier are stored; the
decision and request snapshot remain as the consent record. The resumed code
issuance audit uses the consent record UUID as its request identifier. Limit
database access to those records; the bounded retention described below deletes
expired records, including decisions. Retain any required audit history through
the audit system instead of keeping raw authorization request snapshots. A lost
response or failure after a decision requires a new authorization request. Do
not reset a decided transaction to pending.

## Request-bound reauthentication

`prompt=login` and `max_age=0` require active authentication for the current
request, including PAR and signed Request Objects. The server retains the
immutable request and a five-minute login transaction in
`aegaeon.authorization_logins`. Successful local login completes it for the new
session; authorization consumes the matching receipt once. Signed prompt values
are preserved, while that receipt prevents an endless login redirect. Consent
continuation inherits the receipt only from its bound session and request.
Positive `max_age` limits and required ACR still apply independently.

Apply both authorization migrations with `atlas migrate apply --env local`
before starting the new server, using the deployment's existing revision-schema
configuration. Applying raw SQL without recording Atlas revisions does not meet
the startup schema gate. The temporary `aegaeon_authorization_login` cookie is
Secure, HttpOnly and SameSite=Lax. Retain the browser's cookie and CSRF flow when
continuing login; wrong-browser, duplicate, expired or substituted continuations
cannot satisfy reauthentication. A failed credential or input retry receives a
fresh bound CSRF form only after the previous CSRF token was admitted.

The bounded retention below also applies to pending, completed and consumed login records.
Do not reset completed/consumed records, reuse another browser's continuation,
or accept an old completed step-up challenge instead of checking the current
session's age and ACR.

## Authorization transaction limits and retention

Login and consent default to 4,096 retained records and 300 newly created records
in a rolling minute, per environment and table. These are deployment storage
budgets shared through PostgreSQL. Configure
`AEGAEON_AUTHORIZATION_TRANSACTION_CAPACITY` and
`AEGAEON_AUTHORIZATION_TRANSACTIONS_PER_MINUTE` for the issuer's aggregate load:
the default minute budget supports only five new continuations per second on
average. Completion and consumption do not refund it. A saturated table returns
no-store HTTP 429 with `Retry-After: 60`; retry later with a fresh request.

Before authorization processing, a separate shared Redis bucket limits each
transport-validated source to 60 requests per minute by default, controlled by
`AEGAEON_AUTHORIZATION_REQUESTS_PER_SOURCE_MINUTE`. Rejected traffic allocates no
authorization rows. Arbitrary forwarding headers and rotating client IDs cannot
reset this bucket; the existing trusted-proxy source rules apply. Without a usable
forwarded source, clients behind a proxy share its address. Configure proxies and
size the source budget for legitimate shared-NAT traffic.

For example, capacity 20,000, minute budget 10,000 and source budget 1,000 allow
higher aggregate throughput while preserving source headroom. Startup requires
`2 * source < minute` and `6 * source < capacity`, and caps both storage budgets at
1,000,000. Use identical settings on all workers serving an environment and
coordinate budget changes; mixed limits are not a coherent deployment. Load-test
these values against database capacity. Source limiting mitigates the cheap
single-source burst; many sources, delayed requests and cleanup backlogs can still
exhaust global budgets. These controls do not establish a denial-of-service
availability guarantee. Keep ingress controls for transport and validation load.

An authorization URI is limited to 32,768 UTF-8 bytes and its serialized request
snapshot to 65,536 bytes before persistence. A query can contain a signed Request
Object, so database access must treat these snapshots as sensitive. They are not
appropriate request logs or permanent audit payloads.

Long queries have an additional continuation limitation: form encoding can
expand punctuation even when the original query fits the 16 KiB ingress limit.
The expanded URI may exceed the storage bound, or a login redirect may fail the
query limit on re-entry. These cases return 400; the initial size check does not
guarantee that a continuation fits. Keep authorization URLs compact, for example
by using PAR for large request parameters. This release does not change the
continuation encoding or its size contract.

Admission explicitly uses a READ COMMITTED transaction and a transaction advisory
lock named by environment and table. It waits up to the two-second statement
deadline, then deletes up to 512
expired rows from the selected table, checks capacity and the recent insertion
count, then inserts. Workers cannot each admit the final free slot from a stale
count. Ordinary short-lived contention queues; a final-slot loser receives 429.
Login and consent use distinct lock names. Hash collisions can add conservative
serialization, but never change row ownership or counter predicates. Acquiring
this lock does not lock the environment row against FK inserts. The inserts
themselves still take ordinary FK key-share locks, so an environment deletion or
explicit exclusive environment update can make them wait. Lock deadlines,
database failures or an unavailable source limiter return 503 without admitting
a continuation. The
existing supervised cleanup task also removes up to 512 expired rows per table
and environment on each cleanup tick, even without new authorization traffic.
It preserves unexpired rows and other environments. Cleanup is retried and its
failures are logged; an outage or old backlog can delay deletion beyond expiry.
Expired records remain unusable while awaiting deletion. Monitor cleanup failures
and backlog; the five-minute validity window is not a guaranteed physical-erasure
deadline when the service or database is unavailable.

Concurrent cleanup can leave rows visible to a READ COMMITTED count until its
delete commits. A capacity-edge 429 in that interval is conservative; the server
does not admit beyond the storage bound to compensate for an uncommitted delete.

## Upgrade and recovery

Drain and stop all workers using the former environment-row admission lock before
starting workers with transaction advisory locks. This admission change requires
a coordinated cutover even when no database migration is pending. Old and new
workers do not share a serialization lock: running them together can admit past
the capacity or rolling-minute budget. Matching limit values does not make a
mixed-version rollout safe. Resume traffic only after every writer uses the same
admission implementation and settings.

This release makes a hard Request Object audience cutover. Read the exact
`issuer` from discovery, configure each Request Object producer to include that
issuer in `aud`, and re-sign the request. An endpoint-only audience such as
`<issuer>/authorize` is no longer accepted, including in previously stored PAR
requests. Discard old PAR handles and push newly signed requests after cutover.
This is Aegaeon's strict recipient policy, following RFC 9101 section 4's
recommendation to use the authorization server's issuer identifier. No
compatibility mode accepts that endpoint-only audience. Client assertions remain
a separate JWT use with their own endpoint audience rules. Prepare and test the
client change before switching server workers. Legacy refresh sessions without
the new saved target/issuer context require a new login and consent as described
below.

The startup database gate looks up the last migration in the binary's embedded
`atlas.sum`. It requires that revision to be complete and error-free, and checks
its description and hash when present. It does not reject additional, later
revisions: an older binary can still pass when its own expected revision remains
in Atlas history. Startup success therefore does not establish downgrade or
mixed-version compatibility. Enforce the matching binary/schema boundary in the
deployment procedure. There is no supported down migration for these changes;
removing an Atlas revision row or changing its checksum is not a recovery
procedure and does not restore schema or authorization state.

Before applying migrations, drain and fence old writers, retain the matching
old/new binaries and migration ledgers, and take a tested database backup using
the deployment's normal backup procedure. On failure, prefer a forward correction
using a binary that matches the current schema head. If rollback is necessary,
keep issuance stopped, restore a consistent pre-migration database backup and
matching old binary/ledger, and reconcile affected external/runtime state before
resuming. Never restore consumed codes or rotated/revoked refresh grants into a
live Redis namespace. Fence previous workers, invalidate affected runtime grants
and sessions, and require new authorization where consistency is uncertain.
Validate the restored schema head and client flow in isolation first; switching
the executable or renaming a runtime namespace alone is not a validated recovery.

## Code exchange and refresh

Authorization-code exchange retains the original stored JSON through validation
and compares those bytes during the Redis commit. Valid legacy JSON does not need
to be rewritten to impose a property order. Client, redirect URI, PKCE, expiry,
and the code's storage identity are checked before issuance.

For authorization-code exchange, the single-resource policy permits an omitted
`resource` or an exact repeat of the explicit resource recorded in the grant.
Adding a resource when none was recorded, or choosing a different one, returns
`invalid_target` before code consumption. The client can retry that code with a
permitted request. An omitted resource preserves the existing default audience.
RFC 8707 §2.2 allows this grant-bound policy; it does not universally prohibit
token-only resource parameters. Clients needing an explicit target must include
it during authorization. Resource URI validation alone does not grant access.

Redis executes the commit script without interleaving other commands, but a Lua
error does not roll back earlier writes. After preflight checks, the script
consumes the authorization code before writing tokens. If a later write fails or
the reply is lost, restart authorization. Do not restore the code or assume that
every token/session write was rolled back. OIDC cleanup during preflight can also
change session indexes independently of token publication.

New refresh records retain the resolved audience separately from the optional
requested `resource`. For an OIDC grant without an explicit resource this is the
UserInfo audience. Refresh preserves the recorded audience; an explicit request
for another resource receives `invalid_target` (RFC 8707 §2.2).

Refresh requests follow RFC 6749 §6: omitted `scope` uses the originally granted
scope; an explicit scope must be a subset. Malformed strings, duplicate tokens
(under the existing scope policy), and expansion receive `invalid_scope` before
rotation. Only the new access token and its bearer metadata are narrowed. The
replacement refresh token retains the original grant, so a subsequent refresh
without `scope` uses that original scope again. Dropping `openid` from an access
token request does not change the recorded audience.

The refresh commit checks that access-token scope is covered by the replacement
refresh token and that old and replacement refresh scopes are equal. Redis binds
the latter check to the original stored payload through compare-and-swap. Initial
grant issuance still requires equal access-token and refresh-token scopes.

The target context also records its format/policy version, token issuer, and OIDC
issuer. Missing historical context, an unsupported version, or changed issuer
context receives `invalid_grant` and requires authorization again. This includes
legacy refresh records, even when they contain an explicit resource: a resource
URI alone does not establish the original issuer context.

Drain and stop old server workers before switching formats. Old versions may
discard the target context when rotating a refresh token. Do not mix versions or
restore pre-consumption code snapshots into the active runtime namespace. If
storage rollback is suspected, stop issuance, fence the old workers, and
invalidate the affected authorization state before resuming with new grants.
Changing an environment identifier alone is not a validated recovery procedure.

These transitions address stored-code identity, target consistency, and refresh
scope selection. The F* model describes parsed scope lists; HTTP and real Redis
regressions exercise runtime behavior. They do not establish mechanically checked
Rust/Lua correspondence or complete refresh-family revocation guarantees. The
separate consent model describes parsed-request and session bindings; database
and HTTP regressions cover consent acquisition, but do not prove Rust/SQL
correspondence. Direct issuer tests start with an already-authorized grant and
do not themselves establish consent acquisition.
