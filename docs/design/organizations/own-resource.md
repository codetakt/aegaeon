# Organizations own resource boundary

Last updated: 2026-10-31

Status: active plan

Owner: Engineering

Audience: implementers, security reviewers, client integrators

## Contract

This specifies the next ORG-R09/R10/R11/R21/R23 implementation boundary and
ORG-G03/G07/G11, with ORG-P01/P03/P06/P08/P12/P13/P14 still open. It supplements
[token enforcement](token-enforcement.md); it does not enable a feature or
establish a proof discharge.

Aegaeon's native Organizations resource uses the exact audience
`{issuer}/organizations`. Configuration must register that audience to an
explicit authorization domain and mark it as a management target. A matching
string, a management flag or an operator session alone grants no access.
An external application's audience never authorizes this resource.

The first read endpoint is `GET /organizations/context`. `HEAD` applies the
same authorization checks and returns the same headers without a body. It returns the current
selected organization authorization detail, the exact subject and the selected
token expiry. Require the explicit `organization.context.read` privilege in the
selected token and current client/role authority. The response contains no
original multi-organization ceiling, root identity or private snapshot. There
is no organization selector in this request: its context comes from the signed,
stored selection. The arbitrary external ID remains a JSON value and is not
interpreted as a UUID or a URL path.

The response also carries `organization: {id, externalId, revision, versionTag}`
from the same locked primary-state check. `id` is the plain UUID for management
paths; `externalId` preserves the exact scoped selector. `versionTag` is the
quoted organization revision validator accepted by invitation issuance's
`If-Match`. Clients obtain it here instead of deriving it or consulting storage.
It is not an ETag for this token-specific context response. A later mutation
still checks its own current authority and rejects stale organization revisions.
This discovery grants no additional privilege and exposes no other organization.

## Authentication and currentness

Admission checks the validated subject namespace and current runtime projection,
transport policy, supported method and absence of query/body credentials.
Require one `Authorization: DPoP <access-token>` header and one DPoP proof.
Use the existing resource-server verifier for signature, allowed algorithm,
public JWK, time/nonce, exact method/URI, `ath`, thumbprint and replay checks.
A token-endpoint proof is not a resource proof. Do not accept Bearer presentation,
access-token query parameters, a second authentication channel or missing `ath`.

Verify the stored access token and refresh/root liveness, the signed RS256
`at+jwt` and exact stored/public selected detail correspondence. Require the
canonical own-resource audience and the endpoint privilege unconditionally,
regardless of optional legacy scope/audience policy toggles. Check the actual
presenting proof key against the original binding. Require the complete current
primary Organizations check before returning a successful response. Missing
structured authority, noncurrent membership, root cancellation, changed
registration or a disabled feature never falls back to ordinary Bearer policy.

The existing generic resource, userinfo and legacy application routes continue
to refuse Organizations credentials. Only the dedicated semantic consumer may
accept them. The offline introspection helper also refuses these credentials.
The new route participates in resource presentation/transport middleware so
error challenges remain DPoP-aware and all responses prevent caching.

## Errors and operations

Missing authentication returns 401. Malformed or duplicate presentation returns
400, an invalid or revoked credential returns 401, and a live credential lacking
the endpoint privilege returns 403. Database, token-store, key or runtime
projection unavailability returns an explicit service error without a positive
fallback. Preserve DPoP nonce challenges from the existing verifier.

Use the existing finite Organizations admission and primary-store timeouts.
Acquire the shared admission before database middleware and body consumption.
All mounted Organizations resource GET/HEAD routes, including the invitation
identity form, consume a strictly empty body within ten seconds before starting
owned store work. A nonempty or malformed body returns 400; a stalled body
returns 503 with no-store. Client cancellation at this input-only stage returns
the lease without closing admission. The total response budget remains thirty
seconds, including body admission. Completed input then enters the owned worker;
its store work still retains its lease through cancellation and cleanup.
The dedicated route owns its primary runtime-projection check instead of using
the generic pre-handler database read. An owned worker retains admission through
the complete token/proof/store operation even if the requester disconnects or
its 30-second response deadline expires. Shutdown before worker completion
closes that admission class until process restart. A selected currentness check
reuses this admission; it does not acquire a second request slot.
All acquired leases remain held through transaction cleanup after cancellation. A failed
protocol drain also closes the admission class: SQLx transport close only sends
Terminate and closes the socket; it does not acknowledge server completion.
A real reply-cut regression retains an executing PostgreSQL query after close
and requires refusal of replacement work until restart.
Token selection and currentness transactions use the same commit-admission
boundary as management mutations. A cleanup closure that wins before that
boundary refuses the pending result, including a read that started earlier.
Admission that wins first may finish; the lock never covers database I/O.
No positive authority cache is introduced. As with introspection, a check after
a completed cancellation must fail; this read endpoint starts no external I/O.

Delegated membership routes in [member-api.md](member-api.md) validate their selected
snapshot again inside the same primary transaction as the mutation and receipt,
check assignable-role restrictions and the last-effective-administrator rule,
and retain atomic audit/outbox publication. A context read does not authorize a
later mutation. Invitations follow [delegated-invitations.md](delegated-invitations.md).
Support grants still need their separate authorization and cancellation contract.

## Required evidence

Use the actual original-grant and selected Token Exchange issuers with real
resource DPoP proofs. Exercise normal JSON output, exact UTF-8 identifiers,
wrong audience/key/ath/method/URI, replay, Bearer and query presentation, missing
privilege, selected/original metadata omission, membership/root cancellation,
read-only primary or failed stores, recovery and finite admission. Retain a
negative control removing the actual current-state guard. Public configuration
admission remains disabled until the browser-consent and own-resource paths
have passing integrated evidence; complete Organizations shipment has additional
open requirements.

The supplier review also identifies a delivery prerequisite: current synchronous
Redis connection setup and reads have no explicit socket deadlines, including
the DPoP replay backend. Request admission bounds their owners but alone does
not establish a finite network lifetime or a timely response while a verifier
blocks the async executor. Public activation must remain disabled until bounded
Redis setup/operations and blocking-proof isolation are implemented and tested
with a stalled peer, cancellation and recovery. This is part of ORG-G03/G11 and
ORG-P08/P12/P13; successful ordinary-path tests do not discharge it.
