# Organizations Operator Authority

Last updated: 2026-10-30

Status: active plan

Owner: Engineering / Verification

Audience: implementers, operators, security reviewers

## Scope

This refines ORG-R04, ORG-R11, ORG-R12, ORG-R16 and ORG-R22 for ORG-G03,
ORG-G08, ORG-G13 and ORG-G14, contributing to ORG-P03, ORG-P06, ORG-P09,
ORG-P10 and ORG-P13. An operator grant never supplies business membership,
a selected access token, an original authorization ceiling or MFA evidence.

## Explicit operator grants

An active human Team owner may explicitly initialize a disabled default
authorization domain and assign its first operator grants through the management
plane. This is a configuration action with a reason and atomic audit record.
It does not enable business access. Existing Team administrator status alone
does not authorize the domain's operational endpoints. API keys and business
tokens cannot perform this bootstrap. The current human identity, Team ownership
and Team/Tenant/Environment state must be locked and checked in its transaction.

Each subsequent domain operation requires an active persisted grant naming
that Environment, domain, human administrator and the exact capability:

| Capability | Permission |
| --- | --- |
| `configure` | Domain configuration and explicit operator-grant administration |
| `provision` | Organization creation, first-administrator invitation, organization lifecycle |
| `reconcile` | Bounded organization and membership reads |
| `export` | Separately authorized audit and authority export |
| `support` | Request a separately validated short-lived AdminAccessGrant |

None implies another capability. In particular, `configure` does not directly
read business data or mutate membership; any additional grant is an explicit,
audited operation. `support` does not bypass the adopted MFA, root, DPoP,
target, privilege and 300-second limits. Ordinary organization membership
changes require delegated authority. Provisioning cannot arbitrarily add an
active member or restore a removed membership.

Grants use plain UUID object identifiers and positive revisions, default to
inactive, and retain their identifiers after revocation. Capabilities are a
nonempty unique set of at most five known values. Mutations use exact ETags,
idempotency receipts, current-authority rechecks and the same transaction as
audit/outbox. At most 64 operator identities may be registered per domain;
revocation does not erase history or reset the quota. A lifecycle/retention
procedure is required before increasing this bound.

## Currentness and lock order

An authenticated management session supplies the principal identifier; request
bodies and audit actor fields do not. After checking the scoped active
Team/Tenant/Environment and human Team membership, acquire the domain lock,
then lock the matching operator grant. Require an active identity and grant,
the exact requested capability and an enabled domain for operational actions.
Configuration of a disabled domain is a separate explicit configuration path.
Absence, malformed stored capabilities, suspended principals, cross-Team/domain
references and storage errors refuse access without existence disclosure.

Revocation and mutation use these same locks. A mutation admitted before a
revocation may finish; a subsequent transaction must see the revocation.
Receipt replay rechecks authority first. Session revocation and expiry remain
additional checks at the authenticated HTTP boundary.

## Configuration transactions

The initial API shape uses `/api/v1/teams/{team}/environments/{environment}/organization-domains/default`
for explicit owner bootstrap, and `/api/v1/teams/{team}/environments/{environment}/organization-domains/{domain}/operators`
for grants. Object paths use plain UUIDs. These paths are specified before route
implementation; they are not activated by the storage changes.

Bootstrap creates only a disabled default domain and a `configure` grant for
the authenticated human owner. It does not grant provisioning, reconciliation,
export or support. An existing domain is never silently adopted or recreated.
The owner check also applies on retry; if the original configure grant was
revoked, the stored bootstrap response is not disclosed. Default-domain creation
is serialized per Environment before reading the domain, including when no row
yet exists. A successful retry returns the original representation.

Grant creation takes a current human Team member, an explicit active flag and a
nonempty capability list. Updating a grant names its immutable UUID and exact
positive revision. Revocation sets `active` to false; it does not delete the
record. Re-enabling the same identity requires a new explicit update and
revision. Exhausted revisions cannot wrap or be reset. An update that revokes
the caller may succeed, but its later retry has no authority unless another
current grant still permits configuration. Self-revocation is allowed and does
not create a hidden recovery bypass.

Before receipt lookup, recheck the caller's current configuration grant.
The receipt digest binds the complete semantic command, revision and reason;
request IDs may change on retry. A changed command conflicts. Mutation,
immutable domain event, outbox and receipt commit atomically. Failure in any
write rolls back all effects. Grant creation counts all retained identities
under the domain lock against the 64-identity limit. No quota reset on revoke.

Configuration receipts retain at most 10,000 ordinary mutations per domain,
plus a shared reserve for active-to-inactive transitions. The client-setting
successor below extends the initial 64 operator slots to 129 total slots.
Replay consumes no slot. At the ordinary limit, new grants, reactivation and
no-op edits are refused. Retained history is never deleted to replenish this
budget. Increasing or rotating it requires the separately validated lifecycle
procedure; this bound does not qualify business audit/export retention.

## Delivery conditions

### Target registration and configuration reads

The next configuration increment covers ORG-R01/R04/R21/R22, ORG-G03/G11/G14
and ORG-P01/P03/P06/P12/P13. `GET .../organization-domains/{domain}` returns
the current configuration, including its exact registered audiences, to a human
with current `configure` authority. It does not disclose memberships. The
response carries the domain's strong ETag and is never cached.

`POST .../organization-domains/{domain}/targets` accepts `audience`, an explicit
`management` Boolean and `reason`, with the domain ETag and idempotency key.
An audience is an opaque, nonblank 1–2048 UTF-8 byte value without controls;
case, Unicode and surrounding nonempty text remain exact. Registration binds
it permanently to this Environment/domain and its declared management purpose.
An existing binding cannot be moved or have its purpose changed through this
operation. A different Environment may register the same value. A repeated
value with a new idempotency key conflicts; a matching authorized retry returns
its original receipt even if the domain has since changed.

The domain lock serializes registration with its other mutations. Check current
human/configure authority before receipt lookup, then the expected revision,
the audience's Environment-wide uniqueness and finite capacity. Register at
most 32 retained targets per domain and at most 48 KiB of serialized target
configuration. Increment the domain revision without consuming its final
revocation increment; target, revision, event, outbox and receipt are atomic.
This uses ordinary configuration receipt/admission capacity. No target removal
or reassignment replenishes it. Database uniqueness also rejects concurrent
claims by different domains. A failed write rolls back the revision and audit.

Registration does not enable the domain, authorize a client, advertise a RAR
type or issue a token. Client registration bindings and explicit domain
activation remain subsequent increments. Original ceilings must retain their
original target/privilege sets, so adding a target cannot widen an old grant.
The reserved disabling path, current client checks and protocol integration
are required before enabling business access.

### Client registration bindings

The client-setting increment maps ORG-R01/R02/R04/R06/R21/R22 to
ORG-G02/G03/G05/G11/G14 and ORG-P02/P03/P04/P06/P12/P13. It establishes
configuration only: no original grant ceiling or business permission is minted.

`POST .../organization-domains/{domain}/clients` accepts the immutable client
registration UUID, explicit `active`, a nonempty `targets` array and a reason.
Each target contains an exact audience and a nonempty unique privilege-key list.
It requires the domain ETag. `PATCH .../clients/{binding}` replaces active state
and the complete target permission set using the binding ETag. The dedicated
`POST .../clients/{binding}/revoke` deactivates it without changing its identity
or permission sets, using the binding ETag and reason. All use current human
configure authority, session/CSRF, idempotency and atomic audit/outbox/receipt.
`GET .../clients` pages at most 64 retained bindings, including inactive ones,
and requires current configure authority. `pageSize` is 1–100 (default 50); the
actual page also stops before 60 KiB of binding payload. Canonical cursors bind
the client collection, Environment and domain. The query materializes at most
65 rows (under 4.1 MiB at the checked database bound); every page rechecks authority. Revoked clients do not hide retained
configuration from an authorized human. All responses are no-store.

A binding gets a new plain UUID and permanently records Environment, domain,
client registration UUID and the exact public client identifier obtained from
the database. No foreign-key cascade may delete this history when a client is
removed. One registration has at most one binding in a domain. A replacement
registration with the same client identifier is a distinct authority and needs
explicit configuration and new original authorization. Requests cannot choose
or rewrite the stored public client identifier.

For creation and any replacement, lock and validate the referenced client under
the same transaction, after the human/domain/operator locks. It must belong to
the Environment's current configuration and retain the exact recorded identifier.
Active settings additionally require current ACTIVE, undeleted, CONFIDENTIAL,
authentication other than none, explicit DPoP minimum true and the Token Exchange
grant type. Missing/null policy refuses activation. Revocation remains available
after client deletion or policy withdrawal; it does not rely on a valid client.
Current token callers must repeat these checks and intersect these settings with
original ceilings, target policy and membership at use time. A configuration
snapshot is never an authorization credential.

At most 64 bindings are retained per domain, 32 exact registered targets per
binding, 256 unique privilege keys per target and 48 KiB serialized settings.
No duplicates, blank sets, unknown targets or byte/case normalization are allowed.
Domain locking serializes quota, registration and mutations. A matching retry
rechecks operator authority before disclosing its original result. Changed bodies
conflict; stale ETags fail. Creation advances the domain revision; binding edits
advance their own revision, with the last increment reserved for deactivation.

The shared configuration receipt reserve increases to 129 slots: 64 operator
revocations, 64 client-binding revocations and one domain disable. Only an actual
active-to-inactive transition may consume a reserve slot; ordinary admission
closes at 10,000 retained receipts and cannot reactivate or replenish identities.
All ordinary operations and retries retain their prior rules. These client-setting endpoints never enable a domain. The explicit lifecycle
below governs activation; protocol callers still need their own integration.

### Explicit domain lifecycle

The domain lifecycle increment maps ORG-R01/R04/R06/R09/R21/R22 to
ORG-G03/G05/G07/G11/G14 and ORG-P03/P04/P08/P12/P13. Separate
`POST .../organization-domains/{domain}/enable` and `/disable` operations
require a current human configure grant, domain ETag, idempotency key and reason.
Bootstrap remains disabled. API keys, Team ownership alone and membership roles
do not enable or disable a domain. Enabling requires at least one registered
target and at least one active client binding; every active binding must still
refer to a current matching confidential, DPoP-required Token Exchange client
and only this domain's targets. The checks and transition share the domain lock.

Disable uses reserved admission and may consume one of the shared 129 revocation
receipt slots only when currently enabled. It does not depend on client validity,
membership, downstream reachability or quota headroom in the ordinary pool.
Enabling consumes ordinary capacity and preserves the last revision increment
for disabling. Both transitions increment the domain revision, atomically write
an event/outbox and save the response. Same-state commands with a new key conflict;
authorized retries return the original response. A revoked operator cannot replay
an earlier result. No row or retained authorization history is deleted.

The domain revision is a required current-state fence for subsequent token and
resource integration. Issued organization token state must bind the observed
domain revision and refuse a mismatch; disabling and re-enabling never revives
an old token. Original authorization ceilings remain an independent upper bound
and cannot grow through configuration. Before issuance is mounted, the actual
mint/introspection/resource callers must enforce this fence and current client
binding revision together with root, identity, membership and DPoP checks.
Configuration enablement alone advertises no RAR type and mounts no token path.
It is not release acceptance or a guarantee that every business workflow is ready.

The new grant table is owned by the permanent non-login authority and joins the
observed physical catalog through a forward migration. Runtime grants permit
only declared insert/read/mutable columns; no grant identity replacement or
history deletion. Domain configuration audit entries use the same immutable
event and outbox tables as organization changes, with an explicitly absent
organization identifier and a `domain.` event type. Existing event identifiers
and payloads remain unchanged.

The storage primitive alone is not an authenticated API. Mounted session/CSRF
authentication, owner bootstrap, finite admission, transaction revalidation,
idempotent grant mutation, outbox/retention and protocol activation are required
before enabling these endpoints. The migration does not create grants or
enable any existing domain.

### Closing an admitted class after cleanup failure

An interrupted cleanup closes its process admission class. Already-held leases
cannot start another connection, expose a retained connection for more SQL, or
admit a management commit after closure is observed. Session verification and
the final commit boundary recheck this state. Work already admitted to commit
cannot be undone by a later closure. Cleanup transfers the connection into
SQLx's return future before awaiting it; an interrupted return never detaches an
empty wrapper or recursively schedules cleanup. Actual failed-return regressions
use isolated admission classes so they do not reopen a closed production class.

Class closure and transaction commit admission use one synchronous locking
boundary. A closure ordered first refuses admission and the transaction rolls
back; a commit admitted first may finish. No database I/O is performed under
this lock, and poisoning refuses further admission. The same rule applies to
configuration reads so a closed class cannot admit their commit. Earlier
observations that only checked closure before commit did not establish this
ordering.
