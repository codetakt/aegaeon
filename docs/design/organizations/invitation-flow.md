# Organizations invitation flow

Last updated: 2026-10-30

Status: active plan

Owner: Engineering

Audience: implementers, operators and security reviewers

This implementation contract; public activation remains gated on the complete
flow, supplier checks and release acceptance. This refines ORG-R13/R14/R15/R16/
R21, ORG-G04/G09/G11/G13 and ORG-P02/P05/P06/P07/P13/P14/P15. It does not discharge
any composite obligation.

## Objects and authority

Invitation and challenge object IDs are plain UUIDs. Scope is the authenticated
Environment/domain, with the organization UUID in a separate field. Secrets use
the separate representation specified in [capability primitives](invitation-capabilities.md).
Neither an email address nor an object ID establishes an authenticated identity.

First-administrator issuance requires a current human operator with explicit
`provision` authority. It is confined to a provisioning organization with no
memberships. Retain the operator's Team, principal, grant UUID and exact revision,
the organization's generation and exact granted role versions. The roles must
include a member manager. Recheck all these facts on delivery, challenge creation
and acceptance. Provision authority does not grant business membership.

Delegated invitations require a separately validated original ceiling, current
DPoP-bound management authority and current assignable roles, including old and
new roles. Their retained authority must also bind client/root/key and expire no
later than the original root ceiling. This path cannot reuse the first-admin
operator path for an active organization. Implement and verify it before enabling
delegated invitation routes.

## Operator HTTP interface

The authenticated operator API uses these paths below `/api/v1/teams/{team}/
environments/{environment}/organization-domains/{domain}`:

- `POST /organizations/{organization}/invitations`: first-admin issuance;
  specific organization `If-Match`, `Idempotency-Key`, JSON `recipient`, unique
  `roles`, optional `lifetimeSeconds` and `reason`.
- `GET/HEAD /invitations/{invitation}`: secret-free metadata and a strong ETag;
  current `reconcile` authority, including expired/cancelled invitations.
- `POST /invitations/{invitation}/revoke`: current `provision` authority,
  invitation `If-Match`, idempotency key and reason. Use reserved cancellation
  admission and permit cancellation even when the original inviter was revoked.

Require the existing current human management session, configured Origin and
CSRF for mutations, strict JSON, no query, 64KiB body and bounded request worker.
The shared transaction owner rechecks the session and commit admission. Responses
never include a capability, recipient address or retained authority document.
An operator cannot accept a recipient invitation through these paths. They do
not imply that recipient HTTP or configured transport integration is complete.

## Recipient and acceptance

The initial transport profile accepts an ASCII dot-atom mailbox and DNS domain,
at most 254 bytes. Preserve the local part byte-for-byte; lowercase only the DNS
domain. Reject whitespace, controls, display names, quoted local parts, empty
labels and non-ASCII addresses. These are explicit supported-profile limits,
not a claim that other standards-compliant mailbox forms are invalid.

A link only selects a pending invitation. GET/HEAD never accept it. An
authenticated, active Environment user requests a fresh address challenge by
POST with the invitation capability. Deliver this challenge to the retained
recipient, never to an address supplied by the claimant. Bind the challenge to
the exact user UUID/subject, client registration/client ID, root and DPoP key.
The recipient token must be authenticated and current before entering the
transaction; an ordinary Organizations selected token cannot be required before
the user has joined. The consuming HTTP boundary must establish this separate
recipient credential profile before mounting a route.

Acceptance is an explicit authenticated POST with both capabilities and the
challenge ID. The challenge has an exclusive five-minute maximum deadline,
capped by invitation and authenticated credential deadlines. No profile email
claim or mail-provider acknowledgment substitutes for this fresh challenge.
An active account may accept an address invitation without changing its login
identity or automatically linking accounts. Unregistered recipients must first
complete the separately enabled signup/activation/recovery policy.

Lock the domain, organization and invitation, recheck the current inviter and
recipient, and verify the invitation, challenge and exact role ceiling in one
transaction. First-admin acceptance creates one active membership and activates
the provisioning organization atomically. Any existing membership, including
invited/suspended/removed membership, rejects this first-admin operation. Existing
suspended/removed identities cannot be revived. Previously captured OAuth roots
do not acquire this new membership; obtaining organization access requires new
authorization. Concurrent acceptance has one effect. A response-loss replay must
match the accepted recipient binding, pass current authority checks and return
the retained result without another event or membership mutation.

## Delivery, bounds and recovery

The protected invitation/challenge rows are the delivery work queue; ordinary
authority events contain object IDs and versions, never addresses or secrets.
An explicit delivery worker claims one row under the same authority locks,
generates a capability and stores only its hash and positive delivery revision.
Commit before handing the secret to a configured transport. The runtime transport
adapter must be scoped, authenticated, have finite request/response/time limits,
disable redirects and use an operator-configured destination. Template IDs are
fixed to invitation or recipient confirmation; caller-provided templates, URLs
and HTML are not accepted. A transport acknowledgment does not authorize anything.

Allow at most 10,000 retained invitations per domain, five delivery attempts per
invitation or challenge, and five retained challenges per invitation. Enforce a
60-second minimum interval between delivery attempts. A resend rotates the hash
and invalidates prior challenges without extending the invitation deadline.
Initial invitation lifetime defaults to 86,400 seconds (60..86,400 allowed).
No secret enters a durable queue, audit, receipt, export or ordinary API response.
Failed/uncertain delivery remains visible and can retry within these limits;
exhaustion refuses further delivery and requires a new authorized invitation.

Issuance uses a scoped idempotency receipt binding the authenticated operator,
organization, canonical recipient, roles, original deadline request, reason and
precondition. Recheck current authority before replay. Revoke uses a specific
ETag, is terminal, invalidates challenges and remains available when ordinary
issuance capacity is exhausted. Every mutation includes state, audit and outbox
in the same transaction. Roll back on any failure. The existing bounded request
worker owns cleanup and commit admission; caller cancellation does not free a
connection still performing database work.

The native service cannot itself authenticate a network caller or confirm that
a returned delivery envelope was committed and sent. Tests of that service are
component evidence. HTTP authentication, configured transport, worker lifecycle,
signup/recovery and actual upgrade/restore remain separate implementation and
verification obligations until their consumers are connected.

## Recipient HTTP credential profile

The recipient resource has the dedicated audience
`{issuer}/organization-invitations` and the single OAuth scope and configured
client privilege `organization.invitation.accept`. The authorization server's
ordinary authorization-code and Token Exchange policies must explicitly permit
that target and scope. A current confidential, DPoP-required registration must
also be enabled for that target in the exact Organizations domain. The target
must be explicitly marked as management. No UserInfo, selected-organization,
application or client-credentials token is accepted as a recipient credential.

The existing token validator checks the stored token, JWT where applicable,
refresh family and exchange root. Require a retained original exchange ceiling
covering the recipient target/scope, an unexpired root, no organization approval,
and an access token lifetime of at most 300 seconds. A fresh request DPoP proof
must match the stored key, method, URI and access-token hash. Resolve the exact
case-sensitive subject in the server's Environment; never parse an object UUID
out of the subject. Recheck active primary Environment/domain, exact registered
client, current configured recipient privilege and active user in the same
transaction as the invitation operation. Preserve the existing inviter-human,
domain, organization, invitation and recipient lock order.

Under `/organization-invitations/{domain}/{invitation}`, `POST /challenge-status`
takes strict JSON `invitationCapability`. A live Pending invitation, current
inviter, eligible new recipient, recipient credential and invitation proof are
required. It returns `remainingChallenges` and `invitationExpiresAt` (exclusive
Unix seconds). All recipients and devices share the five allocations. Reading
status takes no slot, sends no mail and makes no reservation.

`POST /challenges` takes the same body and an `Idempotency-Key`. Ordinary JSON
returns only `challengeId`. An explicit
`Accept: application/vnd.aegaeon.invitation-challenge.v2+json` selects extended
JSON with `challengeId`, `expiresAt` (exclusive Unix seconds) and
`remainingChallenges`. The response varies on Accept. An unsupported
representation returns 406 before allocation. An authenticated same-key replay
returns the original ID and deadline with the current remaining count. A live
fifth allocation can be replayed at zero remaining. A sixth new key is refused.

### Preview, confirmation and response loss

`POST /preview` and `POST /accept` take the same strict JSON fields
`invitationCapability`, `challengeId` and `challengeCapability`.
For preview the invitation must be Pending, the current recipient must be
eligible to join, and both the invitation and challenge proofs must still be
live for the original credential. The response contains the issuer, the full
organization UUID and display name, and each offered role's key and label.
It carries a strong opaque ETag and `Cache-Control: no-store`. Preview spends
no challenge slot, changes no membership and leaves both deadlines intact.

A hosted invitation pins the recipient client registration at issuance. Its
organization and offered roles must have display metadata before issuance or
a new challenge allocation. Every recipient operation checks the pinned
registration. An ordinary invitation supports the existing independent client
and unconditional acceptance. The public issuance routes currently select
the independent-client profile. Hosted configuration and browser delivery
belong to the subsequent browser and delivery increments.

The validator binds the issuer, Environment, domain, organization, invitation
and challenge to their current recipient and delivery revisions. It includes
the invitation revision, both the organization's revision and grant generation,
its display revision, and each offered role's key, label, permission version
and display revision in key order. A change to an unrelated role leaves the
validator usable. Clearing and restoring the same display text advances its
revision and requires a new preview.

For a hosted invitation send one specific strong `If-Match` on acceptance.
Other clients may opt in by sending the preview ETag. The server checks current
authority, eligibility or accepted membership, and both proofs before reporting
a missing required header (428), an invalid header (400), or a stale tag (412).
If a name or offered label was cleared after allocation, an authorized Pending
preview or conditional accept with a valid tag syntax returns
`409 display_metadata_unavailable`. The recipient may retry the same challenge
after the operator restores the metadata, up to its original deadline.

The acceptance transaction creates the membership, performs any first-admin
activation, records the event and stores the accepted challenge and result.
For a conditional acceptance it also stores the matched pre-accept ETag.
If the response is lost, send both proofs again with fresh request DPoP and
that same ETag. While the original credential, challenge, authority and exact
membership remain current, the server returns the original organization ID,
user ID, membership incarnation and revision with no duplicate effect.
An accepted invitation cannot be previewed again. A legacy unconditional
receipt replays with an absent header. After proof expiry the API cannot
confirm an uncertain outcome through a replay.

All four endpoints reject query parameters, unsupported content types and
duplicate or unknown JSON fields. GET and HEAD never accept. The existing
Organizations request worker, body/deadline, connection ownership, primary
projection and commit-admission checks apply. Changing the recipient
credential requires a new challenge. A join never expands existing grants.

This profile is an Aegaeon resource-server policy using existing OAuth/DPoP
mechanisms, not a new OAuth grant or a claim that the invitation API is an IETF
standard. The configured mail transport and signup/recovery policy are separate
required suppliers. Recipient HTTP is not release-ready until those suppliers
and the complete flow are verified.
