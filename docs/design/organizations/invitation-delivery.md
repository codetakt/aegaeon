# Organizations invitation delivery

Last updated: 2026-10-30

Status: active plan

Owner: Engineering

Audience: implementers, operators and security reviewers

This implementation contract refines ORG-R13/R14/R16/R21, ORG-G04/G11/G13/G14
and ORG-P05/P06/P07/P12/P13/P14/P15. It does not establish proof discharge.

## Configuration and trust

A domain has one explicitly enabled delivery configuration, initially absent.
It contains a canonical HTTPS endpoint and SHA-256 digest of an independently
provisioned, high-entropy transport credential. The credential itself is never
stored in the database, receipts, logs or exports. Configuration requires current
human `configure` authority, the domain ETag, an idempotency key and a reason.
Use GET/HEAD and PUT `/api/v1/teams/{team}/environments/{environment}/
organization-domains/{domain}/invitation-delivery`, and POST to its `/disable`
child with a reason. Require the current management session and configured
Origin/CSRF for mutations, strict JSON, no query and the shared body/deadline
limits. Disable remains available through the cancellation reserve. A configuration
revision change fences an outstanding claim from a new send admission.

The operator-controlled endpoint implements Aegaeon's versioned JSON delivery
adapter. It receives exactly one fixed `organization_invitation` or
`organization_recipient_challenge` template, recipient address, issuer,
Environment/domain/invitation/challenge object IDs, capability and expiry.
No caller HTML, template, redirect URL or alternate recipient is accepted.
The adapter must render a link that keeps the capability out of query strings,
access logs and referrers; link navigation never accepts an invitation.
An acknowledgment means that the transport accepted the envelope, not that the
recipient received it or is authorized. The separate fresh recipient challenge
remains mandatory. Actual mail-provider operation is a deployment supplier.

Only absolute HTTPS with a DNS hostname, port 443, no userinfo/query/fragment
and a bounded path is permitted. Disable redirects, system proxies and HTTP
fallback. Validate the hostname and use the existing non-routable DNS resolver
on actual connection. TLS certificate validation stays enabled. The request is
at most 8KiB; connect timeout is 3 seconds, complete response timeout 10 seconds,
and response body at most 1KiB. Only HTTP 204 with an empty body acknowledges.
Never log network errors containing request data, credential or provider body.

## Durable attempts and recovery

The existing protected invitation/challenge rows remain the work queue. Add an
outcome of `unclaimed`, `uncertain`, `acknowledged` or `rejected` for the current
positive delivery revision. `delivered_at` is the claim time, not a receipt.
Claim under current inviter/domain/organization/recipient authority, rotate the
capability hash, set `uncertain` and commit before any network operation. A crash
or lost commit response never exposes the envelope to transport. After a known
successful commit, recheck current primary state and the exact configured channel
at send admission. Revocation after this admission cannot recall an in-flight
message, but acceptance still checks current authority.

A private claim binds scope, invitation, object, revision, purpose, channel and
claim time. Record a result only for that exact current revision; late completion
cannot overwrite a resend. This bookkeeping does not reactivate an invitation
or confer authority. Its audit and outbox records are atomic. A crash, timeout,
ambiguous response or lost completion leaves `uncertain`; a definitive refusal
records `rejected`. HTTP 429 and 5xx remain uncertain. Only unclaimed or uncertain
work is eligible for automatic recovery, after the existing 60-second interval.
Each retry consumes one of the five retained attempts, rotates the hash and never
extends the deadline. An acknowledged attempt is not automatically resent.

The one-shot `aegaeon-organization-delivery` worker authenticates its restricted
runtime database and validates the same Environment namespace as the server.
It accepts a bounded private JSON credential on stdin, selects the named invitation or challenge work
item in that domain, performs at most one network request, and exits. It has a
45-second operation deadline, shared finite Organizations admission and normal
connection cleanup ownership. Scheduling another invocation is an explicit
operator action; there is no hidden background retry or unbounded scan. The scheduler obtains object IDs from authorized audit/outbox consumption; it
cannot supply a recipient or URL. Multiple workers serialize the named item
under domain/organization locks. A stale
candidate must be rechecked before rotating a hash. Emit only object IDs,
revision and outcome. When no eligible authorized work is found, emit `idle`.

Fresh install remains disabled. Apply schema/catalog changes only with serving
runtimes stopped and drained. Preserve every prior migration and existing claim;
map a historical positive revision to `uncertain`, never to acknowledged. Test
real HTTP/TLS transport, concurrent claims, revocation, stale completion, timeout,
process loss and recovery; native model tests alone do not verify the supplier.
