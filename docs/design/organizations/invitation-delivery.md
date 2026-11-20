# Organizations invitation delivery

Last updated: 2026-11-20

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

The independent runtime configuration may additionally contain `delivery_trust`,
an array of at most eight `{ "origin": "https://delivery.example.test",
"root_cert": "/private/delivery-ca.pem" }` entries. Origins are unique canonical
HTTPS DNS origins on port 443, without a path, userinfo, query or fragment. Each
explicit PEM trust bundle is an absolute regular-file input of at most 64 KiB;
the combined retained input is at most 512 KiB. The normal bounded file reader
rejects FIFO/device inputs and never reads more than 1 MiB plus one byte before
applying this smaller per-bundle bound. Load and validate these inputs once during
independent startup, before admission. Invalid or missing configured trust is an
error; it must not fall back to public roots. An exact origin match uses only its
selected CA bundle; other origins retain the built-in public root set. This trust
input grants no endpoint, credential, recipient or organization authority. It is
not stored in management configuration or snapshots. Actual connection DNS and
hostname verification, no proxies/redirects and the existing transport budgets
apply to both modes. This makes self-operated adapters possible with explicit
trust custody; it does not qualify a provider or authorize private IP access.

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

## Hosted and custom delivery profiles

The existing delivery configuration under `channel` selects the custom UI.
New invitations issued under this configuration retain its revision and exact
endpoint fingerprint. To change the endpoint while an old invitation can
still send, convert to a catalog and keep the original route.
The same scoped management PUT also accepts a catalog under `channel` with
`defaultRevision`, `legacyRevision`, `returnUrl` and `routes`. Each route
contains `revision`, `enabled`, a transport `channel` in the original format,
and `hostedClientRegistrationId` (a UUID for hosted, null for custom).
A catalog supports up to eight routes within the existing 4096-byte PostgreSQL
JSONB text budget. Fetch the current configuration and ETag before changing it.

1. In the existing Environment clients POST set `hostedInvitationDomainId`
   to the authorization domain UUID. Use a human session with both client
   lifecycle authority in the team and `configure` in that domain. Aegaeon
   derives the identifier `aegaeon-hosted-invitation-<domain UUID>`.
   Specify `client_secret_basic`, DPoP, the sole callback
   `{issuer}/organization-invitations/hosted/callback` and grants
   `authorization_code`, `refresh_token` and
   `urn:ietf:params:oauth:grant-type:token-exchange`. Allow exactly `openid`,
   `read`, `offline_access` and `organization.invitation.accept`. Configure the
   single exchange rule from `{issuer}/userinfo` with `read` to
   `{issuer}/organization-invitations` with `organization.invitation.accept`.
   The domain binding for its registration UUID must be active, with only this
   management target and privilege. Enable OIDC, strict redirect checks, refresh
   chain retention and sender binding in the active Environment policy. Issue
   a secret using the client's `clientSecrets` POST and install it in the
   BFF secret configuration. Keep at least one active, unexpired credential.
   Set the organization and role display names.
2. Configure an HTTPS v2 adapter with a separate durable spool, immutable
   recipient UI `{issuer}/organization-invitations/hosted`, public encryption
   key, and a separately provisioned worker credential. Check it using the
   [mail link fixtures and checklist](notification-adapter-v2.md#mail-link-interoperability).
   Keep each custom UI on its own adapter endpoint. Align worker credentials
   and keyrings with the corresponding route.
3. On first conversion preserve the previous custom channel byte-for-byte in
   a custom route with the current domain revision. Set `legacyRevision` to
   that revision. If there was no previous channel, leave `legacyRevision`
   null. Assign the new hosted route the next domain revision and select it as
   `defaultRevision`. This transition pins pre-upgrade invitations to their
   original custom route, including already encrypted mail. Subsequent
   invitations capture the selected revision in the issuing transaction.
4. An operator can switch the default between enabled routes. Each original
   invitation, identity registration or recovery, recipient challenge, retry
   and explicit reissue uses its invitation's pinned route. Route revisions,
   endpoints and client registrations cannot be reassigned. To rotate a worker
   credential or wrapping key while retaining the same recipient UI, submit the
   replacement channel under the same route and set its `transportRevision` to
   the next domain revision. Omit `transportRevision` when creating a route.
   Existing ciphertext remains bound to its prior transport revision. Use
   explicit reissue under the new material when delivery is still required.
   Setting `defaultRevision` to null suspends new issuance. To withhold dispatch,
   disable the route. The protected disable operation suspends all routes and
   preserves their pins. Keep the old adapter's UI mapping immutable until its
   last invitation expires. A disabled hosted client or target also prevents
   access to the hosted flow. An operator can change an optional exact HTTPS
   `returnUrl` independently. The BFF checks the registered value again at the
   recipient's explicit return action.

The catalog is part of the domain snapshot. Verify the matching adapter, key
custody, worker credential and active registration before resuming restored
traffic. A changed deployment or runtime generation retains the existing
outbox authority checks. See the [v2 adapter contract](notification-adapter-v2.md)
for encrypted delivery and identical-byte transport retries.
