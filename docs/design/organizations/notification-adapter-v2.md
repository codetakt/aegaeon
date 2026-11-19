# Notification adapter protocol, version 2

Last updated: 2026-11-17

Status: current implementation baseline

Owner: Engineering

Audience: implementers and operators

The durable worker sends an HTTPS `POST` to the configured `/envelopes` endpoint.
The endpoint path is operator configured; `/envelopes` is the reference path.
TLS, actual-connection address validation, request limits and explicit trust
follow [invitation delivery](invitation-delivery.md). No URL or transport
credential comes from the message payload.

`Authorization: Bearer <credential>` carries the independently provisioned
32-byte credential in canonical unpadded base64url. `Content-Type` is
`application/json`. `Idempotency-Key` is the canonical lowercase message UUID.
It must equal `messageId`. Each retry sends the same UTF-8 body bytes and key.
The body is at most 8192 bytes, contains one JSON object and has these fields:

| Field | Meaning |
| --- | --- |
| `version` | Integer `2` |
| `messageId` | Stable nonzero UUID; independent of transport attempt UUIDs |
| `template` | One of the four fixed names below |
| `recipient` | Exact authorized destination; never substituted by the adapter |
| `issuer` | Aegaeon's HTTPS issuer |
| `environmentId`, `domainId`, `invitationId`, `objectId` | Nonzero UUID bindings |
| `deliveryRevision` | Owning proof revision, integer 1–5 |
| `capability` | Canonical unpadded base64url encoding of the 32-byte proof |
| `expiresAt` | Original exclusive Unix-seconds expiry; never extended by retry |

Templates are `organization_invitation`, `organization_recipient_challenge`,
`organization_identity_registration` and `organization_identity_recovery`.
For an invitation, `objectId` equals `invitationId`; other templates bind a
distinct child object. Unknown versions, fields, duplicate JSON keys, template
names, malformed bindings and expired new messages are refused. A successful
adapter validates the configured issuer and renders a fixed template; the body
never supplies HTML, a template path or a redirect destination.

Links use an explicitly configured recipient UI with proof material in the URL
fragment. Keep it out of query strings, access logs and referrers. Link navigation
does not perform acceptance. The recipient flow submits the proof to the owning
Aegaeon endpoint, which checks current authority and any required fresh challenge.
The adapter neither creates an account nor grants membership.

## Acceptance and deduplication

Atomically retain the message UUID, a digest of the exact received bytes and the
accepted delivery work before acknowledging. A repeated UUID with identical
bytes returns the previous acceptance without another delivery work item. A
repeated UUID with different bytes is a conflict and must not replace the first
message. Retain deduplication through at least the original `expiresAt`, including
recovery after process restart. The longest current proof lifetime is 24 hours.
An adapter configured with a shorter retention window must refuse this profile
or declare that duplicate delivery remains possible; Aegaeon does not infer a
provider's retention from a successful HTTP response.

Return HTTP `204` with an empty body only after durable acceptance. This records
adapter acceptance, not inbox delivery. A lost response can cause an identical
retry. External delivery after admission cannot be recalled; old proof use is
still rejected after explicit reissue or loss of authority. SMTP or other
downstream submission can have its own uncertain outcome and duplicate behavior.

`429` and `5xx` permit retry within the original deadline and attempt bound.
`Retry-After` may contain a nonnegative integer number of seconds or an HTTP
date; it is a lower bound. Redirects and permanent `4xx` responses are terminal
refusals, except `408`, which is uncertain. Network errors, timeouts, nonempty
`204` responses, oversized response bodies and other unexpected status codes
are uncertain. Responses are limited to 1024 bytes and 10 seconds. Error bodies
must not echo the request, credentials or proof.

The adapter is a separately operated supplier. Its stored bodies and rendered
mail contain actionable secrets and need restricted access, appropriate storage
encryption, bounded retention and recovery custody. Aegaeon's encrypted outbox
does not provide those controls for an external adapter.
