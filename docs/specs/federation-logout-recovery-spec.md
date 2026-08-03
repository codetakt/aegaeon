# Federation Logout Recovery Specification

Last updated: 2026-07-07

Status: current implementation baseline

Owner: Product / Engineering

Audience: implementers, reviewers

## Purpose

This document defines the missing recovery layer for brokered upstream logout flows.
It exists to close the current gap where Aegaeon clears the local broker session
fail-closed, but cannot yet prove that the upstream OP completed the corresponding
end-session step.

The goal is not to weaken logout. The goal is to make unknown upstream logout
results explicit, auditable, and recoverable from the management plane and the
admin console.

## Current Runtime Baseline

As of 2026-04-22, the server already does the following:

- parses `configurationDocument.federation.logout` with:
  - `backChannel`
  - `sessionHintClaim`
  - `recoveryPolicy` (defaulting to `force_prompt_login` when omitted)
- stores upstream logout context on brokered auth sessions, including the normalized
  recovery-policy snapshot
- clears the local `aegaeon_auth_session` cookie and auth-session entry on:
  - `POST /auth/logout`
  - RP-facing `GET /logout`
- when `post_logout_redirect_uri` is present, relays through
  `/oauth/upstream/logout/callback` using one-time state stored in a TTL cache
- rejects missing / invalid / expired relay state at the callback endpoint
- exposes the recovery-policy control in the admin-console configuration editor
- includes the normalized logout posture, including `recoveryPolicy`, in the
  `management.federationLogoutPolicy.changed.v1` audit event
- creates durable `federation_logout_recovery_incidents` records for front-channel
  upstream logout relay flows
- records relay lifecycle audit events:
  - `federation.upstreamLogoutRelay.started.v1`
  - `federation.upstreamLogoutRelay.completed.v1`
  - `federation.upstreamLogoutRelay.expired.v1`
  - `federation.upstreamLogoutRelay.callbackRejected.v1` for known replay / stale callbacks
- uses the durable incident record as the callback source of truth so relay completion
  can survive TTL-cache misses and process restarts
- applies runtime recovery policy during the next upstream authorize attempt:
  - `force_prompt_login` appends upstream `prompt=login`
  - `disable_connection` blocks the connection fail-closed until remediation
- routes local `POST /auth/logout` through the same relay helper when upstream
  front-channel logout is active so the auth surface and RP-facing logout share
  the same recovery model
- admits discovered upstream `end_session_endpoint` values under the same
  HTTPS, no-credentials, no-query/no-fragment, SSRF, and
  `policy.upstreamOutboundAllowedDomains` policy used for the upstream
  authorization, token, and JWKS endpoints, and rechecks the stored endpoint
  against the current active policy when constructing a later logout relay target

This gives the server and sibling admin console a delivered logout-recovery
baseline for the current B6/B7 scope. Broader broker/federation roadmap items
remain tracked separately.

## Problem Statement

The current design leaves an operational blind spot in these cases:

1. the browser never reaches the upstream OP logout endpoint
2. the upstream OP does not redirect back to the local callback
3. the local callback state expires before the browser returns
4. the upstream OP accepts logout but the result is not observable by Aegaeon

In all of those cases, the local broker session is already gone, which is the
correct security posture for Aegaeon itself. The unresolved question is whether
the upstream OP session is still live and may silently re-authenticate the same
user on the next brokered login.

## Security Requirements

The recovery design MUST satisfy these requirements:

1. Local logout remains fail-closed and immediate.
2. Unknown upstream logout completion MUST NOT be recorded as success.
3. Recovery data MUST be durable across process restarts; an in-memory TTL cache
   alone is insufficient for operator workflows.
4. Sensitive session-hint values SHOULD be redacted or stored as a hash; raw
   upstream logout hints should not become a new long-lived secret store.
5. Recovery actions MUST be auditable from the management plane.
6. The default posture SHOULD prefer forcing fresh upstream authentication over
   optimistic reuse of a potentially live upstream session.
7. There is no `ignore` or fail-open recovery mode in the security baseline.
8. A published upstream `end_session_endpoint` MUST be admitted fail-closed
   before Aegaeon appends `logout_hint`, `post_logout_redirect_uri`, or relay
   `state`; optional OIDC logout metadata does not bypass upstream outbound
   allowlisting or SSRF policy.

## Proposed Recovery Model

### Recovery Policy

Extend `configurationDocument.federation.logout` with a recovery policy field:

```json
{
  "federation": {
    "logout": {
      "backChannel": false,
      "sessionHintClaim": "sid",
      "recoveryPolicy": "force_prompt_login"
    }
  }
}
```

Allowed values for `recoveryPolicy`:

- `force_prompt_login`
  - recommended default
  - if upstream logout completion is unknown, the next upstream login attempt
    for the affected broker path forces fresh upstream authentication
- `disable_connection`
  - stricter operator-controlled posture
  - unknown logout completion marks the connection degraded and blocks new
    brokered login attempts until the operator clears the incident

Values deliberately not supported:

- `ignore`
- silent retry loops that claim success without operator-visible evidence

### Incident Record

Introduce a durable recovery incident record with the following minimum fields:

- `incident_id`
- `team_id`
- `tenant_id`
- `environment_id`
- `connection_id` or resolved upstream issuer identity
- `downstream_client_id` when available
- `status`
  - `pending`
  - `completed`
  - `expired`
  - `callback_rejected`
  - `operator_cleared`
- `policy`
  - snapshot of the active recovery policy
- `session_hint_claim`
- `session_hint_value_hash`
- `created_at`
- `expires_at`
- `resolved_at`
- `failure_reason`
- `request_id`

The existing TTL relay store may remain as the fast path for one-time callback
state, but it must point to the durable incident record rather than being the
only source of truth.

## Runtime Behavior

### Logout Start

When Aegaeon initiates upstream front-channel logout through the relay path:

1. clear the local broker auth session immediately
2. create a durable recovery incident with `status = pending`
3. store a one-time relay token that resolves to that incident
4. emit a start audit event

The relay target is constructed only when the stored upstream `end_session_endpoint`
still passes the current active endpoint-admission policy. A provider-published or
previously stored endpoint containing credentials, a query, a fragment, a non-HTTPS
scheme, a literal non-routable target, or a host outside the current
`policy.upstreamOutboundAllowedDomains` is not used as a front-channel relay target.

### Callback Success

When `/oauth/upstream/logout/callback` receives a valid relay token:

1. mark the incident `completed`
2. emit a completion audit event
3. redirect back to the downstream RP

### Callback Missing / Invalid / Expired

When the relay result cannot be matched or times out:

1. mark the incident as `expired` or `callback_rejected`
2. emit a recovery-required audit event
3. apply the configured recovery policy

## Recovery Actions

### `force_prompt_login`

For the affected broker path, the next upstream authorization attempt MUST:

- add `prompt=login`
- avoid silently treating the upstream OP session as trustworthy state reuse

The degraded marker can be cleared when one of the following happens:

- a clean upstream logout relay completes later for the same path
- the operator explicitly clears the incident
- a fresh upstream authentication round-trip completes under the degraded mode
  and establishes a new broker session

### `disable_connection`

For the affected connection, new brokered login attempts MUST fail closed until
an operator clears the incident or replaces the connection posture.

This mode is appropriate when the upstream OP has unreliable front-channel
logout behavior and the deployment requires explicit operator acknowledgement
before reopening the broker path.

## Audit Events

The recovery flow should emit dedicated audit events, separate from the existing
configuration activation event:

- `federation.upstreamLogoutRelay.started.v1`
- `federation.upstreamLogoutRelay.completed.v1`
- `federation.upstreamLogoutRelay.expired.v1`
- `federation.upstreamLogoutRelay.callbackRejected.v1`
- `management.federationBrokenSession.cleared.v1`

The existing
`management.federationLogoutPolicy.changed.v1`
remains the audit event for policy posture changes. It does not replace the
runtime recovery audit trail.

## Management Plane and Admin Console Requirements

As of 2026-04-22, the management plane exposes:

- list incidents by team / environment / connection / status / recovery policy
- inspect a single incident
- clear an incident with an operator-supplied reason
  - clear writes `management.federationBrokenSession.cleared.v1`
  - clear changes the durable incident status to `operator_cleared`

As of 2026-04-22, the admin console exposes:

- an incident list and filters
- a degraded / recovery-needed indicator on the affected broker connection
- operator remediation actions
- audit visibility for both runtime recovery events and policy changes

## Non-Goals

This phase does not attempt to:

- prove that the upstream OP actually destroyed its own session
- add browser automation to confirm third-party logout UX
- silently repair unknown upstream logout state without an audit trail

## Delivery Notes

This specification now records the delivered Phase B6 / B7 logout-recovery
baseline:

- durable runtime incident tracking and relay recovery handling in the server
- management-plane list / inspect / clear operations over those incidents
- sibling admin-console remediation, degraded-state visibility, and audit
  affordances

Current broker/federation behaviour is specified in `oidc-rp-brokering-spec.md`. Future
broker/federation enhancements should be promoted through `../program-management/roadmaps/future/future-projects.md`,
not by reopening this specification's delivered baseline.
