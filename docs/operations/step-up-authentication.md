# Step-Up Authentication (RFC 9470)

Last updated: 2026-08-03

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

## Overview

Aegaeon enforces step-up requirements at the authorization endpoint using `acr_values` and
`max_age`. When a request requires stronger assurance than the current session (ACR mismatch or
stale authentication time), the server requires step-up completion before issuing an authorization
code.

Key behaviors:

- `acr_values` and `max_age` are accepted from the request object and PAR form data.
- Request Object values take precedence over PAR form values.
- `prompt=none` fails with `login_required` if step-up is required or no session exists.
- Interactive authorization issues a challenge bound to the client, current auth session, and
  normalized authorization request before redirecting to local login.
- Successful local login completes the old-session challenge and creates a completed successor
  bound to the newly issued auth session. Authorization consumes that successor exactly once.
- Challenge consumption applies to interactive retries only: `prompt=none` requests are rejected
  with `login_required` before the challenge store is consulted.
- When `max_age` is supplied only inside a signed Request Object (not as a query parameter), the
  login-side request-id recomputation cannot see it, so the challenge is not completed and the
  flow falls back to the fresh-login satisfaction path.

## Configuration

| Setting | Default | Notes |
| --- | --- | --- |
| `policy.acrValuesSupported` | _empty_ | Allow-list of supported ACR values in the active configuration document. Empty means `acr_values` is rejected. |
| `policy.defaultAcr` | first entry of `policy.acrValuesSupported` | Default ACR for new sessions when no ACR is requested. |
| `policy.stepupChallengeTtlSeconds` | 300 | Authoritative TTL for step-up challenges in the supported PostgreSQL-backed runtime. |
| `AEGAEON_STEPUP_CHALLENGE_TTL_SECS` | _removed_ | Removed startup fallback. In the supported PostgreSQL-backed runtime, `policy.stepupChallengeTtlSeconds` is authoritative. |
| `AEGAEON_STEPUP_REDIS_URL` | _unset_ | Redis URL for shared step-up challenge state in multi-server deployments. This remains a process-global system setting. |

## Recommended ACR Values

Use stable, explicit identifiers to keep integration consistent across clients and audits.

- `urn:pwd` — password-only authentication
- `urn:mfa` — multi-factor authentication
- `urn:hwk` — hardware-backed authentication (if supported by your IdP)

Avoid ad-hoc per-tenant values. Use a small shared vocabulary and map upstream IdP signals to the
closest supported ACR.

## Management UI Integration

For a management console or login UI:

1. Parse `acr_values` and `max_age` from the request object or PAR data.
2. If `acr_values` is present, the UI should prompt for the strongest factor requested.
3. If `max_age` is present and exceeded, force re-authentication before continuing.
4. On success, resume `/authorize`. The server transfers challenge completion from the prior auth
   session to the newly issued session and consumes the successor before issuing a code.

When `prompt=none` is used, the UI must not attempt interactive login. Return control to the client
and surface `login_required` to the relying party.

## Operational Guidance

- Keep `policy.defaultAcr` aligned with your lowest-assurance login.
- Only list values in `policy.acrValuesSupported` that your login stack can actually satisfy.
- Tune `policy.stepupChallengeTtlSeconds` for highly sensitive operations within the 1-600 second
  policy range.
- Set `AEGAEON_STEPUP_REDIS_URL` before running more than one server instance with step-up enabled.

## Observability

Metrics:

- `oauth_stepup_events_total{event}` tracks step-up requirements and challenge lifecycle.

Structured logs:

- `event=stepup_required` includes `client_id`, `reason`, `prompt`.
- `event=stepup_challenge_issued|consumed|completed` includes `client_id`, `request_id`.

Use these signals to correlate step-up enforcement with user friction and security outcomes.
