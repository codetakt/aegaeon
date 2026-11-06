# Management database outages

Last updated: 2026-11-06

Status: current implementation baseline

Owner: Operations

Audience: operators, API consumers, maintainers

Management temporary failures return HTTP 503 with `Retry-After: 1`,
`Cache-Control: no-store`, and a request ID in `X-Request-ID` and the management
JSON envelope. The delay is a minimum backoff hint, not permission to replay a
write. A 503 does not establish rollback: a commit can succeed before its reply
is lost. Permanent SQL or stored-data defects remain 500; validation, conflict,
authorization and not-found outcomes retain their existing meanings.

OAuth endpoints use their own protocol error envelope (`error` and
`error_description`). Do not parse an OAuth response as a management response
(`errorCode`, `message`, `requestId`).

## Retry and reconciliation

| Operation | Action after an uncertain response |
| --- | --- |
| Read-only management request | Retry after backoff with current credentials. Recheck authorization and current state. |
| Organizations command with an existing receipt contract | Retain the same actor, scope, idempotency key and canonical body. Follow that endpoint's replay contract, including current authority checks. Never change the key to bypass an uncertain result. |
| Create account link | Inspect the exact environment, issuer, upstream subject binding, connection ID, link ID and end-user ID. A subsequent 409 only establishes a current conflict; another actor may have created or changed the link. |
| Delete account link | Inspect the original link ID and its current binding. A 404 is not proof that this command deleted it. A replacement with the same upstream subject is a different object. |
| Retire connection | Inspect the original connection ID, configuration version and terminal status. A subsequent 404 is not a receipt for the earlier request. Do not substitute a new connection with the same identifier. |
| Create management session | A missing response/cookie leaves the outcome uncertain. Do not automatically repeat login or treat a 503 as authentication success. |
| Delete management session | The cookie is cleared even on storage failure, but server-side revocation remains unconfirmed. Reconcile revocation before claiming logout completed. |

Account-link and connection routes have no command receipt or same-key replay
guarantee. If inspection cannot identify the outcome because state or ownership
changed, retain the request ID and report an unconfirmed outcome. Require an
explicit reconciliation decision before another mutation; do not automatically
re-create, re-delete or attach a different identity. State and its success audit
are committed together. Correlated audit records help investigation but do not
replace current authorization or create an idempotency contract.

## Session outage diagnostics

Each process shares three fixed aggregation slots across session-store clones:
`get`, `create` and `delete`. The first transient failure emits a warning
immediately. Further outage or recovery summaries share one emission budget per
operation per 60 seconds, measured with a monotonic clock. Success does not
refill the budget. Summaries include failure, suppressed-failure and recovery
counts, the interval duration, and bounded first and most recent request IDs.
WARN/INFO summaries retain fixed-length first and most recent failure SQLSTATE codes and
the most recent failure boundary's source file/line, including an idle recovery
summary. A failure without a SQLSTATE is reported as `none`; driver text is never
substituted for a code. These diagnostics do not require DEBUG logging.

The existing management-session cleanup job flushes pending summaries, including
an observed recovery followed by idle traffic. Delivery is at the next cleanup
pass after the 60-second budget becomes available; a stalled cleanup scheduler
can delay it. Lack of requests does not establish recovery. No per-outage task
or database retry is created by the logger.

`aegaeon_management_session_failures_total{operation,class}` counts each terminal
store failure once. Its label values are fixed (`get|create|delete` and
`unavailable|permanent`); request IDs and SQL text are never metric labels.
Optional DEBUG events retain sanitized per-request correlation and SQLSTATE.
Permanent faults retain separate ERROR reporting; security audit events retain
their existing behavior. Driver text, credentials, session tokens and SQL
parameters are not logged by this boundary.

Alert on failure rates and sustained outages, and observe recovery summaries.
Raw ERROR line counts are not request counts. Aggregation is disposable local
state: process restart resets it. Use the collector's process/restart handling
when comparing counts across replicas or restarts. This change has no schema
migration and makes no throughput or latency claim.
