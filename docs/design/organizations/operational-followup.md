# Organizations operational follow-up

Last updated: 2026-11-05

Status: active plan

Owner: Engineering

Audience: implementers, operators, reviewers

## Report provenance

A downstream operator reported local PostgreSQL 18.6 testing of `48a42d2bf`.
Only provisioning used superuser; other application roles were restricted.
No actual RDS test was performed. The reporter's evidence and harness have not
been independently replayed here; these are reported observations, not new
product guarantees or provider acceptance.

| Reported observation | Result and limit |
| --- | --- |
| No Redis/control store | Ready in 0.7 seconds |
| PostgreSQL restart/crash/connection termination during writes | Automatic recovery; most reads recovered below one second, maximum 1.3 seconds |
| 20 focused retransmission trials | 132 retransmissions returned 200; 690 confirmed operations matched 690 rows. The committed-but-response-lost subset was not classified |
| Earlier retransmission conflict | One 409 retained; reporter suspects changed `reason`; corrected trials did not reproduce it |
| 10-second database outage | Process survived and recovered |
| 45/120-second database outage | Process exited around 35 seconds with rc=1; startup failed with rc=78 until database recovery |
| Simulated rewind | Stopped file copy, not WAL PITR. Old generation failed startup, old sessions returned 401, later writes disappeared, password login and new writes succeeded |
| Activation with live worker | Refused |
| Crash response classification | Initial 8 POST / 5 GET responses; later 16 crash trials captured 29 POST / 7 GET responses |

Downstream IaC changes removing Redis/control-store resources were reported as
uncommitted and unapplied. They are outside this checkout and are not modified
or certified by this record. The reported BFF does not use assertions/JAR, but its
post-restore interaction with the 5101-second barrier has not been exercised.
Private delivery constraints, invitation-based password recovery and mail design
remain as adopted. Performance remains an unmeasured target.

The later crash run captured 36 identical error bodies except for request ID:
`internal_error` / `Database query failed`, without Retry-After, on GET and POST
`.../organization-domains/{domain}/organizations`. Repeated operations with their
original keys returned 200; this still does not classify commit status at the
500 response. The reporter overwrote the original focused JSON, then reconstructed
its 20 scenarios from the retained output log with a `restored_from` marker; that
reconstruction is not byte-identical to the original evidence. The new crash JSON
and retained server logs are separate inputs.

Source inspection identifies the outer path:
`observed_dispatch::management_target` calls
`management::authenticate_observed_environment`, which calls the generic session
lookup and `scope::ensure_team_visible_as`. The latter converts database errors to
the reported 500 body before the Organizations handler runs. This explains why
generic session lookup logs appear for Organizations requests. A controlled runtime
regression is still required to bind the failure and repaired status classification.

## Current PR work items

| ID | Status | Required outcome |
| --- | --- | --- |
| OPS-01 | Done; local acceptance passes | [Non-superuser provisioning](managed-postgres-provisioning.md), default and optional self-grants, positive installation plus privilege refusals |
| OPS-02 | Done; local acceptance passes | SQLx late-return close race: drain actual sessions, preserve deadlines and activation fencing, deterministic real-PG regression |
| OPS-03 | Done; local acceptance passes | Environment inventory includes and classifies test-only replay store variables instead of excluding the same prefix |
| OPS-04 | Open; cause identified | Keep a healthy process through temporary DB unavailability, refuse protected requests/readiness, retain bounded work and fresh authority validation. Distinguish transient transport loss from policy/key drift, generation mismatch, corruption and failed cleanup. Review monitor, request guard, listener and cleanup supervisor together |
| OPS-05 | Open | Document and supply a concrete restricted runtime grant procedure for ordinary application tables; test it without borrowing broad fixture-only grants |
| OPS-06 | Open; design required | Provide unattended external audit custody with explicit machine authority, least privilege, durable acknowledgment, current revocation and replay checks. The existing interactive consumer alone does not satisfy unattended operation |
| OPS-07 | Open; outer team-visibility path identified | Classify retryable database failures as 503 in the actual failing path; preserve uncertain-commit semantics and identical idempotency input |
| OPS-08 | Open | Replace obsolete control-store diagnostics and distinguish a selected-generation refusal from general database unavailability |

OPS-04 must not simply suppress supervisor errors or reuse stale authorization.
A completed bounded read may be retried; uncertain retained work requires its
actual completion/cleanup boundary. Retryable HTTP status is not a guarantee that
a write did not commit. Startup on an invalid generation must never self-activate.

Provider tests, complete OIDC journeys, old production data migration rehearsal,
connection sizing, membership discovery and SUPER_ADMIN alternatives remain
separate explicit open validation items. None is closed by local restart timing.
The Task 1b/Task 3 conformance/refinement/measurement handoffs remain in force;
known functional defects in this table remain the current PR's responsibility.

## Delivery boundary

PR #295 stays Draft. Signed publication, CI and Copilot review are authorized;
Ready, enqueue, merge, paid provider experiments and performance campaigns are not
part of this repair. Historical CI failures and initial reproduction failures are
retained. The [CI repair record](ci-repair.md) records source-bound checks.
