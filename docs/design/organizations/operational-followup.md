# Organizations operational follow-up

Last updated: 2026-11-05

Status: current implementation baseline

Owner: Engineering

Audience: implementers, operators, reviewers

Local implementation acceptance is complete; candidate CI and review remain pending.

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
generic session lookup logs appear for Organizations requests. An isolated real-PostgreSQL regression now blocks that actual team-visibility
query, terminates its backend, verifies a 503 with the request ID, and succeeds
on the next lookup through the same pool. Permission/schema controls remain 500;
structured logs include the fixed surface, request ID and SQLSTATE without SQL
text, parameters, credentials or driver detail.

## Current PR work items

| ID | Status | Required outcome |
| --- | --- | --- |
| OPS-01 | Done; local acceptance passes | [Non-superuser provisioning](managed-postgres-provisioning.md), default and optional self-grants, positive installation plus privilege refusals |
| OPS-02 | Done; local acceptance passes | SQLx late-return close race: drain actual sessions, preserve deadlines and activation fencing, deterministic real-PG regression |
| OPS-03 | Done; local acceptance passes | Environment inventory includes and classifies test-only replay store variables instead of excluding the same prefix |
| OPS-04 | Done; combined local acceptance passes | Keep a healthy process through temporary DB unavailability, refuse protected requests/readiness, retain bounded work and fresh authority validation. Distinguish transient transport loss from policy/key drift, generation mismatch, corruption and failed cleanup. Review monitor, request guard, listener and cleanup supervisor together |
| OPS-05 | Done; local acceptance passes | Document and supply a concrete restricted runtime grant procedure for ordinary application tables; test it without borrowing broad fixture-only grants |
| OPS-06 | Done; local acceptance passes | Provide unattended external audit custody with explicit machine authority, least privilege, durable acknowledgment, current revocation and replay checks. Private API-key-file mode removes the interactive-session requirement |
| OPS-07 | Done; local acceptance passes | Classify retryable database failures as 503 in the actual failing path; preserve uncertain-commit semantics and identical idempotency input |
| OPS-08 | Done; local acceptance passes | Replace obsolete control-store diagnostics and distinguish a selected-generation refusal from general database unavailability |
| OPS-09 | Done; local acceptance passes | Copilot review 5780472775: register the distinct management writer in selected-generation admission, preserve credentials/reserved capacity and validate actual startup, writes, replacement fences and cleanup; correct the obsolete LTI pending-record description |

OPS-04 must not simply suppress supervisor errors or reuse stale authorization.
A completed bounded read may be retried; uncertain retained work requires its
actual completion/cleanup boundary. Retryable HTTP status is not a guarantee that
a write did not commit. Startup on an invalid generation must never self-activate.

Provider tests, complete OIDC journeys, old production data migration rehearsal,
connection sizing, membership discovery and SUPER_ADMIN alternatives remain
separate explicit open validation items. None is closed by local restart timing.
The Task 1b/Task 3 conformance/refinement/measurement handoffs remain in force;
known functional defects in this table remain the current PR's responsibility.

## Local acceptance and remaining admission

Combined packaged artifact
`qfldgbffrirrhc5va35g86l6cwkh39w0-aegaeon-organizations-production-runtime`
passes machine fetch/ACK/replay/refusal, 45/120-second outages, same-process
recovery and explicit old-generation refusal. PostgreSQL, signals, HTTP and
activation checks use the actual distribution; Redis/control suppliers are absent.
It includes post-lock API-key expiry validation. The separate real-PG credential
lock regression and normal/failing cleanup cases pass on
`682kiiq0cr13xk7ajpldjndr9yi3rfa7-aegaeon-database-tests-0.0.0` with default
thread stacks. Five human audit/operator regressions, 12 consumer checks and
three API-key capability checks retain their own source-bound results.

Catalog artifact
`xjs98i58smzajlk0i4yiqngps5vy4dnn-aegaeon-organizations-catalog-upgrade`
passes the populated single-migration upgrade and both non-superuser installation
profiles with the ordinary runtime grant script. Canonical OpenAPI check
`q2qgbgmsklmp4r524r0kl4gb9mgzizz0-aegaeon-openapi-check-0.0.0` passes. These
local acceptance results do not claim actual RDS, a complete hosted CI result,
independent review, performance measurement or new proof discharge.

The published `7944c4908` CI failure is a distinct admission obligation: cleanup
future stack size and two obsolete configuration-test expectations were repaired;
original failures remain in the [CI repair record](ci-repair.md). Fresh signed
candidate CI and review must be evaluated before delivery can be called complete.
The corrected configuration group passes 114 cases (five supplier-dependent
cases skipped) on `ydzr71fda93lwkkvd1683a4pnp8f7j7c-aegaeon-database-tests-0.0.0`;
strict Rust passes on `xfc8s300a153zilvhzb6ryzdx711qd36-aegaeon-rust-strict-packages-0.0.0`.
The only code difference from the combined packaged source is the legacy
configuration inventory test. Runtime-linked source guards and strict formal
reference validation pass; this is reference integrity, not new proof discharge.

The first operational publication `8fe922874` failed documentation metadata in
job 127070317406 because its Status text was not in the allowed vocabulary. The
same error appeared in the staged hook output; inspecting only its successful
tail missed that failure. The status now uses the repository vocabulary, while
the acceptance/admission distinction is ordinary prose. The original failed hook
and CI logs are retained; the correction requires the complete hook exit result
before publication. Runtime source and its acceptance artifacts are unchanged.

The distinct management-pool follow-up passes all three packaged profiles
(enabled, disabled and separate management credential) on
`ghvrbrlq0l21fw45i15x3bsr99ky3l12-aegaeon-organizations-production-runtime`.
Both enabled profiles include real HTTP audit operations, shutdown, 45/120-second
outages, unchanged generation and explicit stale-generation startup refusal.
Twenty related lifecycle, LTI privilege and human/machine audit checks pass on
`kmb4hlamibk5805n3i178vlgz7h82yx2-aegaeon-database-tests-0.0.0`. Both dedicated
Clippy profiles and strict Rust pass. The updated catalog check
`qjmk0zzfcqy1i76xzfa2cm2685dg9naq-aegaeon-organizations-catalog-upgrade` retains
the 24-to-25 upgrade and both non-superuser profiles with all 16 refusals.

The initial management fixture failed full preflight because it substituted the
management target for the primary snapshot-entry runtime. The ordinary grant
script now separates those explicit role inputs and checks both appropriately;
snapshot authority is unchanged. The first negative-control attempt refused an
ambient TLS setting before runtime and is not evidence of the pool-identity bug;
the corrected TLS control reaches owned startup and reproduces its refusal.
These failures remain retained. Final candidate CI/review still requires evaluation.

## Delivery boundary

PR #295 stays Draft. Signed publication, CI and Copilot review are authorized;
Ready, enqueue, merge, paid provider experiments and performance campaigns are not
part of this repair. Historical CI failures and initial reproduction failures are
retained. The [CI repair record](ci-repair.md) records source-bound checks.
