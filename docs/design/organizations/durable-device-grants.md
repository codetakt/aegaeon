# Durable device authorization and atomic publication

Last updated: 2026-11-05

Status: current implementation baseline

Owner: Engineering

Audience: implementers and reviewers

This increment implements S03 under the adopted
[recovery responsibilities](recovery-responsibilities.md). It is current domain
state in the selected database. It does not replay authorization transitions,
retain a restoration journal or override the operator's chosen PITR state.

## Transaction boundaries

A single row binds a hashed device code and hashed normalized user code to the
client, optional environment, scope, resource, deadline and current approval.
Approval and denial lock that row and change only a still-pending, unexpired
request. Both decisions recheck the DB clock after lock waits. Creation uses
fresh randomness, bounded collision attempts, unique selectors and exact expired
user-code collision reclamation. Raw device/user codes are not stored.

Polling first checks environment, expiry, client and requested resource. Wrong
context does not alter the current approval or poll clock. A valid poll updates
its last-poll time and interval under the same row lock; a too-early poll adds
five seconds with a representable saturation bound. Missing and expired requests
refuse. The clock is database wall time; no cross-machine monotonic clock or
rollback-resistant clock claim is made.

The HTTP token path prepares a current approved observation without consuming it.
Its commit context is bound to the same cloned `PostgresGrantDatabase` as the token
store, plus the client, subject, scope, resource, environment, expiry and resolved
audience. Token publication locks and rechecks that observation, writes the
access capability and metadata, checks expiry, consumes the device row and commits
one SQL transaction. No credential is returned before confirmed commit. A token
collision, wrong database, changed approval or expiry rolls the transaction back.
There is no automatic retry after an uncertain commit.

The standalone polling API retains its explicit consume behavior; SQL token
issuance uses the separate prepare/commit path. Synchronous SQL facades refuse.
Legacy Redis/memory token paths retain their previous behavior until the coupled
production migration is complete; their early consume behavior is not SQL
atomic-publication evidence.

## Resources and cleanup

All operations use the admitted asynchronous SQL connection and a five-second
operation deadline. Per-row fields have schema byte bounds. Cleanup uses the
shared 4,096-row batch, 256-batch/15-second pass, `SKIP LOCKED` and an observed
backlog counter. Live device rows remain usable. An exact active count is an
observational SQL scan over the namespace's live range; it is not on token
acceptance and remains part of REC-T11 accounting. These are functional bounds,
not evidence of 10,000 HTTP/s or p99 below 200 ms.

## Current PR checks

| Item | State | Required evidence |
| --- | --- | --- |
| SQL adapter and native facade | Implemented and checked | Creation, lookup, approval/denial, pending/slow-down and wrong-context checks |
| Atomic access publication | Implemented and checked | 32 prepared contenders, one committed token; failed insertion preserves approval |
| Expiry and cleanup | Implemented and checked | Observed row-lock expiry, live row preservation, 8,193-row cleanup with locked remainder |
| Real route integration | Implemented and checked | Restricted-runtime approval/denial, namespace refusal and token publication |
| Production constructor | Open | Coupled code/OIDC/token/device selection, one database identity, startup checks |
| Lifecycle and restore activation | Open, REC-T06–09 | Fresh serving namespace, old-worker exclusion, selected-state activation |

The source currently uses 84 Atlas revisions through
`20261105027000_runtime_security_catalog`. The initial Clippy argument-count
failure was fixed by using a creation request value. Clippy passes for the v3
source. The v4 artifact `a1x5zxqdg8jw9xdn0ilzm86f1sggwlnf` passes 48 affected
native checks (45 device tests and three token-handler tests) and 17 PostgreSQL/
HTTP checks: five new device SQL checks, three consent/code/refresh routes, seven
device routes/regressions and two shared-cleanup regressions. The latter also
exercise 8,193 expired rows with the existing timestamp expiry format. These
inventories overlap earlier component checks and must not be summed as new
distinct product coverage. All owned suppliers were stopped. Immutable artifact source
bindings distinguish each local candidate and retain earlier failures.

## Task 1b and Task 3 handoff

Task 1b owns renewed protocol/claim mapping for the affected device grant and
scope/resource/response requirements. Task 3 owns strict SQL/Rust refinement,
clock/isolation and entropy premises, whole-protocol composition and qualified
provider/load evidence. Current-PR functional, concurrency and threat checks
remain here. Existing formal registration and compiler success do not discharge
those proof obligations or the open serving-generation lifecycle.
