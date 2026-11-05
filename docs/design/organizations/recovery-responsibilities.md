# Organizations storage and recovery responsibilities

Last updated: 2026-11-05

Status: active plan

Owner: Engineering

Audience: implementers, reviewers, operators

The user adopted this boundary on 2026-11-05. It supersedes the proposed
per-operation independent journal, three-phase confirmation, all-state replay,
and paired PostgreSQL/Redis recovery in the earlier recovery redesign documents.
Those proposals and their numerical estimates are historical, not requirements.
This decision does not assert that the existing runtime already implements it.
See the [implementation plan](recovery-workplan.md) and
[security and verification assessment](recovery-security.md).

## Responsibilities

| Owner | Responsibility |
| --- | --- |
| Application | Domain invariants, authorization, transaction boundaries, concurrent mutation, idempotency, audit/event provenance and external-effect reconciliation |
| RDBMS and operator | Commit durability under the selected failure model, replication, backups, WAL retention, PITR target, RPO/RTO and restoration execution |
| Application after restoration | Validate the selected authority, exclude old workers, discard incompatible volatile state and converge external interactions |
| Audit operator and application | Preserve attributable history independently of an intentional business-data rewind; expose delivery gaps, restoration actions and their scope |

An authorized PITR intentionally selects an earlier durable state. Changes after
that point need not be replayed into business tables. Ordinary transaction
durability, accidental loss and an authorized historical restoration are distinct
contracts. An old snapshot cannot select itself as the live authority. Passwords, client
secrets, registered keys and revocation status at the selected point are included
in that authority. No later audit event automatically changes them; see
[REC-D01](restore-credential-decision.md).

The application does not implement a replacement WAL, generic event-sourced
database recovery, or reproduction of pre-restore memory. Model convergence is
toward the selected durable state, with explicit treatment of effects already
observed outside the database. Audit events explain activity; they are not the
state-reconstruction authority.

## Design rules

### REC-01: one durable application authority

Use the selected PostgreSQL state for durable organization, identity, policy,
membership, command outcome and audit/outbox data. Enforce domain constraints
inside the relevant transaction and recheck authorization before returning a
stored command result. A cache or surviving old process cannot override this
authority. Ordinary reads do not require an independent journal round trip.

### REC-02: transaction outcome and retry

Commit each business mutation, its audit/event records, outbox work and idempotent
result together. A lost response is an unknown outcome, not evidence of rollback.
Resolve it from the same authority using the actor/scope/operation/payload-bound
receipt; do not repeat an external side effect merely because its response was
lost. Cancellation must retain or terminate connection/worker ownership safely.
This is bounded business-operation reconciliation, not generic database redo.

### REC-03: volatile loss is normal

Every volatile family must declare its loss behavior. A derived cache is discarded
and rebuilt from its authoritative source. Missing positive session/capability
state denies its use. No volatile value is restored solely to reproduce the old
runtime. Incompatible generations and values are discarded; a stale value must
never be used as an availability fallback for an authorization decision.

### REC-04: absence must not create authority

Replay tombstones, revocation-only deny lists and security limit counters are not
ordinary caches: their absence can grant access or extra attempts. Either retain
the necessary decision in PostgreSQL, or invalidate every dependent credential/
window when the volatile generation is lost. If neither is established, refuse
the affected operation. An empty store, a new Redis process, or a missing key is
not proof that a credential is unused or a security budget is fresh.

These rules cover normal operation and unplanned cache loss. They do not require
preserving post-target durable revocations or budgets across an authorized PITR.
Externally presented proofs still require replay-safe activation under the new
session generation or their bounded acceptance horizon.

Loss includes eviction and partial loss, not only whole-process restart. A single
surviving marker cannot attest that every security key survived. Atomic consume,
expiry, clock/skew bounds and cross-worker uniqueness remain application duties.

### REC-05: generations belong to lifecycle boundaries

At PITR or a reset requiring volatile-session invalidation, fence the old runtime
and select a fresh session/runtime generation which is not reused from the
restored snapshot. Bind volatile credentials and namespaces to that generation,
or establish that all dependent sessions are otherwise invalid. This does not
invalidate restored durable passwords, client secrets or registered keys. This is a lifecycle
operation, not a per-request counter or a journal of every state transition.
Ordinary DB reconnection with unchanged authority is not automatically a PITR.

### REC-06: recovery does not merge authorities

Stop or exclude old writers and deferred workers before reopening a restored
authority. Drop caches, connection-local state and incompatible in-flight work.
Restart from the chosen durable state. Do not union old and restored privileges.
External notifications cannot be unsent by PITR; stable event identities,
recipient deduplication and reconciliation handle their observable outcomes.

### REC-07: identity remains an explicit domain contract

Permanent subject/external-ID ownership and non-reassignment remain domain
invariants enforced against the selected durable ownership records. Restoration
adopts those records along with the rest of the selected database. Audit is not
an independent current ownership authority and must not silently recreate later
ownership changes. Use fresh unguessable identifiers for new identities; never
union an old process's ownership cache with restored records. Any externally
retained identity references are external effects requiring explicit reconciliation,
not an instruction to replay the entire post-target application history.

### REC-08: audit survives a business-data rewind

Record actor, scope, request/operation identity, event type, result, applicable
versions and time without secrets. Retain accepted audit history in independently
protected custody under an explicit retention/delivery contract. Planned PITR
preserves available undelivered records before the rewind and record the selected
target, initiating operator, invalidation and reactivation. Disaster loss cannot
be described as complete audit if the last records were never retained elsewhere.
Expose any known gap. No claim of zero-loss audit follows from asynchronous
outbox delivery alone. Exact audit-loss acceptance is an operator policy boundary.

### REC-09: bounded refusal and recovery

Distinguish capacity exhaustion, unavailable authority, invalid/stale credentials,
and uncertain committed effects. Capacity pressure before work is admitted does
not close the service or require restart. A failed read-only preflight does not
establish an uncertain mutation. Refuse the affected request and retry later
within bounds. A potentially committed mutation still requires its own outcome
handling. Do not clear unknown durable work by age or reopen a closed guard
without establishing its safety condition.

### REC-10: observability without secrets

Use stable reason codes and bounded-cardinality scope/component metrics for
admission refusal, cache loss/reset, outcome uncertainty, audit backlog/gap and
recovery readiness. Correlate operator actions and business receipts. Do not log
tokens, secrets, connection URLs, arbitrary database errors or full recovery data.
Fail-closed behavior must be distinguishable from healthy service operation.

### REC-11: managed services

Require the DB and cache capabilities actually used by the implementation.
Application caches do not require Redis AOF, WAITAOF, OS access, an ACL file or
preservation of Redis run_id across restart. Removing those requirements is safe
only after all enabled security-state families satisfy REC-04. A provider's
durability/consistency promise is a deployment premise, not an application proof.

### REC-12: acceptance and performance

The current PR owns functional behavior, practical threat regressions and checks
of the actual model used by the changed code. Known exploitable defects are not
deferred as proof work. Task 1b owns remaining standards applicability/refinement;
Task 3 owns full composition, independently qualified suppliers and high precision
or production-scale campaigns. Neither a handoff nor a model proof establishes
product conformance. The target remains 10,000 HTTP requests/s with ordinary API
p99 at most 200 ms; it is not a measured result. The previous independent-control
capacity and reconstruction-throughput budgets are withdrawn.

## State-family migration inventory

These are required dispositions, not a statement that the Redis backends have
already been migrated. S identifiers refer to the retained
[source inventory](recovery-redesign-inventory.md).

| Families | Loss contract and implementation requirement |
| --- | --- |
| S01 DPoP, S06 request-object JTI, S19 client assertions | Durable uniqueness through the full acceptance horizon, or verified invalidation of every still-acceptable proof/assertion; missing negative history never means unused |
| S02 PAR, S04 codes, S08 device codes, S09 device CSRF, S11 local CSRF, S13 step-up, S16 upstream state, S17 logout relay, S18 nonce | Positive capability state: absence rejects/restarts the flow; consume is atomic; restored or partially lost state must not resurrect consumed capabilities |
| S03 tokens/refresh/revocation, S07 auth sessions, S14 management sessions, S20 OIDC sessions | Loss invalidates affected credentials; root, refresh-family and revocation dependencies must be complete; logout delivery also has external-effect obligations |
| S05 JWKS | Split refetchable key cache from security history/policy such as changed-key reuse and refresh exclusion; authenticate a refetch and preserve applicable key-policy constraints |
| S10 device, S12 local/source, S15 management limits | Durable security budgets or conservative refusal until the original bounded window expires; a reset cannot buy attempts |
| P01–P10/P13 application SQL | Transactional source of truth; WAL/PITR operated by the DB owner; source-dependent budgets and continuation expiry remain enforced |
| P11 ownership/import, P12 lifecycle | Retain domain ownership and lifecycle/fencing; retire generic per-operation observation/seal history after consumers are migrated |
| B01–B09 background and detached work | Bounded ownership, same durable authority, stable external-effect identity; no old-generation worker may resume after restore |

## References

- [PostgreSQL PITR](https://www.postgresql.org/docs/18/continuous-archiving.html): backup/WAL restoration and selected historical targets.
- [PostgreSQL transactions](https://www.postgresql.org/docs/18/transaction-iso.html): isolation and retry obligations.
- [RFC 9449 section 11.1](https://www.rfc-editor.org/rfc/rfc9449.html#section-11.1): proof replay protection and acceptance horizons.
- [OWASP logging guidance](https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html): attributable events, protection and sensitive-data exclusion.
