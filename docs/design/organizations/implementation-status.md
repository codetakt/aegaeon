# Organizations Implementation Status

Last updated: 2026-11-05

Status: current implementation baseline

Owner: Engineering

Audience: implementers, reviewers and operators

## Current implementation

The candidate implements Organizations domain configuration, memberships, roles,
invitations, delegated administration, selected-organization authorization,
management APIs, audit delivery and nonsecret snapshots. Enablement remains
explicit and disabled by default. The adopted recovery responsibility replaces
the predecessor independent control database and per-request recovery journal.

PostgreSQL is the authority for domain facts, ownership, credentials, revocations,
operation receipts, audit/outbox data and security state. Codes, grants, replay
protection, attempt budgets, sessions, nonce state and JWKS trust decisions use
current durable state. Coupled code/OIDC/token publication is one transaction;
missing positive authority cannot become an authorization fallback. In-memory
projections are disposable. No production security-store Redis, AOF, WAITAOF or
Redis process-identity requirement remains.

The mandatory runtime binds selected deployment/generation and Environment
inventory. Every physical SQL connection validates that selection and holds a
shared lifecycle fence across transactions. Activation takes an exclusive fence
and refuses while current connections remain. This database-local mechanism does
not fence a separate old cluster: operational exclusion of old writers is a
required restore precondition. Ordinary reads do not consult an independent
mutation journal. Maintenance CLIs take the same exclusive fence and check the
selected generation.

Authorized PITR selects historical passwords, client secrets, keys, revocations
and ownership. Audit never silently reapplies later changes. A new runtime
generation invalidates prior transient credentials. External JWT assertions and
Request Objects wait for the bounded acceptance horizon; DPoP resumes with a
fresh generation/role nonce. Deadlines survive same-generation restart. Empty
restored data does not prove first-ever installation. Only an explicit operator
assertion, with no selected predecessor or Environment, can omit the initial wait.

See the [responsibility rules](recovery-responsibilities.md),
[generation contract](runtime-generation.md) and [restore runbook](restore-runbook.md).
Predecessor control/recovery modules and tooling remain only as historical test
fixtures; their successful runs are not acceptance evidence for this replacement.

## Migration and resource limits

The PR adds one transactional migration to the unchanged 24-file published
baseline. Tests exercise populated upgrade, preservation of existing identity,
password, attribute and LTI data, fresh/schema/dump correspondence, a late DDL
failure with complete rollback, and ordinary retry. Intermediate development
schemas are not supported upgrade targets. See [migration composition](migration-composition.md).

Bounded request admission, reserved revocation SQL capacity, aggregate response
payload accounting, indexed cleanup and bounded atomic administration are
implemented. The pool reserve is included in the configured total. Response
charges remain attached to byte clones until transport releases them. Oversized
browser/OIDC bulk operations fail atomically. See [resource design](recovery-performance.md).

The target is 10,000 HTTP requests/second and ordinary API p99 at most 200 ms.
Measurement is explicitly outside this round. Resource bounds are neither a
throughput result nor a total RSS or latency guarantee.

## Validation and remaining release conditions

Direct PostgreSQL, native HTTP, actual distribution startup/shutdown, maintenance,
model and source checks are recorded in the [workplan](recovery-workplan.md).
Results from successive artifacts retain their original boundaries; overlapping
inventories are not summed. Earlier fixture/tool failures and zero-test filters
remain in private evidence and are not passing checks.

PR #295 remains Draft at its published predecessor. Local completion does not
publish a candidate, run hosted CI, qualify an AWS deployment, approve production
activation, enqueue or merge. Final published-candidate CI, review and signature
requirements remain. These are admission conditions, not an instruction to resume
unrelated paused work.

## Formal evidence and release meaning

The selected-state Tamarin diagnostic checks restored-credential reachability and
old-session refusal. The external-proof model checks nonce/horizon behavior and
negative controls. Kani checks the actual production SQL-pool partition arithmetic.
Retained predecessor Kani results remain tied to their test-only source; they are
not relabeled as current production proofs. F\* invariant/expiry models were
reviewed, with native SQL refinement and composition explicitly handed off.

[Security assessment and REC-H01–05](recovery-security.md) assign standards mapping
to Task 1b and rigorous composition, provider/custody qualification and high
precision testing to Task 3. Known implementation defects stay in this PR; those
handoffs do not defer a discovered defect. Unrelated paused proof and measurement
campaigns remain paused. The frozen 8,805-obligation baseline is unchanged; new
product/composite discharge remains zero.

[Historical component checkpoints](implementation-history.md) retain their original
candidate meanings and must not be interpreted as today's runtime requirements.
