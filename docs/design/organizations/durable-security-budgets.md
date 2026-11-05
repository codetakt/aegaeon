# Durable authentication security budgets

Last updated: 2026-11-05

Status: active plan

Owner: Engineering

Audience: implementers, reviewers, operators

Device verification, local login/source and management login attempt budgets use
the selected application PostgreSQL database. Losing Redis keys or constructing
a new runtime cannot grant additional attempts. This increment addresses S10,
S12 and S15 of the [recovery migration](recovery-workplan.md); other Redis security
families and the legacy witness still require migration.

## Transaction and failure behavior

`runtime_security_budgets` contains a namespace, a hashed bucket, an attempt count
and expiry. `consume_runtime_security_budget` locks at most 16 distinct buckets
in sorted order and charges all of them only if all permit the attempt. The
normal limit remains 10 attempts per 60 seconds. Separately configured source
limits use their existing limit and the same window. Namespaces retain the
Environment and flow boundary; raw account names and source addresses are not
stored in the budget table.

Expiry uses the DB clock. A backward clock step can extend refusal; it does not
reset an unexpired budget. Concurrent requests share the same decision. A failed
or missing DB reply refuses authentication and never falls back to Redis or
process-local counters. A retry may consume another attempt if the first result
was lost; it cannot reclaim a committed charge. Each call has a five-second query
deadline and retains the existing connection cleanup owner.

Expired records do not authorize anything. Background cleanup removes at most
4,096 expired rows per batch, at most 256 batches per namespace per pass, with
a 15-second work deadline and separately bounded connection cleanup. It skips
locked rows and detects remaining backlog. Active records are retained. See the
[shared cleanup bounds and metrics](durable-replay-decisions.md#admission-and-expiry). Cleanup lag affects storage capacity and must be monitored; no
unmeasured storage/throughput bound is claimed. There is no global completion
lock or independent operation journal in this budget implementation.

## Upgrade and restoration

Apply migrations through `20261105021000_runtime_security_catalog` (including
`20261105000000_runtime_security_budgets`) under the normal stopped
runtime schema-upgrade procedure. **Before enabling the new backend, keep all
old authentication workers stopped for at least the old 60-second budget window.**
This prevents switching from a live exhausted Redis budget to an empty SQL budget.
Do not perform a rolling transition with old Redis-backed workers still serving.
The wait is a deployment prerequisite; this migration does not implement a
cross-version supervisor or infer that workers have stopped.
The [replay migration](durable-replay-decisions.md) requires a longer proof horizon
when those families also change; 60 seconds alone does not cover that upgrade.

The runtime role needs EXECUTE on the consume function and SELECT, INSERT, UPDATE
and DELETE on `aegaeon.runtime_security_budgets`. The function uses invoker rights.
The existing disposable production fixture grants ordinary table privileges to
its runtime role; independently restricted deployments must update their grants.
Missing permissions refuse budget checks. The three former rate-limit Redis URLs
are no longer consulted by production constructors and cannot select a fallback.
The Redis implementation remains for existing isolated regression fixtures.

Authorized PITR restores these rows along with credentials and policy at the
selected point. Audit does not reapply post-target attempts or revocations.
Ordinary cache loss, process restart and reconnection do not reset SQL budgets.

## Verification boundary

Direct PostgreSQL tests exercise simultaneous workers, reversed/duplicate bucket
order, refusal without partial charges, namespace separation, facade recreation,
expiry, bounded cleanup, invalid input, missing function and transaction outcomes.
They do not prove a managed provider's durability or simulate a network-level
lost COMMIT response. The current PR retains integration/cancellation checks;
Task 3 retains provider and production-scale qualification.
