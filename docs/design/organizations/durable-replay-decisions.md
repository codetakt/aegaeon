# Durable replay decisions

Last updated: 2026-11-05

Status: active plan

Owner: Engineering

Audience: implementers, reviewers, operators

Production DPoP and client-assertion replay decisions now use the application
PostgreSQL database. This addresses S01 and S19 of the
[storage migration](recovery-storage-migration.md). JAR replay and code/grant
publication remain a separate atomic migration; their existing guard remains.

## Admission and expiry

`runtime_replay_entries` holds an Environment/surface namespace, a SHA-256 digest
of length-delimited proof identity, and expiry. It contains no raw proof, client
secret or event stream. `record_runtime_replay` performs a single atomic insert
or replacement of an expired row. Only one concurrent use succeeds. Reopening a
facade or losing Redis cannot remove the decision. Ordinary database durability
and authorized historical PITR retain their distinct meanings.

Cryptographic, claim, audience and nonce checks precede the mutation. A private
prepared value crosses the bounded cryptographic worker boundary; it cannot
expose an accepted binding before the asynchronous DB decision. Freshness is
checked again after storage. A missing reply, DB error or expiry refuses the
request; it does not remove a possibly committed record or fall back to memory.
The existing connection owner retains cleanup on cancellation.

DPoP retention covers the maximum supported acceptance-window change and the
inclusive final second (currently at least 601 seconds). Assertion retention
covers `exp + maximum supported leeway`, including its final accepted second
and later supported leeway increases. This preserves single use while workers
apply a changed policy at different times. Millisecond conversion
rounds upward. Overflow fails closed. Cross-machine clock assumptions and clock
rollback handling remain explicit lifecycle/provider obligations; SQL storage
does not establish clock synchronization.

Each SQL operation has a five-second query deadline. Cleanup removes expired rows
in batches of at most 4,096, with at most 256 batches per namespace per pass and a
15-second work deadline starting before acquisition. Owned connection cleanup is
separately bounded; this is not a 15-second total response guarantee. Each batch
releases its row locks and uses `SKIP LOCKED`. The final existence check detects
locked leftovers, including after a short batch. Live rows and other namespaces
are preserved. Fixed-label counters report confirmed removals and complete,
backlog or error outcomes; a backlog also emits a warning.

The count ceiling is 1,048,576 removals per pass, not measured throughput. A
sustained 10,000 DPoP/s stream still requires retention/storage capacity, suitable
cleanup scheduling and load qualification under REC-T11. No scale or latency
result is claimed.

## Upgrade and restore

Apply the ordinary migrations through `20261105021000_runtime_security_catalog`,
including the budget and replay tables. This catalog migration is new and
unpublished; the earlier local budget-only test artifact used a predecessor
catalog name. Previously published migrations are unchanged.

The runtime role needs EXECUTE on `record_runtime_replay` and SELECT, INSERT,
UPDATE and DELETE on `runtime_replay_entries`. Missing permissions refuse use.
The old DPoP/client-assertion Redis URL variables cannot select a production
fallback. Existing Redis constructors remain for legacy regression fixtures.

Do not perform a mixed Redis/SQL rolling upgrade. An empty SQL table cannot stand
in for unexpired decisions made by old workers. The conservative stopped-worker
procedure waits out the complete old proof horizon before enabling new workers:
601 seconds for supported DPoP and at most 3,901 seconds for supported assertions
(3,600-second replay window, 300-second leeway and final inclusive second), under
the stated clock assumptions. The budget-only 60-second wait is insufficient
when upgrading these replay families. A bounded transfer of current unexpired
entries can reduce that outage, but is not implemented or claimed by this change.
REC-T09 owns the concrete deployment procedure and old-worker exclusion.

An authorized PITR adopts the replay rows, credentials and revocations present at
the selected durable point. Audit does not import later replay decisions. Fresh
volatile/session generations and old-worker exclusion are lifecycle obligations,
not an automatic rewrite of the selected historical credential state.

## Evidence boundary

Targeted verification covers concurrent duplicate use, namespace separation,
expiry and bounded cleanup, transaction rollback, unavailable storage, caller
cancellation, and real signed DPoP/client assertions over PostgreSQL. Verification
is in progress; results belong in the [workplan](recovery-workplan.md).
Prepared-value and actual I/O checks do not establish Tamarin/F*/Kani refinement
or provider durability. Task 1b/3 retain the strict correspondence and qualified
scale/provider work described in the [security plan](recovery-security.md).
