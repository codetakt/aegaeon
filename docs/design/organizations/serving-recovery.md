# Serving and recovery after Organizations cutover

Last updated: 2026-11-04

Status: historical record

Owner: Engineering

Audience: implementers and recovery operators

This specifies steps 14–16 of [credential cutover](cutover-credentials.md)
for ORG-R18/R19/R21/R22/R23, ORG-G10/G11/G14 and
ORG-P08/P11/P12/P13/P14. The packaged `aegaeon-organization-cutover-validate`
entry implements them with `--start-workers SETTINGS`, using the same config,
native-validation config and retained directory as the preceding activation.
This component does not establish full restoration completion, deployment
qualification or proof discharge.

## Superseded operational design

This page records predecessor behavior and its source-scoped evidence. Its
control-store, paired-seal, generic history-replay and credential-cutover commands
are not shipped or supported by the current implementation. Use the
[current generation contract](runtime-generation.md) and
[restore runbook](restore-runbook.md). Predecessor code retained under test-only
modules is not a production fallback. Historical test results below do not prove
the replacement implementation.

## Responsibility revision — 2026-11-05

The [adopted recovery rules](recovery-responsibilities.md) are the successor
design. The mechanisms and results below describe the existing implementation
and its historical validation, not a requirement to preserve volatile state or
implement application-level WAL/PITR. The [workplan](recovery-workplan.md) tracks
the replacement; legacy guards are test-only after their consumers migrated.

## First start

Before enabling a credential, the root coordinator retains and registers one
start intent. It binds the completed activation receipt, exact startup manifest,
settings, distribution artifacts, selected runtime identities, and fresh parent
and child operation IDs reserved for recovery fencing. The full selected
Environment inventory must match the active control selection.

Only the selected control-runtime and primary-runtime SQL roles and the fresh
token role become usable. Their OIDs, privileges, verifiers and finite password
expirations remain unchanged. Maintenance identities and retired identities stay
disabled. Initial token enablement still requires the exact empty replacement
store; that condition must never be imposed on recovery after accepted writes.

The launcher supplies every shared runtime store requirement from the selected
TLS token endpoint, including replay, authorization-code and management-session
stores. The checked inventory includes conditional requirements without enabling
their features. A CI comparison with the native requirement inventory detects
omissions. The launcher rejects missing, additional or redirected store settings
and supplies `SSL_CERT_FILE` from the hash-bound `root-cert` credential copy.
This CA bundle must cover the deployment's required native-certificate consumers;
the launcher does not inherit a caller's alternate trust file or disable TLS
verification. Each store's existing key namespace remains unchanged.

The same invocation starts only the manifest's dedicated system services and
checks their loaded definitions, credentials, process custody and actual bounded
HTTP readiness. Every selected worker must be ready before recording step 15;
the final retained receipt then completes step 16. Readiness proves neither full
protocol conformance nor nonrollback storage custody.

## Interrupted start

An invocation finding unfinished step 14 or 15 performs closure. It never starts
another worker or reenables a credential for that operation. A failed first-start
attempt follows the same closure path. Each selected service is stopped, each
selected runtime credential is disabled, and actual SQL backends and token
clients are drained. Cleanup attempts all independent exclusions even when one
fails, retaining uncertainty rather than reporting completion.

The destination may have accepted work. Closure preserves all primary data,
token contents, permanent ownership, checkpoints and unfinished observations.
It neither compares the destination with the retired source as a prerequisite
for stopping nor restores old data over the destination. It does not clear a
pending owner merely because its process or connection has disappeared.

With service and credential exclusion confirmed, one control transaction fences
the current parent and every selected child using the retained operation IDs.
Exact replay reconciles those same fences. Conflicting selections, missing
inputs, unavailable stores and unconfirmed exits refuse completion.

An aborted operation has a distinct retained receipt and terminal status,
mutually exclusive with successful step 16. It preserves its original step,
receipt chain and uncertainty history. Only confirmed closure releases the
one-unfinished-cutover slot. A forward operation still requires ordinary pending
owner reconciliation and complete current authoritative data/history; marking
an operation aborted grants no admission or restoration authority.

## Replay and custody

A completed-step-16 replay observes the retained inputs and current serving
selection without enabling credentials or starting services. Missing runtime-only
unit fragments can be reconstructed from the exact retained manifest; current
authority, credentials and processes are never repaired by completed replay.
Prepared-only publication checks continue to require no
prior process execution; a separate serving observer handles actual running or
stopped services after the start intent.

Forced coordinator death can leave already authorized serving components alive
until explicit recovery. The registered intent records that uncertainty; it is
not evidence of automatic shutdown. Root protection, service-manager integrity,
independent control persistence and credential exclusion remain explicit supply
conditions. Missing conditions never become an allow fallback.

## Forward recovery contract

Closure does not restart an aborted operation. Retain its directory and journal
unchanged. The current source is the destination that accepted work, never the
primary retired by the preceding cutover. Use the ordinary runtime-recovery
operator against the current control, primary and token identities, the closed
worker inventory, and the exact current fence and state digest. Its excluded
principal inventory must include the current renamed runtime identities. A
missing worker is not evidence that its unfinished owner can be cleared.

After independently confirming exclusion, runtime recovery reconciles pending
owners and retains their original observations. Obtain the new fenced inventory;
the digest from before pending reconciliation is no longer current. A new full
backup/current-state comparison must include all accepted writes and current
authority history. Supply another inactive destination and a fresh empty token
store, unused replacement principal names, a new cutover operation, a new private
directory and dedicated new workers. Run preparation, native validation, epoch
preparation, startup publication, activation and serving start through their
ordinary entries. No earlier comparison, epoch or successful readiness receipt
substitutes for these checks. Preserve old operation IDs, associations and data.

The required acceptance journey demonstrates that new authenticated work succeeds
after this second cutover and that the earlier accepted organization and pending
recovery history survive. It rejects an actual pre-write backup and stale recovery
inputs. Two Environments run through this sequence on four independent SQL
clusters and three TLS Redis instances. The old session is rejected by the new
token store. The original operator's capabilities remain unchanged; reading the
restored organization requires an explicit reconciliation grant. The preceding
aborted operation and private receipts remain unchanged. Source-unavailable
restoration is a distinct contract requiring independently current evidence.

## Verification boundaries

The required service integration runner exercises two actual Environments with
the distributed native server and selected-worker launcher. Cases cover normal
readiness and authenticated writes, process death after one SQL enablement,
death after an accepted organization write and an unfinished runtime owner,
and loss of the final successful reply. The interrupted-write case also loses
the aborted-result reply and reconciles the same receipt without another
closure attempt. It checks the retained organization, exact pending owner,
complete parent/child fence and excluded identities. Live background generations
are variable; the fixture checks an HTTP-derived lower bound and exact unresolved
owners, rather than treating a zero-work offline fixture as a serving workload.

Separate actual SQL/Redis tests check finite-expiry preservation, retained token
data, aborted journal constraints, migration refusal, role denial, fresh-intent
admission and refusal to reuse an old operation. The old unfinished-operation
predicate remains an executed negative control. Real service tests include
never-started units, whose inactive state needs no `reset-failed` operation.

`cutover_serving.smt2` checks three conditional transition properties: permission
requires the initial retained intent, terminal closure requires complete exclusion
and fencing, and closure preserves accepted data, pending owners and highwater.
It retains witnesses for live authority after coordinator death and lost successful
replies, plus a counterexample for restoring old data during closure. SQL durability,
exclusion observations, service custody and implementation correspondence remain
explicit premises. This finite model and the component fixtures are not a new
atomic or composite proof discharge. The complete forward service journey checks
implementation and fixture correspondence. Source-unavailable restoration,
deployment qualification and full formal composition remain separate.
