# Organizations recovery storage migration

Last updated: 2026-11-05

Status: active plan

Owner: Engineering

Audience: implementers, reviewers

This is the concrete backend direction for REC-T04. It implements the
[responsibility rules](recovery-responsibilities.md), including the selected
[durable credential policy](restore-credential-decision.md). The inventory below
is a migration plan, not a claim that all backends have changed.

## Storage choices

Use current PostgreSQL rows for security decisions. These are ordinary application
state, with expiry and transaction semantics; they are not a change journal,
replay stream or a second database recovery mechanism. Redis may cache a derived
value only when the selected DB state validates its use. A missing or old cached
value cannot establish issuance, unrevoked status or absence of prior use.

A volatile positive record is safe on a miss, but an old replica value can also
reappear after cache failover. Consequently, loss classification must cover both
absence and stale presence. A new Redis process marker cannot prove that consumed
capabilities or revoked roots stayed consumed/revoked. This is why simply removing
the old run_id/WAITAOF guard is insufficient while Redis holds security authority.

| Families | Selected implementation boundary | Required integration checks |
| --- | --- | --- |
| S10/S12/S15 security budgets | PostgreSQL current bucket counts and expiry; one multi-bucket transaction; implemented increment described in [durable budgets](durable-security-budgets.md) | Concurrency, no partial charge, expiry, cancellation, unavailable DB, stopped-worker upgrade |
| S01/S06/S19 replay | PostgreSQL unique namespace/digest until the complete proof acceptance horizon; no Redis-only negative history | Cross-worker replay, committed reply loss, expiry/skew, configuration changes; JAR consumption remains part of authorization-code issuance semantics |
| S02/S04 PAR and authorization code | PostgreSQL current capability and request binding; atomic consumption and grant publication | Competing redemption, missing/stale cache, reply loss, wrong PKCE/client/redirect/DPoP, no partial issuance |
| S03/S07/S14/S20 grants, sessions and logout | PostgreSQL current roots, family status and dependent bindings; derived payloads are caches; logout external work has durable event identity | Root/descendant revocation, rotation race, replay of a revoked family, selected-state PITR and fresh-session recovery |
| S08 device authorization | PostgreSQL pending/approved/consumed state, poll interval and expiry; approval and token issue keep their existing authorization boundary | Concurrent polling/approval, expired/consumed code, duplicate grant publication and limit interaction |
| S09/S11/S13/S16/S17/S18 browser and upstream continuations | PostgreSQL current one-use state where stale presence can authorize; disposable cache misses restart the flow; delivery/reconciliation uses domain outbox state. S09/S11/S17 implementation is described in [durable form/challenge state](durable-form-challenges.md); S13/S18 in [durable upstream continuations](durable-upstream-continuations.md); S16 in [durable step-up](durable-stepup.md) | CSRF/nonce and issuer binding, callback replay, stale presence, timeout/cancel and external-delivery deduplication |
| S05 JWKS | Authenticated key fetch cache plus current durable trust/changed-key policy; cached data never overrides selected registration | Unknown/stale key, changed-key reuse, refresh contention, issuer mismatch and registration change |
| P01–P10/P13 domain data | Existing application transactions/receipts; selected DB is authoritative | Constraint/concurrency/retry and audit/outbox atomicity |
| P11/P12 and B01–B09 lifecycle | Selected durable ownership; lifecycle-only runtime/session generation and operational old-worker exclusion | No authority union, no post-restore deferred write, old-session rejection and reachable new login |

## Integration sequence

1. Move security budgets; keep the old guards while other consumers still rely on
   them. Update migration, startup inventory, cleanup and directly affected tests.
2. Move replay decisions and transactional capability consumption. Keep atomic
   code/grant/session publication intact; a backend substitution must not split
   an existing one-time decision into independent accepting steps.
3. Independently movable form/nonce continuations can move while the atomic
   code/grant group is being prepared. Move session/root/refresh authority and the
   remaining continuations. Validate cached
   content against current durable bindings or read the durable record directly.
4. Replace per-request independent admission, observations, paired seals and
   completion serialization with bounded local ownership and the selected primary
   transactions. Retain domain idempotency receipts and audit/outbox semantics.
5. Replace current-source equality restoration with operator-selected DB activation,
   old-worker exclusion, fresh volatile namespaces and readiness checks. Do not
   import later credentials, memberships or revocations from audit.
6. Remove obsolete Redis persistence/incarnation requirements and operator
   credentials, migrate configuration, then exercise managed-service-compatible
   local fault behavior. Real provider qualification remains separately scoped.

Every stage leaves the application safely closed on unsupported intermediate
states. Completion means the relevant serving path actually uses the new storage;
an unused adapter or model does not close the migration.

## Performance and scope

The budget path uses one DB command and locks only the selected buckets. The
remaining migration must reuse bounded connection pools, keep request work and
cleanup ownership bounded, and avoid any deployment-wide row lock on ordinary
requests. Do not increase concurrency limits before reviewing the actual pool and
worker resources. Test overload refusal and recovery without requiring restart.

The 10,000 HTTP requests/s and ordinary API p99 200 ms objective remains unmeasured.
No connection-count arithmetic or local functional result establishes it. Exact
protocol refinement, whole-product proof composition and qualified high precision
or provider-scale tests remain Task 1b/Task 3 work; exploitable storage/transaction
defects and the required ordinary fault tests stay in the current PR.

The S14 management-session increment is described in [durable management sessions](durable-management-sessions.md); the remaining session/root families and generation activation are still open.

The S07 browser-session increment is described in [durable browser sessions](durable-browser-sessions.md).

## Completed backend selection

All production security/continuation families above now select PostgreSQL under
the current generation. There is no production Redis requirement, AOF/WAITAOF
admission, process run-ID seal or independent control journal. Incremental notes
above are historical checkpoints, not remaining Redis migrations. The remaining
provider and rigorous proof work follows the explicit Task 1b/3 handoff. Current
operations are in the [restore runbook](restore-runbook.md).
