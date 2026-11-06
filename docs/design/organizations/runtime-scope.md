# Organizations runtime and management scope

Last updated: 2026-11-05

Status: active plan

Owner: Engineering / Verification

Audience: runtime, management and recovery implementers

The current runtime uses the [selected database generation](runtime-generation.md)
and [recovery responsibility rules](recovery-responsibilities.md). Predecessor
parent/child control slots, pending journals and paired store seals are test-only.

## Deployment and Environment scopes

One issuer runtime selects one Environment and issuer. Global management also
owns bootstrap, session and topology operations, and routes can target other
Environments. Deployment ownership therefore differs from Environment ownership.
A deployment capability cannot become an Environment capability merely by
accepting a request-supplied ID. The immutable configured inventory determines
which Environment/issuer pairs this runtime may use.

These capabilities establish execution ownership and resource limits. Every
operation still authenticates its caller and checks current user, client, team,
organization and original-grant authority in its actual transaction. There is no
administrator bypass, disclosure grant or automatic membership.

Management acquires deployment ownership before body/database work. Targeted
routes authenticate and check Team visibility before resolving their selected
Environment. Unknown and unselected targets have the same opaque refusal after
authentication. Global session, Team, Tenant and directory operations do not borrow
the issuer's Environment. A newly created Environment needs explicit selection in
the runtime configuration before its issuer can serve.

## Work ownership and failure

Physical PostgreSQL sessions validate the selected generation and retain a shared
lifecycle fence. The application reuses those sessions without an independent
per-request recovery transaction. Ordinary, reserved revocation and snapshot
admission are bounded. Revocation has reserved physical connections within the
total configured pool size. Capacity exhaustion before work starts refuses the
request and does not permanently close the runtime.

An admitted execution retains its connection and worker ownership through caller
cancellation, commit/rollback and cleanup. A lost reply is not proof of rollback;
existing business receipts resolve retries. There is no generic independent
completion journal. PostgreSQL owns transaction durability, and the application
owns its domain invariants and idempotency. Ordinary reads do not union later
history into the selected state.

Finite responses are bounded before publication. Streaming and completed response
payloads retain their shared byte-budget charge until transport clones release
them. See [resource bounds](recovery-performance.md) for the distinction between
payload accounting, deployment connection limits and total process memory.

## Startup, background work and shutdown

`aegaeon-organizations-server` requires protected version 2
`AEGAEON_ORGANIZATION_RUNTIME_CONFIG`, including for a disabled Organizations
policy. Its primary URL must match bootstrap selection; verified CA/hostname TLS,
restricted SQL privileges, schema and Environment/issuer checks precede serving.
Security state uses PostgreSQL. Redis and a separate control database are not
required. The schema launcher also accepts only the current configuration version.

Issuer configuration changes retain the existing graceful restart contract.
Background cleanup, currentness checks and delivery use the selected runtime and
bounded ownership. Shutdown closes admission, drains owned work and closes both
ordinary and reserved SQL pools. Health is process liveness; readiness is not a
certificate of provider durability or a proof of global service availability.

Ordinary restart retains the selected generation and proof deadlines. Controlled
restore/reset excludes all former writers, activates a fresh generation and
starts disposable state from the selected database. Offline ownership/import
maintenance holds an exclusive SQL session fence, excluding online workers. See
the [restore runbook](restore-runbook.md) for audit gaps, external effects and
operator prerequisites. A separate former primary requires operational fencing;
a PostgreSQL advisory lock cannot span independent clusters.

## Evidence boundary

Actual local tests cover generation/pool replacement, privilege refusals, bounded
admission, reserved SQL progress, cancellation, domain receipt convergence,
external-proof deferral, nonce single use, offline maintenance exclusion and the
packaged server's startup/restart/signals without Redis or a control supplier.
Predecessor TLS/control fixtures retain their original scope. They are not proof
of this replacement. Managed-service qualification, full protocol refinement and
performance measurement remain separate Task 1b/3 work.
