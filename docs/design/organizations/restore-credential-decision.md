# Restored durable credential policy

Last updated: 2026-11-05

Status: active plan

Owner: Engineering

Audience: operators, implementers, security reviewers

## Decision REC-D01: selected durable state is authoritative

The user resolved this decision on 2026-11-05. An authorized PITR adopts the
persistent authentication data at the selected point, including passwords,
client secrets, registered keys, credential status and revocations. A password
changed after that point may therefore authenticate a new session after restore.
This is the intended consequence of selecting that database state.

No extra application approval, blanket credential reset or independent current
credential ledger is required. Audit records describe later events; they do not
automatically replay changes or revocations into the restored database. An
operator may separately request a new change after restoration, using the normal
authorized application operation. That is a new operation, not implicit recovery.

The earlier recommendation to disable restored long-lived credentials and the
claim that this required another product decision are withdrawn. Historical
model runs for that proposal remain evidence of the old model only.

## Application responsibilities

- Exclude old workers and connections before reopening the selected authority.
- Discard incompatible caches and volatile sessions, tokens and continuations.
  A fresh runtime/session generation does not change stored passwords or keys.
- Authenticate new sessions against the selected durable credentials and policy.
  A credential revoked at that point remains revoked; a later revocation is not
  silently reapplied from audit.
- Preserve audit visibility, record the restoration and expose known delivery
  gaps. Do not require an audit replay to establish business state.
- Keep atomic consumption, replay protection and security budgets correct during
  normal operation and unplanned volatile loss. Authorized historical selection
  is distinct from an attacker causing a cache miss or choosing an old snapshot.

## Source and verification boundary

`local_credentials/authentication.rs` and `client_registry/client_types.rs`
already verify the selected durable password/client-secret state. Their use of
historical active values after authorized PITR is expected behavior, not a defect.

The existing current-source comparison still prevents intentional historical
PITR. Replacing it requires lifecycle exclusion and volatile-state disposal, not
reconstructing all subsequent durable changes. The work remains tracked in
[REC-T04 through REC-T10](recovery-workplan.md).

`proofs/tamarin/organizations/restore_credentials.spthy` is a finite diagnostic model of
the selected-state policy, old-session exclusion and reachable fresh login. It
does not authenticate operators, prove DB restoration or establish refinement
to the running server. Those implementation boundaries are checked separately.
