# Organizations independent control-store reference service

Last updated: 2026-11-02

Status: historical record

Owner: Engineering / Operations

Audience: implementers, operators and security reviewers

This configuration implements one part of ORG-D02, contributing to
ORG-R02/R19/R21/R24, ORG-G02/G10/G11/G12 and ORG-P02/P08/P11/P12/P13/P14/P15.
It does not enable Organizations or qualify production supply. Runtime assembly,
all writers, activation, actual restore and composed acceptance remain required.

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

## Placement and custody

Import `nixosModules.organizations-control-store` from the pinned Aegaeon flake
on a dedicated control host, outside
the primary and token-store host's restore domain. The control host has a
separate persistent data mount, administrator credentials and backup custody.
Primary/token restore operators receive neither control-host login nor volume,
database-owner, backup-restore or hypervisor privileges over this host. Runtime
and maintenance logins are separate non-owner PostgreSQL principals. The normal
runtime cannot perform maintenance, schema changes or direct table operations.

The module selects PostgreSQL 18 from the host's pinned Nixpkgs input. The
repository check uses the repository-pinned Nixpkgs and PostgreSQL package; a
deployment must retain its actual input/package identity as a supplier condition.
TLS and SCRAM are required; only explicitly supplied source networks, database
and logins are admitted. Plaintext network access and other local/network logins
are rejected. Local peer access for the dedicated host's PostgreSQL administrator
is a provisioning responsibility, never the application connection.
The host firewall must allow the selected PostgreSQL port only from the declared
networks. The module does not open a global firewall port.

The host and mount separation must be checked in the actual deployment. A
different PostgreSQL system identifier, a path string or successful Nix evaluation
does not establish independence from VM/disk snapshots or administrator rewrites.
Control-host rollback and loss have no automatic recovery that may resume old
authority. Preserve evidence, close admission and use the separate reconciliation
contract; do not restore an old control backup and call it current history.

## Explicit provisioning and fail-closed restart

The service deliberately requires an already provisioned cluster. First install
the pinned PostgreSQL package, mount the dedicated volume, initialize a fresh
cluster as its dedicated local administrator and apply the unmodified witness
schema v1 through v16 in order to `aegaeon_organization_control`. Versions 15 and
16 require drained, fenced authorities; see [store continuity](store-continuity.md)
for the matching primary migration and preparation requirements. Provision only
the named runtime or maintenance group membership to each SCRAM login, following
the schema's restrictions. Retain the exact catalog and privilege checks from
the existing `Control::checked` implementation. Do not grant the owner role or
direct table access to service principals.

Record the cluster's actual system identifier from `pg_controldata` in an
independently retained, root-controlled file outside the control data volume.
Supply certificate, key and identity paths explicitly; systemd passes their
contents as service credentials. Do not put a secret value in a Nix expression,
the Nix store, shell history or public receipts. This operational identity file
is a startup identity guard, not an epoch or an acceptance receipt.

Before the upstream NixOS service can reach its automatic `initdb` branch, the
module requires PostgreSQL version 18 and an exact match to that retained cluster
identity. A missing mount, missing `PG_VERSION`, missing anchor, wrong cluster or
wrong major version stops startup. Restart never creates an empty replacement
control database. The existing application-side live catalog, privilege,
durability and observed-store checks remain mandatory after connection.

Record the provisioning and qualification recipe, selected host/volume/provider,
certificate chain, credentials' role assignments, package/source hashes and
backup/restore access policy in the private deployment record. The record must
also explain the allowed clock/RNG, power-loss durability and reply-size/resource
assumptions. Storing a receipt does not prove its statements or grant admission.

## Bounded service and remaining acceptance

The reference service enables fsync, full-page writes and synchronous commit.
Connections are limited to 96; statement, lock and idle-transaction limits are
10, 5 and 10 seconds. Startup/stop have 30-second systemd limits. SQL statements
and bound parameters are excluded from ordinary error logs. These service limits
must be composed with per-Environment admission slots, observed work deadlines,
all application connections and reserved revocation capacity before declaring a
supported maximum configuration. Exhaustion must fail closed.

Required acceptance includes successful explicit provisioning and restart with
retained authority/history; runtime/maintenance separation; incorrect TLS,
privileges and cluster identity; missing/empty/replaced volumes; primary/token
restore while control records remain current; control outage and full capacity;
and normal recovery without old grants or tombstoned identities returning.
Execution must bind the real service, SQL catalog, client, artifact and deployment
configuration. Nix evaluation or a startup-guard test alone does not close D02.

`nix build .#checks.x86_64-linux.organizations-control-store` evaluates the real
NixOS module and tests the generated service pre-start against an actual private
PostgreSQL cluster. It covers accepted initialization state, prohibited
configurations, missing/changed identity and version, and refusal before the
upstream automatic initialization branch can remove existing configuration.
The same check also provisions schema v1–v11 into a separate actual PostgreSQL
cluster, installs the generated configuration and exercises TLS `verify-full`,
SCRAM, restricted logins, runtime/maintenance separation, outage refusal and
restart with retained fenced authority. In this sandbox the two TLS credential
paths are redirected to private fixture files and the client is `psql`. It does
not execute systemd credential delivery/mount assertions, the Rust connector,
active epoch transitions or deployment backup/restore custody. Those remain
separate acceptance conditions; neither this check nor its receipt enables serving.

For global/cross-Environment management, startup and recovery still follow D01:
one Environment's owner cannot authorize global operations or another target.
Do not mount the dispatcher before that contract and D03–D06's joint runtime
boundary are implemented. See [import and restore](import-activation.md) and
[observed connectors](observed-connector.md).
