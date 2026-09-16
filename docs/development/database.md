# Database (PostgreSQL + Atlas + SQLx)

Last updated: 2026-09-16

Status: current implementation baseline

Owner: Engineering

Audience: contributors, maintainers

This repository uses:

- PostgreSQL **18.1** (local/dev via Docker)
- **Atlas CLI** for schema migrations (versioned migrations)
- **SQLx** for Postgres access in the Rust server

## Quick start (local)

1) Start the local Postgres service:

```bash
docker compose -f tests/docker/docker-compose.yml up -d postgres
```

If port `5432` is already in use, override it:

```bash
AEGAEON_POSTGRES_PORT=15432 docker compose -f tests/docker/docker-compose.yml up -d postgres
```

1) Point tooling to the database:

```bash
export DATABASE_URL='postgres://aegaeon:aegaeon@localhost:5432/aegaeon?sslmode=disable'
```

If you used a different port, update `DATABASE_URL` accordingly.

1) Apply migrations (Atlas):

```bash
atlas migrate apply --env local
```

1) For local protocol/performance smoke tests, create the active management
   environment/configuration and runtime keys through the management API or
   `aegaeon-hosted-bootstrap`. Then use that environment issuer host as
   `AEGAEON_RUNTIME_ISSUER_HOST`.

## Layout

- `db/schema.sql`: desired schema state (source of truth)
- `db/migrations/`: versioned migrations generated/applied by Atlas
- `atlas.hcl`: Atlas project configuration

## Notes

### Startup schema checks and upgrades

The server and management initialization tools check Atlas revision metadata
against the migration inventory compiled into their binary. Startup requires the
compiled migration head and rejects unknown revisions anywhere in the table,
including newer revisions whose `executed_at` timestamp predates the known head.
Duplicate numeric/file-stem aliases and failed or partial recorded migrations
also fail the check. The existing head description/hash checks and legacy
numeric/file-stem formats remain supported.

This is a startup check of migration metadata. It does not attest the physical
schema, authenticate database administrators, or prevent a migration applied
after startup. Stop all runtime instances before applying an incompatible schema
update. Do not edit Atlas metadata to make an incompatible binary start.

Older binaries that only look up their own head can still start against a newer
database. Updating the current binary does not repair those older executables.
Deployment controls must prevent starting such binaries on an upgraded database.
The Linux [guarded distribution](../operations/schema-guarded-launch.md) binds
the executable to its complete migration inventory before launching it; the
OCI image uses that entrypoint by default. Historical bare executables require
separate guarded packaging and validation before use in this deployment path.
For rollback, restore the matching pre-upgrade database, configuration, encryption
keys and token/session-store state before starting the matching older binary.

The PostgreSQL regression tests create and remove uniquely named schemas. With a
dedicated test database configured, run:

```bash
nix develop -c cargo test -p aegaeon-server --lib db::schema_revision_tests -- --ignored
```

They also run in the PostgreSQL lane of `server-container-integration`.

### Tooling and configuration

- This project uses Atlas for migrations. Do not add SQLx migrations (`sqlx migrate`) to avoid
  having two migration systems.
- PostgreSQL is required for `aegaeon-server`. Provide `AEGAEON_DATABASE_URL` for the server
  runtime. `DATABASE_URL` is used by local database tooling/examples only and is not a server
  runtime fallback. `AEGAEON_DB_ENABLED` was removed; omit it. Any configured value fails closed.
