# Database (PostgreSQL + Atlas + SQLx)

Last updated: 2026-07-07

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

- This project uses Atlas for migrations. Do not add SQLx migrations (`sqlx migrate`) to avoid
  having two migration systems.
- PostgreSQL is required for `aegaeon-server`. Provide `AEGAEON_DATABASE_URL` for the server
  runtime. `DATABASE_URL` is used by local database tooling/examples only and is not a server
  runtime fallback. `AEGAEON_DB_ENABLED` was removed; omit it. Any configured value fails closed.
