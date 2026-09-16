# Launch against a matching migration inventory

Last updated: 2026-09-16

Status: current implementation baseline

Owner: Operations

Audience: operators, maintainers

## Supported entrypoints

On Linux, `nix build .#server-distribution` produces guarded `aegaeon-server`
and `aegaeon-management-init` entrypoints. The OCI image from
`nix build .#docker-image` uses that server entrypoint by default. Keep the
packaged entrypoint when supplying server arguments, including host and port.
An entrypoint override that directly invokes the underlying executable bypasses
this protection and is outside the guarded deployment path.

```bash
nix build .#server-distribution --out-link result-distribution
# Supply the documented runtime configuration, including AEGAEON_DATABASE_URL.
./result-distribution/bin/aegaeon-server --host 127.0.0.1 --port 8080
```

The launcher consumes the same `AEGAEON_DATABASE_URL` as the server. It requires
permission to read the Atlas revision table and makes no database writes. Atlas
migration execution remains a separate operator action. Apply migrations before
running the guarded management initializer; initialization does not migrate an
empty database.

Before connecting, the launcher requires a `postgres://` or `postgresql://` URL
with an explicit host and no fragment. Non-loopback destinations require exactly
one `sslmode=require`, `sslmode=verify-ca`, or `sslmode=verify-full` parameter.
The check also covers a destination override in a `host` parameter; a loopback
URL cannot permit an insecure remote connection. A local Unix socket may be
selected with a `host` parameter while keeping an explicit `localhost` URL
authority.

The launcher and server use different PostgreSQL drivers. To keep their selected
database and schema consistent, the launcher refuses `hostaddr`, service files
(`service` or `PGSERVICE`), and the environment defaults `PGHOST`, `PGHOSTADDR`,
`PGPORT`, `PGDATABASE`, `PGUSER` and `PGOPTIONS`. Unset these variables and supply
the settings explicitly in the URL. Connection options `host`, `port`, `dbname`,
`user` and `options` must be nonempty and unique. Multiple hosts and database
paths beginning with `//` are unsupported. Encode query spaces as `%20` and
literal plus signs as `%2B`; the drivers interpret unescaped `+` differently.
These restrictions apply to the guarded packages. Refusal occurs before any
database connection and does not include credentials or the supplied URL.
The validated strong `sslmode` is passed explicitly to the driver so libpq's
deprecated `requiressl` option cannot downgrade it.

`nix build .#server` retains the underlying development/build package. Existing
bare executables and historical images do not acquire protection from this
change. In particular, a historical executable may still accept a newer database
when run directly. Do not deploy those executables directly against an upgraded
database.

## Admission and process behavior

Each entrypoint has an immutable Nix manifest in `share/aegaeon/`. Packaging binds
its absolute executable path and SHA-256 to the release's `db/migrations/atlas.sum`.
The launcher opens a read-only, regular executable without following its final
symlink, hashes the held file descriptor, checks the database, and executes that
same descriptor. Arguments, process identity, signals, and executable exit status
are preserved after admission. A refusal exits with status 78 before invoking
the executable and reports a fixed message without raw driver diagnostics.

The migration table is located in the current schema, `public`, or `aegaeon`, in
that preference order, matching the server preflight. Admission requires every
packaged revision exactly once and rejects unknown revisions, missing revisions,
duplicate numeric/file-stem aliases, and failed or partial migrations. The head
description and checksum must match the existing server compatibility rules:
legacy file stems and nullable head checksums remain supported. A checksum, when
present, must match the packaged head file or inventory checksum, with or without
the `h1:` prefix.

The complete-ledger requirement is deliberately stricter than the underlying
server preflight, which requires the head and checks all recorded entries but
does not require every historical row. A database bootstrapped by recording only
the head revision is not accepted by this launcher. Restore a matching,
Atlas-managed database; do not fabricate missing metadata to bypass admission.

Packaged migration filenames use a 14-digit revision, an underscore, a nonempty
description containing only ASCII letters, digits and underscores, and `.sql`.
This is stricter than the underlying server parser. The `schema-guard` check
parses the repository's actual `atlas.sum`, so a new filename outside this
packaging grammar fails validation before release.

## Upgrade and rollback

Before applying an incompatible migration, stop runtime instances and prevent
automatic restarts of the previous deployment. Retain the previous guarded
distribution, its matching database backup, runtime configuration, encryption
keys, and token/session-store state. After migration, start the distribution
whose manifest matches the applied inventory. The previous guarded distribution
must refuse the upgraded database. For rollback, restore the matching earlier
state into a separate cluster and use the corresponding earlier distribution.

For a historical executable that predates guarded packaging, a maintainer can
use `nix/schema-guarded-launch.nix` with the fixed historical package and the
`atlas.sum` from its exact source revision. This is a new distribution artifact:
verify its correspondence and startup behavior before deploying it. Pairing an
old executable with a new inventory is not a valid package. The launcher trusts
the build's executable-to-inventory binding; it cannot infer that binding from
an arbitrary ELF file.

This check does not attest physical schema, authenticate metadata or database
administrators, validate migration file semantics, or prevent migrations after
startup. Trusted immutable packaging, the database destination and administrators,
and deployment control over entrypoints remain prerequisites. Startup success is
not OAuth, recovery, or whole-deployment acceptance.

## Validation

```bash
nix build .#checks.x86_64-linux.schema-guard --print-build-logs
```

The check runs admission counterexamples and launches immutable test executables
through the production wrappers against a private PostgreSQL cluster. It covers
old/new inventories, unavailable and malformed metadata, search-path selection,
both entrypoints, argument and exit-code propagation, and PID/signal preservation.
It does not replace migration tests with actual release binaries and actual
Atlas migrations, or inspection of the final OCI entrypoint.
