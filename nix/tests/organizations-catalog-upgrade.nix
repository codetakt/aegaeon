# One linear pre-PR-to-Organizations upgrade, preserved data and fresh schema equivalence.
{ pkgs }:
let
  check =
    baseline:
    pkgs.runCommand "aegaeon-organizations-catalog-upgrade"
      {
        nativeBuildInputs = [
          pkgs.postgresql_18
          pkgs.atlas
          (pkgs.python3.withPackages (p: [ p.psycopg ]))
          pkgs.coreutils
        ];
      }
      ''
        set -euo pipefail
        mkdir -p "$out" "$TMPDIR/socket"
        export PGHOST="$TMPDIR/socket" PGUSER=postgres PGDATABASE=postgres
        export PGOPTIONS='-c statement_timeout=10000 -c lock_timeout=5000'
        initdb -D "$TMPDIR/data" -U postgres --no-locale --encoding=UTF8 --auth-local=trust --auth-host=reject > "$out/initdb.log"
        trap 'pg_ctl -D "$TMPDIR/data" -w -t 20 -m immediate stop >> "$out/stop.log" 2>&1 || true' EXIT
        pg_ctl -D "$TMPDIR/data" -l "$out/postgres.log" -w -t 20 -o "-k $PGHOST -c listen_addresses=" start
        timeout 180 python3 ${../../tests/organizations/catalog_upgrade.py} \
          --migrations ${../../db/migrations} --schema ${../../db/schema.sql} \
          --provision ${../../scripts/operations/provision-subject-ownership.sql} \
          --runtime-provision ${../../scripts/operations/provision-organizations.sql} \
          --activation ${../../scripts/operations/activate-organizations-runtime.sql} \
          --baseline ${baseline} --output "$out"
        pg_ctl -D "$TMPDIR/data" -w -t 20 -m fast stop > "$out/stop.log"
        trap - EXIT
      '';
in
check ../../tests/organizations/catalog-upgrade-baseline.json
