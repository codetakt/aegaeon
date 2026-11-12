# Actual fresh/main-to-LTI SQL, retained attributes and old-checker controls.
{ pkgs }:
pkgs.runCommand "aegaeon-lti-catalog-upgrade"
  {
    nativeBuildInputs = with pkgs; [
      postgresql_18
      atlas
      (python3.withPackages (p: [ p.psycopg ]))
      coreutils
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
    timeout 180 python3 ${../../tests/lti/catalog_upgrade.py} \
      --migrations ${../../db/migrations} --schema ${../../db/schema.sql} \
      --provision ${../../scripts/operations/provision-subject-ownership.sql} \
      --management-provision ${../../scripts/operations/provision-management-authority.sql} \
      --baseline ${../../tests/lti/catalog-upgrade-baseline.json} --output "$out"
    # SQL assertions are complete. This disposable catalog fixture does not test
    # shutdown durability; wait for actual exit without a final disk checkpoint.
    pg_ctl -D "$TMPDIR/data" -w -t 20 -m immediate stop > "$out/stop.log"
    trap - EXIT
  ''
