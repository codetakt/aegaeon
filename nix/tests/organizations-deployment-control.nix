# Actual PostgreSQL permissions and parent/child transitions, independently of
# server runtime integration and physical nonrollback supplier qualification.
{ pkgs }:
pkgs.runCommand "aegaeon-organization-deployment-control-tests"
  {
    nativeBuildInputs = [
      pkgs.postgresql_18
      (pkgs.python3.withPackages (p: [ p.psycopg ]))
      pkgs.z3
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
    createdb baseline
    for version in 1 2 3 4 5 6; do
      psql -X -v ON_ERROR_STOP=1 -d baseline -f ${../../db/organization-witness}/schema-v$version.sql >> "$out/install.log"
    done
    psql -X -v ON_ERROR_STOP=1 <<'SQL' >> "$out/install.log"
    CREATE ROLE organization_runtime LOGIN IN ROLE aegaeon_organization_witness_runtime;
    CREATE ROLE organization_runtime_other LOGIN IN ROLE aegaeon_organization_witness_runtime;
    CREATE ROLE organization_maintenance LOGIN IN ROLE aegaeon_organization_witness_maintenance;
    SQL
    createdb migration -T baseline
    timeout 120 python3 ${../../tests/organizations/deployment_control.py} --database migration --migration ${../../db/organization-witness/schema-v7.sql} --receipt "$out/migration.json"
    createdb positive -T baseline
    createdb negative -T baseline
    psql -X -v ON_ERROR_STOP=1 -d positive -f ${../../db/organization-witness/schema-v7.sql} >> "$out/install.log"
    python3 - ${../../db/organization-witness/schema-v7.sql} "$TMPDIR/negative.sql" <<'PY'
    import pathlib, sys
    source = pathlib.Path(sys.argv[1]).read_text()
    guard = 'IF EXISTS(SELECT FROM organization_witness.deployment_child_slots c JOIN organization_witness.slots child_slot'
    assert source.count(guard) == 1
    pathlib.Path(sys.argv[2]).write_text(source.replace(guard, 'IF false AND EXISTS(SELECT FROM organization_witness.deployment_child_slots c JOIN organization_witness.slots child_slot'))
    PY
    psql -X -v ON_ERROR_STOP=1 -d negative -f "$TMPDIR/negative.sql" >> "$out/install.log"
    psql -X -At -v ON_ERROR_STOP=1 -d positive -f ${../../db/organization-witness/catalog-v5.sql} > "$out/catalog-v7.json"
    timeout 120 python3 ${../../tests/organizations/deployment_control.py} --database positive --receipt "$out/positive.json"
    timeout 120 python3 ${../../tests/organizations/deployment_control.py} --database negative --negative --receipt "$out/negative.json"
    timeout 60 z3 ${../../tests/organizations/deployment_control.smt2} > "$out/model.txt"
    python3 - "$out" ${../../db/organization-witness/catalog-v7.json} <<'PYMODEL'
    import json, pathlib, sys
    root = pathlib.Path(sys.argv[1])
    answers = [line for line in (root / 'model.txt').read_text().splitlines() if line in ('sat', 'unsat', 'unknown')]
    assert answers == ['unsat'] * 4 + ['sat'], answers
    actual = json.loads((root / 'catalog-v7.json').read_text())
    assert len(actual) <= 1024
    assert actual == json.loads(pathlib.Path(sys.argv[2]).read_text())
    PYMODEL
    pg_ctl -D "$TMPDIR/data" -w -t 20 -m fast stop > "$out/stop.log"
    trap - EXIT
  ''
