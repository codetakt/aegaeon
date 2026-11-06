# Retained maintenance state transitions, not worker/supplier qualification.
{ pkgs }:
let
  recovery = import ./organizations-legacy-recovery-tool.nix { inherit pkgs; };
  fixtures = pkgs.lib.fileset.toSource {
    root = ../../tests/organizations;
    fileset = pkgs.lib.fileset.fileFilter (file: file.hasExt "py") ../../tests/organizations;
  };
  recoverySchemas = pkgs.runCommand "aegaeon-recovery-schema-input" { } ''
    mkdir -p "$out/db"
    ln -s ${../../db/organization-witness} "$out/db/organization-witness"
  '';
in
pkgs.runCommand "aegaeon-organization-maintenance-control-tests"
  {
    nativeBuildInputs = with pkgs; [
      postgresql_18
      (python3.withPackages (p: [
        p.psycopg
        p.pytest
      ]))
      coreutils
      redis
      openssl
      z3
    ];
  }
  ''
    set -euo pipefail
    mkdir -p "$out" "$TMPDIR/socket"
    timeout 30 python3 ${fixtures}/startup_inputs.py \
      --store-inventory ${../../tests/organizations/legacy_operations/organization_runtime_stores.json} \
      --operations ${../../tests/organizations/legacy_operations} --output "$out/startup-inputs.json" > "$out/startup-inputs.log" 2>&1 || {
        cat "$out/startup-inputs.log"
        exit 1
      }
    timeout 30 python3 ${fixtures}/epoch_process.py \
      --operations ${../../tests/organizations/legacy_operations} --output "$out/epoch-process.json" > "$out/epoch-process.log" 2>&1 || {
        cat "$out/epoch-process.log"
        exit 1
      }
    timeout 30 python3 ${fixtures}/recovery_retention.py \
      --operator ${recovery} --output "$out/retention.json" > "$out/retention.log" 2>&1 || {
        cat "$out/retention.log"
        exit 1
      }
    timeout 10 z3 ${../../tests/organizations/maintenance_control.smt2} > "$out/conditional-model.txt"
    timeout 10 z3 ${../../tests/organizations/maintenance_recovery.smt2} > "$out/recovery-model.txt"
    timeout 10 z3 ${../../tests/organizations/runtime_recovery.smt2} > "$out/runtime-recovery-model.txt"
    python3 - "$out/conditional-model.txt" <<'PYCODE'
    import pathlib, sys
    assert pathlib.Path(sys.argv[1]).read_text().splitlines() == ["unsat", "unsat", "sat"]
    PYCODE
    python3 - "$out/recovery-model.txt" <<'PYCODE'
    import pathlib, sys
    assert pathlib.Path(sys.argv[1]).read_text().splitlines() == ["unsat", "unsat", "sat", "sat"]
    PYCODE
    python3 - "$out/runtime-recovery-model.txt" <<'PYCODE'
    import pathlib, sys
    assert pathlib.Path(sys.argv[1]).read_text().splitlines() == ["unsat", "unsat", "unsat", "sat"]
    PYCODE
    timeout 10 z3 ${../../tests/organizations/cutover_journal.smt2} > "$out/cutover-model.txt"
    python3 - "$out/cutover-model.txt" <<'PYCODE'
    import pathlib, sys
    assert pathlib.Path(sys.argv[1]).read_text().splitlines() == ["unsat"] * 4 + ["sat"] * 2
    PYCODE
    timeout 10 z3 ${../../tests/organizations/cutover_activation.smt2} > "$out/activation-model.txt"
    python3 - "$out/activation-model.txt" <<'PYCODE'
    import pathlib, sys
    assert pathlib.Path(sys.argv[1]).read_text().splitlines() == ["unsat"] * 3 + ["sat"] * 2
    PYCODE
    timeout 10 z3 ${../../tests/organizations/cutover_serving.smt2} > "$out/serving-model.txt"
    python3 - "$out/serving-model.txt" <<'PYCODE'
    import pathlib, sys
    assert pathlib.Path(sys.argv[1]).read_text().splitlines() == ["unsat"] * 3 + ["sat"] * 3
    PYCODE
    export PGHOST="$TMPDIR/socket" PGUSER=postgres PGDATABASE=postgres
    export PGOPTIONS='-c statement_timeout=10000 -c lock_timeout=5000'
    initdb -D "$TMPDIR/data" -U postgres --no-locale --encoding=UTF8 --auth-local=trust --auth-host=reject > "$out/initdb.log"
    trap 'pg_ctl -D "$TMPDIR/data" -w -t 20 -m immediate stop >> "$out/stop.log" 2>&1 || true' EXIT
    pg_ctl -D "$TMPDIR/data" -l "$out/postgres.log" -w -t 20 -o "-k $PGHOST -c listen_addresses=" start
    createdb baseline
    for version in 1 2 3 4 5 6 7 8; do
      psql -X -v ON_ERROR_STOP=1 -d baseline -f ${../../db/organization-witness}/schema-v$version.sql >> "$out/install.log"
    done
    psql -X -v ON_ERROR_STOP=1 <<'SQL' >> "$out/install.log"
    CREATE ROLE organization_runtime LOGIN IN ROLE aegaeon_organization_witness_runtime;
    CREATE ROLE organization_maintenance LOGIN IN ROLE aegaeon_organization_witness_maintenance;
    CREATE ROLE organization_maintenance_other LOGIN IN ROLE aegaeon_organization_witness_maintenance;
    SQL
    createdb positive -T baseline
    createdb negative -T baseline
    createdb migration -T baseline
    createdb runtime_migration -T baseline
    psql -X -v ON_ERROR_STOP=1 -d runtime_migration -f ${../../db/organization-witness/schema-v9.sql} >> "$out/install.log"
    timeout 60 python3 ${fixtures}/runtime_recovery_migration.py \
      --schema ${../../db/organization-witness}/schema-v10.sql \
      --catalog ${../../db/organization-witness/catalog-v10.json} \
      --cutover-schema ${../../db/organization-witness/schema-v11.sql} \
      --cutover-catalog ${../../db/organization-witness/catalog-v11.json} \
      --output "$out/runtime-migration.json" > "$out/runtime-migration.log" 2>&1 || {
        cat "$out/runtime-migration.log"
        exit 1
      }
    createdb epoch_migration -T baseline
    for version in 9 10 11; do
      psql -X -v ON_ERROR_STOP=1 -d epoch_migration -f ${../../db/organization-witness}/schema-v$version.sql >> "$out/install.log"
    done
    timeout 30 python3 ${fixtures}/epoch_inventory.py \
      --schema ${../../db/organization-witness}/schema-v12.sql \
      --catalog ${../../db/organization-witness/catalog-v12.json} \
      --output "$out/epoch-inventory.json" > "$out/epoch-inventory.log" 2>&1 || {
        cat "$out/epoch-inventory.log"
        exit 1
      }
    createdb activation_migration -T baseline
    for version in 9 10 11 12; do
      psql -X -v ON_ERROR_STOP=1 -d activation_migration -f ${../../db/organization-witness}/schema-v$version.sql >> "$out/install.log"
    done
    timeout 30 python3 ${fixtures}/activation_inventory.py \
      --schema ${../../db/organization-witness}/schema-v13.sql \
      --catalog ${../../db/organization-witness/catalog-v13.json} \
      --output "$out/activation-inventory.json" > "$out/activation-inventory.log" 2>&1 || {
        cat "$out/activation-inventory.log"
        exit 1
      }
    createdb serving_migration -T baseline
    for version in 9 10 11 12 13; do
      psql -X -v ON_ERROR_STOP=1 -d serving_migration -f ${../../db/organization-witness}/schema-v$version.sql >> "$out/install.log"
    done
    timeout 30 python3 ${fixtures}/serving_recovery_migration.py \
      --schema ${../../db/organization-witness}/schema-v14.sql \
      --catalog ${../../db/organization-witness/catalog-v14.json} \
      --output "$out/serving-migration.json" > "$out/serving-migration.log" 2>&1 || {
        cat "$out/serving-migration.log"
        exit 1
      }
    if ! timeout 90 python3 ${fixtures}/maintenance_control.py --database migration --migration ${../../db/organization-witness/schema-v9.sql} --receipt "$out/migration.json" > "$out/migration.log" 2>&1; then
      cat "$out/migration.log"
      exit 1
    fi
    psql -X -v ON_ERROR_STOP=1 -d positive -f ${../../db/organization-witness/schema-v9.sql} >> "$out/install.log"
    python3 - ${../../db/organization-witness/schema-v9.sql} "$TMPDIR/negative.sql" <<'PY'
    import pathlib, sys
    source = pathlib.Path(sys.argv[1]).read_text()
    guard = "IF EXISTS(SELECT FROM organization_witness.maintenance_slots WHERE deployment_id=p_deployment AND pending) THEN RAISE EXCEPTION 'maintenance still pending'; END IF;"
    assert source.count(guard) == 2
    pathlib.Path(sys.argv[2]).write_text(source.replace(guard, "", 1))
    PY
    psql -X -v ON_ERROR_STOP=1 -d negative -f "$TMPDIR/negative.sql" >> "$out/install.log"
    psql -X -At -v ON_ERROR_STOP=1 -d positive -f ${../../db/organization-witness/catalog-v5.sql} > "$out/catalog-v9.json"
    for scenario in positive negative; do
      args=()
      if [ "$scenario" = negative ]; then args=(--negative); fi
      if ! timeout 90 python3 ${fixtures}/maintenance_control.py --database "$scenario" "''${args[@]}" --receipt "$out/$scenario.json" > "$out/$scenario.log" 2>&1; then
        cat "$out/$scenario.log"
        exit 1
      fi
    done
    python3 - "$out/catalog-v9.json" ${../../db/organization-witness/catalog-v9.json} <<'PYCODE'
    import json, pathlib, sys
    actual, expected = [json.loads(pathlib.Path(p).read_text()) for p in sys.argv[1:]]
    assert len(actual) <= 1024
    assert actual == expected
    PYCODE
    timeout 180 python3 ${fixtures}/restore_content.py \
      --schema ${../../db/schema.sql} --operator ${recovery} \
      --output "$TMPDIR/restore-content" > "$out/restore-content.log" 2>&1 || {
        cat "$out/restore-content.log"
        exit 1
      }
    cp "$TMPDIR/restore-content/result.json" "$out/restore-content.json"
    pg_ctl -D "$TMPDIR/data" -w -t 20 -m fast stop > "$out/stop.log"
    trap - EXIT
    # Independent clusters and actual restricted logins; no service-manager
    # qualification is inferred from this SQL-only CI fixture.
    timeout 90 python3 ${fixtures}/maintenance_recovery.py \
      --root ${recoverySchemas} --operator ${recovery} --sql-only \
      --output "$TMPDIR/recovery" > "$out/recovery.log" 2>&1 || {
        cat "$out/recovery.log"
        exit 1
      }
    cp "$TMPDIR/recovery/result.json" "$out/recovery.json"
    cp "$TMPDIR/recovery/credentials-result.json" "$out/credentials.json"
    cp "$TMPDIR/recovery/login-result.json" "$out/login.json"
    cp "$TMPDIR/recovery/serving-sql-result.json" "$out/serving-sql.json"
    cp "$TMPDIR/recovery/journal-result.json" "$out/journal.json"
    timeout 90 python3 ${fixtures}/redis_recovery.py \
      --operator ${recovery} --output "$TMPDIR/redis-recovery" > "$out/redis-recovery.log" 2>&1 || {
        cat "$out/redis-recovery.log"
        exit 1
      }
    cp "$TMPDIR/redis-recovery/result.json" "$out/redis-recovery.json"
    timeout 90 python3 ${fixtures}/redis_recovery.py \
      --operator ${recovery} --cutover --output "$TMPDIR/token-prepare" > "$out/token-prepare.log" 2>&1 || {
        cat "$out/token-prepare.log"
        exit 1
      }
    cp "$TMPDIR/token-prepare/result.json" "$out/token-prepare.json"
    cp "$TMPDIR/token-prepare/serving-token-result.json" "$out/serving-token.json"
    timeout 90 python3 ${fixtures}/maintenance_recovery.py \
      --root ${recoverySchemas} --operator ${recovery} --runtime-sql \
      --output "$TMPDIR/runtime-recovery" > "$out/runtime-recovery.log" 2>&1 || {
        cat "$out/runtime-recovery.log"
        exit 1
      }
    cp "$TMPDIR/runtime-recovery/runtime-result.json" "$out/runtime-recovery.json"
  ''
