{ pkgs }:
let
  version = pkgs.lib.trim (builtins.readFile ../ci/postgresql-version);
  postgres = pkgs.postgresql_18;
in
assert pkgs.lib.assertMsg (
  postgres.version == version
) "PostgreSQL Nix package differs from ci/postgresql-version";
pkgs.runCommand "postgresql-version-check"
  {
    nativeBuildInputs = with pkgs; [
      postgres
      (python3.withPackages (ps: [ ps.psycopg ]))
    ];
  }
  ''
    test "$(postgres --version)" = "postgres (PostgreSQL) ${version}"
    mkdir -p source/scripts/tests source/ci "$out"
    cp ${../ci/postgresql-version} source/ci/postgresql-version
    cp ${../scripts/tests/check_postgresql_version.py} source/scripts/tests/check_postgresql_version.py
    initdb -D data -U postgres --no-locale --encoding=UTF8 --auth=trust > init.log
    mkdir socket
    trap 'pg_ctl -D data -m immediate -w stop > stop.log' EXIT
    pg_ctl -D data -l postgres.log -o "-k $PWD/socket -c listen_addresses=" -w start
    export AEGAEON_TEST_ADMIN_DATABASE_URL="postgresql://postgres@localhost/postgres?host=$PWD/socket"
    python3 source/scripts/tests/check_postgresql_version.py > "$out/version.log"
    pg_ctl -D data -m fast -w stop
    trap - EXIT
  ''
