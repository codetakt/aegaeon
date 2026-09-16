{ pkgs }:
let
  python = pkgs.python3.withPackages (ps: [ ps.psycopg ]);
  fixture = pkgs.runCommandCC "schema-guard-fixture" { } ''
    mkdir -p "$out/bin"
    cat > fixture.c <<'C'
    #include <stdio.h>
    #include <stdlib.h>
    #include <string.h>
    #include <unistd.h>
    int main(int argc, char **argv) {
      if (argc > 1 && strcmp(argv[1], "wait") == 0) {
        printf("pid:%ld\n", (long)getpid()); fflush(stdout);
        for (;;) pause();
      }
      if (argc != 3) return 99;
      printf("executed:%s\n", argv[2]);
      return atoi(argv[1]);
    }
    C
    $CC -Wall -Wextra -Werror fixture.c -o "$out/bin/aegaeon-server"
    cp "$out/bin/aegaeon-server" "$out/bin/aegaeon-management-init"
  '';
  hash = "h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
  oldSum = pkgs.writeText "old-atlas.sum" ''
    ${hash}
    20260101000000_baseline.sql ${hash}
  '';
  newSum = pkgs.writeText "new-atlas.sum" ''
    ${hash}
    20260101000000_baseline.sql ${hash}
    20260201000000_upgrade.sql ${hash}
  '';
  wrap =
    atlasSum:
    import ./schema-guarded-launch.nix {
      inherit pkgs atlasSum;
      serverPackage = fixture;
    };
in
pkgs.runCommand "schema-guard-check"
  {
    nativeBuildInputs = [
      python
      pkgs.postgresql
    ];
  }
  ''
    export LC_ALL=C.UTF-8
    export PYTHONDONTWRITEBYTECODE=1
    mkdir -p scripts tests/ci db/migrations
    cp -r ${../scripts/runtime} scripts/runtime
    cp ${../tests/ci/test_schema_guard.py} tests/ci/test_schema_guard.py
    cp ${../db/migrations/atlas.sum} db/migrations/atlas.sum
    python -m unittest discover -s tests/ci -p test_schema_guard.py -v
    mkdir -m 700 socket
    initdb -D pgdata --no-locale --encoding=UTF8 --auth=trust > initdb.log
    printf "listen_addresses = '%s'\n" "" >> pgdata/postgresql.conf
    trap 'pg_ctl -D pgdata -m immediate -w stop > stop.log' EXIT
    pg_ctl -D pgdata -l postgres.log -o "-k $PWD/socket" -w start
    export AEGAEON_DATABASE_URL="postgresql:///postgres?host=$PWD/socket&port=5432"
    python ${../tests/ci/schema_guard_pg.py} ${wrap oldSum} ${wrap newSum}
    mkdir -p "$out"
    touch "$out/passed"
  ''
