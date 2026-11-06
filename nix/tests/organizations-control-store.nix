# Linux sandbox check of the actual NixOS pre-start chain. No daemon or timing
# campaign is started. Service/TLS/restore qualification is a separate boundary.
{
  nixpkgs,
  system ? "x86_64-linux",
}:
let
  testRoot = "/build/organization-control";
  evaluateWith =
    extra: host:
    nixpkgs.lib.nixosSystem {
      inherit system;
      modules = [
        ../organizations-control-store.nix
        {
          boot.isContainer = true;
          system.stateVersion = "26.11";
          services.aegaeonOrganizationControlStore = {
            enable = true;
            storageRoot = testRoot;
            clusterIdentityFile = "/etc/aegaeon-control/identity";
            certificateFile = "/etc/aegaeon-control/cert.pem";
            privateKeyFile = "/etc/aegaeon-control/key.pem";
            listenAddress = "192.0.2.10";
            runtimeLogin = "organization_runtime";
            maintenanceLogin = "organization_maintenance";
            runtimeNetworks = [ "192.0.2.20/32" ];
            maintenanceNetworks = [ "192.0.2.30/32" ];
          }
          // extra;
        }
        host
      ];
    };
  evaluate = extra: evaluateWith extra { };
  live =
    evaluateWith
      {
        listenAddress = "127.0.0.1";
        runtimeNetworks = [ "127.0.0.1/32" ];
        maintenanceNetworks = [ "127.0.0.1/32" ];
      }
      {
        # The sandbox has no systemd credential manager. Only the two file locations
        # differ; service credential delivery/mount custody require deployment tests.
        services.postgresql.settings = {
          ssl_cert_file = nixpkgs.lib.mkForce "${testRoot}/credentials/server-certificate";
          ssl_key_file = nixpkgs.lib.mkForce "${testRoot}/credentials/server-key";
        };
      };
  liveStart = builtins.head live.config.systemd.services.postgresql.serviceConfig.ExecStartPre;
  mappedWildcard =
    (evaluate { listenAddress = "::ffff:0.0.0.0"; })
    .config.system.build.aegaeonOrganizationControlPreflight;
  normal = evaluate { };
  failures = extra: builtins.filter (a: !a.assertion) (evaluate extra).config.assertions;
  pg = normal.config.services.postgresql.package;
  pkgs = nixpkgs.legacyPackages.${system};
  preflight = normal.config.system.build.aegaeonOrganizationControlPreflight;
  fullStart = builtins.head normal.config.systemd.services.postgresql.serviceConfig.ExecStartPre;
  withoutGuard = pkgs.writeShellScript "organization-control-guard-removal" (
    "set -e\n"
    +
      nixpkgs.lib.replaceStrings [ "${preflight}\n" ] [ "" ]
        normal.config.systemd.services.postgresql.preStart
  );
in
assert failures { } == [ ];
assert
  builtins.length (failures {
    maintenanceLogin = "organization_runtime";
  }) == 1;
assert
  builtins.length (failures {
    runtimeLogin = "postgres";
  }) == 1;
assert
  builtins.length (failures {
    clusterIdentityFile = "${testRoot}/identity";
  }) == 1;
assert
  builtins.length (failures {
    privateKeyFile = "/nix/store/example-key";
  }) == 1;
assert
  builtins.length (failures {
    listenAddress = "0.0.0.0";
  }) == 1;
assert
  builtins.length (failures {
    runtimeNetworks = [ "0.0.0.0/0" ];
  }) == 1;
assert
  builtins.length (failures {
    listenAddress = "0:0:0:0:0:0:0:0";
  }) == 1;
assert
  builtins.length (failures {
    runtimeNetworks = [ "0.0.0.0/00" ];
  }) == 1;
assert
  builtins.length (failures {
    clusterIdentityFile = "/etc/../control/identity";
  }) == 1;
pkgs.runCommand "aegaeon-organization-control-startup-tests"
  {
    nativeBuildInputs = [
      pg
      pkgs.coreutils
      pkgs.gnused
      pkgs.python3
      pkgs.openssl
    ];
  }
  ''
      set -euo pipefail
      test "$NIX_BUILD_TOP" = /build
      mkdir -p ${testRoot} "$TMPDIR/credentials"
      export CREDENTIALS_DIRECTORY="$TMPDIR/credentials"
      initdb -D ${testRoot}/postgresql --no-locale --encoding=UTF8 --auth-local=peer --auth-host=scram-sha-256 >initdb.log
      pg_controldata ${testRoot}/postgresql | sed -n 's/^Database system identifier: *//p' > "$CREDENTIALS_DIRECTORY/cluster-identity"
      ${preflight}
      cp "$CREDENTIALS_DIRECTORY/cluster-identity" identity.saved
      refuse() {
        if "$@"; then
          echo "unsafe control startup accepted" >&2
          exit 1
        fi
      }
      refuse ${mappedWildcard}
      printf '1\n' > "$CREDENTIALS_DIRECTORY/cluster-identity"
      refuse ${preflight}
      cp identity.saved "$CREDENTIALS_DIRECTORY/cluster-identity"
      printf '17\n' > ${testRoot}/postgresql/PG_VERSION
      refuse ${preflight}
      printf '18\n' > ${testRoot}/postgresql/PG_VERSION
      mv "$CREDENTIALS_DIRECTORY/cluster-identity" identity.absent
      refuse ${preflight}
      mv identity.absent "$CREDENTIALS_DIRECTORY/cluster-identity"
      mv ${testRoot}/postgresql/PG_VERSION version.absent
      printf 'preserve evidence\n' > ${testRoot}/postgresql/sentinel.conf
      refuse ${fullStart}
      test ! -e ${testRoot}/postgresql/PG_VERSION
      test "$(cat ${testRoot}/postgresql/sentinel.conf)" = 'preserve evidence'
      mv version.absent ${testRoot}/postgresql/PG_VERSION
      ${preflight}
      export PGDATA=${testRoot}/postgresql
      ${fullStart}
      test ! -e ${testRoot}/postgresql/.first_startup
    # The same missing-version case reaches the upstream destructive cleanup when
    # only the added guard is removed. Retain this fault control, not an assertion
    # that a previous Aegaeon production control service had already existed.
    mv ${testRoot}/postgresql/PG_VERSION version.absent
    refuse ${withoutGuard}
    test ! -e ${testRoot}/postgresql/sentinel.conf
    mv version.absent ${testRoot}/postgresql/PG_VERSION
      mkdir "$out"
    python3 ${../../tests/organizations/control_service.py} \
      --root ${testRoot} --pre-start ${liveStart} \
      --schemas ${../../db/organization-witness} --receipt "$out/service.json"
    printf '%s\n' 'nine configuration refusals; two normal guards and one generated service pre-start; five startup refusals; one guard-removal control detects destructive cleanup' > "$out/result.txt"
  ''
