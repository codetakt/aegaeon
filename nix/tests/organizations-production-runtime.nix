# Real production constructors on independent owned TLS stores. The fixture
# supplies activation receipts and TLS delivery trust, not production custody.
{
  pkgs,
  nodejsRuntime,
  databaseTests,
  serverPackage,
  source,
}:
pkgs.runCommand "aegaeon-organizations-production-runtime"
  {
    # Host qualification is separate from the cached product check. CI rebuilds
    # this probe before allowing any namespace-dependent acceptance case.
    passthru = {
      namespaceUnshare = pkgs.lib.getExe' pkgs.util-linux "unshare";
      namespaceProbe =
        pkgs.runCommand "aegaeon-organizations-userns-probe"
          {
            nativeBuildInputs = with pkgs; [
              util-linux
              coreutils
            ];
          }
          ''
            set -euo pipefail
            expected_uid=$(id -u)
            expected_gid=$(id -g)
            test "$expected_uid" -ne 0
            unshare --user --map-current-user --keep-caps --net --mount --fork \
              sh -eu -c 'test "$(id -u)" = "$1"; test "$(id -g)" = "$2"' \
              probe "$expected_uid" "$expected_gid"
            touch "$out"
          '';
    };
    nativeBuildInputs = with pkgs; [
      (python3.withPackages (python: [ python.psycopg ]))
      nodejsRuntime
      postgresql_18
      atlas
      openssl
      coreutils
      util-linux
      iproute2
      procps
    ];
  }
  ''
    set -euo pipefail
    mkdir -p "$out" "$TMPDIR/evidence"
    for case in enabled disabled; do
      args=()
      if [ "$case" = disabled ]; then args+=(--disabled); fi
      if ! python3 ${../../tests/organizations}/current_runtime.py \
        --root ${source} --package ${databaseTests} --server-package ${serverPackage} \
        --postgres-bin ${pkgs.postgresql_18}/bin --atlas-bin ${pkgs.atlas}/bin \
        --output "$TMPDIR/evidence/$case" "''${args[@]}"; then
        cat "$TMPDIR/evidence/$case/result.json"
        exit 1
      fi
      cp "$TMPDIR/evidence/$case/result.json" "$out/$case.json"
    done
  ''
