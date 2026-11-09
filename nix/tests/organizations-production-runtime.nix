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
      # Real lifecycle qualification uses a fresh output per case. It exercises
      # the same namespace executable while the independent owner observes work.
      namespaceCancellationProbe =
        { nonce }:
        assert builtins.match "[0-9a-f]{32}" nonce != null;
        builtins.derivation {
          name = "aegaeon-userns-lifecycle-${nonce}";
          system = pkgs.stdenv.hostPlatform.system;
          builder = "${pkgs.bash}/bin/bash";
          args = [
            "-euc"
            ''
              exec ${pkgs.lib.getExe' pkgs.util-linux "unshare"} \
                --user --map-current-user --keep-caps --net --mount --fork \
                ${pkgs.bash}/bin/bash -euc '
                  for ((i=0; i<60; i++)); do
                    printf "namespace-lifecycle ${nonce} %s\n" "$i" >&2
                    ${pkgs.coreutils}/bin/sleep 1
                  done
                  printf completed > "$out"
                '
            ''
          ];
          AEGAEON_NAMESPACE_LIFECYCLE_NONCE = nonce;
          preferLocalBuild = true;
          allowSubstitutes = false;
        };
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
    python3 ${../../tests/organizations}/check_current_runtime_postgres.py \
      --root ${source} --postgres-bin ${pkgs.postgresql_18}/bin \
      --output "$TMPDIR/evidence/cleanup"
    cp "$TMPDIR/evidence/cleanup/result.json" "$out/cleanup.json"
    for case in enabled disabled management; do
      args=()
      if [ "$case" = disabled ]; then args+=(--disabled); fi
      if [ "$case" = management ]; then args+=(--management); fi
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
