{
  pkgs,
  serverPackage,
  atlasSum,
}:
let
  python = pkgs.python3.withPackages (ps: [ ps.psycopg ]);
  manifestBuilder = pkgs.writeText "aegaeon-launch-manifest.py" ''
    import hashlib
    import json
    import pathlib
    import sys

    executable = pathlib.Path(sys.argv[1])
    print(json.dumps({
        "schema_version": 1,
        "binary": {"path": str(executable), "sha256": hashlib.sha256(executable.read_bytes()).hexdigest()},
        "atlas_sum": pathlib.Path(sys.argv[2]).read_text(),
    }, sort_keys=True))
  '';
in
assert pkgs.stdenv.hostPlatform.isLinux;
pkgs.runCommand "aegaeon-server-distribution"
  {
    nativeBuildInputs = with pkgs; [ makeWrapper ];
    meta.mainProgram = "aegaeon-server";
    passthru = {
      unwrapped = serverPackage;
      inherit atlasSum;
    };
  }
  ''
    mkdir -p "$out/bin" "$out/share/aegaeon"
    for name in aegaeon-server aegaeon-organizations-server aegaeon-management-init aegaeon-organization-delivery; do
      ${python}/bin/python ${manifestBuilder} \
        ${serverPackage}/bin/"$name" ${atlasSum} > "$out/share/aegaeon/$name.json"
      if [ "$name" = aegaeon-organization-delivery ]; then
        # Include schema preflight, blocked stdin/stdout and runtime shutdown in
        # the one-shot deadline. Database receipts retain uncertain outcomes.
        makeWrapper ${pkgs.coreutils}/bin/timeout "$out/bin/$name" \
          --add-flags '--signal=TERM --kill-after=5s 90s' \
          --add-flags ${python}/bin/python \
          --add-flags ${../scripts/runtime/schema_guard.py} \
          --add-flags "$out/share/aegaeon/$name.json"
      else
        makeWrapper ${python}/bin/python "$out/bin/$name" \
          --add-flags ${../scripts/runtime/schema_guard.py} \
          --add-flags "$out/share/aegaeon/$name.json"
      fi
    done
    # Offline ownership maintenance excludes online runtime sessions.
    makeWrapper ${pkgs.coreutils}/bin/timeout "$out/bin/aegaeon-organization-subject-ownership" \
      --add-flags "--signal=TERM --kill-after=5s 95s" \
      --add-flags ${serverPackage}/bin/aegaeon-organization-subject-ownership

    # Bound blocked filesystem I/O as well as SQL waits.
    makeWrapper ${pkgs.coreutils}/bin/timeout "$out/bin/aegaeon-organization-import-inspect" \
      --add-flags '--signal=TERM --kill-after=30s 3600s' \
      --add-flags ${serverPackage}/bin/aegaeon-organization-import-inspect
    # Preparation independently checks the compiled maintenance catalog before
    # writing an inactive scope. It has no activation entrypoint.
    makeWrapper ${pkgs.coreutils}/bin/timeout "$out/bin/aegaeon-organization-import-prepare" \
      --add-flags '--signal=TERM --kill-after=30s 3600s' \
      --add-flags ${serverPackage}/bin/aegaeon-organization-import-prepare
    # HTTPS consumer custody has no direct database or runtime authority.
    makeWrapper ${pkgs.coreutils}/bin/timeout "$out/bin/aegaeon-organization-audit-consumer" \
      --add-flags '--signal=TERM --kill-after=5s 35s' \
      --add-flags ${pkgs.python3}/bin/python3 \
      --add-flags ${../scripts/organization_audit_consumer.py}
  ''
