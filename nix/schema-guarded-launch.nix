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
    nativeBuildInputs = [ pkgs.makeWrapper ];
    meta.mainProgram = "aegaeon-server";
    passthru = {
      unwrapped = serverPackage;
      inherit atlasSum;
    };
  }
  ''
    mkdir -p "$out/bin" "$out/share/aegaeon"
    for name in aegaeon-server aegaeon-management-init; do
      ${python}/bin/python ${manifestBuilder} \
        ${serverPackage}/bin/"$name" ${atlasSum} > "$out/share/aegaeon/$name.json"
      makeWrapper ${python}/bin/python "$out/bin/$name" \
        --add-flags ${../scripts/runtime/schema_guard.py} \
        --add-flags "$out/share/aegaeon/$name.json"
    done
  ''
