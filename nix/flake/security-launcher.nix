# Security-suite only: reject inherited functions before starting any Bash.
{
  lib,
  pkgs,
  name,
  runtimeInputs,
  script,
}:
let
  dispatch = pkgs.writeShellApplication {
    inherit name;
    runtimeInputs = lib.unique runtimeInputs;
    text = ''
      set -euo pipefail
      exec ${pkgs.bash}/bin/bash ${script} "$@"
    '';
  };
in
pkgs.writeTextFile {
  name = "${name}-entry";
  destination = "/bin/${name}";
  executable = true;
  meta.mainProgram = name;
  text = ''
    #!${pkgs.python3}/bin/python3 -I
    import os
    import sys

    if any(key.startswith(b"BASH_FUNC_") for key in os.environb):
        sys.stderr.write("[security] inherited Bash functions are not supported\n")
        sys.exit(1)

    bash = os.fsencode(${builtins.toJSON pkgs.runtimeShell})
    dispatch = os.fsencode(${builtins.toJSON "${dispatch}/bin/${name}"})
    os.execve(
        bash,
        [bash, dispatch, *(os.fsencode(arg) for arg in sys.argv[1:])],
        os.environb,
    )
  '';
}
