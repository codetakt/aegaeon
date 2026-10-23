{ pkgs }:
pkgs.runCommand "lint-workflows"
  {
    # Include the entire Actions tree, including local actions and lint config.
    src = pkgs.lib.fileset.toSource {
      root = ../.;
      fileset = ../.github;
    };
    nativeBuildInputs = with pkgs; [
      bash
      coreutils
      findutils
      actionlint
      shellcheck
    ];
  }
  ''
    cp -r "$src" source
    chmod -R u+w source
    cd source
    ${pkgs.bash}/bin/bash ${../scripts/flake/lint_workflows.sh}
    mkdir -p "$out"
    touch "$out/success"
  ''
