{ pkgs }:
pkgs.runCommand "verify-ffi-contracts"
  {
    # Retain whole source trees: newly added declarations and generated files
    # must reach the lexical drift checker without updating a file allowlist.
    src = pkgs.lib.fileset.toSource {
      root = ../.;
      fileset = pkgs.lib.fileset.unions [
        ../fstar
        ../c
        ../crates/ffi
        ../generated
        ../artifacts/karamel
        ../scripts/validation
        ../scripts/flake/verify_ffi_contracts.sh
        ../spec/assumption-register.json
        ../spec/assumption-register.schema.json
        ../tests/ci/test_foreign_assumption_inventory.py
      ];
    };
    nativeBuildInputs = with pkgs; [
      bash
      coreutils
      gnugrep
      perl
      (import ./ci-controller-python.nix { inherit pkgs; })
    ];
  }
  ''
    cp -r "$src" source
    chmod -R u+w source
    cd source
    mkdir -p "$out"
    OUT_DIR="$out" ${pkgs.bash}/bin/bash ${../scripts/flake/verify_ffi_contracts.sh}
    touch "$out/success"
  ''
