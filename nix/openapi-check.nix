{
  pkgs,
  craneLib,
  stdenv,
  src,
  llvmPackages,
  karamel,
  evercryptDist,
}:
let
  common =
    (import ./rust-test-environment.nix {
      inherit
        pkgs
        stdenv
        llvmPackages
        karamel
        evercryptDist
        ;
      src = import ./openapi-source.nix {
        inherit (pkgs) lib;
        source = src;
      };
      checkCxx = true;
    })
    // {
      pname = "aegaeon-openapi-check";
    };
  cargoArtifacts = craneLib.buildDepsOnly (
    common
    // {
      pname = "aegaeon-openapi-dependencies";
      buildPhaseCargoCommand = "cargo build --locked --package xtask --bin xtask --features openapi";
      doCheck = false;
    }
  );
in
craneLib.mkCargoDerivation (
  common
  // {
    inherit cargoArtifacts;
    buildPhaseCargoCommand = ''
      cargo run --locked --package xtask --bin xtask --features openapi -- openapi --check
    '';
    checkPhaseCargoCommand = ''
      cargo test --locked --package xtask --bin xtask --features openapi openapi::tests
    '';
    doCheck = true;
    installPhaseCommand = ''
      mkdir -p "$out"
      cp generated/openapi/aegaeon-management-api.v1.json "$out/"
      cp generated/openapi/aegaeon-ops.v1.json "$out/"
    '';
    doInstallCargoArtifacts = false;
  }
)
