{
  pkgs,
  craneLib,
  stdenv,
  src,
  verificationRuntimeInputs,
  haclStar,
  steel,
  evercryptDist,
  buildPhaseCargoCommand,
}:
let
  common = {
    inherit src;
    stdenv = _: stdenv;
    version = "0.0.0";
    cargoToml = ../Cargo.toml;
    cargoLock = ../Cargo.lock;
    nativeBuildInputs = verificationRuntimeInputs;
    CARGO_PROFILE = "dev";
    CARGO_INCREMENTAL = "0";
    # Crane restores artifacts during postPatch, before the verification script
    # runs. Select its actual test output directory before that hook executes.
    CARGO_TARGET_DIR = "target/verify-jose";
    HACL_FSTAR_PATH = "${haclStar}/share/hacl-star/fstar";
    STEEL_PATH = steel;
    EVERCRYPT_DIST = evercryptDist;
  };
  cargoArtifacts = craneLib.buildDepsOnly (
    common
    // {
      pname = "aegaeon-jose-test-dependencies";
      buildPhaseCargoCommand = ''
        ${pkgs.bash}/bin/bash ${../scripts/flake/prepare_jose_dependencies.sh}
      '';
      doCheck = false;
    }
  );
in
craneLib.mkCargoDerivation (
  common
  // {
    pname = "verify-jose";
    inherit cargoArtifacts buildPhaseCargoCommand;
    checkPhaseCargoCommand = "";
    installPhaseCommand = ''
      mkdir -p "$out"
      touch "$out/success"
    '';
    doInstallCargoArtifacts = false;
  }
)
