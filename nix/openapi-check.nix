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
  common = {
    inherit src;
    stdenv = _: stdenv;
    pname = "aegaeon-openapi-check";
    version = "0.0.0";
    cargoToml = ../Cargo.toml;
    cargoLock = ../Cargo.lock;
    CARGO_PROFILE = "dev";
    CARGO_INCREMENTAL = "0";
    # Match the compiler variables in the CI development shell.
    CC = "${pkgs.stdenv.cc}/bin/cc";
    CXX = "${pkgs.stdenv.cc}/bin/c++";
    nativeBuildInputs = [
      llvmPackages.clang
      llvmPackages.bintools
      pkgs.pkg-config
      karamel
    ];
    buildInputs = [
      pkgs.mbedtls
      pkgs.libsodium
      evercryptDist
    ];
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
