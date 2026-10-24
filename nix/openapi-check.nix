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
    # Cargo's target configuration forces bare cc/c++/ar names. Resolve them
    # to the same LLVM tools as commonShellHook, after stdenv setup hooks run.
    preBuild = ''
      export PATH="${llvmPackages.bintools}/bin:${llvmPackages.clang}/bin:$PATH"
      export CC=${llvmPackages.clang}/bin/clang
      export CXX=${llvmPackages.clang}/bin/clang++
      export AR=${llvmPackages.bintools}/bin/ar
      export LD=${llvmPackages.bintools}/bin/ld.lld
      test "$(command -v cc)" = ${llvmPackages.clang}/bin/cc
      test "$(command -v c++)" = ${llvmPackages.clang}/bin/c++
      test "$(command -v ar)" = ${llvmPackages.bintools}/bin/ar
    '';
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
