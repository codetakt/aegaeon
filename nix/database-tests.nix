{
  pkgs,
  craneLib,
  stdenv,
  src,
  rustToolchain,
  llvmPackages,
  karamel,
  evercryptDist,
}:
let
  command = "cargo test --locked -p aegaeon-server --lib --test dcr_database_test --no-run";
  common = {
    inherit src;
    stdenv = _: stdenv;
    version = "0.0.0";
    cargoToml = ../Cargo.toml;
    cargoLock = ../Cargo.lock;
    CARGO_PROFILE = "dev";
    CARGO_INCREMENTAL = "0";
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
    preBuild = ''
      export PATH="${llvmPackages.bintools}/bin:${llvmPackages.clang}/bin:$PATH"
      export CC=${llvmPackages.clang}/bin/clang
      export CXX=${llvmPackages.clang}/bin/clang++
      export AR=${llvmPackages.bintools}/bin/ar
      export LD=${llvmPackages.bintools}/bin/ld.lld
      test "$(command -v cc)" = ${llvmPackages.clang}/bin/cc
      test "$(command -v ar)" = ${llvmPackages.bintools}/bin/ar
    '';
  };
  cargoArtifacts = craneLib.buildDepsOnly (
    common
    // {
      pname = "aegaeon-database-test-dependencies";
      # Crane's dummy source omits auto-discovered integration targets. The
      # library-test target compiles this package's same dev dependencies;
      # the final derivation below always builds both real test targets.
      buildPhaseCargoCommand = "cargo test --locked -p aegaeon-server --lib --no-run";
      doCheck = false;
    }
  );
  identity = pkgs.writeText "database-test-build.json" (
    builtins.toJSON {
      schema_version = 1;
      source = toString src;
      cargo = "${rustToolchain}/bin/cargo";
      rustc = "${rustToolchain}/bin/rustc";
      target = stdenv.hostPlatform.config;
      native_cc = "${llvmPackages.clang}/bin/cc";
      native_ar = "${llvmPackages.bintools}/bin/ar";
      evercrypt = toString evercryptDist;
      build_command = command;
    }
  );
in
craneLib.mkCargoDerivation (
  common
  // {
    pname = "aegaeon-database-tests";
    inherit cargoArtifacts;
    buildPhaseCargoCommand = ''
      ${command} --message-format=json-render-diagnostics > database-build.jsonl
    '';
    checkPhaseCargoCommand = "";
    installPhaseCommand = ''
      ${pkgs.python3}/bin/python3 scripts/validation/database_test_package.py \
        install database-build.jsonl ${identity} "$out"
    '';
    doCheck = false;
    doInstallCargoArtifacts = false;
    dontStrip = true;
    dontPatchELF = true;
  }
)
