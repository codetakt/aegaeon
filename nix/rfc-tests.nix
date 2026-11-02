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
  serverCommand = "cargo test --locked --package aegaeon-server rfc_tests --no-fail-fast --no-run";
  joseCommand = "cargo test --locked --package aegaeon-jose --test rfc7520_vectors --no-run";
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
      pname = "aegaeon-rfc-test-dependencies";
      # Crane's dummy source omits auto-discovered integration targets. The
      # library-test target compiles this package's same dev dependencies;
      # the final derivation below builds every selected real RFC target.
      buildPhaseCargoCommand = "cargo test --locked -p aegaeon-server --lib --no-run";
      doCheck = false;
    }
  );
  identity = pkgs.writeText "rfc-test-build.json" (
    builtins.toJSON {
      schema_version = 1;
      source = toString src;
      cargo = "${rustToolchain}/bin/cargo";
      rustc = "${rustToolchain}/bin/rustc";
      target = stdenv.hostPlatform.config;
      native_cc = "${llvmPackages.clang}/bin/cc";
      native_ar = "${llvmPackages.bintools}/bin/ar";
      evercrypt = toString evercryptDist;
      server_command = serverCommand;
      jose_command = joseCommand;
    }
  );
in
craneLib.mkCargoDerivation (
  common
  // {
    pname = "aegaeon-rfc-tests";
    inherit cargoArtifacts;
    buildPhaseCargoCommand = ''
      mkdir rfc-build
      cargo metadata --locked --no-deps --format-version=1 > rfc-build/metadata.json
      ${serverCommand} --message-format=json-render-diagnostics > rfc-build/server.jsonl
      cargo test --locked --package aegaeon-server --doc rfc_tests -- --list > rfc-build/doc-list.txt
      ${joseCommand} --message-format=json-render-diagnostics > rfc-build/jose.jsonl
    '';
    checkPhaseCargoCommand = "";
    installPhaseCommand = ''
      ${pkgs.python3}/bin/python3 scripts/validation/rfc_test_package.py \
        install rfc-build ${identity} "$out"
    '';
    doCheck = false;
    doInstallCargoArtifacts = false;
    dontStrip = true;
    dontPatchELF = true;
  }
)
