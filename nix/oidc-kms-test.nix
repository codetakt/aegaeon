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
  command = "cargo test --locked -p aegaeon-server --features kms-aws --lib --no-run";
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
    # Match the native tools selected by the existing CI shell, including the
    # bare tool names forced by .cargo/config.toml.
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
      pname = "aegaeon-oidc-kms-test-dependencies";
      buildPhaseCargoCommand = command;
      doCheck = false;
    }
  );
  identity = pkgs.writeText "oidc-kms-build.json" (
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
    pname = "aegaeon-oidc-kms-test";
    inherit cargoArtifacts;
    buildPhaseCargoCommand = ''
      ${command} --message-format=json-render-diagnostics > kms-build.jsonl
    '';
    checkPhaseCargoCommand = "";
    installPhaseCommand = ''
      ${pkgs.python3}/bin/python3 scripts/validation/oidc_kms_test_package.py \
        install kms-build.jsonl ${identity} "$out"
    '';
    doCheck = false;
    doInstallCargoArtifacts = false;
    # Preserve the bytes selected from Cargo's artifact messages.
    dontStrip = true;
    dontPatchELF = true;
  }
)
