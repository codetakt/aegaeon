# Shared native tool selection for isolated Cargo dev-profile checks.
{
  pkgs,
  stdenv,
  src,
  llvmPackages,
  karamel,
  evercryptDist,
  checkCxx ? false,
}:
{
  inherit src;
  stdenv = _: stdenv;
  version = "0.0.0";
  cargoToml = ../Cargo.toml;
  cargoLock = ../Cargo.lock;
  CARGO_PROFILE = "dev";
  CARGO_INCREMENTAL = "0";
  nativeBuildInputs = with pkgs; [
    llvmPackages.clang
    llvmPackages.bintools
    pkg-config
    karamel
  ];
  buildInputs = with pkgs; [
    mbedtls
    libsodium
    evercryptDist
  ];
  preBuild = ''
    export PATH="${llvmPackages.bintools}/bin:${llvmPackages.clang}/bin:$PATH"
    export CC=${llvmPackages.clang}/bin/clang
    export CXX=${llvmPackages.clang}/bin/clang++
    export AR=${llvmPackages.bintools}/bin/ar
    export LD=${llvmPackages.bintools}/bin/ld.lld
    test "$(command -v cc)" = ${llvmPackages.clang}/bin/cc
  ''
  + pkgs.lib.optionalString checkCxx ''
    test "$(command -v c++)" = ${llvmPackages.clang}/bin/c++
  ''
  + ''
    test "$(command -v ar)" = ${llvmPackages.bintools}/bin/ar
  '';
}
