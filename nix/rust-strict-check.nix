{
  lib,
  craneLib,
  src,
  cargoArtifacts,
  stdenv,
}:
let
  strictPackageClippyExtraArgs =
    "-- -D warnings -W clippy::pedantic -W clippy::cargo "
    + "-A clippy::multiple_crate_versions -A clippy::missing_errors_doc "
    + "-A clippy::missing_panics_doc -A clippy::doc_markdown "
    + "-D clippy::unwrap_used -D clippy::expect_used -D clippy::panic "
    + "-D clippy::todo -D clippy::unimplemented";
  strictServerClippyExtraArgs =
    "-- -D warnings -W clippy::cargo -A clippy::multiple_crate_versions "
    + "-D clippy::unwrap_used -D clippy::expect_used -D clippy::panic "
    + "-D clippy::todo -D clippy::unimplemented";
in
craneLib.mkCargoDerivation {
  inherit cargoArtifacts;
  src = import ./workspace-check-source.nix {
    inherit lib;
    source = src;
  };
  stdenv = _: stdenv;
  pname = "aegaeon-rust-strict-packages";
  version = "0.0.0";
  cargoToml = ../Cargo.toml;
  cargoLock = ../Cargo.lock;
  buildPhaseCargoCommand = ''
    cargo clippy --release \
      -p aegaeon-client -p aegaeon-loadtest -p aegaeon-observability -p aegaeon-postgres -p ffi \
      --all-targets --all-features \
      ${strictPackageClippyExtraArgs}
    cargo clippy --release \
      -p aegaeon-server --lib --bin aegaeon-server \
      --features kms-aws,openapi,verified-claim --no-deps \
      ${strictServerClippyExtraArgs}
  '';
  checkPhaseCargoCommand = "";
  installPhaseCommand = ''
    mkdir -p $out
    touch $out/success
  '';
  doInstallCargoArtifacts = false;
}
