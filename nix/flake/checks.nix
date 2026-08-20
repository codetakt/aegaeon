{
  pkgs,
  isLinux,
  craneLib,
  src,
  cargoArtifacts,
  stdenv,
  pre-commit-check,
  mkVerification,
  mkLightVerification,
  verifyFstar,
  verifyTamarin,
  verifyKani,
  verifyDudect,
  verifyJose,
  karamel,
  evercryptDist,
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
{
  inherit pre-commit-check;

  fmt = craneLib.cargoFmt {
    inherit src cargoArtifacts;
    stdenv = _: stdenv;
    pname = "aegaeon-workspace-fmt";
    version = "0.0.0";
    cargoToml = ../../Cargo.toml;
    cargoExtraArgs = "--all --manifest-path Cargo.toml";
  };

  compliance-matrix =
    mkVerification "verify-compliance-matrix" ../../scripts/flake/verify_compliance_matrix.sh
      [ ];

  verified-reqs = mkLightVerification "verify-reqs" ../../scripts/flake/verify_reqs.sh [ ];

  ffi-contracts =
    mkLightVerification "verify-ffi-contracts" ../../scripts/flake/verify_ffi_contracts.sh
      [ ];

  workflow-lint = mkVerification "lint-workflows" ../../scripts/flake/lint_workflows.sh [
    pkgs.actionlint
    pkgs.shellcheck
  ];

  rust-strict-packages = craneLib.mkCargoDerivation {
    inherit src cargoArtifacts;
    stdenv = _: stdenv;
    pname = "aegaeon-rust-strict-packages";
    version = "0.0.0";
    cargoToml = ../../Cargo.toml;
    cargoLock = ../../Cargo.lock;
    buildPhaseCargoCommand = ''
      cargo clippy --release \
        -p aegaeon-client -p aegaeon-loadtest -p aegaeon-observability -p ffi \
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
  };

  server-clippy-inventory = craneLib.cargoClippy {
    inherit src cargoArtifacts;
    stdenv = _: stdenv;
    pname = "aegaeon-server-clippy-inventory";
    version = "0.0.0";
    cargoToml = ../../Cargo.toml;
    cargoExtraArgs = "-p aegaeon-server --lib --bin aegaeon-server --no-deps";
    cargoClippyExtraArgs =
      "-- -D clippy::map_unwrap_or -D clippy::ref_option "
      + "-D clippy::needless_pass_by_value -D clippy::too_many_lines "
      + "-D clippy::too_many_arguments";
  };

  clippy = craneLib.cargoClippy {
    inherit src cargoArtifacts;
    stdenv = _: stdenv;
    pname = "aegaeon-workspace-clippy";
    version = "0.0.0";
    cargoToml = ../../Cargo.toml;
    cargoExtraArgs = "--workspace";
  };

  tests = craneLib.cargoNextest {
    inherit src cargoArtifacts;
    stdenv = _: stdenv;
    pname = "aegaeon-workspace-nextest";
    version = "0.0.0";
    cargoToml = ../../Cargo.toml;
    cargoExtraArgs = "--workspace";
    nativeBuildInputs = [
      pkgs.pkg-config
      karamel
    ];
    buildInputs = [
      pkgs.mbedtls
      pkgs.libsodium
      evercryptDist
    ];
  };

  inherit
    verifyFstar
    verifyTamarin
    verifyDudect
    verifyJose
    ;
}
// pkgs.lib.optionalAttrs isLinux {
  inherit verifyKani;
}
