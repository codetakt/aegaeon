{
  pkgs,
  isLinux,
  craneLib,
  src,
  cargoArtifacts,
  cargoLintChecks,
  stdenv,
  pre-commit-check,
  mkVerification,
  mkLightVerification,
  verifiedReqs,
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

  release-tags =
    pkgs.runCommand "release-tag-tests"
      {
        nativeBuildInputs = [
          pkgs.bash
          pkgs.git
          pkgs.gnupg
          (pkgs.python3.withPackages (ps: [ ps.pytest ]))
        ];
      }
      ''
        mkdir -p source/scripts/release source/tests/ci "$out"
        cp ${../../scripts/release/create_release.sh} source/scripts/release/create_release.sh
        cp ${../../scripts/release/create_release.py} source/scripts/release/create_release.py
        cp ${../../tests/ci/test_release_tags.py} source/tests/ci/test_release_tags.py
        cd source
        python3 -m pytest -q tests/ci/test_release_tags.py
        touch "$out/success"
      '';

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

  verified-reqs = verifiedReqs;

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

  server-clippy-inventory = cargoLintChecks.serverInventory;
  server-clippy-inventory-dev = cargoLintChecks.serverInventoryDev;
  supplemental-clippy = cargoLintChecks.supplemental;

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
  schema-guard = import ../schema-guard-check.nix { inherit pkgs; };
  preview-review-contract = import ../../examples/preview-review/check.nix { inherit pkgs; };
}
