{
  openapiCheck,
  ffiContractCheck,
  pkgs,
  isLinux,
  craneLib,
  src,
  cargoArtifacts,
  databaseTests,
  aegaeonServerDistribution,
  nodejsRuntime,
  cargoLintChecks,
  strictRustCheck,
  stdenv,
  pre-commit-check,
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
  workspaceCheckSource = import ../workspace-check-source.nix {
    inherit (pkgs) lib;
    source = src;
  };

in
{
  inherit pre-commit-check;

  openapi = openapiCheck;

  release-tags =
    pkgs.runCommand "release-tag-tests"
      {
        nativeBuildInputs = with pkgs; [
          bash
          git
          gnupg
          (python3.withPackages (ps: [ ps.pytest ]))
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
    mkLightVerification "verify-compliance-matrix" ../../scripts/flake/verify_compliance_matrix.sh
      [ ];

  verified-reqs = verifiedReqs;

  ffi-contracts = ffiContractCheck;

  workflow-lint = import ../workflow-lint.nix { inherit pkgs; };

  lti-claim-sources =
    pkgs.runCommand "lti-claim-sources"
      { nativeBuildInputs = [ (pkgs.python3.withPackages (ps: [ ps.pytest ])) ]; }
      ''
        export PYTHONDONTWRITEBYTECODE=1
        cd ${src}
        python3 scripts/validation/generate_lti_time_zones.py --check
        python3 -m pytest -q -p no:cacheprovider scripts/validation/test_lti_time_zones.py
        touch "$out"
      '';

  lti-catalog-upgrade = import ../tests/lti-catalog-upgrade.nix { inherit pkgs; };
  postgresql-version = import ../postgresql-version-check.nix { inherit pkgs; };

  rust-strict-packages = strictRustCheck;

  server-clippy-inventory = cargoLintChecks.serverInventory;
  server-clippy-inventory-dev = cargoLintChecks.serverInventoryDev;
  supplemental-clippy = cargoLintChecks.supplemental;

  clippy = craneLib.cargoClippy {
    inherit cargoArtifacts;
    src = workspaceCheckSource;
    stdenv = _: stdenv;
    pname = "aegaeon-workspace-clippy";
    version = "0.0.0";
    cargoToml = ../../Cargo.toml;
    cargoExtraArgs = "--workspace";
  };

  tests = import ../workspace-tests.nix {
    inherit
      pkgs
      craneLib
      stdenv
      src
      cargoArtifacts
      karamel
      evercryptDist
      ;
  };

  inherit
    verifyFstar
    verifyTamarin
    verifyDudect
    verifyJose
    ;
}
// pkgs.lib.optionalAttrs isLinux {
  lti-packaged-runtime = import ../tests/lti-packaged-runtime.nix {
    inherit
      pkgs
      src
      databaseTests
      aegaeonServerDistribution
      nodejsRuntime
      ;
  };
  lti-browser-consent = import ../tests/lti-browser-consent.nix {
    inherit
      pkgs
      src
      databaseTests
      nodejsRuntime
      ;
  };

  inherit verifyKani;
  schema-guard = import ../schema-guard-check.nix { inherit pkgs; };
  preview-review-contract = import ../../examples/preview-review/check.nix { inherit pkgs; };
}
