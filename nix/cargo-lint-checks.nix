# Keep shell, package, and flake-check entry points on the same lint commands.
{
  pkgs,
  craneLib,
  src,
  cargoArtifacts,
  stdenv,
  karamel,
  evercryptDist,
}:
let
  common = {
    inherit src;
    stdenv = _: stdenv;
    version = "0.0.0";
    cargoToml = ../Cargo.toml;
    cargoLock = ../Cargo.lock;
    nativeBuildInputs = [
      pkgs.pkg-config
      pkgs.ripgrep
      karamel
    ];
    buildInputs = [
      pkgs.mbedtls
      pkgs.libsodium
      evercryptDist
    ];
    CARGO_INCREMENTAL = "0";
  };
  # The direct Cargo checks used the dev profile. Share its dependency metadata
  # separately from the existing release artifacts; never alias different profiles.
  devArtifacts = craneLib.buildDepsOnly (
    common
    // {
      pname = "aegaeon-cargo-lint-artifacts";
      CARGO_PROFILE = "dev";
      buildPhaseCargoCommand = "cargo check --profile dev --workspace --all-targets --locked";
      doCheck = false;
    }
  );
  mkLint =
    name: profile: artifacts: script:
    craneLib.mkCargoDerivation (
      common
      // {
        pname = name;
        CARGO_PROFILE = profile;
        cargoArtifacts = artifacts;
        buildPhaseCargoCommand = ''
          ${pkgs.bash}/bin/bash ${script}
        '';
        checkPhaseCargoCommand = "";
        installPhaseCommand = ''
          mkdir -p "$out"
          touch "$out/success"
        '';
        doInstallCargoArtifacts = false;
      }
    );
in
{
  inherit devArtifacts;
  supplemental =
    mkLint "aegaeon-supplemental-clippy" "dev" devArtifacts
      "scripts/flake/lint_supplemental_clippy.sh";
  serverInventoryDev =
    mkLint "aegaeon-server-clippy-inventory-dev" "dev" devArtifacts
      "scripts/flake/lint_server_clippy_inventory.sh";
  serverInventory =
    mkLint "aegaeon-server-clippy-inventory" "release" cargoArtifacts
      "scripts/flake/lint_server_clippy_inventory.sh";
}
