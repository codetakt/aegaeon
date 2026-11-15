{
  pkgs,
  craneLib,
  stdenv,
  src,
  cargoArtifacts,
  karamel,
  evercryptDist,
}:
let
  testSource = import ./workspace-check-source.nix {
    inherit (pkgs) lib;
    source = src;
  };
  compilationSource = import ./workspace-test-compilation-source.nix {
    inherit (pkgs) lib;
    source = testSource;
  };
  common = {
    stdenv = _: stdenv;
    version = "0.0.0";
    cargoToml = ../Cargo.toml;
    nativeBuildInputs = with pkgs; [
      pkg-config
      openssl
      karamel
    ];
    buildInputs = with pkgs; [
      mbedtls
      libsodium
      evercryptDist
    ];
  };
  testBuild = craneLib.mkCargoDerivation (
    common
    // {
      pname = "aegaeon-workspace-test-build";
      src = compilationSource;
      # Match the nextest consumer's native inputs, including Crane's zstd.
      nativeBuildInputs = common.nativeBuildInputs ++ [ pkgs.cargo-nextest ];
      cargoArtifacts = cargoArtifacts.overrideAttrs (old: {
        nativeBuildInputs = [ pkgs.openssl ] ++ old.nativeBuildInputs;
      });
      buildPhaseCargoCommand = ''
        cargo test --locked --workspace --profile "$CARGO_PROFILE" --no-run
      '';
      doCheck = false;
    }
  );
in
craneLib.cargoNextest (
  common
  // {
    pname = "aegaeon-workspace-nextest";
    # Re-run every original test against the complete runtime input, even when
    # compilation can reuse artifacts after a workflow-only change.
    src = testSource;
    cargoArtifacts = testBuild;
    cargoExtraArgs = "--workspace";
    passthru = { inherit testBuild; };
  }
)
