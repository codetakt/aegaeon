# Check that hosted page assets ship in the server Cargo package and Docker
# build inputs. Crane vendors the locked dependencies, so `cargo package` runs
# offline from an empty CARGO_HOME with the pinned toolchain; the test refuses
# to skip here.
{
  pkgs,
  craneLib,
  src,
  stdenv,
}:
let
  inherit (pkgs) lib;
  root = src.origSrc or src;
in
craneLib.mkCargoDerivation {
  src = lib.fileset.toSource {
    inherit root;
    fileset = lib.fileset.unions [
      (root + "/Cargo.toml")
      (root + "/Cargo.lock")
      (root + "/README.md")
      (root + "/Dockerfile")
      (root + "/assets/brand")
      (root + "/crates")
      (root + "/xtask")
      (root + "/tests/ci/test_hosted_presentation_distribution.py")
    ];
  };
  stdenv = _: stdenv;
  pname = "aegaeon-hosted-presentation-distribution";
  version = "0.0.0";
  cargoToml = ../Cargo.toml;
  cargoLock = ../Cargo.lock;
  cargoArtifacts = null;
  nativeBuildInputs = [ (pkgs.python3.withPackages (ps: [ ps.pytest ])) ];
  buildPhaseCargoCommand = ''
    test -z "$(find "''${CARGO_HOME:?}" -path '*/registry/*' -print -quit)"
    AEGAEON_REQUIRE_DISTRIBUTION_TOOLS=1 \
      python3 -m pytest -q tests/ci/test_hosted_presentation_distribution.py
  '';
  checkPhaseCargoCommand = "";
  installPhaseCommand = ''
    mkdir -p $out
    touch $out/success
  '';
  doInstallCargoArtifacts = false;
}
