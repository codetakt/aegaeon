{
  mkLightVerification,
  craneLib,
  src,
  cargoArtifacts,
  stdenv,
  aegaeonWorkspace,
  aegaeonDockerImage,
  verifiedCoreWasm,
  verifyFstar,
  verifyTamarin,
  verifyKani,
  verifyDudect,
  dudectCheck,
  verifyJose,
  verifyFstarAbstract,
  rustToolchain,
  asanRustToolchain,
  sharedCompilerRt,
  everparse,
  evercryptLib,
  evercryptDist,
  kani',
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
  inherit cargoArtifacts;

  default = aegaeonWorkspace;
  server = aegaeonWorkspace;
  docker-image = aegaeonDockerImage;
  verified-core-wasm = verifiedCoreWasm;

  verify-fstar = verifyFstar;
  verify-tamarin = verifyTamarin;
  verify-kani = verifyKani;
  verify-dudect = verifyDudect;
  dudect-check = dudectCheck;
  verify-jose = verifyJose;
  verify-abstract = verifyFstarAbstract;
  verified-reqs = mkLightVerification "verify-reqs" ../../scripts/flake/verify_reqs.sh [ ];
  ffi-contracts =
    mkLightVerification "verify-ffi-contracts" ../../scripts/flake/verify_ffi_contracts.sh
      [ ];
  lint-rust-strict-packages = craneLib.mkCargoDerivation {
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

  lint-server-clippy-inventory = craneLib.cargoClippy {
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

  toolchain-nightly = rustToolchain;
  toolchain-nightly-asan = asanRustToolchain;

  compiler-rt-shared = sharedCompilerRt;

  inherit
    verifyFstar
    verifyTamarin
    verifyKani
    verifyDudect
    verifyJose
    verifyFstarAbstract
    ;
  rustNightly = rustToolchain;
  rustNightlyAsan = asanRustToolchain;
  compilerRtShared = sharedCompilerRt;
  inherit everparse;
  evercrypt = evercryptLib;
  "evercrypt-dist" = evercryptDist;

  inherit kani';
}
