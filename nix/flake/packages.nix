{
  pkgs,
  src,
  openapiCheck,
  oidcKmsTest,
  joseServerTests,
  databaseTests,
  rfcTests,
  ffiContractCheck,
  assuranceStandards,
  verifiedReqs,
  lib,
  isLinux,
  cargoArtifacts,
  cargoLintChecks,
  strictRustCheck,
  aegaeonWorkspace,
  aegaeonDockerImage,
  aegaeonServerDistribution,
  verifiedCoreWasm,
  verifyFstar,
  verifyTamarin,
  verifyKani,
  verifyDudect,
  dudectCheck,
  dudectAnalysis,
  dudectAnalysisNatives,
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
{
  inherit cargoArtifacts;

  openapi-check = openapiCheck;

  oidc-kms-test = oidcKmsTest;
  database-tests = databaseTests;
  rfc-tests = rfcTests;
  jose-server-tests = joseServerTests "default";
  jose-server-strict-tests = joseServerTests "strict";

  default = aegaeonWorkspace;
  server = aegaeonWorkspace;
  verified-core-wasm = verifiedCoreWasm;

  verify-fstar = verifyFstar;
  verify-tamarin = verifyTamarin;
  verify-dudect = verifyDudect;
  dudect-check = dudectCheck;
  dudect-analysis = dudectAnalysis;
  dudect-analysis-native-gcc-legacy = dudectAnalysisNatives.gcc-legacy;
  dudect-analysis-native-gcc-nix = dudectAnalysisNatives.gcc-nix;
  dudect-analysis-native-clang-legacy = dudectAnalysisNatives.clang-legacy;
  dudect-analysis-native-clang-nix = dudectAnalysisNatives.clang-nix;
  verify-jose = verifyJose;
  verify-abstract = verifyFstarAbstract;
  assurance-standards = assuranceStandards;
  verified-reqs = verifiedReqs;
  ffi-contracts = ffiContractCheck;
  lint-rust-strict-packages = strictRustCheck;

  lint-server-clippy-inventory = cargoLintChecks.serverInventory;
  lint-server-clippy-inventory-dev = cargoLintChecks.serverInventoryDev;
  lint-supplemental-clippy = cargoLintChecks.supplemental;
  cargo-lint-artifacts = cargoLintChecks.devArtifacts;

  toolchain-nightly = rustToolchain;
  toolchain-nightly-asan = asanRustToolchain;

  compiler-rt-shared = sharedCompilerRt;

  inherit
    verifyFstar
    verifyTamarin
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

}
// lib.optionalAttrs isLinux {
  docker-image = aegaeonDockerImage;
  server-distribution = aegaeonServerDistribution;
  organizations-recovery = import ../organizations-recovery.nix { inherit pkgs; };
  organizations-recovery-integration = import ../organizations-recovery-integration.nix {
    inherit pkgs databaseTests;
    distribution = aegaeonServerDistribution;
    server = aegaeonWorkspace;
    source = src;
  };
  verify-kani = verifyKani;
  inherit verifyKani kani';
}
