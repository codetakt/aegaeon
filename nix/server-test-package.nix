# Compile an isolated server test suite and preserve Cargo-selected artifact bytes.
# Callers declare suite identity/commands; dependency and receipt construction stay shared.
{
  pkgs,
  craneLib,
  stdenv,
  src,
  rustToolchain,
  llvmPackages,
  karamel,
  evercryptDist,
}:
{
  pname,
  dependencyName,
  command,
  dependencyCommand ? command,
  identityName,
  buildLog,
  installer,
  profile ? null,
}:
let
  common = import ./rust-test-environment.nix {
    inherit
      pkgs
      stdenv
      src
      llvmPackages
      karamel
      evercryptDist
      ;
  };
  cargoArtifacts = craneLib.buildDepsOnly (
    common
    // {
      pname = dependencyName;
      buildPhaseCargoCommand = dependencyCommand;
      doCheck = false;
    }
  );
  identity = pkgs.writeText identityName (
    builtins.toJSON (
      {
        schema_version = 1;
        source = toString src;
        cargo = "${rustToolchain}/bin/cargo";
        rustc = "${rustToolchain}/bin/rustc";
        target = stdenv.hostPlatform.config;
        native_cc = "${llvmPackages.clang}/bin/cc";
        native_ar = "${llvmPackages.bintools}/bin/ar";
        evercrypt = toString evercryptDist;
        build_command = command;
      }
      // pkgs.lib.optionalAttrs (profile != null) { inherit profile; }
    )
  );
in
craneLib.mkCargoDerivation (
  common
  // {
    inherit pname cargoArtifacts;
    buildPhaseCargoCommand = ''
      ${command} --message-format=json-render-diagnostics > ${buildLog}
    '';
    checkPhaseCargoCommand = "";
    installPhaseCommand = ''
      ${pkgs.python3}/bin/python3 ${installer} \
        install ${buildLog} ${identity} "$out"
    '';
    doCheck = false;
    doInstallCargoArtifacts = false;
    # Preserve the bytes selected from Cargo's artifact messages.
    dontStrip = true;
    dontPatchELF = true;
  }
)
