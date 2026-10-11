# One pinned build supplies URL-only admission and the actual workload.
{
  lib,
  pkgs,
  craneLib,
  stdenv,
  rustToolchain,
  llvmPackages,
  cargoArtifacts,
  buildSrc,
  source,
  runtimeInputs,
}:
let
  python = "${pkgs.python3}/bin/python3";
  producer = "${source}/scripts/perf/loadtest_supplier.py";
  target = stdenv.hostPlatform.config;
  argv = [
    "${rustToolchain}/bin/cargo"
    "build"
    "--release"
    "--frozen"
    "--offline"
    "--target"
    target
    "-p"
    "aegaeon-loadtest"
    "--bin"
    "aegaeon-loadtest"
    "--bin"
    "aegaeon-loadtest-url-check"
    "--message-format=json-render-diagnostics"
  ];
  toolchain = {
    cargo = "${rustToolchain}/bin/cargo";
    rustc = "${rustToolchain}/bin/rustc";
    inherit target;
  };
  package = craneLib.mkCargoDerivation {
    pname = "aegaeon-perf-load-supplier";
    version = "0.0.0";
    src = buildSrc;
    inherit cargoArtifacts;
    stdenv = _: stdenv;
    cargoToml = "${source}/Cargo.toml";
    cargoLock = "${source}/Cargo.lock";
    nativeBuildInputs = [
      llvmPackages.clang
      llvmPackages.bintools
      pkgs.pkg-config
    ];
    buildPhaseCargoCommand = ''
      ${rustToolchain}/bin/cargo metadata --frozen --offline --format-version=1 > loadtest-graph.json
      ${lib.escapeShellArgs argv} > loadtest-build.jsonl
    '';
    checkPhaseCargoCommand = "";
    installPhaseCommand = ''
      ${python} -I -B ${producer} install "$out" \
        ${lib.escapeShellArg (builtins.toJSON argv)} \
        ${lib.escapeShellArg (builtins.toJSON toolchain)}
    '';
    doInstallCargoArtifacts = false;
    doCheck = false;
    # P independently checks that the installed bytes equal the selected artifacts.
    dontStrip = true;
    dontPatchELF = true;
  };
  manifest = pkgs.runCommand "aegaeon-perf-source-inventory.json" { } ''
    ${python} -I -B ${producer} inventory ${source} ${pkgs.nix}/bin/nix-store "$out"
  '';
  binding = pkgs.runCommand "aegaeon-perf-load-supplier.json" { } ''
    ${python} -I -B ${producer} bind ${manifest} ${buildSrc} ${package} \
      ${pkgs.nix}/bin/nix-store "$out"
  '';
  controller =
    pkgs.runCommand "aegaeon-perf-load"
      {
        meta.mainProgram = "aegaeon-perf-load";
      }
      ''
        ${python} -I -B ${producer} launchers ${source} ${binding} "$out/bin" \
          ${lib.escapeShellArg (
            builtins.toJSON {
              inherit python;
              git = "${pkgs.git}/bin/git";
              bash = "${pkgs.bash}/bin/bash";
              runtime_path = lib.makeBinPath (
                lib.unique (
                  [
                    pkgs.git
                    pkgs.python3
                    pkgs.bash
                  ]
                  ++ runtimeInputs
                )
              );
            }
          )}
      '';
in
{
  inherit
    package
    manifest
    binding
    controller
    ;
}
